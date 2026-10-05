package adgo

import (
	"bytes"
	"crypto/hmac"
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/cryptogo"
)

// PA-ENC-TIMESTAMP padata for authenticated AS-REQ.
//
// To get a TGT (rather than just an AS-REP roast), the client must prove
// knowledge of the account's long-term key. The standard method is
// PA-ENC-TIMESTAMP: encrypt a timestamp with the user's key, wrap it in
// padata, and put it in the AS-REQ's padata [3] field. The DC decrypts it,
// verifies the timestamp is fresh, and returns an AS-REP with a session
// key encrypted under the same long-term key.
//
// The long-term key derivation depends on the encryption type:
//
//   RC4-HMAC (etype 23): key = NT hash = MD4(UTF-16LE(password))
//   AES-128  (etype 17): key = PBKDF2-HMAC-SHA1(password, salt, 4096, 16)
//   AES-256  (etype 18): key = PBKDF2-HMAC-SHA1(password, salt, 4096, 32)
//
// The padata stream (RFC 4120 §5.2.7):
//
//   PA-DATA ::= SEQUENCE {
//       padata-type  [1] Int32,
//       padata-value [2] OCTET STRING
//   }
//
//   padata-type 2 = PA-ENC-TIMESTAMP
//   padata-value = EncryptedData containing the timestamp

// PADataType identifiers.
const (
	PADataEncTimestamp       = 2
	PADataPacRequest         = 128
	PADataEncryptedChallenge = 11
)

// KerbKey is a long-term key derived from a password.
type KerbKey struct {
	EType int32
	Bytes []byte
}

// DeriveRC4Key returns the RC4-HMAC long-term key: MD4(UTF-16LE(password)).
// Same as the NT hash — the RC4-HMAC Kerberos key IS the NT hash.
func DeriveRC4Key(password string) ([]byte, error) {
	// NT hash = MD4(UTF-16LE(password))
	runes := []rune(password)
	u16 := utf16Encode(runes)
	return cryptogo.MD4(u16), nil
}

// utf16Encode returns the UTF-16LE encoding of the runes.
func utf16Encode(runes []rune) []byte {
	out := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		if r < 0x10000 {
			out = append(out, byte(r), byte(r>>8))
		} else {
			// surrogate pair
			r -= 0x10000
			hi := 0xD800 + (r >> 10)
			lo := 0xDC00 + (r & 0x3FF)
			out = append(out, byte(hi), byte(hi>>8), byte(lo), byte(lo>>8))
		}
	}
	return out
}

// RC4Encrypt applies the RC4 stream cipher. Pure-Go implementation —
// crypto/rc4 was deprecated and removed from the stdlib.
func RC4Encrypt(key, plaintext []byte) []byte {
	// KSA
	var S [256]byte
	for i := 0; i < 256; i++ {
		S[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(S[i]) + int(key[i%len(key)])) & 0xFF
		S[i], S[j] = S[j], S[i]
	}
	// PRGA
	out := make([]byte, len(plaintext))
	i, jj := 0, 0
	for k := 0; k < len(plaintext); k++ {
		i = (i + 1) & 0xFF
		jj = (jj + int(S[i])) & 0xFF
		S[i], S[jj] = S[jj], S[i]
		ks := S[(int(S[i])+int(S[jj]))&0xFF]
		out[k] = plaintext[k] ^ ks
	}
	return out
}

// HMACMD5 computes HMAC-MD5(key, data).
func HMACMD5(key, data []byte) []byte {
	h := hmac.New(md5.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// EncryptTimestampRC4 performs the RC4-HMAC encryption used by
// PA-ENC-TIMESTAMP for etype 23.
//
// RFC 4757 §7.5.1: for key usage K, the RC4-HMAC key is:
//
//	K1 = HMAC-MD5(nt_hash, usage_le)
//	K3 = HMAC-MD5(K1, checksum)
//	ciphertext = RC4(K3, plaintext)
//
// For PA-ENC-TIMESTAMP with a request, key usage = 1. The checksum is
// HMAC-MD5(K1, plaintext).
func EncryptTimestampRC4(ntHash []byte, timestamp []byte) ([]byte, error) {
	if len(ntHash) != 16 {
		return nil, errors.New("adgo: NT hash must be 16 bytes")
	}
	// key usage 1 (AS-REQ PA-ENC-TIMESTAMP)
	var usage [4]byte
	binary.LittleEndian.PutUint32(usage[:], 1)
	k1 := HMACMD5(ntHash, usage[:])
	checksum := HMACMD5(k1, timestamp)
	k3 := HMACMD5(k1, checksum)
	cipher := RC4Encrypt(k3, timestamp)
	// output = checksum || ciphertext (RFC 4757 §7.5.2)
	out := append([]byte{}, checksum...)
	out = append(out, cipher...)
	return out, nil
}

// DERGeneralizedTimeStamp formats time.Now() as Kerberos generalized time.
func DERGeneralizedTimeStamp() string {
	return time.Now().UTC().Format("20060102150405") + "Z"
}

// PAEncTimestamp is a PA-ENC-TIMESTAMP padata element.
type PAEncTimestamp struct {
	KerbKeyBytes []byte // the long-term key (NT hash for RC4)
	EType        int32
}

// Marshal encodes the padata into a PA-DATA SEQUENCE.
//
// ASN.1 PA-ENC-TIMESTAMP:
//
//	PA-ENC-TIMESTAMP ::= EncryptedData   -- contains PA-ENC-TS-ENC
//
//	PA-ENC-TS-ENC ::= SEQUENCE {
//	    patimestamp [0] KerberosTime,
//	    pausec      [1] Microseconds OPTIONAL
//	}
func (p PAEncTimestamp) Marshal() ([]byte, error) {
	// build PA-ENC-TS-ENC (the plaintext)
	ts := DERGeneralizedTimeStamp()
	inner := DERContextTag(0, false, DERGeneralizedTime(ts))
	// add pausec (microseconds) optional — skip for now

	tsEnc := DERSequence(inner)

	// etype-aware: RC4-HMAC, AES-128, or AES-256 via the dispatcher. The
	// caller is responsible for having derived the key at the right length
	// for the requested etype.
	cipher, err := EncryptWithEType(p.KerbKeyBytes, tsEnc, KerbUsageASReqPAEncTimestamp, p.EType)
	if err != nil {
		return nil, err
	}

	// EncryptedData ::= SEQUENCE {
	//     etype [0] Int32,
	//     kvno  [1] Int32 OPTIONAL,
	//     cipher [2] OCTET STRING
	// }
	var encBody []byte
	encBody = append(encBody, DERContextTag(0, false, DERInteger(int64(p.EType)))...)
	encBody = append(encBody, DERContextTag(2, false, DEROctetString(cipher))...)
	encData := DERSequence(encBody)

	// PA-DATA ::= SEQUENCE {
	//     padata-type [1] Int32,
	//     padata-value [2] OCTET STRING
	// }
	var pdBody []byte
	pdBody = append(pdBody, DERContextTag(1, false, DERInteger(PADataEncTimestamp))...)
	pdBody = append(pdBody, DERContextTag(2, false, DEROctetString(encData))...)
	return DERSequence(pdBody), nil
}

// BuildASREQWithPadata is the authenticated AS-REQ variant. Same shape
// as BuildASREQ but with the padata [3] field populated.
func BuildASREQWithPadata(opts ASREQOptions, padata []byte) ([]byte, error) {
	base, err := BuildASREQ(opts)
	if err != nil {
		return nil, err
	}
	// rebuild with padata by inserting the [3] field inside the
	// KDC-REQ SEQUENCE. The base AS-REQ is:
	//   [APPLICATION 10] SEQUENCE {
	//     [1] INTEGER 5 (pvno),
	//     [2] INTEGER 10 (msg-type),
	//     [4] KDC-REQ-BODY
	//   }
	// We want to insert [3] padata between [2] and [4].
	//
	// Simplest approach: parse the base, insert, re-encode.
	r := NewDERReader(base)
	tag, content, err := r.ReadTLV()
	if err != nil {
		return nil, err
	}
	if TagClass(tag) != ClassApplication || TagNumber(tag) != 10 {
		return nil, errors.New("adgo: base AS-REQ has unexpected tag")
	}
	rr := NewDERReader(content)
	_, inner, err := rr.ReadTLV()
	if err != nil {
		return nil, err
	}

	// walk the fields
	var out []byte
	ir := NewDERReader(inner)
	inserted := false
	for {
		ft, fc, err := ir.ReadTLV()
		if err != nil {
			break
		}
		// insert padata [3] before req-body [4]
		if TagNumber(ft) == 4 && !inserted {
			// padata is a SEQUENCE OF PA-DATA; wrap our single PA-DATA
			padataSeq := DERSequence(padata)
			out = append(out, DERContextTag(3, true, padataSeq)...)
			inserted = true
		}
		out = append(out, TLV(ft, fc)...)
	}
	if !inserted {
		// no [4] field? append at end
		padataSeq := DERSequence(padata)
		out = append(out, DERContextTag(3, true, padataSeq)...)
	}

	// re-wrap
	return DERApplicationTag(10, true, DERSequence(out)), nil
}

// RandomBytes returns n bytes of cryptographic randomness.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}
	return b, nil
}

// BytesEqual compares two byte slices.
func BytesEqual(a, b []byte) bool {
	return bytes.Equal(a, b)
}
