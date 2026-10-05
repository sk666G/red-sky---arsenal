package adgo

import (
	"crypto/hmac"
	"crypto/md5"
	"errors"
	"fmt"
)

// RC4-HMAC decryption for Kerberos messages. The inverse of
// EncryptTimestampRC4 — used to decrypt AS-REP parts after obtaining
// the long-term key from a password (verified against the encrypt
// round-trip), or to decrypt TGS encrypted parts after a successful
// Kerberoast crack.
//
// RFC 4757 §7.5.2 decryption:
//   K1 = HMAC-MD5(long_term_key, usage_le)
//   checksum_expected = plaintext_prefix of length 16
//   K3 = HMAC-MD5(K1, checksum_received)
//   plaintext = RC4(K3, ciphertext)
//   verify: HMAC-MD5(K1, plaintext) == checksum_received

// DecryptRC4 reverses an RC4-HMAC encryption. ciphertext is the full
// blob: [16-byte HMAC checksum][RC4-encrypted plaintext].
func DecryptRC4(longTermKey, ciphertext []byte, keyUsage uint32) ([]byte, error) {
	if len(longTermKey) != 16 {
		return nil, errors.New("adgo: RC4 long-term key must be 16 bytes")
	}
	if len(ciphertext) < 16 {
		return nil, errors.New("adgo: ciphertext shorter than checksum")
	}
	// usage little-endian
	var usageBytes [4]byte
	usageBytes[0] = byte(keyUsage)
	usageBytes[1] = byte(keyUsage >> 8)
	usageBytes[2] = byte(keyUsage >> 16)
	usageBytes[3] = byte(keyUsage >> 24)

	k1 := HMACMD5(longTermKey, usageBytes[:])
	checksum := ciphertext[:16]
	enc := ciphertext[16:]
	k3 := HMACMD5(k1, checksum)
	plaintext := RC4Encrypt(k3, enc)

	// verify checksum over the recovered plaintext
	want := HMACMD5(k1, plaintext)
	if !hmac.Equal(want, checksum) {
		return nil, errors.New("adgo: RC4-HMAC checksum mismatch (wrong key or corrupted)")
	}
	return plaintext, nil
}

// Key usages for Kerberos messages (RFC 4120 §7.5.1).
const (
	KerbUsageASReqPAEncTimestamp  = 1
	KerbUsageASRepEncPart         = 3
	KerbUsageTGSReqPAEncTimestamp = 2
	KerbUsageTGSRepEncPart        = 8
	KerbUsageTGSRepEncPart2       = 9
	KerbUsageASRepEncPartOld      = 8 // legacy, some KDCs
)

// DecryptASRepPart decrypts the AS-REP encrypted part using the user's
// long-term key (NT hash for RC4-HMAC). Returns the DER-encoded
// EncASRepPart — the caller can then parse it to extract the session key
// and the TGT.
//
// encPart should be the raw bytes of the AS-REP's enc-part cipher field
// (i.e., resp.EncPart from ParseASREP).
func DecryptASRepPart(key, encPart []byte, etype int32) ([]byte, error) {
	// key usage 3 for AS-REP enc-part
	plain, err := DecryptWithEType(key, encPart, KerbUsageASRepEncPart, etype)
	if err != nil {
		// try the legacy usage (8) as a fallback — some older KDCs
		// mis-set this
		plain2, err2 := DecryptWithEType(key, encPart, 8, etype)
		if err2 == nil {
			return plain2, nil
		}
		return nil, err
	}
	return plain, nil
}

// DecryptTGSRepPart decrypts a TGS-REP encrypted part. Used after a
// Kerberoast when the operator has cracked the SPN owner's password.
// Key usage 8 or 9 depending on the response.
func DecryptTGSRepPart(key, encPart []byte, etype int32) ([]byte, error) {
	plain, err := DecryptWithEType(key, encPart, KerbUsageTGSRepEncPart, etype)
	if err == nil {
		return plain, nil
	}
	// try usage 9
	return DecryptWithEType(key, encPart, KerbUsageTGSRepEncPart2, etype)
}

// EncASRepPart is the parsed AS-REP encrypted part. Holds the fields
// the operator actually cares about: the session key, the ticket flags,
// and the TGT expiry.
type EncASRepPart struct {
	SessionKeyType  int32
	SessionKeyBytes []byte
	StartTime       string
	EndTime         string
	RenewTill       string
	Flags           uint32
	Realm           string
	ServerName      []string
	Raw             []byte
}

// ParseEncASRepPart walks the DER-encoded EncASRepPart and extracts the
// session key. It's not a full decoder — the interesting field is the
// session key, and that's what this returns.
//
//	EncASRepPart ::= SEQUENCE {
//	    key              [0] EncryptionKey,
//	    last-req         [1] LastReq,
//	    nonce            [2] UInt32,
//	    key-expiration   [3] KerberosTime OPTIONAL,
//	    flags            [4] TicketFlags,
//	    authtime         [5] KerberosTime,
//	    starttime        [6] KerberosTime OPTIONAL,
//	    endtime          [7] KerberosTime,
//	    renew-till       [8] KerberosTime OPTIONAL,
//	    srealm           [9] Realm,
//	    sname            [10] PrincipalName,
//	    caddr            [11] HostAddresses OPTIONAL
//	}
func ParseEncASRepPart(der []byte) (*EncASRepPart, error) {
	out := &EncASRepPart{Raw: der}
	r := NewDERReader(der)
	// outer SEQUENCE
	tag, content, err := r.ReadTLV()
	if err != nil {
		return nil, err
	}
	if TagClass(tag) != ClassUniversal || TagNumber(tag) != 16 {
		return nil, fmt.Errorf("adgo: EncASRepPart not a SEQUENCE (tag 0x%02x)", tag)
	}
	rr := NewDERReader(content)
	for {
		ft, fc, err := rr.ReadTLV()
		if err != nil {
			break
		}
		switch TagNumber(ft) {
		case 0:
			// key — EncryptionKey SEQUENCE { [0] etype, [1] value }
			sr := NewDERReader(fc)
			_, seqContent, err := sr.ReadTLV()
			if err != nil {
				continue
			}
			er := NewDERReader(seqContent)
			for {
				kt, kc, err := er.ReadTLV()
				if err != nil {
					break
				}
				if TagNumber(kt) == 0 {
					// etype Int32
					ir := NewDERReader(kc)
					_, ival, err := ir.ReadTLV()
					if err == nil {
						v, _ := DecodeInteger(ival)
						out.SessionKeyType = int32(v)
					}
				} else if TagNumber(kt) == 1 {
					// value — OCTET STRING
					vr := NewDERReader(kc)
					_, v, err := vr.ReadTLV()
					if err == nil {
						out.SessionKeyBytes = append([]byte(nil), v...)
					}
				}
			}
		case 4:
			// flags — TicketFlags (bit string)
			fr := NewDERReader(fc)
			_, fv, err := fr.ReadTLV()
			if err == nil && len(fv) >= 4 {
				// bit string content: 1 byte unused-bits count, then the
				// remaining bytes are the flag bits MSB first
				if len(fv) >= 5 {
					out.Flags = uint32(fv[1])<<24 | uint32(fv[2])<<16 | uint32(fv[3])<<8 | uint32(fv[4])
				}
			}
		case 5:
			// authtime
			tr := NewDERReader(fc)
			_, tv, err := tr.ReadTLV()
			if err == nil {
				out.StartTime = string(tv)
			}
		case 7:
			// endtime
			tr := NewDERReader(fc)
			_, tv, err := tr.ReadTLV()
			if err == nil {
				out.EndTime = string(tv)
			}
		case 8:
			// renew-till
			tr := NewDERReader(fc)
			_, tv, err := tr.ReadTLV()
			if err == nil {
				out.RenewTill = string(tv)
			}
		case 9:
			// srealm
			tr := NewDERReader(fc)
			_, tv, err := tr.ReadTLV()
			if err == nil {
				out.Realm = string(tv)
			}
		case 10:
			// sname — PrincipalName
			sr := NewDERReader(fc)
			_, seqContent, err := sr.ReadTLV()
			if err != nil {
				continue
			}
			er := NewDERReader(seqContent)
			for {
				st, sc, err := er.ReadTLV()
				if err != nil {
					break
				}
				if TagNumber(st) == 1 {
					// SEQUENCE OF KerberosString
					inner := NewDERReader(sc)
					_, listContent, err := inner.ReadTLV()
					if err != nil {
						continue
					}
					lr := NewDERReader(listContent)
					for {
						nt, nc, err := lr.ReadTLV()
						if err != nil {
							break
						}
						if TagNumber(nt) == 27 {
							out.ServerName = append(out.ServerName, string(nc))
						}
					}
				}
			}
		}
	}
	return out, nil
}

var _ = md5.New
