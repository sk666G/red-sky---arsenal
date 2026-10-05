package adgo

import (
	"crypto/sha1"
	"errors"
	"fmt"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
	"github.com/jcmturner/gokrb5/v8/crypto/etype"
	"golang.org/x/crypto/pbkdf2"
)

// AES encryption for Kerberos — RFC 3961 §5.3, RFC 3962 §7.
//
// ETypeAES128 = 17, ETypeAES256 = 18 (declared in kerberos_asreq.go).
//
// Key derivation:
//
//	salt = REALM || username (uppercase realm)
//	key  = PBKDF2-HMAC-SHA1(pw, salt, 4096, 16 | 32)
//
// Encrypt / decrypt delegate to jcmturner/gokrb5/v8/crypto, which
// prepends a 16-byte confounder, runs AES-CTS, and appends the
// HMAC-SHA1-96 — all RFC 3962-correct. Output format is the standard
// Kerberos wire blob: AES-CTS(confounder || plaintext) || HMAC-SHA1-96.
const kerbPBKDF2Iterations = 4096

// DeriveAESKey derives an AES key from a password and salt.
// keyBits is 128 or 256. Salt for a normal user is REALM + username,
// REALM uppercase.
func DeriveAESKey(password, salt string, keyBits int) ([]byte, error) {
	if keyBits != 128 && keyBits != 256 {
		return nil, fmt.Errorf("adgo: AES keyBits must be 128 or 256, got %d", keyBits)
	}
	return pbkdf2.Key([]byte(password), []byte(salt), kerbPBKDF2Iterations, keyBits/8, sha1.New), nil
}

// gokrb5EType maps our etype int32 to a gokrb5 etype.EType.
func gokrb5EType(etypeVal int32) (etype.EType, error) {
	e, err := krbcrypto.GetEtype(etypeVal)
	if err != nil {
		return nil, fmt.Errorf("adgo: unsupported AES etype %d: %w", etypeVal, err)
	}
	return e, nil
}

// AESEncrypt encrypts plaintext with the AES etype at key usage keyUsage.
// Returns the wire blob: AES-CTS(confounder || plaintext) || HMAC.
func AESEncrypt(key []byte, plaintext []byte, keyUsage uint32, etypeVal int32) ([]byte, error) {
	e, err := gokrb5EType(etypeVal)
	if err != nil {
		return nil, err
	}
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("adgo: AES-%d key must be %d bytes, got %d",
			etypeVal, e.GetKeyByteSize(), len(key))
	}
	// gokrb5 EncryptMessage returns (iv, ciphertext||hmac, err). IV is
	// unused by the caller; the second return is the full wire blob.
	_, blob, err := e.EncryptMessage(key, plaintext, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("adgo: AES encrypt: %w", err)
	}
	return blob, nil
}

// AESDecrypt reverses AESEncrypt. ciphertext is the wire blob produced by
// AESEncrypt — the library verifies the HMAC and strips the confounder.
func AESDecrypt(key []byte, ciphertext []byte, keyUsage uint32, etypeVal int32) ([]byte, error) {
	e, err := gokrb5EType(etypeVal)
	if err != nil {
		return nil, err
	}
	macLen := e.GetHMACBitLength() / 8
	if len(ciphertext) < macLen+16 {
		return nil, errors.New("adgo: AES ciphertext shorter than mac+one block")
	}
	plaintext, err := e.DecryptMessage(key, ciphertext, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("adgo: AES decrypt: %w", err)
	}
	return plaintext, nil
}
