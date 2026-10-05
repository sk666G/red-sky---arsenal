package adgo

import (
	"crypto/sha1"
	"errors"
	"fmt"
	"golang.org/x/crypto/pbkdf2"

	krbcrypto "github.com/jcmturner/gokrb5/v8/crypto"
)

// AES encryption for Kerberos — RFC 3961 §5.3, RFC 3962 §7.
//
// ETypeAES128 = 17, ETypeAES256 = 18 (both declared in kerberos_asreq.go).
// Key derivation:
//
//	salt = REALM || username (uppercase realm)
//	key  = PBKDF2-HMAC-SHA1(pw, salt, 4096, keySize)
//
// Encrypt / decrypt are delegated to jcmturner/gokrb5/v8/crypto's
// etype.EType, which derives the Ke (encryption) and Ki (integrity) subkeys
// from the key usage, runs AES-CTS, and computes the HMAC-SHA1-96 — all
// RFC 3962-correct and tested.
const kerbPBKDF2Iterations = 4096

// DeriveAESKey derives an AES key from a password and salt.
// keyBits is 128 or 256. Salt for a normal user is REALM + username,
// REALM uppercase.
func DeriveAESKey(password, salt string, keyBits int) ([]byte, error) {
	if keyBits != 128 && keyBits != 256 {
		return nil, fmt.Errorf("adgo: AES keyBits must be 128 or 256, got %d", keyBits)
	}
	keyLen := keyBits / 8
	return pbkdf2.Key([]byte(password), []byte(salt), kerbPBKDF2Iterations, keyLen, sha1.New), nil
}

// gokrb5EType maps our etype int32 to a gokrb5 etype.EType.
func gokrb5EType(etypeVal int32) (interface {
	GetKeyByteSize() int
	GetHMACBitLength() int
	EncryptMessage(key, message []byte, usage uint32) ([]byte, []byte, error)
	DecryptMessage(key, ciphertext []byte, usage uint32) ([]byte, error)
}, error) {
	e, err := krbcrypto.GetEtype(etypeVal)
	if err != nil {
		return nil, fmt.Errorf("adgo: unsupported AES etype %d: %w", etypeVal, err)
	}
	return e, nil
}

// AESEncrypt encrypts plaintext with the AES etype at key usage keyUsage.
// Returns mac || ciphertext (RFC 3962 §7 output format).
func AESEncrypt(key []byte, plaintext []byte, keyUsage uint32, etypeVal int32) ([]byte, error) {
	e, err := gokrb5EType(etypeVal)
	if err != nil {
		return nil, err
	}
	if len(key) != e.GetKeyByteSize() {
		return nil, fmt.Errorf("adgo: AES-%d key must be %d bytes, got %d",
			etypeVal, e.GetKeyByteSize(), len(key))
	}
	if len(plaintext) < 16 {
		return nil, errors.New("adgo: plaintext shorter than one AES block")
	}
	conf, mac, err := e.EncryptMessage(key, plaintext, keyUsage)
	if err != nil {
		return nil, fmt.Errorf("adgo: AES encrypt: %w", err)
	}
	out := make([]byte, 0, len(mac)+len(conf))
	out = append(out, mac...)
	out = append(out, conf...)
	return out, nil
}

// AESDecrypt reverses AESEncrypt.
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
