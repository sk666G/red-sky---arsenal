package adgo

import (
	"errors"
	"fmt"
)

// EType-aware encrypt/decrypt dispatch for the full Kerberos chain.
//
// RC4-HMAC (etype 23) goes through our own EncryptTimestampRC4 / DecryptRC4.
// AES-128 (17) and AES-256 (18) go through the gokrb5-backed AESEncrypt /
// AESDecrypt wrappers.
//
// Every site that needs "the right cipher for this etype" calls these two
// functions. Call sites stop branching on etype; the branch lives here.

// ErrUnsupportedEType — the etype isn't one of the ones this package
// handles.
var ErrUnsupportedEType = errors.New("adgo: unsupported etype")

// EncryptionKeyFor derives the long-term key for the given etype from a
// password and realm/username. RC4 uses MD4(UTF-16LE(pw)); AES uses
// PBKDF2-HMAC-SHA1(pw, REALM||user, 4096, keyBytes).
func EncryptionKeyFor(etype int32, password, realm, username string) ([]byte, error) {
	switch etype {
	case ETypeRC4_HMAC:
		return DeriveRC4Key(password)
	case ETypeAES128:
		return DeriveAESKey(password, realm+username, 128)
	case ETypeAES256:
		return DeriveAESKey(password, realm+username, 256)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEType, etype)
	}
}

// EncryptWithEType encrypts plaintext at key usage keyUsage using whichever
// cipher the etype names. RC4-HMAC output is HMAC || ciphertext; AES output
// is AES-CTS(confounder || plaintext) || HMAC (the gokrb5 wire format).
func EncryptWithEType(key, plaintext []byte, keyUsage uint32, etype int32) ([]byte, error) {
	switch etype {
	case ETypeRC4_HMAC:
		return encryptRC4WithUsage(key, plaintext, keyUsage)
	case ETypeAES128, ETypeAES256:
		return AESEncrypt(key, plaintext, keyUsage, etype)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEType, etype)
	}
}

// DecryptWithEType reverses EncryptWithEType.
func DecryptWithEType(key, ciphertext []byte, keyUsage uint32, etype int32) ([]byte, error) {
	switch etype {
	case ETypeRC4_HMAC:
		return DecryptRC4(key, ciphertext, keyUsage)
	case ETypeAES128, ETypeAES256:
		return AESDecrypt(key, ciphertext, keyUsage, etype)
	default:
		return nil, fmt.Errorf("%w: %d", ErrUnsupportedEType, etype)
	}
}
