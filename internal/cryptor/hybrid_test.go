package cryptor

import (
	"bytes"
	"os"
	"testing"
)

// TestMagicBytes pins the header prefix. This is the invariant that keeps
// the Go and Python .rsky files byte-compatible.
func TestMagicBytes(t *testing.T) {
	want := []byte{'R', 'S', 'K', 'Y', '4', '2', 0x01, 0x00}
	if !bytes.Equal(Magic, want) {
		t.Fatalf("magic mismatch:\n  got  %q\n  want %q", Magic, want)
	}
	if len(Magic) != 8 {
		t.Fatalf("magic length %d, want 8", len(Magic))
	}
}

// TestVersion pins the file format version.
func TestVersion(t *testing.T) {
	if Version[0] != 1 || Version[1] != 0 {
		t.Fatalf("version %v, want (1,0)", Version)
	}
}

// TestKeygenPEMShape confirms the keygen produces valid PEM PEM blocks.
func TestKeygenPEMShape(t *testing.T) {
	priv, pub, err := GenerateKey(2048, "")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(priv, []byte("-----BEGIN PRIVATE KEY-----")) {
		t.Fatalf("priv PEM prefix wrong: %q", priv[:40])
	}
	if !bytes.HasSuffix(priv, []byte("-----END PRIVATE KEY-----\n")) {
		t.Fatalf("priv PEM suffix wrong")
	}
	if !bytes.HasPrefix(pub, []byte("-----BEGIN PUBLIC KEY-----")) {
		t.Fatalf("pub PEM prefix wrong: %q", pub[:40])
	}
}

// TestKeygenPasswordProtects confirms a passphrase produces an encrypted
// PEM block.
func TestKeygenPasswordProtects(t *testing.T) {
	priv, _, err := GenerateKey(2048, "secret")
	if err != nil {
		t.Fatal(err)
	}
	// encrypted PEM blocks carry a "Proc-Type: 4,ENCRYPTED" or
	// "DEK-Info:" header inside the base64 blob
	if !bytes.Contains(priv, []byte("Proc-Type")) && !bytes.Contains(priv, []byte("DEK-Info")) {
		t.Fatalf("encrypted PEM missing header markers:\n%s", priv[:300])
	}
}

// TestKeygenRoundTrip — generate, load, and confirm the loaded key
// functions.
func TestKeygenRoundTrip(t *testing.T) {
	privPEM, pubPEM, err := GenerateKey(2048, "")
	if err != nil {
		t.Fatal(err)
	}
	priv, err := LoadPrivateKey(privPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := LoadPublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	// verify the two keys match by comparing their N
	if priv.N.Cmp(pub.N) != 0 {
		t.Fatalf("loaded keys don't match")
	}
}

// TestEncryptDecryptRoundTrip — the fundamental invariant. Encrypt a small
// blob, decrypt with the private key, get the original back.
func TestEncryptDecryptRoundTrip(t *testing.T) {
	privPEM, pubPEM, err := GenerateKey(2048, "")
	if err != nil {
		t.Fatal(err)
	}
	priv, _ := LoadPrivateKey(privPEM, "")
	pub, _ := LoadPublicKey(pubPEM)

	plaintext := []byte("hello, world")
	blob, err := EncryptBlob(plaintext, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptBlob(blob, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("round-trip mismatch:\n  got  %q\n  want %q", got, plaintext)
	}
}

// TestEncryptHeaderLayout verifies the header starts with the magic and
// carries the expected fields at fixed offsets.
func TestEncryptHeaderLayout(t *testing.T) {
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	blob, err := EncryptBlob([]byte("x"), pub, 0xDEADBEEF)
	if err != nil {
		t.Fatal(err)
	}
	// magic (8 bytes)
	if !bytes.Equal(blob[:8], Magic) {
		t.Fatalf("magic prefix wrong")
	}
	// version (2 bytes) at 8
	if blob[8] != 1 || blob[9] != 0 {
		t.Fatalf("version bytes wrong: %02x%02x", blob[8], blob[9])
	}
	// key_id (4 bytes) at 10, big-endian
	if blob[10] != 0xDE || blob[11] != 0xAD || blob[12] != 0xBE || blob[13] != 0xEF {
		t.Fatalf("key_id wrong: %02x%02x%02x%02x", blob[10], blob[11], blob[12], blob[13])
	}
	// wlen (2 bytes) at 14, big-endian. 2048-bit RSA wrap = 256 bytes
	wlen := int(blob[14])<<8 | int(blob[15])
	if wlen != 256 {
		t.Fatalf("wrapped key length %d, want 256", wlen)
	}
}

// TestEncryptProducesDifferentCiphertextForSamePlaintext — GCM with a
// fresh nonce means identical plaintext produces different ciphertext.
func TestEncryptProducesDifferentCiphertextForSamePlaintext(t *testing.T) {
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)
	plaintext := []byte("same")
	b1, _ := EncryptBlob(plaintext, pub, 0)
	b2, _ := EncryptBlob(plaintext, pub, 0)
	if bytes.Equal(b1, b2) {
		t.Fatalf("two encryptions of the same plaintext produced identical output — nonce reuse")
	}
}

// TestDecryptFailsOnTamperedCiphertext — GCM authentication must reject
// modified ciphertext.
func TestDecryptFailsOnTamperedCiphertext(t *testing.T) {
	privPEM, pubPEM, _ := GenerateKey(2048, "")
	priv, _ := LoadPrivateKey(privPEM, "")
	pub, _ := LoadPublicKey(pubPEM)

	blob, _ := EncryptBlob([]byte("tamper target"), pub, 0)
	// flip a byte in the ciphertext portion
	tampered := append([]byte(nil), blob...)
	tampered[len(tampered)-1] ^= 0xFF
	_, err := DecryptBlob(tampered, priv)
	if err == nil {
		t.Fatalf("tampered ciphertext decrypted without error")
	}
}

// TestDecryptFailsOnTamperedTag — flipping the GCM tag must be caught.
func TestDecryptFailsOnTamperedTag(t *testing.T) {
	privPEM, pubPEM, _ := GenerateKey(2048, "")
	priv, _ := LoadPrivateKey(privPEM, "")
	pub, _ := LoadPublicKey(pubPEM)

	blob, _ := EncryptBlob([]byte("x"), pub, 0)
	// tag is at offset: 8 (magic) + 2 (ver) + 4 (keyid) + 2 (wlen) + wlen
	// + 12 (nonce)
	wlen := int(blob[14])<<8 | int(blob[15])
	tagOff := 8 + 2 + 4 + 2 + wlen + 12
	tampered := append([]byte(nil), blob...)
	tampered[tagOff] ^= 0xFF
	_, err := DecryptBlob(tampered, priv)
	if err == nil {
		t.Fatalf("tampered GCM tag decrypted without error")
	}
}

// TestIsEncryptedHitsMagic — IsEncrypted checks the header prefix.
func TestIsEncryptedHitsMagic(t *testing.T) {
	if IsEncrypted([]byte("plaintext")) {
		t.Fatalf("plaintext identified as encrypted")
	}
	if !IsEncrypted(Magic) {
		t.Fatalf("magic prefix not recognized")
	}
	if !IsEncrypted(append(append([]byte(nil), Magic...), []byte("more")...)) {
		t.Fatalf("magic + payload not recognized")
	}
	// short input should not panic
	if IsEncrypted([]byte{0x01}) {
		t.Fatalf("short input flagged as encrypted")
	}
	if IsEncrypted(nil) {
		t.Fatalf("nil flagged as encrypted")
	}
}

// TestDecryptRejectsBadMagic — a blob that starts with the wrong magic
// must fail cleanly, not corrupt memory.
func TestDecryptRejectsBadMagic(t *testing.T) {
	privPEM, _, _ := GenerateKey(2048, "")
	priv, _ := LoadPrivateKey(privPEM, "")
	fake := append([]byte("WRONGMAG"), []byte("lots of trailing bytes to satisfy the length check ...")...)
	_, err := DecryptBlob(fake, priv)
	if err == nil {
		t.Fatalf("bad magic decrypted without error")
	}
}

// TestDecryptRejectsShortBlob confirms the length guard.
func TestDecryptRejectsShortBlob(t *testing.T) {
	privPEM, _, _ := GenerateKey(2048, "")
	priv, _ := LoadPrivateKey(privPEM, "")
	_, err := DecryptBlob([]byte("RS"), priv)
	if err == nil {
		t.Fatalf("short blob decrypted without error")
	}
}

// TestEncryptFileRoundTrip writes a file, encrypts in place, decrypts,
// compares.
func TestEncryptFileRoundTrip(t *testing.T) {
	tmp := t.TempDir()
	src := tmp + "/test.txt"
	content := []byte("this is the content of the test file, in plain bytes")
	if err := writeFile(src, content); err != nil {
		t.Fatal(err)
	}

	privPEM, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)
	priv, _ := LoadPrivateKey(privPEM, "")

	in, out, err := EncryptFile(src, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if in != len(content) {
		t.Fatalf("EncryptFile in=%d, want %d", in, len(content))
	}
	if out <= len(content) {
		t.Fatalf("EncryptFile out=%d, should be larger than plaintext", out)
	}

	// read the encrypted blob back
	enc, err := readFile(src + ".rsky")
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptBlob(enc, priv)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, content) {
		t.Fatalf("file round-trip mismatch")
	}
}

// TestEncryptFileRejectsAlreadyEncrypted — encrypting an .rsky file
// should fail with a clear error.
func TestEncryptFileRejectsAlreadyEncrypted(t *testing.T) {
	tmp := t.TempDir()
	src := tmp + "/blob"
	// write an already-encrypted-looking file
	if err := writeFile(src, append(Magic, []byte("rest")...)); err != nil {
		t.Fatal(err)
	}
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)
	_, _, err := EncryptFile(src, pub, 0)
	if err == nil {
		t.Fatalf("already-encrypted file encrypted again")
	}
}

// --- tiny io helpers ---

func writeFile(path string, b []byte) error {
	return osWriteFileImpl(path, b)
}

func readFile(path string) ([]byte, error) {
	return osReadFileImpl(path)
}

func osWriteFileImpl(path string, b []byte) error {
	return os.WriteFile(path, b, 0o600)
}

func osReadFileImpl(path string) ([]byte, error) {
	return os.ReadFile(path)
}
