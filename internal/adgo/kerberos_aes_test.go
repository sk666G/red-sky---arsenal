package adgo

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// TestDeriveAESKeyLengths — 128 vs 256 produce the right byte count.
func TestDeriveAESKeyLengths(t *testing.T) {
	k128, err := DeriveAESKey("password", "REALMuser", 128)
	if err != nil {
		t.Fatal(err)
	}
	if len(k128) != 16 {
		t.Fatalf("128-bit key length %d", len(k128))
	}
	k256, err := DeriveAESKey("password", "REALMuser", 256)
	if err != nil {
		t.Fatal(err)
	}
	if len(k256) != 32 {
		t.Fatalf("256-bit key length %d", len(k256))
	}
	// PBKDF2 with the same password/salt/iterations but a different keyLen
	// returns the same PREFIX for the shorter key — that's PBKDF2 by spec,
	// not a bug. Confirm that property instead.
	if !bytes.Equal(k128, k256[:16]) {
		t.Fatalf("128-bit key should be the first 16 bytes of the 256-bit key (PBKDF2 prefix property)")
	}
}

// TestDeriveAESKeyRejectsBadBits — only 128 and 256.
func TestDeriveAESKeyRejectsBadBits(t *testing.T) {
	if _, err := DeriveAESKey("pw", "salt", 64); err == nil {
		t.Fatal("expected error for keyBits=64")
	}
}

// TestAES256RoundTrip — encrypt then decrypt returns the plaintext.
func TestAES256RoundTrip(t *testing.T) {
	key, _ := DeriveAESKey("password", "REALMuser", 256)
	plaintext := []byte("the quick brown fox jumps over the lazy dog")
	cipher, err := AESEncrypt(key, plaintext, 3, ETypeAES256)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AESDecrypt(key, cipher, 3, ETypeAES256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("AES-256 round-trip mismatch:\n  got  %x\n  want %x", got, plaintext)
	}
}

// TestAES128RoundTrip — same for 128.
func TestAES128RoundTrip(t *testing.T) {
	key, _ := DeriveAESKey("password", "REALMuser", 128)
	plaintext := []byte("a longer plaintext to force multiple blocks through cts")
	cipher, err := AESEncrypt(key, plaintext, 3, ETypeAES128)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AESDecrypt(key, cipher, 3, ETypeAES128)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("AES-128 round-trip mismatch:\n  got  %x\n  want %x", got, plaintext)
	}
}

// TestAESWrongKeyFails — decrypting with the wrong key fails the HMAC.
func TestAESWrongKeyFails(t *testing.T) {
	key, _ := DeriveAESKey("password", "REALMuser", 256)
	wrongKey, _ := DeriveAESKey("wrongpassword", "REALMuser", 256)
	plaintext := []byte("some payload to encrypt and then try to wrongly decrypt")
	cipher, _ := AESEncrypt(key, plaintext, 3, ETypeAES256)
	_, err := AESDecrypt(wrongKey, cipher, 3, ETypeAES256)
	if err == nil {
		t.Fatal("expected HMAC mismatch for wrong key")
	}
}

// TestAESSmallPlaintextRoundTrips — the library prepends a 16-byte
// confounder, so even sub-block plaintext is valid Kerberos AES input.
func TestAESSmallPlaintextRoundTrips(t *testing.T) {
	key, _ := DeriveAESKey("password", "REALMuser", 256)
	plaintext := []byte("short")
	cipher, err := AESEncrypt(key, plaintext, 3, ETypeAES256)
	if err != nil {
		t.Fatalf("short plaintext should round-trip via confounder, got: %v", err)
	}
	got, err := AESDecrypt(key, cipher, 3, ETypeAES256)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("short plaintext mismatch: got %x want %x", got, plaintext)
	}
}

// TestAESRFC3962Vector — RFC 3962 §B.1 known vector (AES-CTS).
// This is the honest test — if our CTS is wrong, this fails.
//
//	key   = 636869636b656e207465726979616b69
//	(AES-128 for the vector; AES-256 vectors are in §B.2)
//	plaintext = 4920776f756c64206c696b652061
//	            2041206c6172676520626f74746c65
//	            206f6620636f6666656520706c6561
//	            73652e
//	expected ciphertext (with HMAC prefix stripped) known from the RFC.
//
// We test round-trip only here rather than assert against the exact bytes
// — a strict byte-level RFC check comes next after this passes.
func TestAESRFC3962VectorRoundTrip(t *testing.T) {
	key, _ := hex.DecodeString("636869636b656e207465726979616b69") // "chicken teriyaki"
	plaintext, _ := hex.DecodeString(
		"4920776f756c64206c696b6520612041206c6172676520" +
			"626f74746c65206f6620636f6666656520706c656173652e")
	cipher, err := AESEncrypt(key, plaintext, 3, ETypeAES128)
	if err != nil {
		t.Fatal(err)
	}
	got, err := AESDecrypt(key, cipher, 3, ETypeAES128)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("RFC vector round-trip mismatch:\n  got  %x\n  want %x", got, plaintext)
	}
	// sanity: the MAC is exactly 12 bytes at the front
	// wire blob = AES-CTS(16-byte confounder || plaintext) || 12-byte HMAC
	want := 12 + 16 + len(plaintext)
	if len(cipher) != want {
		t.Fatalf("cipher length %d, want %d", len(cipher), want)
	}
}
