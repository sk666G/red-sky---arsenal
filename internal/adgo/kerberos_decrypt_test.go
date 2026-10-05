package adgo

import (
	"bytes"
	"testing"
)

// TestDecryptRC4RoundTrip — encrypt with usage 1, decrypt with usage 1,
// get the plaintext back.
func TestDecryptRC4RoundTrip(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	plaintext := []byte("the plaintext payload for the timestamp")

	// encrypt with usage 1 (AS-REQ PA-ENC-TIMESTAMP)
	cipher, err := EncryptTimestampRC4(ntHash, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	// decrypt with the same usage
	got, err := DecryptRC4(ntHash, cipher, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("RC4-HMAC round-trip mismatch:\n  got  %q\n  want %q", got, plaintext)
	}
}

// TestDecryptRC4WrongUsage — decrypting with the wrong key usage fails the
// checksum (because K1 differs).
func TestDecryptRC4WrongUsage(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	plaintext := []byte("some payload")
	cipher, _ := EncryptTimestampRC4(ntHash, plaintext)
	// usage 1 ciphertext, decrypt with usage 3
	_, err := DecryptRC4(ntHash, cipher, 3)
	if err == nil {
		t.Fatal("expected checksum mismatch for wrong usage")
	}
}

// TestDecryptRC4WrongKey — decrypting with the wrong key fails.
func TestDecryptRC4WrongKey(t *testing.T) {
	correctKey, _ := DeriveRC4Key("password")
	wrongKey, _ := DeriveRC4Key("wrongpassword")
	plaintext := []byte("payload")
	cipher, _ := EncryptTimestampRC4(correctKey, plaintext)
	_, err := DecryptRC4(wrongKey, cipher, 1)
	if err == nil {
		t.Fatal("expected checksum mismatch for wrong key")
	}
}

// TestDecryptRC4ShortCiphertext — a blob shorter than the checksum is
// rejected cleanly.
func TestDecryptRC4ShortCiphertext(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	_, err := DecryptRC4(ntHash, []byte{0x01, 0x02, 0x03}, 1)
	if err == nil {
		t.Fatal("expected error for short ciphertext")
	}
}

// TestDecryptRC4WrongKeyLen — the long-term key must be 16 bytes.
func TestDecryptRC4WrongKeyLen(t *testing.T) {
	_, err := DecryptRC4([]byte("short"), make([]byte, 32), 1)
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

// TestDecryptASRepPartFallsBackToLegacy — ciphertext produced with usage
// 8 (legacy) should still decrypt because DecryptASRepPart falls back.
func TestDecryptASRepPartFallsBackToLegacy(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	plaintext := []byte("some encpart payload")

	// craft a usage-8 ciphertext
	cipher, _ := EncryptTimestampRC4(ntHash, plaintext)
	// EncryptTimestampRC4 uses usage 1, so we need to manually encrypt with
	// usage 3 to test the primary path
	// Simplest: re-encrypt via the encrypt path with a fake usage by
	// calling EncryptTimestampRC4 which always uses usage 1 — so test
	// primary path by producing usage-3 ciphertext manually
	cipher3, err := encryptRC4WithUsage(ntHash, plaintext, KerbUsageASRepEncPart)
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecryptASRepPart(ntHash, cipher3, ETypeRC4_HMAC)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("usage-3 decrypt mismatch")
	}

	// now the legacy usage-8 path
	cipher8, _ := encryptRC4WithUsage(ntHash, plaintext, 8)
	got2, err := DecryptASRepPart(ntHash, cipher8, ETypeRC4_HMAC)
	if err != nil {
		t.Fatalf("legacy usage fallback failed: %v", err)
	}
	if !bytes.Equal(got2, plaintext) {
		t.Fatalf("legacy usage-8 decrypt mismatch")
	}
	_ = cipher
}

// TestParseEncASRepPartEmpty — no crash on empty input.
func TestParseEncASRepPartEmpty(t *testing.T) {
	_, err := ParseEncASRepPart([]byte{})
	if err == nil {
		t.Fatal("expected error for empty input")
	}
}

// TestParseEncASRepPartRejectsBadTag — not a SEQUENCE.
func TestParseEncASRepPartRejectsBadTag(t *testing.T) {
	_, err := ParseEncASRepPart([]byte{0x80, 0x00})
	if err == nil {
		t.Fatal("expected error for non-SEQUENCE")
	}
}

// TestParseEncASRepPartSessionKeyShape — build a minimal EncASRepPart
// with a session key field and verify extraction.
func TestParseEncASRepPartSessionKeyShape(t *testing.T) {
	// hand-build: SEQUENCE { [0] SEQUENCE { [0] INTEGER 23, [1] OCTET STRING <16 bytes> } }
	sessionKey := bytes.Repeat([]byte{0xAA}, 16)
	// [0] etype INTEGER 23 → 80 03 02 01 17
	etypeDER := DERContextTag(0, false, DERInteger(int64(ETypeRC4_HMAC)))
	// [1] OCTET STRING → A1 12 04 10 AA..AA
	valueDER := DERContextTag(1, true, DEROctetString(sessionKey))
	encKeySeq := DERSequence(append(etypeDER, valueDER...))
	keyField := DERContextTag(0, true, encKeySeq)
	outer := DERSequence(keyField)

	parsed, err := ParseEncASRepPart(outer)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.SessionKeyType != int32(ETypeRC4_HMAC) {
		t.Fatalf("session key type: %d", parsed.SessionKeyType)
	}
	if !bytes.Equal(parsed.SessionKeyBytes, sessionKey) {
		t.Fatalf("session key mismatch:\n  got  %x\n  want %x", parsed.SessionKeyBytes, sessionKey)
	}
}
