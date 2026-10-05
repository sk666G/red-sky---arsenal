package adgo

import (
	"bytes"
	"testing"
)

// TestDeriveRC4KeyKnownVector — NTLM of "password" is the classic NT hash.
// RC4-HMAC Kerberos key for a password IS the NT hash, so this test also
// pins the NTLM computation.
func TestDeriveRC4KeyKnownVector(t *testing.T) {
	got, err := DeriveRC4Key("password")
	if err != nil {
		t.Fatal(err)
	}
	// MD4(UTF-16LE("password")) = 8846f7eaee8fb117ad06bdd830b7586c
	want := []byte{0x88, 0x46, 0xf7, 0xea, 0xee, 0x8f, 0xb1, 0x17,
		0xad, 0x06, 0xbd, 0xd8, 0x30, 0xb7, 0x58, 0x6c}
	if !bytes.Equal(got, want) {
		t.Fatalf("NT hash mismatch:\n  got  %x\n  want %x", got, want)
	}
	if len(got) != 16 {
		t.Fatalf("key length %d, want 16", len(got))
	}
}

// TestUTF16EncodeBasic confirms UTF-16LE encoding.
func TestUTF16EncodeBasic(t *testing.T) {
	got := utf16Encode([]rune("AB"))
	want := []byte{'A', 0x00, 'B', 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("utf16: %x, want %x", got, want)
	}
}

// TestUTF16EncodeSurrogatePair confirms astral-plane characters get the
// surrogate treatment.
func TestUTF16EncodeSurrogatePair(t *testing.T) {
	// U+1F600 = 😀, surrogate pair D83D DE00 in UTF-16LE = 3D D8 00 DE
	got := utf16Encode([]rune{0x1F600})
	want := []byte{0x3D, 0xD8, 0x00, 0xDE}
	if !bytes.Equal(got, want) {
		t.Fatalf("surrogate: %x, want %x", got, want)
	}
}

// TestRC4KnownVector — RFC 6229 has test vectors for RC4.
//
// The classic vector: key = "Key", plaintext = "Plaintext" produces
// BBF316E8D940AF0AD3.
func TestRC4KnownVector(t *testing.T) {
	got := RC4Encrypt([]byte("Key"), []byte("Plaintext"))
	want := []byte{0xBB, 0xF3, 0x16, 0xE8, 0xD9, 0x40, 0xAF, 0x0A, 0xD3}
	if !bytes.Equal(got, want) {
		t.Fatalf("RC4 mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestRC4KnownVector2 — second RFC 6229 vector.
// key = "Wiki", plaintext = "pedia" produces 1021BF0420.
func TestRC4KnownVector2(t *testing.T) {
	got := RC4Encrypt([]byte("Wiki"), []byte("pedia"))
	want := []byte{0x10, 0x21, 0xBF, 0x04, 0x20}
	if !bytes.Equal(got, want) {
		t.Fatalf("RC4 mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestRC4RoundTrip — RC4 is its own inverse.
func TestRC4RoundTrip(t *testing.T) {
	key := []byte("somekey123")
	plaintext := []byte("hello, world")
	enc := RC4Encrypt(key, plaintext)
	dec := RC4Encrypt(key, enc)
	if !bytes.Equal(dec, plaintext) {
		t.Fatalf("RC4 round-trip failed")
	}
}

// TestHMACMD5KnownVector — RFC 2104 test vector: HMAC-MD5 of "Hi There"
// with key 0x0b repeated 16 times.
func TestHMACMD5KnownVector(t *testing.T) {
	key := bytes.Repeat([]byte{0x0b}, 16)
	got := HMACMD5(key, []byte("Hi There"))
	want := []byte{0x92, 0x94, 0x72, 0x7a, 0x36, 0x38, 0xbb, 0x1c,
		0x13, 0xf4, 0x8e, 0xf8, 0x15, 0x8b, 0xfc, 0x9d}
	if !bytes.Equal(got, want) {
		t.Fatalf("HMAC-MD5 mismatch:\n  got  %x\n  want %x", got, want)
	}
}

// TestEncryptTimestampRC4Shape — verify the output is (checksum || cipher)
// with checksum being 16 bytes.
func TestEncryptTimestampRC4Shape(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	ts := []byte{0xDE, 0xAD, 0xBE, 0xEF}
	got, err := EncryptTimestampRC4(ntHash, ts)
	if err != nil {
		t.Fatal(err)
	}
	// output = 16-byte checksum + len(plaintext) ciphertext
	if len(got) != 16+len(ts) {
		t.Fatalf("encrypted timestamp length %d, want %d", len(got), 16+len(ts))
	}
}

// TestEncryptTimestampRC4WrongKeyLen — the NT hash must be exactly 16.
func TestEncryptTimestampRC4WrongKeyLen(t *testing.T) {
	_, err := EncryptTimestampRC4([]byte("short"), []byte("ts"))
	if err == nil {
		t.Fatal("expected error for wrong key length")
	}
}

// TestPAEncTimestampMarshalShape — verify the DER structure.
func TestPAEncTimestampMarshalShape(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	p := PAEncTimestamp{KerbKeyBytes: ntHash, EType: ETypeRC4_HMAC}
	got, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	// outer tag should be SEQUENCE (0x30)
	if got[0] != 0x30 {
		t.Fatalf("outer tag: 0x%02x", got[0])
	}
	// the PA-DATA should contain the padata-type=2 marker. RFC 4120
	// uses primitive context tags for [1] Int32, so the encoding is
	// 81 03 02 01 02 (context tag 1, primitive, length 3, INTEGER 2).
	want := []byte{0x81, 0x03, 0x02, 0x01, 0x02}
	if !bytes.Contains(got, want) {
		t.Fatalf("PA-DATA type 2 marker not found in output:\n  %x", got)
	}
}

// TestPAEncTimestampNonRC4 — AES not implemented, error expected.
func TestPAEncTimestampNonRC4(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	p := PAEncTimestamp{KerbKeyBytes: ntHash, EType: ETypeAES256}
	_, err := p.Marshal()
	if err == nil {
		t.Fatal("expected error for AES etype")
	}
}

// TestBuildASREQWithPadataShape — the authenticated AS-REQ has a [3]
// padata field.
func TestBuildASREQWithPadataShape(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	p := PAEncTimestamp{KerbKeyBytes: ntHash, EType: ETypeRC4_HMAC}
	padata, err := p.Marshal()
	if err != nil {
		t.Fatal(err)
	}
	req, err := BuildASREQWithPadata(ASREQOptions{Realm: "R.LOCAL", Username: "u"}, padata)
	if err != nil {
		t.Fatal(err)
	}
	// outer tag still APPLICATION 10
	if req[0] != 0x6A {
		t.Fatalf("outer tag = 0x%02x, want 0x6A", req[0])
	}
	// the padata [3] marker (A3) should be present
	if !bytes.Contains(req, []byte{0xA3}) {
		t.Fatalf("padata [3] field missing from authenticated AS-REQ")
	}
}

// TestBuildASREQWithPadataStillHasBody — the KDC-REQ-BODY is preserved.
func TestBuildASREQWithPadataStillHasBody(t *testing.T) {
	ntHash, _ := DeriveRC4Key("password")
	p := PAEncTimestamp{KerbKeyBytes: ntHash, EType: ETypeRC4_HMAC}
	padata, _ := p.Marshal()
	req, err := BuildASREQWithPadata(ASREQOptions{Realm: "R.LOCAL", Username: "user1"}, padata)
	if err != nil {
		t.Fatal(err)
	}
	// the realm and username should still be in the message
	if !bytes.Contains(req, []byte("R.LOCAL")) {
		t.Fatalf("realm lost in rebuild")
	}
	if !bytes.Contains(req, []byte("user1")) {
		t.Fatalf("username lost in rebuild")
	}
}

// TestRandomBytesShape confirms the helper.
func TestRandomBytesShape(t *testing.T) {
	b, err := RandomBytes(16)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 16 {
		t.Fatalf("random length %d", len(b))
	}
	// two calls differ
	c, _ := RandomBytes(16)
	if bytes.Equal(b, c) {
		t.Fatalf("random bytes collided")
	}
}
