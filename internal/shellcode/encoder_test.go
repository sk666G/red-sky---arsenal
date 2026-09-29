package shellcode

import (
	"bytes"
	"strings"
	"testing"
)

// TestROT13KnownInput pins the classic ROT13 pair.
func TestROT13KnownInput(t *testing.T) {
	e := NewROT13()
	got := string(e.Encode([]byte("hello world")))
	want := "uryyb jbeyq"
	if got != want {
		t.Fatalf("rot13 mismatch:\n  got  %q\n  want %q", got, want)
	}
}

// TestXORKeyChosen verifies the auto-key picker avoids nulls on a null-rich
// input.
func TestXORKeyChosen(t *testing.T) {
	in := bytes.Repeat([]byte{0x00, 0x41, 0x00, 0x42}, 8)
	e := NewXOR(0)
	out := e.Encode(in)
	// the chosen key must not be zero (input has zeros, so 0x00 key would
	// produce zeros)
	for i, b := range out {
		if b == 0x00 {
			t.Fatalf("null byte at offset %d after auto-key XOR", i)
		}
	}
}

// TestNullFreeGuarantee confirms no forbidden byte escapes.
func TestNullFreeGuarantee(t *testing.T) {
	in := []byte{
		0x00, 0x0A, 0x0D, 0x01, 0x02, 0x00, 0x0A, 0xFF,
		0x00, 0x0A, 0x0D, 0x00, 0x00, 0x0A,
	}
	e := NewNullFree()
	out := e.Encode(in)
	for i, b := range out {
		if b == 0x00 || b == 0x0A || b == 0x0D {
			t.Fatalf("forbidden byte 0x%02x at %d after null_free encode", b, i)
		}
	}
}

// TestChunkedXORKeyRotation checks that key rotation changes the output
// per chunk.
func TestChunkedXORKeyRotation(t *testing.T) {
	in := bytes.Repeat([]byte{0xFF}, 16)
	keys := []byte{0xA5, 0x5A}
	e := NewChunkedXOR(8, keys)
	out := e.Encode(in)
	// first 8 bytes should be 0xFF ^ 0xA5 = 0x5A
	for i := 0; i < 8; i++ {
		if out[i] != 0x5A {
			t.Fatalf("chunk 0 byte %d: got 0x%02x want 0x5a", i, out[i])
		}
	}
	// next 8 bytes should be 0xFF ^ 0x5A = 0xA5
	for i := 8; i < 16; i++ {
		if out[i] != 0xA5 {
			t.Fatalf("chunk 1 byte %d: got 0x%02x want 0xa5", i, out[i])
		}
	}
}

// TestBase64KnownInput pins a well-known base64 encoding.
func TestBase64KnownInput(t *testing.T) {
	e := NewBase64()
	got := string(e.Encode([]byte("hello world")))
	want := "aGVsbG8gd29ybGQ="
	if got != want {
		t.Fatalf("base64 mismatch:\n  got  %q\n  want %q", got, want)
	}
}

// TestBase64Padding covers the 1- and 2-byte tails.
func TestBase64Padding(t *testing.T) {
	cases := []struct {
		in, out string
	}{
		{"a", "YQ=="},
		{"ab", "YWI="},
		{"abc", "YWJj"},
	}
	e := NewBase64()
	for _, c := range cases {
		got := string(e.Encode([]byte(c.in)))
		if got != c.out {
			t.Fatalf("base64(%q) = %q, want %q", c.in, got, c.out)
		}
	}
}

// TestUUIDPackFewerThanSixteen checks that short input is padded.
func TestUUIDPackFewerThanSixteen(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03}
	out := UUIDStrings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 UUID, got %d", len(out))
	}
	if !strings.HasPrefix(out[0], "01020300") {
		t.Fatalf("short UUID padding wrong: %s", out[0])
	}
}

// TestIPv4PackFewerThanFour checks short input padding.
func TestIPv4PackFewerThanFour(t *testing.T) {
	in := []byte{0x01, 0x02}
	out := IPv4Strings(in)
	if len(out) != 1 {
		t.Fatalf("expected 1 IP, got %d", len(out))
	}
	if out[0] != "10.1.2.0" {
		t.Fatalf("short IP padding wrong: got %s want 10.1.2.0", out[0])
	}
}

// TestEncodersByName looks up each encoder via the string name.
func TestEncodersByName(t *testing.T) {
	names := []string{"xor", "rot13", "null_free", "chunked_xor", "base64"}
	for _, name := range names {
		e, err := EncoderByName(name, 0xA5)
		if err != nil {
			t.Fatalf("EncoderByName(%q) error: %v", name, err)
		}
		if e.Name() == "" {
			t.Fatalf("EncoderByName(%q) returned an empty Name()", name)
		}
	}
}

// TestEncoderByNameUnknown rejects nonsense names.
func TestEncoderByNameUnknown(t *testing.T) {
	_, err := EncoderByName("not-a-thing", 0)
	if err == nil {
		t.Fatalf("expected error for unknown encoder")
	}
}

// TestStackedEncoders verifies xor(null_free(x)) has no forbidden bytes.
func TestStackedEncoders(t *testing.T) {
	in := []byte{0x00, 0x0A, 0x0D, 0x42, 0x00, 0xFF}
	e1 := NewXOR(0x55)
	e2 := NewNullFree()
	out := e2.Encode(e1.Encode(in))
	for i, b := range out {
		if b == 0x00 || b == 0x0A || b == 0x0D {
			t.Fatalf("stacked encoders left forbidden byte 0x%02x at %d", b, i)
		}
	}
}
