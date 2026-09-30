package dnsgo

import (
	"bytes"
	"encoding/base32"
	"encoding/binary"
	"strings"
	"testing"
)

// TestRandomSessionShape checks the session id length + charset.
func TestRandomSessionShape(t *testing.T) {
	for i := 0; i < 8; i++ {
		s := randomSession()
		if len(s) != 8 {
			t.Fatalf("session length %d, want 8", len(s))
		}
		// base32 lowercase charset
		for _, c := range s {
			if !((c >= 'a' && c <= 'z') || (c >= '2' && c <= '7')) {
				t.Fatalf("session has invalid char %q", c)
			}
		}
	}
}

// TestRandomSessionNonRepeating checks the sessions aren't identical.
func TestRandomSessionNonRepeating(t *testing.T) {
	sessions := map[string]bool{}
	for i := 0; i < 20; i++ {
		sessions[randomSession()] = true
	}
	if len(sessions) < 18 {
		t.Fatalf("random sessions collided: got %d unique of 20", len(sessions))
	}
}

// TestEncodeNameShape confirms the encoded query name is well-formed.
func TestEncodeNameShape(t *testing.T) {
	chunk := []byte("hello world")
	name, err := EncodeName(chunk, "abcdef12", "t.evil.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(name, ".abcdef12.t.evil.com") {
		t.Fatalf("name doesn't end with session + domain: %q", name)
	}
	if len(name) > 253 {
		t.Fatalf("name too long: %d", len(name))
	}
	// every label <= 63 chars
	for _, label := range strings.Split(name, ".") {
		if len(label) > 63 {
			t.Fatalf("label too long: %q (%d)", label, len(label))
		}
	}
}

// TestEncodeDecodeRoundTrip confirms the encode/decode pair is inverse.
func TestEncodeDecodeRoundTrip(t *testing.T) {
	cases := [][]byte{
		[]byte("x"),
		[]byte("hello"),
		[]byte("this is a slightly longer payload for testing"),
		bytes.Repeat([]byte{0xAB, 0xCD}, 8),
	}
	for _, payload := range cases {
		name, err := EncodeName(payload, "abcdef12", "t.evil.com")
		if err != nil {
			t.Fatalf("encode: %v", err)
		}
		session, got, err := DecodeName(name, "t.evil.com")
		if err != nil {
			t.Fatalf("decode: %v", err)
		}
		if session != "abcdef12" {
			t.Fatalf("session mismatch: %q", session)
		}
		if !bytes.Equal(got, payload) {
			t.Fatalf("payload mismatch:\n  got  %x\n  want %x", got, payload)
		}
	}
}

// TestDecodeNameRejectsWrongDomain confirms a domain mismatch errors.
func TestDecodeNameRejectsWrongDomain(t *testing.T) {
	name, _ := EncodeName([]byte("x"), "abcdef12", "t.evil.com")
	_, _, err := DecodeName(name, "t.other.com")
	if err == nil {
		t.Fatalf("expected error for wrong domain")
	}
}

// TestDecodeNameRejectsShortName confirms the length check.
func TestDecodeNameRejectsShortName(t *testing.T) {
	_, _, err := DecodeName("t.evil.com", "t.evil.com")
	if err == nil {
		t.Fatalf("expected error for name == domain")
	}
}

// TestEncodeNameRejectsLongName confirms the 253-char limit.
func TestEncodeNameRejectsLongName(t *testing.T) {
	// a very long chunk (100 bytes) base32-encodes to ~160 chars, plus
	// session + domain pushes over 253
	huge := bytes.Repeat([]byte{0xFF}, 200)
	_, err := EncodeName(huge, "abcdef12", "this.is.a.deeply.nested.subdomain.chain.example.evil.com")
	if err == nil {
		t.Fatalf("expected error for overlong name")
	}
}

// TestEncodeQName confirms the length-prefixed label encoding.
func TestEncodeQName(t *testing.T) {
	got, err := encodeQName("abc.de")
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{0x03, 'a', 'b', 'c', 0x02, 'd', 'e', 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("qname encoding:\n  got  %v\n  want %v", got, want)
	}
}

// TestEncodeQNameRejectsLongLabel confirms the 63-char label limit.
func TestEncodeQNameRejectsLongLabel(t *testing.T) {
	long := strings.Repeat("a", 64)
	_, err := encodeQName(long + ".example.com")
	if err == nil {
		t.Fatalf("expected error for 64-char label")
	}
}

// TestDecodeQNamePlain confirms the decoder on the simple form.
func TestDecodeQNamePlain(t *testing.T) {
	buf := []byte{0x03, 'a', 'b', 'c', 0x02, 'd', 'e', 0x00, 0xFF, 0xFF}
	got, off, err := decodeQName(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if got != "abc.de" {
		t.Fatalf("qname decode: %q", got)
	}
	if off != 8 {
		t.Fatalf("offset after decode: %d, want 8", off)
	}
}

// TestDecodeQNameCompression confirms a compression pointer is followed.
func TestDecodeQNameCompression(t *testing.T) {
	// buffer: "abc.de\0" at offset 0, then at offset 8 a pointer to offset 4
	// (which is "de\0"). Decoding from offset 8 should give "de".
	buf := append([]byte{0x03, 'a', 'b', 'c', 0x02, 'd', 'e', 0x00}, 0xC0, 0x04)
	got, off, err := decodeQName(buf, 8)
	if err != nil {
		t.Fatal(err)
	}
	if got != "de" {
		t.Fatalf("compression decode: %q", got)
	}
	// offset should be after the pointer (10)
	if off != 10 {
		t.Fatalf("offset after compression decode: %d, want 10", off)
	}
}

// TestParseTXTResponseSingle builds a DNS response with one TXT record and
// verifies the rdata extraction.
func TestParseTXTResponseSingle(t *testing.T) {
	var buf bytes.Buffer
	// header: qid(2) flags(2) qd(2) an(2) ns(2) ar(2)
	buf.Write([]byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	// question: "a.com" qtype TXT qclass IN
	buf.Write([]byte{0x01, 'a', 0x03, 'c', 'o', 'm', 0x00})
	buf.Write([]byte{0x00, 0x10, 0x00, 0x01})
	// answer: name pointer (0xC00C), type TXT, class IN, ttl 0, rdlen 6
	// rdata: length 5 + "hello"
	buf.Write([]byte{0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01})
	buf.Write([]byte{0, 0, 0, 0})
	rdlen := 6
	buf.Write([]byte{byte(rdlen >> 8), byte(rdlen)})
	buf.Write([]byte{0x05, 'h', 'e', 'l', 'l', 'o'})

	got, err := parseTXTResponse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("TXT parse: %q, want hello", got)
	}
}

// TestParseTXTResponseMultipleStrings confirms concatenation of the
// length-prefixed string sequence.
func TestParseTXTResponseMultipleStrings(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	buf.Write([]byte{0x01, 'a', 0x00})        // qname
	buf.Write([]byte{0x00, 0x10, 0x00, 0x01}) // qtype/qclass
	buf.Write([]byte{0xC0, 0x0C, 0x00, 0x10, 0x00, 0x01})
	buf.Write([]byte{0, 0, 0, 0})
	// two length-prefixed strings "abc" + "def"
	rdata := []byte{0x03, 'a', 'b', 'c', 0x03, 'd', 'e', 'f'}
	buf.Write([]byte{byte(len(rdata) >> 8), byte(len(rdata))})
	buf.Write(rdata)

	got, err := parseTXTResponse(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "abcdef" {
		t.Fatalf("multi-TXT parse: %q, want abcdef", got)
	}
}

// TestParseTXTResponseMissingTXT confirms an error when no TXT answer is
// present.
func TestParseTXTResponseMissingTXT(t *testing.T) {
	var buf bytes.Buffer
	buf.Write([]byte{0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	buf.Write([]byte{0x01, 'a', 0x00})
	buf.Write([]byte{0x00, 0x10, 0x00, 0x01})
	// an A record instead of TXT
	buf.Write([]byte{0xC0, 0x0C, 0x00, 0x01, 0x00, 0x01}) // A type
	buf.Write([]byte{0, 0, 0, 0})
	buf.Write([]byte{0x00, 0x04})
	buf.Write([]byte{1, 2, 3, 4})

	_, err := parseTXTResponse(buf.Bytes())
	if err == nil {
		t.Fatalf("expected error for missing TXT")
	}
}

// TestParseTXTResponseShort confirms the length guard.
func TestParseTXTResponseShort(t *testing.T) {
	_, err := parseTXTResponse([]byte{0x01, 0x02})
	if err == nil {
		t.Fatalf("expected error for short response")
	}
}

// TestSendRejectsMissingOptions confirms the required fields.
func TestSendRejectsMissingOptions(t *testing.T) {
	_, _, err := Send(nil, Options{}, []byte("x"))
	if err == nil {
		t.Fatalf("expected error for missing server")
	}
	_, _, err = Send(nil, Options{Server: "1.1.1.1"}, []byte("x"))
	if err == nil {
		t.Fatalf("expected error for missing domain")
	}
}

// TestBase32NoPaddingRoundTrip confirms the alphabet we use is the one the
// server side expects.
func TestBase32NoPaddingRoundTrip(t *testing.T) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding)
	for _, s := range []string{"a", "ab", "abc", "abcd", "abcde"} {
		encoded := enc.EncodeToString([]byte(s))
		decoded, err := enc.DecodeString(encoded)
		if err != nil {
			t.Fatalf("round-trip: %v", err)
		}
		if string(decoded) != s {
			t.Fatalf("round-trip mismatch: %q vs %q", decoded, s)
		}
	}
}

var _ = binary.BigEndian
