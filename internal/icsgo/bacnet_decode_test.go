package icsgo

import (
	"encoding/binary"
	"testing"
)

// BACnet ComplexACK decoding — known-answer tests. The test vectors here
// are constructed from the BACnet specification's own tag encoding rules.

// TestBACnetObjectIDPackingRoundTrip confirms the 4-byte packed object id
// decodes back to the same (objectType, instance) pair.
func TestBACnetObjectIDPackingRoundTrip(t *testing.T) {
	// objectType 8 (DEVICE), instance 1000 → packed =
	// (8 << 22) | 1000 = 0x0200_03E8
	packed := uint32(8)<<22 | uint32(1000)
	// build a context 0 tag with length 4 followed by the packed bytes
	buf := []byte{0x84} // context 0, length 4
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], packed)
	buf = append(buf, tmp[:]...)

	got, n, err := bacnetContextObjectID(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("consumed %d bytes, want 5", n)
	}
	if got.ObjectType != 8 {
		t.Fatalf("objectType %d, want 8", got.ObjectType)
	}
	if got.Instance != 1000 {
		t.Fatalf("instance %d, want 1000", got.Instance)
	}
}

// TestBACnetDecodeReal constructs a real application-tagged Real value.
// Real = application tag 4, length 4, four bytes of IEEE-754 float32.
func TestBACnetDecodeReal(t *testing.T) {
	// float32(72.5)
	buf := []byte{0x44} // tag 4, length 4
	var f [4]byte
	binary.BigEndian.PutUint32(f[:], 0x42910000) // 72.5 in IEEE-754 BE
	buf = append(buf, f[:]...)

	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 5 {
		t.Fatalf("consumed %d bytes, want 5", n)
	}
	if v.Type != "real" {
		t.Fatalf("type %q, want real", v.Type)
	}
	fv, ok := v.Value.(float64)
	if !ok {
		t.Fatalf("value not float64: %T", v.Value)
	}
	if fv != 72.5 {
		t.Fatalf("value %v, want 72.5", fv)
	}
}

// TestBACnetDecodeUnsigned constructs an application-tagged Unsigned.
func TestBACnetDecodeUnsigned(t *testing.T) {
	// tag 2, length 2, value 0xBEEF = 48879
	buf := []byte{0x22, 0xBE, 0xEF}
	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Fatalf("consumed %d bytes, want 3", n)
	}
	if v.Type != "unsigned" {
		t.Fatalf("type %q", v.Type)
	}
	uv, ok := v.Value.(uint64)
	if !ok {
		t.Fatalf("value not uint64: %T", v.Value)
	}
	if uv != 0xBEEF {
		t.Fatalf("value %d, want 48879", uv)
	}
}

// TestBACnetDecodeSignedPositive confirms positive signed values.
func TestBACnetDecodeSignedPositive(t *testing.T) {
	// tag 3, length 1, value 0x7F = 127
	buf := []byte{0x31, 0x7F}
	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("consumed %d bytes", n)
	}
	if v.Type != "signed" {
		t.Fatalf("type %q", v.Type)
	}
	sv, ok := v.Value.(int64)
	if !ok {
		t.Fatalf("value not int64: %T", v.Value)
	}
	if sv != 127 {
		t.Fatalf("value %d, want 127", sv)
	}
}

// TestBACnetDecodeSignedNegative confirms sign extension.
func TestBACnetDecodeSignedNegative(t *testing.T) {
	// tag 3, length 1, value 0xFF = -1 in two's complement
	buf := []byte{0x31, 0xFF}
	v, _, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	sv := v.Value.(int64)
	if sv != -1 {
		t.Fatalf("value %d, want -1", sv)
	}
}

// TestBACnetDecodeBoolean confirms boolean handling.
func TestBACnetDecodeBoolean(t *testing.T) {
	// tag 1, length is the value
	trueBuf := []byte{0x11}  // tag 1, length 1 → true
	falseBuf := []byte{0x10} // tag 1, length 0 → false
	v, n, err := bacnetDecodeValue(trueBuf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || v.Type != "boolean" || v.Value.(bool) != true {
		t.Fatalf("true decode: type=%q value=%v n=%d", v.Type, v.Value, n)
	}
	v, _, err = bacnetDecodeValue(falseBuf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if v.Value.(bool) != false {
		t.Fatalf("false decode: value=%v", v.Value)
	}
}

// TestBACnetDecodeCharacterString confirms the encoding-byte-prefixed
// CharacterString.
func TestBACnetDecodeCharacterString(t *testing.T) {
	// tag 7, length = encoding(1) + len("hello")=5 → total 6
	buf := []byte{0x76, 0x00} // tag 7, length 6, encoding = 0 (UTF-8)
	buf = append(buf, []byte("hello")...)

	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 7 {
		t.Fatalf("consumed %d, want 7", n)
	}
	if v.Type != "string" {
		t.Fatalf("type %q", v.Type)
	}
	if v.Value.(string) != "hello" {
		t.Fatalf("value %q, want hello", v.Value)
	}
}

// TestBACnetDecodeEnumerated confirms enumerated values.
func TestBACnetDecodeEnumerated(t *testing.T) {
	// tag 9, length 1, value 12
	buf := []byte{0x91, 0x0C}
	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("consumed %d", n)
	}
	if v.Type != "enumerated" {
		t.Fatalf("type %q", v.Type)
	}
	if v.Value.(uint64) != 12 {
		t.Fatalf("value %v, want 12", v.Value)
	}
}

// TestBACnetDecodeNull confirms null handling.
func TestBACnetDecodeNull(t *testing.T) {
	buf := []byte{0x00}
	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 || v.Type != "null" {
		t.Fatalf("null decode: type=%q n=%d", v.Type, n)
	}
}

// TestBACnetContextUnsigned confirms context unsigned extraction.
func TestBACnetContextUnsigned(t *testing.T) {
	// context 1, length 1, value 85
	buf := []byte{0x91, 0x55}
	got, n, err := bacnetContextUnsigned(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 2 || got != 85 {
		t.Fatalf("context unsigned: value=%d n=%d", got, n)
	}
}

// TestBACnetContextObjectIDRejectsShortTag confirms the length check.
func TestBACnetContextObjectIDRejectsShortTag(t *testing.T) {
	// context 0 with length 2 (not 4)
	buf := []byte{0x82, 0x00, 0x01}
	_, _, err := bacnetContextObjectID(buf, 0)
	if err == nil {
		t.Fatalf("expected error for short object id tag")
	}
}

// TestBACnetFormatValue exercises the pretty-printer.
func TestBACnetFormatValue(t *testing.T) {
	cases := []struct {
		v    BACnetValue
		want string
	}{
		{BACnetValue{Type: "real", Value: 72.5}, "72.5"},
		{BACnetValue{Type: "unsigned", Value: uint64(42)}, "42"},
		{BACnetValue{Type: "enumerated", Value: uint64(3)}, "3"},
		{BACnetValue{Type: "boolean", Value: true}, "true"},
		{BACnetValue{Type: "string", Value: "hello"}, `"hello"`},
		{BACnetValue{Type: "null"}, "<nil>"},
	}
	for _, c := range cases {
		got := BACnetFormatValue(c.v)
		if got != c.want {
			t.Fatalf("format %q = %q, want %q", c.v.Type, got, c.want)
		}
	}
}

// TestBACnetDecodeDouble confirms IEEE-754 double decode.
func TestBACnetDecodeDouble(t *testing.T) {
	// tag 5, length 8, float64(1.5) = 0x3FF8000000000000
	buf := []byte{0x58}
	var d [8]byte
	binary.BigEndian.PutUint64(d[:], 0x3FF8000000000000)
	buf = append(buf, d[:]...)

	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 9 || v.Type != "double" {
		t.Fatalf("double decode: n=%d type=%q", n, v.Type)
	}
	if v.Value.(float64) != 1.5 {
		t.Fatalf("value %v, want 1.5", v.Value)
	}
}

// TestBACnetDecodeOctetString confirms octet string passthrough.
func TestBACnetDecodeOctetString(t *testing.T) {
	buf := []byte{0x63, 0xAA, 0xBB, 0xCC} // tag 6, length 3
	v, n, err := bacnetDecodeValue(buf, 0)
	if err != nil {
		t.Fatal(err)
	}
	if n != 4 || v.Type != "octet-string" {
		t.Fatalf("octet string: n=%d type=%q", n, v.Type)
	}
	got := v.Value.([]byte)
	if len(got) != 3 || got[0] != 0xAA || got[2] != 0xCC {
		t.Fatalf("octet string bytes wrong: %x", got)
	}
}
