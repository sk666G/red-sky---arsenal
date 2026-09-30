package adgo

import (
	"bytes"
	"testing"
)

// TestTagComposition confirms class + constructed + number packing.
func TestTagComposition(t *testing.T) {
	cases := []struct {
		class       DERClass
		constructed bool
		num         byte
		want        byte
	}{
		{ClassUniversal, false, 2, 0x02},   // INTEGER
		{ClassUniversal, true, 16, 0x30},   // SEQUENCE
		{ClassUniversal, false, 4, 0x04},   // OCTET STRING
		{ClassUniversal, true, 17, 0x31},   // SET
		{ClassApplication, true, 1, 0x61},  // Kerberos AS-REQ tag
		{ClassApplication, true, 11, 0x6B}, // Kerberos AS-REP tag
		{ClassContext, false, 0, 0x80},     // [0] primitive
		{ClassContext, true, 1, 0xA1},      // [1] constructed
		{ClassPrivate, false, 5, 0xC5},
	}
	for _, c := range cases {
		got := Tag(c.class, c.constructed, c.num)
		if got != c.want {
			t.Fatalf("Tag(%02x,%v,%d) = 0x%02x, want 0x%02x", byte(c.class), c.constructed, c.num, got, c.want)
		}
	}
}

// TestLengthShortForm confirms lengths < 128 encode as one byte.
func TestLengthShortForm(t *testing.T) {
	for n := 0; n < 128; n++ {
		got := Len(n)
		if len(got) != 1 || got[0] != byte(n) {
			t.Fatalf("Len(%d) = %v", n, got)
		}
	}
}

// TestLengthLongForm covers 0x81, 0x82, 0x83, 0x84.
func TestLengthLongForm(t *testing.T) {
	cases := []struct {
		n    int
		want []byte
	}{
		{128, []byte{0x81, 0x80}},
		{255, []byte{0x81, 0xFF}},
		{256, []byte{0x82, 0x01, 0x00}},
		{65535, []byte{0x82, 0xFF, 0xFF}},
		{65536, []byte{0x83, 0x01, 0x00, 0x00}},
		{0xFFFFFF, []byte{0x83, 0xFF, 0xFF, 0xFF}},
		{0x1000000, []byte{0x84, 0x01, 0x00, 0x00, 0x00}},
	}
	for _, c := range cases {
		got := Len(c.n)
		if !bytes.Equal(got, c.want) {
			t.Fatalf("Len(%d) = %v, want %v", c.n, got, c.want)
		}
	}
}

// TestDERIntegerKnownVectors pins the DER integer encoding for classic
// values. The leading-zero prepend when the top bit is set is critical
// for correctness.
func TestDERIntegerKnownVectors(t *testing.T) {
	cases := []struct {
		v    int64
		want []byte
	}{
		{0, []byte{0x02, 0x01, 0x00}},
		{1, []byte{0x02, 0x01, 0x01}},
		{127, []byte{0x02, 0x01, 0x7F}},
		// 128 has the top bit set — DER pads with a 0x00
		{128, []byte{0x02, 0x02, 0x00, 0x80}},
		{255, []byte{0x02, 0x02, 0x00, 0xFF}},
		{256, []byte{0x02, 0x02, 0x01, 0x00}},
		{32767, []byte{0x02, 0x02, 0x7F, 0xFF}},
		{32768, []byte{0x02, 0x03, 0x00, 0x80, 0x00}},
		// negative — -1 is 0xFF
		{-1, []byte{0x02, 0x01, 0xFF}},
		{-128, []byte{0x02, 0x01, 0x80}},
		{-129, []byte{0x02, 0x02, 0xFF, 0x7F}},
	}
	for _, c := range cases {
		got := DERInteger(c.v)
		if !bytes.Equal(got, c.want) {
			t.Fatalf("DERInteger(%d) = %v, want %v", c.v, got, c.want)
		}
	}
}

// TestDEROctetStringShape confirms the OCTET STRING encoding.
func TestDEROctetStringShape(t *testing.T) {
	got := DEROctetString([]byte{0xAA, 0xBB, 0xCC})
	want := []byte{0x04, 0x03, 0xAA, 0xBB, 0xCC}
	if !bytes.Equal(got, want) {
		t.Fatalf("DEROctetString: %v, want %v", got, want)
	}
}

// TestDERNullShape — NULL is 05 00.
func TestDERNullShape(t *testing.T) {
	got := DERNull()
	if !bytes.Equal(got, []byte{0x05, 0x00}) {
		t.Fatalf("DERNull = %v", got)
	}
}

// TestDERBooleanShape — TRUE is 0xFF, FALSE is 0x00.
func TestDERBooleanShape(t *testing.T) {
	if !bytes.Equal(DERBoolean(true), []byte{0x01, 0x01, 0xFF}) {
		t.Fatalf("TRUE wrong: %v", DERBoolean(true))
	}
	if !bytes.Equal(DERBoolean(false), []byte{0x01, 0x01, 0x00}) {
		t.Fatalf("FALSE wrong: %v", DERBoolean(false))
	}
}

// TestDERSequenceShape — SEQUENCE tag is 0x30.
func TestDERSequenceShape(t *testing.T) {
	got := DERSequence([]byte{0xAA, 0xBB})
	want := []byte{0x30, 0x02, 0xAA, 0xBB}
	if !bytes.Equal(got, want) {
		t.Fatalf("DERSequence = %v, want %v", got, want)
	}
}

// TestDERContextTagShape — context tags.
func TestDERContextTagShape(t *testing.T) {
	// [0] primitive
	got := DERContextTag(0, false, []byte{0x01})
	if !bytes.Equal(got, []byte{0x80, 0x01, 0x01}) {
		t.Fatalf("[0] primitive = %v", got)
	}
	// [1] constructed
	got = DERContextTag(1, true, []byte{0x30, 0x00})
	if !bytes.Equal(got, []byte{0xA1, 0x02, 0x30, 0x00}) {
		t.Fatalf("[1] constructed = %v", got)
	}
}

// TestDERApplicationTagShape — Kerberos uses app tags extensively.
func TestDERApplicationTagShape(t *testing.T) {
	// AS-REQ is [APPLICATION 10] = 0x6A
	got := DERApplicationTag(10, true, []byte{0x00})
	if got[0] != 0x6A {
		t.Fatalf("app tag 10 constructed = 0x%02x", got[0])
	}
	// AS-REP is [APPLICATION 11] = 0x6B
	got = DERApplicationTag(11, true, []byte{0x00})
	if got[0] != 0x6B {
		t.Fatalf("app tag 11 constructed = 0x%02x", got[0])
	}
}

// TestKerbPrincipalShape — verify PrincipalName structure.
func TestKerbPrincipalShape(t *testing.T) {
	got := KerbPrincipal(1, []string{"user"})
	// expected: SEQUENCE { [0] INTEGER 1, [1] SEQUENCE { GeneralString "user" } }
	// check the outer tag is SEQUENCE (0x30)
	if got[0] != 0x30 {
		t.Fatalf("not a sequence: 0x%02x", got[0])
	}
	// ensure it round-trips through the reader
	r := NewDERReader(got)
	tag, content, err := r.ReadTLV()
	if err != nil {
		t.Fatal(err)
	}
	if tag != 0x30 {
		t.Fatalf("outer tag: 0x%02x", tag)
	}
	// inner should be [0] (0x80) then [1] (0xA1)
	if len(content) < 2 || content[0] != 0x80 {
		t.Fatalf("inner [0] missing: %v", content)
	}
}

// TestDERReaderRoundTrip — every encoding we make should read back.
func TestDERReaderRoundTrip(t *testing.T) {
	v := DERInteger(42)
	r := NewDERReader(v)
	tag, content, err := r.ReadTLV()
	if err != nil {
		t.Fatal(err)
	}
	if tag != 0x02 {
		t.Fatalf("tag: 0x%02x", tag)
	}
	got, err := DecodeInteger(content)
	if err != nil {
		t.Fatal(err)
	}
	if got != 42 {
		t.Fatalf("decoded %d, want 42", got)
	}
}

// TestDecodeIntegerSignExtension — negative values sign-extend.
func TestDecodeIntegerSignExtension(t *testing.T) {
	// -1 encoded as 0xFF
	got, err := DecodeInteger([]byte{0xFF})
	if err != nil {
		t.Fatal(err)
	}
	if got != -1 {
		t.Fatalf("decode 0xFF = %d, want -1", got)
	}
	// -128 encoded as 0x80
	got, err = DecodeInteger([]byte{0x80})
	if err != nil {
		t.Fatal(err)
	}
	if got != -128 {
		t.Fatalf("decode 0x80 = %d, want -128", got)
	}
}

// TestTagClassHelpers confirms the tag byte helpers.
func TestTagClassHelpers(t *testing.T) {
	if TagClass(0x30) != ClassUniversal {
		t.Fatalf("0x30 class")
	}
	if TagClass(0x61) != ClassApplication {
		t.Fatalf("0x61 class")
	}
	if TagClass(0xA1) != ClassContext {
		t.Fatalf("0xA1 class")
	}
	if !IsConstructed(0x30) {
		t.Fatalf("0x30 should be constructed")
	}
	if IsConstructed(0x04) {
		t.Fatalf("0x04 should not be constructed")
	}
	if TagNumber(0x02) != 2 {
		t.Fatalf("0x02 number: %d", TagNumber(0x02))
	}
	if TagNumber(0x30) != 16 {
		t.Fatalf("0x30 number: %d", TagNumber(0x30))
	}
}
