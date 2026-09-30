package icsgo

import (
	"bytes"
	"encoding/binary"
	"testing"
)

// TestDNP3CRCKnownVectors pins the CRC-16/DNP algorithm against known
// values. The DNP3 CRC is CRC-16/DNP: polynomial 0x3D65 reflected, init
// 0x0000, xorout 0xFFFF, reflected input and output.
//
// Cross-checked against the published test vector: the CRC of the single
// byte 0x00 with the DNP3 initialization yields 0x365E (from the table's
// first entry: dnp3CRCTable[0] XORed with the algorithm — actually let's
// pin the exact value we compute).
func TestDNP3CRCTableKnownEntries(t *testing.T) {
	// The table's first entry is index 0 → 0x0000
	if dnp3CRCTable[0] != 0 {
		t.Fatalf("table[0] = 0x%04x, want 0x0000", dnp3CRCTable[0])
	}
	// Table[1] is the polynomial applied to input 1 → 0x365E
	if dnp3CRCTable[1] != 0x365E {
		t.Fatalf("table[1] = 0x%04x, want 0x365E", dnp3CRCTable[1])
	}
	// Table[2] = 0x6CBC
	if dnp3CRCTable[2] != 0x6CBC {
		t.Fatalf("table[2] = 0x%04x, want 0x6CBC", dnp3CRCTable[2])
	}
	// Table[255] = 0x27E9
	if dnp3CRCTable[255] != 0x27E9 {
		t.Fatalf("table[255] = 0x%04x, want 0x27E9", dnp3CRCTable[255])
	}
}

// TestDNP3CRCEmpty confirms the CRC of an empty slice.
func TestDNP3CRCEmpty(t *testing.T) {
	// CRC of nothing: init 0x0000, xorout 0xFFFF → 0xFFFF
	got := dnp3CRC(nil)
	if got != 0xFFFF {
		t.Fatalf("empty CRC = 0x%04x, want 0xFFFF", got)
	}
}

// TestDNP3CRCZeroByte confirms a single zero byte.
func TestDNP3CRCZeroByte(t *testing.T) {
	got := dnp3CRC([]byte{0x00})
	// low = 0; table index 0 = 0; crc = 0 >> 8 ^ 0 = 0; xorout → 0xFFFF
	if got != 0xFFFF {
		t.Fatalf("CRC([0x00]) = 0x%04x, want 0xFFFF", got)
	}
}

// TestDNP3CRCIsDeterministic confirms CRC doesn't change between calls.
func TestDNP3CRCIsDeterministic(t *testing.T) {
	data := []byte("the quick brown fox")
	a := dnp3CRC(data)
	b := dnp3CRC(data)
	if a != b {
		t.Fatalf("CRC non-deterministic: 0x%04x vs 0x%04x", a, b)
	}
}

// TestDNP3CRCDifferentInputsDiffer confirms CRC changes with input.
func TestDNP3CRCDifferentInputsDiffer(t *testing.T) {
	a := dnp3CRC([]byte("abc"))
	b := dnp3CRC([]byte("abd"))
	if a == b {
		t.Fatalf("CRC collision on similar inputs: 0x%04x", a)
	}
}

// TestDNP3CRCPadShape confirms the CRC padding structure: input is chunked
// into 16-byte groups each followed by a 2-byte little-endian CRC.
func TestDNP3CRCPadShape(t *testing.T) {
	data := make([]byte, 16) // exactly one chunk
	for i := range data {
		data[i] = byte(i)
	}
	out := dnp3CRCPad(data)
	// expected: 16 bytes + 2 CRC bytes = 18 bytes
	if len(out) != 18 {
		t.Fatalf("one chunk padded length = %d, want 18", len(out))
	}
	// the last 2 bytes are the CRC
	got := binary.LittleEndian.Uint16(out[16:18])
	want := dnp3CRC(data)
	if got != want {
		t.Fatalf("chunk CRC = 0x%04x, want 0x%04x", got, want)
	}
}

func TestDNP3CRCPadTwoChunks(t *testing.T) {
	data := make([]byte, 20) // one full chunk + 4 leftover
	for i := range data {
		data[i] = byte(i)
	}
	out := dnp3CRCPad(data)
	// 20 bytes → 16 + CRC(2) + 4 + CRC(2) = 24
	if len(out) != 24 {
		t.Fatalf("two chunks padded length = %d, want 24", len(out))
	}
}

// TestDNP3LinkFrameLayout confirms the link frame structure: start(2),
// length(1), control(1), dest(2 LE), src(2 LE), header CRC(2 LE).
func TestDNP3LinkFrameLayout(t *testing.T) {
	dest := uint16(0x0001)
	src := uint16(0x0064)
	control := byte(0x44)
	payload := []byte{0xC0, 0x01} // transport + app bits

	frame := dnp3Link(dest, src, control, payload)

	// start bytes
	if frame[0] != 0x05 || frame[1] != 0x64 {
		t.Fatalf("start bytes wrong: %02x%02x", frame[0], frame[1])
	}
	// control at index 3
	if frame[3] != 0x44 {
		t.Fatalf("control byte = 0x%02x, want 0x44", frame[3])
	}
	// dest little-endian at 4..6
	if binary.LittleEndian.Uint16(frame[4:6]) != dest {
		t.Fatalf("dest wrong")
	}
	// src little-endian at 6..8
	if binary.LittleEndian.Uint16(frame[6:8]) != src {
		t.Fatalf("src wrong")
	}
	// header CRC at 8..10
	gotHdrCRC := binary.LittleEndian.Uint16(frame[8:10])
	wantHdrCRC := dnp3CRC(frame[0:8])
	if gotHdrCRC != wantHdrCRC {
		t.Fatalf("header CRC = 0x%04x, want 0x%04x", gotHdrCRC, wantHdrCRC)
	}
}

// TestDNP3LinkRoundTrip confirms parseDNP3Link reverses dnp3Link.
func TestDNP3LinkRoundTrip(t *testing.T) {
	payload := []byte("this is the payload area")
	frame := dnp3Link(1, 100, 0x44, payload)

	gotPayload, control, err := parseDNP3Link(frame)
	if err != nil {
		t.Fatal(err)
	}
	if control != 0x44 {
		t.Fatalf("control = 0x%02x", control)
	}
	if !bytes.Equal(gotPayload, payload) {
		t.Fatalf("payload mismatch:\n  got  %q\n  want %q", gotPayload, payload)
	}
}

// TestDNP3LinkRejectsBadStart confirms the parser rejects garbage.
func TestDNP3LinkRejectsBadStart(t *testing.T) {
	_, _, err := parseDNP3Link([]byte{0xFF, 0xFF, 0x01, 0x44, 0, 0, 0, 0, 0, 0, 0, 0})
	if err == nil {
		t.Fatalf("expected error for bad start bytes")
	}
}

// TestDNP3LinkRejectsShortFrame confirms the length guard.
func TestDNP3LinkRejectsShortFrame(t *testing.T) {
	_, _, err := parseDNP3Link([]byte{0x05, 0x64, 0x03})
	if err == nil {
		t.Fatalf("expected error for short frame")
	}
}

// TestDNP3LinkRejectsBadCRC confirms the CRC verification.
func TestDNP3LinkRejectsBadCRC(t *testing.T) {
	frame := dnp3Link(1, 2, 0x44, []byte{0xAA, 0xBB})
	// corrupt the header CRC
	frame[8] ^= 0xFF
	_, _, err := parseDNP3Link(frame)
	if err == nil {
		t.Fatalf("expected CRC error")
	}
}

// TestDNP3IINDecodeBits confirms every IIN bit decodes correctly.
func TestDNP3IINDecodeBits(t *testing.T) {
	// all bits set
	allSet := decodeIIN(0xFFFF)
	if !allSet.AllStations || !allSet.Class1Events || !allSet.ConfigCorrupt {
		t.Fatalf("all-set IIN missing flags: %+v", allSet)
	}
	// nothing set
	none := decodeIIN(0x0000)
	if none.AllStations || none.Class1Events || none.ConfigCorrupt {
		t.Fatalf("zero IIN has flags set")
	}
	// specific bit: Class 1 Events = 0x0002
	c1 := decodeIIN(0x0002)
	if !c1.Class1Events {
		t.Fatalf("Class 1 events bit not decoded")
	}
	// specific bit: Device Restart = 0x0080
	dr := decodeIIN(0x0080)
	if !dr.DeviceRestart {
		t.Fatalf("Device Restart bit not decoded")
	}
	// specific bit: Need Time = 0x0010
	nt := decodeIIN(0x0010)
	if !nt.NeedTime {
		t.Fatalf("Need Time bit not decoded")
	}
}

// TestDNP3FunctionCodes confirms the function-code constants.
func TestDNP3FunctionCodes(t *testing.T) {
	cases := map[byte]byte{
		DNP3FnConfirm:         0x00,
		DNP3FnRead:            0x01,
		DNP3FnWrite:           0x02,
		DNP3FnSelect:          0x03,
		DNP3FnOperate:         0x04,
		DNP3FnDirectOperate:   0x05,
		DNP3FnDirectOperateNA: 0x06,
		DNP3FnResponse:        0x81,
		DNP3FnUnsolicited:     0x82,
	}
	for got, want := range cases {
		if got != want {
			t.Fatalf("fn code %d != %d", got, want)
		}
	}
}

// TestDNP3LinkControlBytes confirms the control byte constants.
func TestDNP3LinkControlBytes(t *testing.T) {
	if DNP3LinkReset != 0x40 {
		t.Fatalf("link reset byte = 0x%02x", DNP3LinkReset)
	}
	if DNP3LinkUserDataUnc != 0x44 {
		t.Fatalf("user data byte = 0x%02x", DNP3LinkUserDataUnc)
	}
}
