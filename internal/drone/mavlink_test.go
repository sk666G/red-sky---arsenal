package drone

import (
	"encoding/binary"
	"testing"
)

// TestHeartbeatFrameShape pins the frame layout for a v1 HEARTBEAT.
func TestHeartbeatFrameShape(t *testing.T) {
	frame, err := Heartbeat(255, 190, 42)
	if err != nil {
		t.Fatal(err)
	}
	if len(frame) < 8 {
		t.Fatalf("frame too short: %d", len(frame))
	}
	if frame[0] != MAVLinkStxV1 {
		t.Fatalf("wrong STX: 0x%02x", frame[0])
	}
	if frame[1] != 9 {
		t.Fatalf("wrong LEN: %d", frame[1])
	}
	if frame[2] != 42 {
		t.Fatalf("wrong SEQ: %d", frame[2])
	}
	if frame[3] != 255 {
		t.Fatalf("wrong SYS: %d", frame[3])
	}
	if frame[4] != 190 {
		t.Fatalf("wrong COMP: %d", frame[4])
	}
	if frame[5] != MsgHeartbeat {
		t.Fatalf("wrong MSG: %d", frame[5])
	}
}

// TestHeartbeatRoundTrip builds a heartbeat and parses it back, verifying
// the decoded fields match what was encoded.
func TestHeartbeatRoundTrip(t *testing.T) {
	frame, err := Heartbeat(1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV1(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.MsgID != MsgHeartbeat {
		t.Fatalf("msg id mismatch: %d", parsed.MsgID)
	}
	if parsed.SysID != 1 || parsed.CompID != 2 {
		t.Fatalf("sys/comp mismatch: %d/%d", parsed.SysID, parsed.CompID)
	}
	h, err := DecodeHeartbeat(parsed.Payload)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if h.Type != 2 || h.Autopilot != 3 || h.MavlinkVersion != 3 {
		t.Fatalf("heartbeat fields wrong: type=%d autopilot=%d ver=%d",
			h.Type, h.Autopilot, h.MavlinkVersion)
	}
}

// TestParseV1RejectsBadCrc catches the CRC check by flipping a byte.
func TestParseV1RejectsBadCrc(t *testing.T) {
	frame, err := Heartbeat(1, 2, 0)
	if err != nil {
		t.Fatal(err)
	}
	// corrupt payload
	frame[6] ^= 0xFF
	_, err = ParseV1(frame)
	if err == nil {
		t.Fatalf("expected CRC error, got nil")
	}
}

// TestParseV1RejectsBadStx confirms the STX check fires.
func TestParseV1RejectsBadStx(t *testing.T) {
	frame, _ := Heartbeat(1, 2, 0)
	frame[0] = 0xAA
	_, err := ParseV1(frame)
	if err == nil {
		t.Fatalf("expected STX error, got nil")
	}
}

// TestCommandLongRoundTrip verifies the command encoding survives.
func TestCommandLongRoundTrip(t *testing.T) {
	var params [7]float32
	params[0] = 1.5
	params[1] = -2.25
	params[2] = 100.0

	frame, err := CommandLong(255, 190, 0, 1, 1, 400, params, 0)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV1(frame)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if parsed.MsgID != MsgCommandLong {
		t.Fatalf("msg id mismatch: %d", parsed.MsgID)
	}
	if len(parsed.Payload) != 33 {
		t.Fatalf("payload len: %d", len(parsed.Payload))
	}
	// verify the first float comes back
	got := float32frombits(binary.LittleEndian.Uint32(parsed.Payload[0:4]))
	if got != 1.5 {
		t.Fatalf("param0 = %v, want 1.5", got)
	}
	// verify the command id at offset 28
	cmd := binary.LittleEndian.Uint16(parsed.Payload[28:30])
	if cmd != 400 {
		t.Fatalf("command = %d, want 400", cmd)
	}
}

// TestV2HeartbeatRoundTrip builds a v2 heartbeat and parses it.
func TestV2HeartbeatRoundTrip(t *testing.T) {
	frame, err := HeartbeatV2(1, 2, 3, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	if frame[0] != MavlinkV2Stx {
		t.Fatalf("wrong v2 STX: 0x%02x", frame[0])
	}
	parsed, err := ParseV2(frame)
	if err != nil {
		t.Fatalf("parse v2: %v", err)
	}
	if parsed.MsgID != MsgHeartbeat {
		t.Fatalf("v2 msg id: %d", parsed.MsgID)
	}
	if parsed.SysID != 1 || parsed.CompID != 2 || parsed.Seq != 3 {
		t.Fatalf("v2 header: sys=%d comp=%d seq=%d", parsed.SysID, parsed.CompID, parsed.Seq)
	}
	if parsed.Signed {
		t.Fatalf("v2 frame should not be signed")
	}
}

// TestV2SignedFrame checks the signature block is present and the
// signed bit is set.
func TestV2SignedFrame(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	frame, err := HeartbeatV2(1, 2, 3, key, 7)
	if err != nil {
		t.Fatal(err)
	}
	// parse and check
	parsed, err := ParseV2(frame)
	if err != nil {
		t.Fatalf("parse v2 signed: %v", err)
	}
	if !parsed.Signed {
		t.Fatalf("signed bit not set")
	}
	if parsed.LinkID != 7 {
		t.Fatalf("link id: %d, want 7", parsed.LinkID)
	}
	// signature block must be present (13 bytes at tail)
	if len(parsed.Signature) != MavlinkV2SigSize {
		t.Fatalf("signature block wrong size: %d", len(parsed.Signature))
	}
}

// TestDecodeStatusText verifies the NUL-terminated string parses.
func TestDecodeStatusText(t *testing.T) {
	// severity (1) + text "hello" + NUL + padding
	payload := append([]byte{3}, []byte("hello\x00")...)
	payload = append(payload, make([]byte, 10)...)
	s, err := DecodeStatusText(payload)
	if err != nil {
		t.Fatal(err)
	}
	if s.Severity != 3 {
		t.Fatalf("severity: %d", s.Severity)
	}
	if s.Text != "hello" {
		t.Fatalf("text: %q", s.Text)
	}
}

// TestDecodeAttitude checks the float extraction.
func TestDecodeAttitude(t *testing.T) {
	payload := make([]byte, 28)
	binary.LittleEndian.PutUint32(payload[0:4], 12345)
	binary.LittleEndian.PutUint32(payload[4:8], mathFloat32bits(0.1))
	binary.LittleEndian.PutUint32(payload[8:12], mathFloat32bits(0.2))
	binary.LittleEndian.PutUint32(payload[12:16], mathFloat32bits(0.3))

	a, err := DecodeAttitude(payload)
	if err != nil {
		t.Fatal(err)
	}
	if a.TimeBootMs != 12345 {
		t.Fatalf("time: %d", a.TimeBootMs)
	}
	// float comparison with tolerance
	if diff := a.Roll - 0.1; diff > 1e-6 || diff < -1e-6 {
		t.Fatalf("roll: %v", a.Roll)
	}
	if diff := a.Pitch - 0.2; diff > 1e-6 || diff < -1e-6 {
		t.Fatalf("pitch: %v", a.Pitch)
	}
}

// TestDecodeGlobalPosition checks the packed lat/lon decode.
func TestDecodeGlobalPosition(t *testing.T) {
	payload := make([]byte, 28)
	binary.LittleEndian.PutUint32(payload[0:4], 100)
	binary.LittleEndian.PutUint32(payload[4:8], 377749000) // 37.7749000 * 1e7
	var negLon int32 = -1224194000
	binary.LittleEndian.PutUint32(payload[8:12], uint32(negLon))
	binary.LittleEndian.PutUint32(payload[12:16], 115000) // 115m above MSL

	g, err := DecodeGlobalPosition(payload)
	if err != nil {
		t.Fatal(err)
	}
	if g.Lat != 377749000 {
		t.Fatalf("lat: %d", g.Lat)
	}
	if g.Lon != -1224194000 {
		t.Fatalf("lon: %d", g.Lon)
	}
	if g.Alt != 115000 {
		t.Fatalf("alt: %d", g.Alt)
	}
}

// TestDescribeFrame exercises the summary path.
func TestDescribeFrame(t *testing.T) {
	h, _ := Heartbeat(1, 2, 0)
	parsed, _ := ParseV1(h)
	desc := DescribeFrame(uint32(parsed.MsgID), parsed.Payload)
	if desc == "" {
		t.Fatalf("empty describe")
	}
	// should mention heartbeat
	if !contains(desc, "heartbeat") {
		t.Fatalf("describe didn't mention heartbeat: %q", desc)
	}
}

// contains is a tiny substring helper.
func contains(haystack, needle string) bool {
	if len(needle) == 0 {
		return true
	}
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return true
		}
	}
	return false
}
