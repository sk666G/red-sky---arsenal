package drone

import (
	"bytes"
	"testing"
)

// TestTruncatePayloadRemovesTrailingZeros confirms the trailing zeros are
// stripped and the declared length is preserved.
func TestTruncatePayloadRemovesTrailingZeros(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03, 0x00, 0x00, 0x00}
	wire, declared := TruncatePayload(in)
	if declared != 6 {
		t.Fatalf("declared length = %d, want 6", declared)
	}
	if !bytes.Equal(wire, []byte{0x01, 0x02, 0x03}) {
		t.Fatalf("truncated wire: %x", wire)
	}
}

func TestTruncatePayloadNoZeros(t *testing.T) {
	in := []byte{0x01, 0x02, 0x03}
	wire, declared := TruncatePayload(in)
	if declared != 3 || !bytes.Equal(wire, in) {
		t.Fatalf("no-trunc case: wire=%x declared=%d", wire, declared)
	}
}

func TestTruncatePayloadAllZeros(t *testing.T) {
	in := []byte{0x00, 0x00, 0x00}
	wire, declared := TruncatePayload(in)
	if declared != 3 {
		t.Fatalf("declared length = %d", declared)
	}
	// at least one byte must survive
	if len(wire) != 1 {
		t.Fatalf("all-zero payload: wire len = %d, want 1", len(wire))
	}
}

// TestExpandPayloadPadsZeros verifies reconstruction.
func TestExpandPayloadPadsZeros(t *testing.T) {
	wire := []byte{0x01, 0x02}
	out, err := ExpandPayload(wire, 5)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(out, []byte{0x01, 0x02, 0x00, 0x00, 0x00}) {
		t.Fatalf("expand: %x", out)
	}
}

// TestTruncatedHeartbeatRoundTrip — build with truncation, parse back,
// verify the payload reconstructs to the original.
func TestTruncatedHeartbeatRoundTrip(t *testing.T) {
	// hand-built heartbeat with trailing zeros
	payload := []byte{0x00, 0x00, 0x00, 0x00, 0x02, 0x03, 0x51, 0x00, 0x00}
	// non-zero middle, zeros at tail
	frame, err := FrameV2Truncated(MsgHeartbeat, 1, 1, 1, payload, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	// wire should be shorter than declared because of the trailing zeros
	if len(frame) >= 10+len(payload)+2 {
		t.Fatalf("frame not truncated: %d bytes", len(frame))
	}
	parsed, err := ParseV2(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("payload mismatch:\n  got  %x\n  want %x", parsed.Payload, payload)
	}
}

// TestUntruncatedFrameStillParses — a full-payload frame parses the same.
func TestUntruncatedFrameStillParses(t *testing.T) {
	payload := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09}
	frame, err := FrameV2Truncated(MsgHeartbeat, 1, 1, 1, payload, nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := ParseV2(frame)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(parsed.Payload, payload) {
		t.Fatalf("untruncated round-trip failed:\n  got  %x\n  want %x", parsed.Payload, payload)
	}
}
