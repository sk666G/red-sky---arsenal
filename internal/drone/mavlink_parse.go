package drone

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// MAVLink v1 frame decoder. Mirrors ParseV2 — takes a byte slice that
// starts with a v1 STX (0xFE) and returns the structured fields with CRC
// verified.
//
// Frame layout (recap from mavlink.go):
//   STX (1)  0xFE
//   LEN (1)
//   SEQ (1)
//   SYS (1)
//   COMP (1)
//   MSG (1)
//   PAYLOAD (LEN)
//   CRC (2 LE)

// V1Frame is the decoded structure.
type V1Frame struct {
	Len     uint8
	Seq     uint8
	SysID   uint8
	CompID  uint8
	MsgID   uint8
	Payload []byte
}

// ParseV1 decodes one MAVLink v1 frame from the byte slice. Returns an
// error if the slice is short, the STX is missing, or the CRC mismatches.
func ParseV1(b []byte) (V1Frame, error) {
	var f V1Frame
	if len(b) < 8 {
		return f, errors.New("drone: v1 frame too short")
	}
	if b[0] != MAVLinkStxV1 {
		return f, errors.New("drone: not a v1 frame")
	}
	f.Len = b[1]
	f.Seq = b[2]
	f.SysID = b[3]
	f.CompID = b[4]
	f.MsgID = b[5]

	need := 6 + int(f.Len) + 2
	if len(b) < need {
		return f, fmt.Errorf("drone: v1 frame too short (need %d, have %d)", need, len(b))
	}
	f.Payload = append([]byte(nil), b[6:6+int(f.Len)]...)

	// CRC verify
	extra, ok := crcExtraTable[f.MsgID]
	if !ok {
		return f, fmt.Errorf("drone: unknown v1 msg id %d", f.MsgID)
	}
	got := binary.LittleEndian.Uint16(b[6+int(f.Len) : 8+int(f.Len)])
	want := crcX25(b[1:6+int(f.Len)], extra)
	if got != want {
		return f, fmt.Errorf("drone: v1 CRC mismatch (got %04x, want %04x)", got, want)
	}
	return f, nil
}

// --- Decoded message shapes ---
//
// The payload decoders below assume the standard field layout of each
// message (MAVLink common dialect). Little-endian, packed, no alignment
// padding — MAVLink is designed for byte streams.

// HeartbeatDecoded is the fields of a HEARTBEAT message.
type HeartbeatDecoded struct {
	CustomMode    uint32
	Type          uint8
	Autopilot     uint8
	BaseMode      uint8
	SystemStatus  uint8
	MavlinkVersion uint8
}

// DecodeHeartbeat extracts the fields of a HEARTBEAT payload.
func DecodeHeartbeat(payload []byte) (HeartbeatDecoded, error) {
	var h HeartbeatDecoded
	if len(payload) < 9 {
		return h, errors.New("drone: heartbeat payload < 9 bytes")
	}
	h.CustomMode = binary.LittleEndian.Uint32(payload[0:4])
	h.Type = payload[4]
	h.Autopilot = payload[5]
	h.BaseMode = payload[6]
	h.SystemStatus = payload[7]
	h.MavlinkVersion = payload[8]
	return h, nil
}

// StatusTextDecoded is a STATUSTEXT message.
type StatusTextDecoded struct {
	Severity uint8
	Text     string
}

// DecodeStatusText extracts the STATUSTEXT fields.
func DecodeStatusText(payload []byte) (StatusTextDecoded, error) {
	var s StatusTextDecoded
	if len(payload) < 1 {
		return s, errors.New("drone: statustext empty")
	}
	s.Severity = payload[0]
	// text is the rest, NUL-terminated
	text := payload[1:]
	for i, c := range text {
		if c == 0 {
			text = text[:i]
			break
		}
	}
	s.Text = string(text)
	return s, nil
}

// AttitudeDecoded is the fields of an ATTITUDE message.
type AttitudeDecoded struct {
	TimeBootMs uint32
	Roll       float32
	Pitch      float32
	Yaw        float32
	Rollspeed  float32
	Pitchspeed float32
	Yawspeed   float32
}

// DecodeAttitude extracts the ATTITUDE fields.
func DecodeAttitude(payload []byte) (AttitudeDecoded, error) {
	var a AttitudeDecoded
	if len(payload) < 28 {
		return a, errors.New("drone: attitude payload < 28 bytes")
	}
	a.TimeBootMs = binary.LittleEndian.Uint32(payload[0:4])
	a.Roll = float32frombits(binary.LittleEndian.Uint32(payload[4:8]))
	a.Pitch = float32frombits(binary.LittleEndian.Uint32(payload[8:12]))
	a.Yaw = float32frombits(binary.LittleEndian.Uint32(payload[12:16]))
	a.Rollspeed = float32frombits(binary.LittleEndian.Uint32(payload[16:20]))
	a.Pitchspeed = float32frombits(binary.LittleEndian.Uint32(payload[20:24]))
	a.Yawspeed = float32frombits(binary.LittleEndian.Uint32(payload[24:28]))
	return a, nil
}

// GlobalPositionDecoded is GLOBAL_POSITION_INT.
type GlobalPositionDecoded struct {
	TimeBootMs uint32
	Lat        int32 // 1e7 degrees
	Lon        int32
	Alt        int32 // mm above MSL
	RelativeAlt int32
	Vx, Vy, Vz int16 // cm/s
	Hdg        uint16
}

// DecodeGlobalPosition extracts the fields.
func DecodeGlobalPosition(payload []byte) (GlobalPositionDecoded, error) {
	var g GlobalPositionDecoded
	if len(payload) < 28 {
		return g, errors.New("drone: global position payload < 28 bytes")
	}
	g.TimeBootMs = binary.LittleEndian.Uint32(payload[0:4])
	g.Lat = int32(binary.LittleEndian.Uint32(payload[4:8]))
	g.Lon = int32(binary.LittleEndian.Uint32(payload[8:12]))
	g.Alt = int32(binary.LittleEndian.Uint32(payload[12:16]))
	g.RelativeAlt = int32(binary.LittleEndian.Uint32(payload[16:20]))
	g.Vx = int16(binary.LittleEndian.Uint16(payload[20:22]))
	g.Vy = int16(binary.LittleEndian.Uint16(payload[22:24]))
	g.Vz = int16(binary.LittleEndian.Uint16(payload[24:26]))
	g.Hdg = binary.LittleEndian.Uint16(payload[26:28])
	return g, nil
}

// VfrHudDecoded is VFR_HUD.
type VfrHudDecoded struct {
	Airspeed    float32
	Groundspeed float32
	Heading     int16
	Throttle    uint16
	Alt         float32
	Climb       float32
}

// DecodeVfrHud extracts the VFR_HUD fields.
func DecodeVfrHud(payload []byte) (VfrHudDecoded, error) {
	var v VfrHudDecoded
	if len(payload) < 20 {
		return v, errors.New("drone: vfr_hud payload < 20 bytes")
	}
	v.Airspeed = float32frombits(binary.LittleEndian.Uint32(payload[0:4]))
	v.Groundspeed = float32frombits(binary.LittleEndian.Uint32(payload[4:8]))
	v.Heading = int16(binary.LittleEndian.Uint16(payload[8:10]))
	v.Throttle = binary.LittleEndian.Uint16(payload[10:12])
	v.Alt = float32frombits(binary.LittleEndian.Uint32(payload[12:16]))
	v.Climb = float32frombits(binary.LittleEndian.Uint32(payload[16:20]))
	return v, nil
}

// float32frombits is a thin wrapper over math.Float32frombits.
func float32frombits(b uint32) float32 {
	return math.Float32frombits(b)
}

// DescribeFrame returns a human-readable one-line summary of a decoded
// v1 or v2 frame based on its message id.
func DescribeFrame(msgID uint32, payload []byte) string {
	switch uint8(msgID) {
	case MsgHeartbeat:
		if h, err := DecodeHeartbeat(payload); err == nil {
			return fmt.Sprintf("heartbeat type=%d autopilot=%d mode=0x%x status=%d v%d",
				h.Type, h.Autopilot, h.CustomMode, h.SystemStatus, h.MavlinkVersion)
		}
	case MsgStatustext:
		if s, err := DecodeStatusText(payload); err == nil {
			return fmt.Sprintf("statustext severity=%d text=%q", s.Severity, s.Text)
		}
	case MsgAttitude:
		if a, err := DecodeAttitude(payload); err == nil {
			return fmt.Sprintf("attitude roll=%.2f pitch=%.2f yaw=%.2f",
				a.Roll, a.Pitch, a.Yaw)
		}
	case MsgGlobalPosInt:
		if g, err := DecodeGlobalPosition(payload); err == nil {
			return fmt.Sprintf("gps lat=%.7f lon=%.7f alt=%.1fm",
				float64(g.Lat)/1e7, float64(g.Lon)/1e7, float64(g.Alt)/1000.0)
		}
	case MsgVfrHud:
		if v, err := DecodeVfrHud(payload); err == nil {
			return fmt.Sprintf("vfr speed=%.1f alt=%.1f heading=%d",
				v.Groundspeed, v.Alt, v.Heading)
		}
	}
	return fmt.Sprintf("msg id=%d %d bytes", msgID, len(payload))
}
