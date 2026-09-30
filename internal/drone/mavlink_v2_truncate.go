package drone

import (
	"errors"
	"fmt"
)

// MAVLink v2 payload truncation.
//
// v2 lets the sender declare a payload of full length but actually transmit
// fewer trailing zero bytes. The receiver pads the payload back up to the
// declared length. This is the wire optimisation that makes v2 frames
// smaller than v1 for the same message.
//
// Concretely: a HEARTBEAT is 9 bytes. If the last 3 bytes are zero, the
// frame can declare LEN=9 but transmit only 6 payload bytes. The receiver
// sees LEN=9 and pads the missing 3 bytes with zeros.
//
// The truncation is safe because MAVLink payload fields are fixed-size
// and the wire order is defined per message. Trailing zeros are the
// common case for optional or default-valued fields.

// TruncatePayload shortens a payload by removing trailing zero bytes.
// Returns the shortened slice and the declared length (which is the
// original length — that's what goes into the LEN field).
//
// The returned bytes still declare `declaredLen` in the header so the
// receiver knows how many bytes to reconstruct.
func TruncatePayload(payload []byte) (wire []byte, declaredLen uint8) {
	if len(payload) > 255 {
		// caller error — this shouldn't happen since frame builders cap at 255
		return payload, uint8(len(payload))
	}
	// find the last non-zero byte
	last := len(payload)
	for last > 0 && payload[last-1] == 0 {
		last--
	}
	// always keep at least one byte
	if last == 0 && len(payload) > 0 {
		last = 1
	}
	return payload[:last], uint8(len(payload))
}

// ExpandPayload reverses truncation: given a wire payload and the declared
// length, pad the payload back up with zeros.
func ExpandPayload(wire []byte, declaredLen uint8) ([]byte, error) {
	if declaredLen > 255 {
		return nil, errors.New("drone: declared length > 255")
	}
	if len(wire) > int(declaredLen) {
		return nil, fmt.Errorf("drone: wire length %d > declared %d", len(wire), declaredLen)
	}
	if len(wire) == int(declaredLen) {
		return wire, nil
	}
	out := make([]byte, declaredLen)
	copy(out, wire)
	return out, nil
}

// FrameV2Truncated builds a v2 frame with payload truncation applied.
// The header's LEN field carries the declared (full) length; the wire
// only carries the non-trailing-zero bytes.
func FrameV2Truncated(msgID uint32, seq, sysID, compID uint8, payload []byte, sigKey []byte, linkID uint8) ([]byte, error) {
	wire, declared := TruncatePayload(payload)
	return frameV2WithDeclaredLen(msgID, seq, sysID, compID, wire, declared, sigKey, linkID)
}

// frameV2WithDeclaredLen is the internal frame builder that separates the
// declared length (which goes on the wire) from the actual payload bytes.
func frameV2WithDeclaredLen(msgID uint32, seq, sysID, compID uint8, wirePayload []byte, declaredLen uint8, sigKey []byte, linkID uint8) ([]byte, error) {
	if len(wirePayload) > int(declaredLen) {
		return nil, errors.New("drone: wire payload longer than declared")
	}
	if msgID > 0xFFFFFF {
		return nil, errors.New("drone: v2 msg id out of 24-bit range")
	}
	var extra uint8
	if msgID <= 255 {
		if e, ok := crcExtraTable[uint8(msgID)]; ok {
			extra = e
		}
	}
	incompat := uint8(0)
	if sigKey != nil && len(sigKey) >= 32 {
		incompat |= V2FlagSigned
	}

	out := make([]byte, 0, 10+len(wirePayload)+2+13)
	// header: STX, LEN=declared, INCOMPAT, COMPAT, SEQ, SYS, COMP, MSG(3 LE)
	out = append(out, MavlinkV2Stx, declaredLen, incompat, 0x00, seq, sysID, compID)
	out = append(out, byte(msgID&0xFF), byte((msgID>>8)&0xFF), byte((msgID>>16)&0xFF))
	out = append(out, wirePayload...)

	// CRC is computed over the truncated bytes on the wire, plus the
	// CRC_EXTRA byte. The declared length is used for the length check
	// but the CRC only covers the bytes actually present.
	crcData := out[1:]
	crc := crcX25(crcData, extra)
	out = append(out, uint8(crc&0xFF), uint8(crc>>8))

	if incompat&V2FlagSigned != 0 {
		sig := buildSignature(sigKey, out[:len(out)-2], linkID)
		out = append(out, sig...)
	}
	return out, nil
}
