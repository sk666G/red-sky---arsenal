package drone

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"time"
)

// MAVLink v2 frame. Same payload structure as v1, different header layout:
//
//   STX (1)            0xFD
//   LEN (1)            payload length (0..255)
//   INCOMPAT_FLAGS (1) bitmask of incompat changes (0x01 = signed)
//   COMPAT_FLAGS (1)   bitmask of compat changes
//   SEQ (1)            sequence number (0..255)
//   SYS (1)            system id
//   COMP (1)           component id
//   MSG (3 LE)         message id (24 bits)
//   PAYLOAD (LEN)
//   CHECKSUM (2 LE)    X.25 CRC over header(byte 1 onward) + payload + CRC_EXTRA
//   SIGNATURE (13)     optional: link id (1), timestamp (6), sha256 truncated (6)
//
// v2's big win is the 24-bit message ID space and the truncated-payload
// feature (v2 allows sending messages with a shorter-than-declared payload
// if the trailing fields are zero, which is what makes v2 frames compact
// for most messages). This file sends full-length payloads — the truncation
// is a wire optimisation, not a semantic change.

// MAVLink v2 header sizes
const (
	MavlinkV2HeaderSize = 10
	MavlinkV2SigSize    = 13
	MavlinkV2Stx        = 0xFD
)

// MavlinkV2Flags is a small helper for the incompat byte.
const (
	V2FlagSigned = 0x01
)

// FrameV2 builds a MAVLink v2 frame around payload for a 24-bit message id.
// If sigKey is non-nil and len(sigKey) >= 32, the frame is signed.
func FrameV2(msgID uint32, seq, sysID, compID uint8, payload []byte, sigKey []byte, linkID uint8) ([]byte, error) {
	if len(payload) > 255 {
		return nil, errors.New("drone: v2 payload too large")
	}
	if msgID > 0xFFFFFF {
		return nil, errors.New("drone: v2 msg id out of 24-bit range")
	}

	// check CRC_EXTRA availability — v2 uses the same table but keyed by
	// msgID (v1's small ids map to the same values)
	var extra uint8
	if msgID <= 255 {
		if e, ok := crcExtraTable[uint8(msgID)]; ok {
			extra = e
		}
	}
	// for v2-only message ids we'd need the full generated table — for the
	// small set we emit, everything is also a v1 id.

	// incompat flags
	incompat := uint8(0)
	if sigKey != nil && len(sigKey) >= 32 {
		incompat |= V2FlagSigned
	}

	out := make([]byte, 0, MavlinkV2HeaderSize+len(payload)+2+MavlinkV2SigSize)
	// header: STX, LEN, INCOMPAT, COMPAT, SEQ, SYS, COMP, MSG(3 LE)
	out = append(out, MavlinkV2Stx, uint8(len(payload)), incompat, 0x00, seq, sysID, compID)
	// 24-bit little-endian message id
	out = append(out, byte(msgID&0xFF), byte((msgID>>8)&0xFF), byte((msgID>>16)&0xFF))
	out = append(out, payload...)

	// CRC over LEN..payload (skip STX)
	crcData := out[1:]
	crc := crcX25(crcData, extra)
	out = append(out, uint8(crc&0xFF), uint8(crc>>8))

	// signature if signed
	if incompat&V2FlagSigned != 0 {
		sig := buildSignature(sigKey, out[:len(out)-2], linkID)
		out = append(out, sig...)
	}

	return out, nil
}

// buildSignature computes the MAVLink v2 signature block: link_id (1),
// timestamp (6 bytes since 2015-01-01), sha256(secret_key || frame_without_sig
// || link_id || timestamp)[:6].
func buildSignature(secretKey []byte, frameWithoutSig []byte, linkID uint8) []byte {
	// 6-byte timestamp since 2015-01-01 00:00:00 UTC
	epoch2015 := time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC)
	since := time.Since(epoch2015)
	tsMicros := uint64(since / time.Microsecond)

	sig := make([]byte, 0, 13)
	sig = append(sig, linkID)
	// timestamp: 6 bytes little-endian
	var tsBuf [8]byte
	binary.LittleEndian.PutUint64(tsBuf[:], tsMicros)
	sig = append(sig, tsBuf[:6]...)

	// hash input: secret_key (32) || frame (header..payload, no CRC) || link_id || timestamp (6)
	h := sha256.New()
	h.Write(secretKey)
	h.Write(frameWithoutSig)
	h.Write([]byte{linkID})
	h.Write(tsBuf[:6])
	sum := h.Sum(nil)
	sig = append(sig, sum[:6]...)
	return sig
}

// HeartbeatV2 is the v2 heartbeat (same payload, v2 header).
func HeartbeatV2(sysID, compID, seq uint8, sigKey []byte, linkID uint8) ([]byte, error) {
	payload := make([]byte, 9)
	binary.LittleEndian.PutUint32(payload[0:4], 0)
	payload[4] = 2
	payload[5] = 3
	payload[6] = 81
	payload[7] = 4
	payload[8] = 3
	return FrameV2(MsgHeartbeat, seq, sysID, compID, payload, sigKey, linkID)
}

// CommandLongV2 is the v2 command long.
func CommandLongV2(sysID, compID, seq uint8, targetSys, targetComp uint16,
	command uint16, params [7]float32, confirmation uint8,
	sigKey []byte, linkID uint8) ([]byte, error) {
	payload := make([]byte, 33)
	for i := 0; i < 7; i++ {
		binary.LittleEndian.PutUint32(payload[i*4:i*4+4], mathFloat32bits(params[i]))
	}
	binary.LittleEndian.PutUint16(payload[28:30], command)
	payload[30] = uint8(targetSys)
	payload[31] = uint8(targetComp)
	payload[32] = confirmation
	return FrameV2(MsgCommandLong, seq, sysID, compID, payload, sigKey, linkID)
}

// ParseV2 extracts the fields of a received v2 frame.
type V2Frame struct {
	Len          uint8
	IncompatFlag uint8
	CompatFlag   uint8
	Seq          uint8
	SysID        uint8
	CompID       uint8
	MsgID        uint32
	Payload      []byte
	Signed       bool
	LinkID       uint8
	Signature    []byte
}

// ParseV2 decodes a MAVLink v2 frame from the byte stream. Returns an error
// if the frame is malformed or the CRC fails.
// ParseV2 decodes a MAVLink v2 frame.
//
// Handles truncated payloads: the LEN field on the wire carries the
// declared payload length, but the wire may carry fewer trailing bytes
// (the truncated-payload feature of v2 — see mavlink_v2_truncate.go).
// The actual wire payload length is derived from the total frame size,
// and the CRC covers only the bytes actually transmitted.
func ParseV2(b []byte) (V2Frame, error) {
	var f V2Frame
	if len(b) < MavlinkV2HeaderSize+2 {
		return f, errors.New("drone: v2 frame too short")
	}
	if b[0] != MavlinkV2Stx {
		return f, errors.New("drone: not a v2 frame")
	}
	f.Len = b[1]
	f.IncompatFlag = b[2]
	f.CompatFlag = b[3]
	f.Seq = b[4]
	f.SysID = b[5]
	f.CompID = b[6]
	f.MsgID = uint32(b[7]) | uint32(b[8])<<8 | uint32(b[9])<<16
	f.Signed = f.IncompatFlag&V2FlagSigned != 0

	// derive the actual wire payload length from the total frame size.
	// layout: header(10) | payload(N) | CRC(2) | signature(13 if signed)
	trailer := 2
	if f.Signed {
		trailer += MavlinkV2SigSize
	}
	if len(b) < MavlinkV2HeaderSize+trailer {
		return f, fmt.Errorf("drone: v2 frame too short for trailer")
	}
	wireLen := len(b) - MavlinkV2HeaderSize - trailer
	if wireLen < 0 {
		return f, errors.New("drone: negative payload length")
	}
	if wireLen > int(f.Len) {
		return f, fmt.Errorf("drone: wire payload %d > declared %d", wireLen, f.Len)
	}

	// reconstruct full payload with zero padding for the truncated tail
	f.Payload = make([]byte, f.Len)
	copy(f.Payload, b[MavlinkV2HeaderSize:MavlinkV2HeaderSize+wireLen])

	// CRC verify — covers the wire bytes only (header from LEN onward +
	// the wire payload + CRC_EXTRA)
	var extra uint8
	if f.MsgID <= 255 {
		if e, ok := crcExtraTable[uint8(f.MsgID)]; ok {
			extra = e
		}
	}
	crcOff := MavlinkV2HeaderSize + wireLen
	gotCRC := binary.LittleEndian.Uint16(b[crcOff : crcOff+2])
	wantCRC := crcX25(b[1:crcOff], extra)
	if gotCRC != wantCRC {
		return f, fmt.Errorf("drone: v2 CRC mismatch (got %04x, want %04x)", gotCRC, wantCRC)
	}

	if f.Signed {
		sigOff := crcOff + 2
		f.LinkID = b[sigOff]
		f.Signature = append([]byte(nil), b[sigOff:sigOff+MavlinkV2SigSize]...)
	}
	return f, nil
}
