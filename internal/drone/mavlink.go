// Package drone implements MAVLink primitives for UAV / drone interaction.
// Go analogue of Program/drone/. MAVLink is a compact binary protocol over
// UDP (default 14550), TCP, or a serial link. No auth on v1 or v2 without
// signing. Ground stations and companion computers accept whatever a peer
// sends if they're on the same broadcast domain.
package drone

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"net"
	"time"
)

// MAVLink v1 frame:
//   STX (1)  0xFE
//   LEN (1)  payload length (0..255)
//   SEQ (1)  sequence number
//   SYS (1)  system id
//   COMP (1) component id
//   MSG (1)  message id
//   PAYLOAD (LEN)
//   CRC (2 LE)
//
// CRC is X.25 / CCITT (poly 0x1021, init 0xFFFF) with the extra "CRC_EXTRA"
// byte appended to the data before the checksum. We carry a small table of
// CRC_EXTRA values for the messages we emit.
//
// v2 differs in the header layout (STX 0xFD, different field order, optional
// signing). This file is v1-only to keep it small. v2 is a follow-up.

const (
	MAVLinkPort  = 14550
	MAVLinkStxV1 = 0xFE
	MAVLinkStxV2 = 0xFD
)

// Message IDs (MAVLink common dialect)
const (
	MsgHeartbeat                  = 0
	MsgSysStatus                  = 1
	MsgSystemTime                 = 2
	MsgPing                       = 4
	MsgChangeOp                   = 5
	MsgSetMode                    = 11
	MsgParamRequestList           = 21
	MsgParamValue                 = 22
	MsgParamSet                   = 23
	MsgGpsRawInt                  = 24
	MsgAttitude                   = 30
	MsgGlobalPosInt               = 33
	MsgRcChannelsRaw              = 35
	MsgCommandLong                = 76
	MsgCommandAck                 = 77
	MsgManualControl              = 69
	MsgSetPositionTargetGlobalInt = 86
	MsgVfrHud                     = 74
	MsgStatustext                 = 253
)

// MAVLinkOptions controls a session.
type MAVLinkOptions struct {
	Host    string
	Port    int
	Timeout time.Duration
	SysID   uint8
	CompID  uint8
}

func droneDefault(opts MAVLinkOptions) MAVLinkOptions {
	if opts.Port == 0 {
		opts.Port = MAVLinkPort
	}
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.SysID == 0 {
		opts.SysID = 255
	}
	if opts.CompID == 0 {
		opts.CompID = 190
	}
	return opts
}

// crcExtraTable carries the CRC_EXTRA byte per message id. Only the ones
// we emit — a real implementation would include the full generated table.
var crcExtraTable = map[uint8]uint8{
	MsgHeartbeat:                  50,
	MsgSysStatus:                  124,
	MsgSystemTime:                 137,
	MsgPing:                       237,
	MsgChangeOp:                   217,
	MsgSetMode:                    89,
	MsgParamRequestList:           159,
	MsgParamValue:                 220,
	MsgParamSet:                   168,
	MsgGpsRawInt:                  24,
	MsgAttitude:                   39,
	MsgGlobalPosInt:               104,
	MsgRcChannelsRaw:              244,
	MsgCommandLong:                152,
	MsgCommandAck:                 143,
	MsgManualControl:              171,
	MsgSetPositionTargetGlobalInt: 143,
	MsgVfrHud:                     20,
	MsgStatustext:                 83,
}

// crcX25 computes the CCITT X.25 CRC over data. The MAVLink CRC appends a
// message-specific extra byte before finalizing.
func crcX25(data []byte, extra uint8) uint16 {
	crc := uint16(0xFFFF)
	for _, b := range data {
		tmp := b ^ uint8(crc&0xFF)
		tmp ^= tmp << 4
		crc = (crc >> 8) ^ uint16(tmp)<<8 ^ uint16(tmp)<<3 ^ uint16(tmp)>>4
	}
	// extra byte
	tmp := extra ^ uint8(crc&0xFF)
	tmp ^= tmp << 4
	crc = (crc >> 8) ^ uint16(tmp)<<8 ^ uint16(tmp)<<3 ^ uint16(tmp)>>4
	return crc
}

// FrameV1 builds a MAVLink v1 frame around payload for msgID.
func FrameV1(msgID uint8, seq, sysID, compID uint8, payload []byte) ([]byte, error) {
	if len(payload) > 255 {
		return nil, errors.New("drone: payload too large")
	}
	extra, ok := crcExtraTable[msgID]
	if !ok {
		return nil, fmt.Errorf("drone: unknown msg id %d (no CRC_EXTRA)", msgID)
	}
	out := make([]byte, 0, 6+len(payload)+2)
	out = append(out, MAVLinkStxV1, uint8(len(payload)), seq, sysID, compID, msgID)
	out = append(out, payload...)
	// CRC over header (from LEN) + payload + extra, but not STX
	crcData := append([]byte{uint8(len(payload)), seq, sysID, compID, msgID}, payload...)
	crc := crcX25(crcData, extra)
	out = append(out, uint8(crc&0xFF), uint8(crc>>8))
	return out, nil
}

// --- specific message builders ---

// Heartbeat builds a MAV_TYPE_QUADROTOR heartbeat. Sent by a GCS to appear
// as a valid MAVLink peer.
func Heartbeat(sysID, compID, seq uint8) ([]byte, error) {
	// custom_mode (4), type (1), autopilot (1), base_mode (1),
	// system_status (1), mavlink_version (1) = 9 bytes
	payload := make([]byte, 9)
	binary.LittleEndian.PutUint32(payload[0:4], 0) // custom_mode
	payload[4] = 2                                 // type: quadrotor
	payload[5] = 3                                 // autopilot: ardupilotmega
	payload[6] = 81                                // base_mode (custom + auto)
	payload[7] = 4                                 // system_status: active
	payload[8] = 3                                 // mavlink_version
	return FrameV1(MsgHeartbeat, seq, sysID, compID, payload)
}

// CommandLong builds a COMMAND_LONG. command is a MAV_CMD id.
// params are the seven float params (little-endian f32).
func CommandLong(sysID, compID, seq uint8, targetSys, targetComp uint16, command uint16, params [7]float32, confirmation uint8) ([]byte, error) {
	// param1..7 (28), command (2), target_system (1), target_component (1), confirmation (1) = 33 bytes
	payload := make([]byte, 33)
	for i := 0; i < 7; i++ {
		binary.LittleEndian.PutUint32(payload[i*4:i*4+4], mathFloat32bits(params[i]))
	}
	binary.LittleEndian.PutUint16(payload[28:30], command)
	payload[30] = uint8(targetSys)
	payload[31] = uint8(targetComp)
	payload[32] = confirmation
	return FrameV1(MsgCommandLong, seq, sysID, compID, payload)
}

// SetMode changes the flight mode (ardupilot / px4 specific numbers).
func SetMode(sysID, compID, seq, targetSys uint8, baseMode, customMode uint32) ([]byte, error) {
	// custom_mode (4), target_system (1), base_mode (1) = 6 bytes
	payload := make([]byte, 6)
	binary.LittleEndian.PutUint32(payload[0:4], customMode)
	payload[4] = targetSys
	payload[5] = uint8(baseMode)
	return FrameV1(MsgSetMode, seq, sysID, compID, payload)
}

// ManualControl sends RC-style control. x, y, z, r in [-1000, 1000].
func ManualControl(sysID, compID, seq, targetSys uint8, x, y, z, r int16, buttons uint16) ([]byte, error) {
	// x (2), y (2), z (2), r (2), buttons (2), target (1) = 11 bytes
	payload := make([]byte, 11)
	binary.LittleEndian.PutUint16(payload[0:2], uint16(x))
	binary.LittleEndian.PutUint16(payload[2:4], uint16(y))
	binary.LittleEndian.PutUint16(payload[4:6], uint16(z))
	binary.LittleEndian.PutUint16(payload[6:8], uint16(r))
	binary.LittleEndian.PutUint16(payload[8:10], buttons)
	payload[10] = targetSys
	return FrameV1(MsgManualControl, seq, sysID, compID, payload)
}

// SetPositionTargetGlobalInt commands a global position target. Coordinate
// types = 0b0000111111111000 (position + velocity + accel + yaw all valid).
func SetPositionTargetGlobalInt(sysID, compID, seq, targetSys, targetComp uint8,
	lat, lon, alt float32, vx, vy, vz, afx, afy, afz, yaw, yawRate float32,
	typMask uint16) ([]byte, error) {
	payload := make([]byte, 53)
	binary.LittleEndian.PutUint32(payload[0:4], mathFloat32bits(lat))
	binary.LittleEndian.PutUint32(payload[4:8], mathFloat32bits(lon))
	binary.LittleEndian.PutUint32(payload[8:12], mathFloat32bits(alt))
	binary.LittleEndian.PutUint32(payload[12:16], mathFloat32bits(vx))
	binary.LittleEndian.PutUint32(payload[16:20], mathFloat32bits(vy))
	binary.LittleEndian.PutUint32(payload[20:24], mathFloat32bits(vz))
	binary.LittleEndian.PutUint32(payload[24:28], mathFloat32bits(afx))
	binary.LittleEndian.PutUint32(payload[28:32], mathFloat32bits(afy))
	binary.LittleEndian.PutUint32(payload[32:36], mathFloat32bits(afz))
	binary.LittleEndian.PutUint32(payload[36:40], mathFloat32bits(yaw))
	binary.LittleEndian.PutUint32(payload[40:44], mathFloat32bits(yawRate))
	// target_system, target_component, coordinate_frame, type_mask = 6 bytes
	payload[44] = targetSys
	payload[45] = targetComp
	payload[46] = 6 // frame: GLOBAL_RELATIVE_ALT_INT
	binary.LittleEndian.PutUint16(payload[47:49], typMask)
	// 4 bytes reserved at the tail
	return FrameV1(MsgSetPositionTargetGlobalInt, seq, sysID, compID, payload[:51])
}

// Ping sends the MAVLink ping.
func Ping(sysID, compID, seq, targetSys, targetComp uint8, timeUsec uint64) ([]byte, error) {
	payload := make([]byte, 14)
	binary.LittleEndian.PutUint64(payload[0:8], timeUsec)
	binary.LittleEndian.PutUint32(payload[8:12], 0)
	payload[12] = targetSys
	payload[13] = targetComp
	return FrameV1(MsgPing, seq, sysID, compID, payload)
}

// --- transport ---

// SendUDP dials host:port and sends the frame. One-shot.
func SendUDP(opts MAVLinkOptions, frame []byte) error {
	opts = droneDefault(opts)
	if opts.Host == "" {
		return errors.New("drone: host required")
	}
	conn, err := net.DialUDP("udp", nil,
		&net.UDPAddr{IP: net.ParseIP(opts.Host), Port: opts.Port})
	if err != nil {
		return fmt.Errorf("drone: dial: %w", err)
	}
	defer conn.Close()
	_, err = conn.Write(frame)
	return err
}

// Listen opens a UDP listener on the given port for a window and returns
// every MAVLink frame received. Useful for identifying active drones on a
// segment via their heartbeat broadcasts.
type ReceivedFrame struct {
	From    string
	MsgID   uint8
	Raw     []byte
	Payload []byte
}

func Listen(port int, duration time.Duration) ([]ReceivedFrame, error) {
	if port == 0 {
		port = MAVLinkPort
	}
	if duration <= 0 {
		duration = 10 * time.Second
	}
	conn, err := net.ListenUDP("udp",
		&net.UDPAddr{IP: net.IPv4zero, Port: port})
	if err != nil {
		return nil, fmt.Errorf("drone: listen: %w", err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(duration))

	var out []ReceivedFrame
	buf := make([]byte, 4096)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout ends the listen
		}
		if n < 8 {
			continue
		}
		if buf[0] != MAVLinkStxV1 && buf[0] != MAVLinkStxV2 {
			continue
		}
		if buf[0] == MAVLinkStxV1 {
			// v1: LEN SEQ SYS COMP MSG PAYLOAD CRC CRC
			plen := int(buf[1])
			if n < 6+plen+2 {
				continue
			}
			fr := ReceivedFrame{
				From:    addr.String(),
				MsgID:   buf[5],
				Raw:     append([]byte(nil), buf[:n]...),
				Payload: append([]byte(nil), buf[6:6+plen]...),
			}
			out = append(out, fr)
		} else {
			// v2: STX LEN INCOMPAT COMPAT SEQ SYS COMP MSG [sig]
			if n < 12 {
				continue
			}
			plen := int(buf[1])
			if n < 10+plen+2 {
				continue
			}
			fr := ReceivedFrame{
				From:    addr.String(),
				MsgID:   buf[7],
				Raw:     append([]byte(nil), buf[:n]...),
				Payload: append([]byte(nil), buf[10:10+plen]...),
			}
			out = append(out, fr)
		}
	}
	return out, nil
}

// mathFloat32bits returns the IEEE-754 bit pattern of a float32.
func mathFloat32bits(f float32) uint32 {
	return math.Float32bits(f)
}

// seqCounter returns a fresh sequence number for one outgoing frame.
func seqCounter() uint8 {
	var b [1]byte
	_, _ = rand.Read(b[:])
	return b[0]
}
