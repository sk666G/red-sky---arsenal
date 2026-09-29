// Package icsgo implements ICS protocol primitives on the agent. It is the
// Go analogue of Program/ics/ and shares wire formats byte-for-byte with the
// Python side so captures and device responses interoperate.
//
// Modbus TCP frame layout (MBAP + PDU):
//
//   MBAP header (7 bytes):
//     transaction id (2 BE)  protocol id = 0 (2 BE)
//     length (2 BE)          unit id (1)
//   PDU:
//     function code (1)  data (N)
//
// Function codes implemented:
//   0x01 Read Coils               0x02 Read Discrete Inputs
//   0x03 Read Holding Registers   0x04 Read Input Registers
//   0x05 Write Single Coil        0x06 Write Single Register
//   0x0F Write Multiple Coils     0x10 Write Multiple Registers
package icsgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Modbus consts
const (
	MBFuncReadCoils        = 0x01
	MBFuncReadDiscrete     = 0x02
	MBFuncReadHolding      = 0x03
	MBFuncReadInput        = 0x04
	MBFuncWriteCoil        = 0x05
	MBFuncWriteRegister    = 0x06
	MBFuncWriteMultiCoils  = 0x0F
	MBFuncWriteMultiRegs   = 0x10
)

// MBOptions controls a Modbus request.
type MBOptions struct {
	Host    string
	Port    int           // 502 default
	Unit    uint8         // 1..247 typical
	Timeout time.Duration // per request
}

// MBResult is the parsed response for a Modbus read or write.
type MBResult struct {
	Function byte
	// For read bit ops:
	Bits []bool
	// For read register ops:
	Regs []uint16
	// For error responses:
	Exception byte // 0 when no exception
}

// mbTransact sends one MBAP+PDU and reads the response.
func mbTransact(opts MBOptions, pdu []byte) ([]byte, error) {
	if opts.Host == "" {
		return nil, errors.New("icsgo/modbus: host required")
	}
	if opts.Port == 0 {
		opts.Port = 502
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)

	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("icsgo/modbus: dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	// MBAP
	length := len(pdu) + 1 // +unit id
	txid := uint16(time.Now().UnixNano() & 0xFFFF)
	hdr := make([]byte, 7)
	binary.BigEndian.PutUint16(hdr[0:2], txid)
	binary.BigEndian.PutUint16(hdr[2:4], 0)
	binary.BigEndian.PutUint16(hdr[4:6], uint16(length))
	hdr[6] = opts.Unit

	frame := append(hdr, pdu...)
	if _, err := conn.Write(frame); err != nil {
		return nil, fmt.Errorf("icsgo/modbus: write: %w", err)
	}

	// read MBAP header
	rhdr := make([]byte, 7)
	if _, err := io.ReadFull(conn, rhdr); err != nil {
		return nil, fmt.Errorf("icsgo/modbus: read hdr: %w", err)
	}
	rlen := binary.BigEndian.Uint16(rhdr[4:6])
	if rlen < 2 {
		return nil, errors.New("icsgo/modbus: short response")
	}
	body := make([]byte, int(rlen)-1)
	if _, err := io.ReadFull(conn, body); err != nil {
		return nil, fmt.Errorf("icsgo/modbus: read body: %w", err)
	}
	return body, nil
}

func mbCheckException(body []byte) (byte, bool) {
	if len(body) >= 2 && (body[0]&0x80) != 0 {
		return body[1], true
	}
	return 0, false
}

// ModbusRead reads coils/discrete/holding/input depending on function.
func ModbusRead(opts MBOptions, function byte, start, count uint16) (MBResult, error) {
	switch function {
	case MBFuncReadCoils, MBFuncReadDiscrete, MBFuncReadHolding, MBFuncReadInput:
	default:
		return MBResult{}, fmt.Errorf("icsgo/modbus: unsupported read function 0x%02x", function)
	}
	pdu := make([]byte, 5)
	pdu[0] = function
	binary.BigEndian.PutUint16(pdu[1:3], start)
	binary.BigEndian.PutUint16(pdu[3:5], count)

	body, err := mbTransact(opts, pdu)
	if err != nil {
		return MBResult{}, err
	}
	if exc, ok := mbCheckException(body); ok {
		return MBResult{Function: function, Exception: exc}, nil
	}
	if len(body) < 2 {
		return MBResult{}, errors.New("icsgo/modbus: short body")
	}
	bc := int(body[1])
	payload := body[2:]
	if len(payload) < bc {
		return MBResult{}, errors.New("icsgo/modbus: truncated payload")
	}
	res := MBResult{Function: function}
	if function == MBFuncReadCoils || function == MBFuncReadDiscrete {
		res.Bits = make([]bool, 0, bc*8)
		for i := 0; i < bc; i++ {
			for b := 0; b < 8; b++ {
				res.Bits = append(res.Bits, (payload[i]>>b)&1 == 1)
			}
		}
	} else {
		res.Regs = make([]uint16, 0, bc/2)
		for i := 0; i+1 < bc; i += 2 {
			res.Regs = append(res.Regs, binary.BigEndian.Uint16(payload[i:i+2]))
		}
	}
	return res, nil
}

// ModbusWriteCoil writes a single coil. value=true for ON.
func ModbusWriteCoil(opts MBOptions, addr uint16, value bool) (MBResult, error) {
	pdu := make([]byte, 5)
	pdu[0] = MBFuncWriteCoil
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	if value {
		binary.BigEndian.PutUint16(pdu[3:5], 0xFF00)
	} else {
		binary.BigEndian.PutUint16(pdu[3:5], 0x0000)
	}
	body, err := mbTransact(opts, pdu)
	if err != nil {
		return MBResult{}, err
	}
	if exc, ok := mbCheckException(body); ok {
		return MBResult{Function: MBFuncWriteCoil, Exception: exc}, nil
	}
	return MBResult{Function: MBFuncWriteCoil}, nil
}

// ModbusWriteRegister writes a single holding register.
func ModbusWriteRegister(opts MBOptions, addr, value uint16) (MBResult, error) {
	pdu := make([]byte, 5)
	pdu[0] = MBFuncWriteRegister
	binary.BigEndian.PutUint16(pdu[1:3], addr)
	binary.BigEndian.PutUint16(pdu[3:5], value)
	body, err := mbTransact(opts, pdu)
	if err != nil {
		return MBResult{}, err
	}
	if exc, ok := mbCheckException(body); ok {
		return MBResult{Function: MBFuncWriteRegister, Exception: exc}, nil
	}
	return MBResult{Function: MBFuncWriteRegister}, nil
}

// ModbusWriteMultiRegs writes a consecutive block of holding registers.
func ModbusWriteMultiRegs(opts MBOptions, start uint16, values []uint16) (MBResult, error) {
	if len(values) == 0 || len(values) > 123 {
		return MBResult{}, errors.New("icsgo/modbus: write-multi-reg count 1..123")
	}
	pdu := make([]byte, 6+2*len(values))
	pdu[0] = MBFuncWriteMultiRegs
	binary.BigEndian.PutUint16(pdu[1:3], start)
	binary.BigEndian.PutUint16(pdu[3:5], uint16(len(values)))
	pdu[5] = byte(2 * len(values))
	for i, v := range values {
		binary.BigEndian.PutUint16(pdu[6+2*i:8+2*i], v)
	}
	body, err := mbTransact(opts, pdu)
	if err != nil {
		return MBResult{}, err
	}
	if exc, ok := mbCheckException(body); ok {
		return MBResult{Function: MBFuncWriteMultiRegs, Exception: exc}, nil
	}
	return MBResult{Function: MBFuncWriteMultiRegs}, nil
}

// ModbusUnitScan fires a single read-holding request at every unit id in
// [from,to]. Returns the unit ids that respond (either success or a
// Modbus exception — either means a device is there).
func ModbusUnitScan(host string, port int, from, to uint8, timeout time.Duration) ([]uint8, error) {
	if from == 0 {
		from = 1
	}
	if to == 0 {
		to = 247
	}
	var alive []uint8
	for u := from; u <= to; u++ {
		opts := MBOptions{Host: host, Port: port, Unit: u, Timeout: timeout}
		res, err := ModbusRead(opts, MBFuncReadHolding, 0, 1)
		if err != nil {
			continue
		}
		// success (Regs present) or exception — either way, we heard from it
		if res.Exception != 0 || res.Regs != nil {
			alive = append(alive, u)
		}
	}
	return alive, nil
}
