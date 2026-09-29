package icsgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// Siemens S7comm — TCP/102. Three stacked layers:
//
//   TPKT        (RFC 1006): version=3, reserved=0, length(2)
//   COTP        (RFC 905):  variable header, TSAP negotiation
//   S7comm:                 protocol id 0x32, ROSCTR, PDU reference, params+data
//
// This implements classic S7comm (S7-300/400, some S7-1200 firmware).
// S7comm-plus (0x72, mutual auth) is a different protocol and out of scope.
//
// Read/write addressing uses a 7-byte pointer:
//   area (1) | DB num (2) | access (1) | address in bits (3)
// Areas: 0x81 inputs, 0x82 outputs, 0x83 merkers, 0x84 DB

// S7 consts
const (
	S7AreaInput   = 0x81
	S7AreaOutput  = 0x82
	S7AreaMerker  = 0x83
	S7AreaDB      = 0x84
	S7AreaCounter = 0x1C
	S7AreaTimer   = 0x1D

	S7FuncReadVar  = 0x04
	S7FuncWriteVar = 0x05
	S7FuncSetup    = 0xF0
	S7FuncReadSZL  = 0x1D
)

// S7Options controls an S7 session.
type S7Options struct {
	Host    string
	Port    int           // 102 default
	Rack    uint8         // 0 default
	Slot    uint8         // 2 default
	Timeout time.Duration // per request
}

// S7Conn is a live S7 session.
type S7Conn struct {
	conn    net.Conn
	opts    S7Options
	pduRef  uint16
}

// S7Connect performs TPKT + COTP connect + S7 setup communication.
func S7Connect(opts S7Options) (*S7Conn, error) {
	if opts.Host == "" {
		return nil, errors.New("icsgo/s7: host required")
	}
	if opts.Port == 0 {
		opts.Port = 102
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)

	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("icsgo/s7: dial: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	// COTP Connection Request
	cr := _s7TPKT(_s7COPTConnect(opts.Rack, opts.Slot))
	if _, err := conn.Write(cr); err != nil {
		conn.Close()
		return nil, fmt.Errorf("icsgo/s7: cotp write: %w", err)
	}
	resp := make([]byte, 64)
	if _, err := io.ReadFull(conn, resp); err != nil {
		conn.Close()
		return nil, fmt.Errorf("icsgo/s7: cotp read: %w", err)
	}
	// expect TPKT(4) + COTP CC (byte 5 should be 0xD0)
	if len(resp) < 6 || resp[5] != 0xD0 {
		conn.Close()
		return nil, errors.New("icsgo/s7: no cotp connect confirm")
	}

	c := &S7Conn{conn: conn, opts: opts, pduRef: 1}

	// Setup Communication
	setup := c._s7Header(0x01, []byte{S7FuncSetup, 0x00, 0x00, 0x01, 0x00, 0x01, 0x03, 0xC0}, nil)
	if _, err := c._transact(setup); err != nil {
		conn.Close()
		return nil, fmt.Errorf("icsgo/s7: setup: %w", err)
	}
	return c, nil
}

// Close ends the S7 session.
func (c *S7Conn) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// _s7TPKT wraps payload with a TPKT header.
func _s7TPKT(payload []byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = 3
	out[1] = 0
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(payload)))
	copy(out[4:], payload)
	return out
}

// _s7COPTConnect builds a COTP Connection Request for the given rack/slot.
// TSAP is 0x0100 | (rack<<5) | slot for the dest — standard Siemens layout.
func _s7COPTConnect(rack, slot uint8) []byte {
	dst := uint16(0x0100) | (uint16(rack) << 5) | uint16(slot)
	// COTP: length, 0xE0, dst-ref(2), src-ref(2), class
	body := []byte{0x11, 0xE0, 0x00, 0x00, 0x00, 0x01, 0x00}
	// TPDU size parameter: 0xC0 0x01 0x0A (1024 bytes)
	body = append(body, 0xC0, 0x01, 0x0A)
	// src TSAP
	body = append(body, 0xC1, 0x02, 0x01, 0x00)
	// dst TSAP
	body = append(body, 0xC2, 0x02, byte(dst>>8), byte(dst&0xFF))
	return body
}

// _s7Header wraps a PDU in a COTP Data envelope and an S7 header.
func (c *S7Conn) _s7Header(rosctr byte, params, data []byte) []byte {
	c.pduRef++
	s7 := make([]byte, 10+len(params)+len(data))
	s7[0] = 0x32 // protocol id
	s7[1] = rosctr
	binary.BigEndian.PutUint16(s7[2:4], 0x0000) // redundancy id
	binary.BigEndian.PutUint16(s7[4:6], c.pduRef)
	binary.BigEndian.PutUint16(s7[6:8], uint16(len(params)))
	binary.BigEndian.PutUint16(s7[8:10], uint16(len(data)))
	copy(s7[10:], params)
	copy(s7[10+len(params):], data)
	// COTP Data: 0x02 0xF0 0x80 + S7 PDU
	cotp := append([]byte{0x02, 0xF0, 0x80}, s7...)
	return _s7TPKT(cotp)
}

func (c *S7Conn) _transact(pkt []byte) ([]byte, error) {
	_ = c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(pkt); err != nil {
		return nil, err
	}
	// read TPKT header
	head := make([]byte, 4)
	if _, err := io.ReadFull(c.conn, head); err != nil {
		return nil, err
	}
	tlen := binary.BigEndian.Uint16(head[2:4])
	if tlen < 4 {
		return nil, errors.New("icsgo/s7: short TPKT")
	}
	body := make([]byte, int(tlen)-4)
	if _, err := io.ReadFull(c.conn, body); err != nil {
		return nil, err
	}
	// body = COTP header (3) + S7 header + params + data
	if len(body) < 3+10 {
		return nil, errors.New("icsgo/s7: short body")
	}
	// return the S7 PDU (skip COTP)
	return body[3:], nil
}

// _s7ReadVarAddr builds the read-var PDU bytes.
func _s7ReadVarAddr(area byte, db uint16, start uint16, length uint16) []byte {
	addrBits := uint32(start) * 8
	item := make([]byte, 12)
	item[0] = 0x12 // item spec
	item[1] = 0x0A // length of following
	item[2] = 0x10 // syntax id
	item[3] = 0x02 // transport size: byte
	binary.BigEndian.PutUint16(item[4:6], length)
	binary.BigEndian.PutUint16(item[6:8], db)
	item[8] = area
	item[9] = byte((addrBits >> 16) & 0xFF)
	item[10] = byte((addrBits >> 8) & 0xFF)
	item[11] = byte(addrBits & 0xFF)
	params := append([]byte{S7FuncReadVar, 0x01}, item...)
	return params
}

// S7Read reads length bytes from the given area.
func (c *S7Conn) S7Read(area byte, db uint16, start uint16, length uint16) ([]byte, error) {
	params := _s7ReadVarAddr(area, db, start, length)
	pkt := c._s7Header(0x01, params, nil)
	resp, err := c._transact(pkt)
	if err != nil {
		return nil, err
	}
	// S7 resp: 10 header + params(2) + data header(4) + payload
	plen := binary.BigEndian.Uint16(resp[6:8])
	dlen := binary.BigEndian.Uint16(resp[8:10])
	off := 10 + int(plen)
	if off+4 > len(resp) {
		return nil, errors.New("icsgo/s7: short resp")
	}
	// data: 0xFF transport(1) length(2) payload
	if resp[off] != 0xFF {
		// could be error response — return whatever is there
		return nil, fmt.Errorf("icsgo/s7: bad data marker 0x%02x", resp[off])
	}
	pl := int(binary.BigEndian.Uint16(resp[off+2 : off+4]))
	if off+4+pl > len(resp) {
		pl = int(dlen) - 4
		if pl < 0 {
			pl = 0
		}
	}
	if off+4+pl > len(resp) {
		pl = len(resp) - off - 4
	}
	return append([]byte(nil), resp[off+4:off+4+pl]...), nil
}

// S7ReadSZL reads a System Status List item (0x1C = component identification).
func (c *S7Conn) S7ReadSZL(szlID uint16) ([]byte, error) {
	params := []byte{S7FuncReadSZL, 0x00, 0x00, 0x00}
	binary.BigEndian.PutUint16(params[2:4], szlID)
	pkt := c._s7Header(0x01, params, nil)
	resp, err := c._transact(pkt)
	if err != nil {
		return nil, err
	}
	if len(resp) < 20 {
		return nil, errors.New("icsgo/s7: szl short")
	}
	return resp[20:], nil
}

// S7Write writes data bytes to the given area/start.
func (c *S7Conn) S7Write(area byte, db uint16, start uint16, data []byte) error {
	addrBits := uint32(start) * 8
	item := make([]byte, 12)
	item[0] = 0x12
	item[1] = 0x0A
	item[2] = 0x10
	item[3] = 0x02
	binary.BigEndian.PutUint16(item[4:6], uint16(len(data)))
	binary.BigEndian.PutUint16(item[6:8], db)
	item[8] = area
	item[9] = byte((addrBits >> 16) & 0xFF)
	item[10] = byte((addrBits >> 8) & 0xFF)
	item[11] = byte(addrBits & 0xFF)
	params := append([]byte{S7FuncWriteVar, 0x01}, item...)

	// data payload: 0x00, 0x04 (byte transport), length*8, data, pad to even
	dataHdr := make([]byte, 4)
	dataHdr[0] = 0x00
	dataHdr[1] = 0x04
	binary.BigEndian.PutUint16(dataHdr[2:4], uint16(len(data)*8))
	payload := append(dataHdr, data...)
	if len(data)%2 != 0 {
		payload = append(payload, 0x00)
	}
	pkt := c._s7Header(0x01, params, payload)
	_, err := c._transact(pkt)
	return err
}
