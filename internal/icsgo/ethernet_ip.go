package icsgo

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// EtherNet/IP — TCP/44818 (explicit messaging) and UDP/2222 (implicit I/O).
// Encapsulation layer carries CIP (Common Industrial Protocol) messages.
//
// Encapsulation header (24 bytes):
//   command (2 BE)    0x0063 ListIdentity, 0x0064 ListInterfaces,
//                     0x0004 ListServices, 0x0065 RegisterSession,
//                     0x0066 UnregisterSession, 0x006F SendRRData,
//                     0x0070 SendUnitData
//   length (2 BE)     length of data following the header
//   session (4 BE)    session handle (0 until RegisterSession)
//   status (4 BE)     sender status, 0 in requests
//   sender ctx (8)    caller-defined correlator
//   options (4 BE)    usually 0
//   data (length)
//
// RegisterSession opens a session for subsequent SendRRData / SendUnitData.
// CIP inside SendRRData is the actual read/write of PLC tags.

// ENIP command constants
const (
	EnipListServices     = 0x0004
	EnipListIdentity     = 0x0063
	EnipListInterfaces   = 0x0064
	EnipRegisterSession  = 0x0065
	EnipUnregisterSess   = 0x0066
	EnipSendRRData       = 0x006F
	EnipSendUnitData     = 0x0070
)

// ENIPPort is the default TCP port for explicit messaging.
const ENIPPort = 44818

// ENIPOptions controls an EtherNet/IP interaction.
type ENIPOptions struct {
	Host    string
	Port    int           // 44818 default
	Timeout time.Duration // per request
}

func enipDefault(opts ENIPOptions) ENIPOptions {
	if opts.Port == 0 {
		opts.Port = ENIPPort
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	return opts
}

// enipHeader builds the 24-byte encapsulation header.
func enipHeader(cmd uint16, length uint16, session uint32) []byte {
	h := make([]byte, 24)
	binary.LittleEndian.PutUint16(h[0:2], cmd)
	binary.LittleEndian.PutUint16(h[2:4], length)
	binary.LittleEndian.PutUint32(h[4:8], session)
	// status (4) and sender-context (8) and options (4) all zero
	return h
}

// ENIPHeader is a parsed encapsulation header.
type ENIPHeader struct {
	Command       uint16
	Length        uint16
	Session       uint32
	Status        uint32
	SenderContext [8]byte
	Options       uint32
}

// parseENIPHeader reads 24 bytes as an encapsulation header.
func parseENIPHeader(b []byte) (ENIPHeader, error) {
	if len(b) < 24 {
		return ENIPHeader{}, errors.New("icsgo/enip: short header")
	}
	return ENIPHeader{
		Command: binary.LittleEndian.Uint16(b[0:2]),
		Length:  binary.LittleEndian.Uint16(b[2:4]),
		Session: binary.LittleEndian.Uint32(b[4:8]),
		Status:  binary.LittleEndian.Uint32(b[8:12]),
	}, nil
}

// enipTransact sends one encapsulation message and returns the response.
func enipTransact(conn net.Conn, cmd uint16, session uint32, data []byte, timeout time.Duration) (ENIPHeader, []byte, error) {
	hdr := enipHeader(cmd, uint16(len(data)), session)
	frame := append(hdr, data...)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(frame); err != nil {
		return ENIPHeader{}, nil, err
	}
	rh := make([]byte, 24)
	if _, err := io.ReadFull(conn, rh); err != nil {
		return ENIPHeader{}, nil, fmt.Errorf("icsgo/enip: read hdr: %w", err)
	}
	parsed, err := parseENIPHeader(rh)
	if err != nil {
		return ENIPHeader{}, nil, err
	}
	body := make([]byte, parsed.Length)
	if parsed.Length > 0 {
		if _, err := io.ReadFull(conn, body); err != nil {
			return ENIPHeader{}, nil, fmt.Errorf("icsgo/enip: read body: %w", err)
		}
	}
	return parsed, body, nil
}

// ENIPIdentity is a parsed ListIdentity response.
type ENIPIdentity struct {
	VendorID    uint16
	DeviceType  uint16
	ProductCode uint16
	RevisionMaj byte
	RevisionMin byte
	Status      uint16
	Serial      uint32
	ProductName string
	State       byte
}

// ListIdentity opens a TCP connection and sends a ListIdentity request.
// Returns every identity payload in the response (there is usually one per
// device in the reply).
func ListIdentity(opts ENIPOptions) ([]ENIPIdentity, error) {
	opts = enipDefault(opts)
	if opts.Host == "" {
		return nil, errors.New("icsgo/enip: host required")
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("icsgo/enip: dial: %w", err)
	}
	defer conn.Close()

	// ListIdentity has no payload
	hdr, body, err := enipTransact(conn, EnipListIdentity, 0, nil, opts.Timeout)
	if err != nil {
		return nil, err
	}
	if hdr.Command != EnipListIdentity {
		return nil, fmt.Errorf("icsgo/enip: unexpected cmd 0x%04x", hdr.Command)
	}
	return parseIdentityList(body), nil
}

// parseIdentityList walks the (item-count, items) structure of a
// ListIdentity response and pulls out every identity block.
func parseIdentityList(b []byte) []ENIPIdentity {
	var out []ENIPIdentity
	if len(b) < 2 {
		return out
	}
	count := int(binary.LittleEndian.Uint16(b[0:2]))
	off := 2
	for i := 0; i < count && off+2 <= len(b); i++ {
		itemType := binary.LittleEndian.Uint16(b[off : off+2])
		off += 2
		if off+2 > len(b) {
			break
		}
		itemLen := int(binary.LittleEndian.Uint16(b[off : off+2]))
		off += 2
		if off+itemLen > len(b) {
			break
		}
		item := b[off : off+itemLen]
		off += itemLen
		// itemType 0x000C = Identity Item
		if itemType == 0x000C {
			id, ok := parseIdentityItem(item)
			if ok {
				out = append(out, id)
			}
		}
	}
	return out
}

// parseIdentityItem parses a single identity item payload (before product
// name and state, which are length-prefixed strings).
func parseIdentityItem(b []byte) (ENIPIdentity, bool) {
	// spec: version (2) + socket addr (16) + vendor (2) + device type (2) +
	// product code (2) + revision (2) + status (2) + serial (4) + product name
	// length (1) + product name + state (1)
	if len(b) < 2+16+2+2+2+2+2+4 {
		return ENIPIdentity{}, false
	}
	off := 2 + 16
	id := ENIPIdentity{
		VendorID:    binary.LittleEndian.Uint16(b[off : off+2]),
		DeviceType:  binary.LittleEndian.Uint16(b[off+2 : off+4]),
		ProductCode: binary.LittleEndian.Uint16(b[off+4 : off+6]),
		RevisionMaj: b[off+6],
		RevisionMin: b[off+7],
		Status:      binary.LittleEndian.Uint16(b[off+8 : off+10]),
		Serial:      binary.LittleEndian.Uint32(b[off+10 : off+14]),
	}
	off += 14
	if off < len(b) {
		nameLen := int(b[off])
		off++
		if off+nameLen <= len(b) {
			id.ProductName = string(b[off : off+nameLen])
			off += nameLen
		}
	}
	if off < len(b) {
		id.State = b[off]
	}
	return id, true
}

// RegisterSession opens a session for subsequent SendRRData calls. Returns
// the session handle. The payload is a 4-byte version (1) + 4-byte options
// (0). The device echoes the handle it assigned.
func RegisterSession(opts ENIPOptions) (uint32, net.Conn, error) {
	opts = enipDefault(opts)
	if opts.Host == "" {
		return 0, nil, errors.New("icsgo/enip: host required")
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return 0, nil, fmt.Errorf("icsgo/enip: dial: %w", err)
	}
	// protocol version 1, options 0
	payload := make([]byte, 4)
	binary.LittleEndian.PutUint16(payload[0:2], 1)
	hdr, _, err := enipTransact(conn, EnipRegisterSession, 0, payload, opts.Timeout)
	if err != nil {
		conn.Close()
		return 0, nil, err
	}
	if hdr.Status != 0 {
		conn.Close()
		return 0, nil, fmt.Errorf("icsgo/enip: register status 0x%x", hdr.Status)
	}
	return hdr.Session, conn, nil
}

// SendRRData sends an unconnected CIP message wrapped in SendRRData.
// cipPath is the EPATH-encoded logical path to the target object;
// cipService is the CIP service code; cipData is the service payload.
func SendRRData(conn net.Conn, session uint32, cipPath []byte, cipService byte, cipData []byte, timeout time.Duration) ([]byte, error) {
	// SendRRData payload: interface handle (4) + timeout (2) + item count (2)
	//                     + item 0 (null address, type 0x0000, len 0)
	//                     + item 1 (unconnected data, type 0x00B2, len)
	// The item 1 payload is: CIP service (1) + CIP path size (1, in words)
	//                       + CIP path + CIP data
	cipMsg := make([]byte, 0, 2+len(cipPath)+len(cipData))
	cipMsg = append(cipMsg, cipService)
	cipMsg = append(cipMsg, byte(len(cipPath)/2)) // path size in words
	cipMsg = append(cipMsg, cipPath...)
	cipMsg = append(cipMsg, cipData...)

	payload := make([]byte, 0, 6+4+4+len(cipMsg))
	// interface handle (0 = CIP)
	payload = append(payload, 0, 0, 0, 0)
	// timeout (0)
	payload = append(payload, 0, 0)
	// item count
	payload = append(payload, 2, 0)
	// item 0: null address, type 0x0000, length 0
	payload = append(payload, 0x00, 0x00, 0x00, 0x00)
	// item 1: unconnected data item (0x00B2)
	payload = append(payload, 0xB2, 0x00)
	var l [2]byte
	binary.LittleEndian.PutUint16(l[:], uint16(len(cipMsg)))
	payload = append(payload, l[:]...)
	payload = append(payload, cipMsg...)

	_, body, err := enipTransact(conn, EnipSendRRData, session, payload, timeout)
	if err != nil {
		return nil, err
	}
	// strip the wrapper to get back to the CIP reply
	// layout: interface(4) + timeout(2) + count(2) + item0(4) + item1 hdr(4) + cip
	// ... skip to the last unconnected-data item
	idx := bytes.Index(body, []byte{0xB2, 0x00})
	if idx < 0 || idx+4 > len(body) {
		return body, nil
	}
	return body[idx+4:], nil
}

// cipTagPath builds the standard EPATH to a symbolic tag by name.
// Class 0x6B (Symbol Object), Instance 1, Attribute 0, then ANSI string.
func cipTagPath(tag string) []byte {
	if len(tag) > 255 {
		tag = tag[:255]
	}
	path := []byte{0x91, 0x01, 0x00, 0x00} // class 0x6B, instance 1 (little endian short)
	// pad to ANSI extended symbolic segment: 0x91 + u8 length + chars + pad
	out := []byte{0x20, 0x6B, 0x25, 0x00, 0x00} // 8-bit class id 0x6B, 8-bit instance 0
	_ = path
	seg := []byte{0x91, byte(len(tag))}
	seg = append(seg, []byte(tag)...)
	if len(tag)%2 == 1 {
		seg = append(seg, 0x00)
	}
	return append(out, seg...)
}

// CIPReadTag sends a Get_Attribute_Single against a symbolic tag.
// service = 0x0E, class 0x6B, attribute 0x03 (Present Value).
// Returns the raw CIP reply; the caller decodes the data type.
func CIPReadTag(conn net.Conn, session uint32, tag string, timeout time.Duration) ([]byte, error) {
	path := cipTagPath(tag)
	return SendRRData(conn, session, path, 0x0E, []byte{0x03}, timeout)
}

// CIPWriteTag sends a Set_Attribute_Single against a symbolic tag.
// service = 0x10, class 0x6B, attribute 0x03. dataType is the CIP type
// (0xC4 = REAL, 0xC3 = DINT, 0xC2 = INT, 0xC1 = SINT, 0xC6 = BOOL) — the
// value bytes follow.
func CIPWriteTag(conn net.Conn, session uint32, tag string, dataType byte, value []byte, timeout time.Duration) ([]byte, error) {
	path := cipTagPath(tag)
	body := make([]byte, 0, 2+len(value))
	body = append(body, 0x03, dataType)
	body = append(body, value...)
	return SendRRData(conn, session, path, 0x10, body, timeout)
}
