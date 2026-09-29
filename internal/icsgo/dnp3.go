package icsgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"time"
)

// DNP3 — TCP/20000 typically. Layered:
//
//   Link layer:   0x05 0x64 | length | control | dest(2 LE) | src(2 LE) | CRC
//                 followed by payload in 16-byte chunks, each with a CRC
//   Transport:    1 byte (FIR | FIN | sequence)
//   Application:  control | function | IIN(2) [response only] | objects
//
// DNP3 without Secure Authentication (v5, rarely enabled) has no auth at
// the application layer — any master on the network can poll and operate.

// DNP3 function codes
const (
	DNP3FnConfirm         = 0x00
	DNP3FnRead            = 0x01
	DNP3FnWrite           = 0x02
	DNP3FnSelect          = 0x03
	DNP3FnOperate         = 0x04
	DNP3FnDirectOperate   = 0x05
	DNP3FnDirectOperateNA = 0x06
	DNP3FnResponse        = 0x81
	DNP3FnUnsolicited     = 0x82
)

// DNP3 link control bytes
const (
	DNP3LinkReset         = 0x40
	DNP3LinkUserDataUnc   = 0x44
)

// DNP3Options controls a session.
type DNP3Options struct {
	Host    string
	Port    int           // 20000 default
	Dest    uint16        // outstation address (typically 1-10)
	Src     uint16        // master address (typically 1-100)
	Timeout time.Duration
}

// DNP3Conn is a live DNP3 session.
type DNP3Conn struct {
	conn net.Conn
	opts DNP3Options
	seq  uint8
}

// DNP3IIN decodes the Internal Indication word from a response.
type DNP3IIN struct {
	Raw uint16
	AllStations    bool
	Class1Events   bool
	Class2Events   bool
	Class3Events   bool
	NeedTime       bool
	LocalControl   bool
	DeviceTrouble  bool
	DeviceRestart  bool
	NoFuncCode     bool
	ObjectUnknown  bool
	ParameterError bool
	EventBufOvf    bool
	AlreadyExec    bool
	ConfigCorrupt  bool
}

func decodeIIN(w uint16) DNP3IIN {
	return DNP3IIN{
		Raw:            w,
		AllStations:    w&0x0001 != 0,
		Class1Events:   w&0x0002 != 0,
		Class2Events:   w&0x0004 != 0,
		Class3Events:   w&0x0008 != 0,
		NeedTime:       w&0x0010 != 0,
		LocalControl:   w&0x0020 != 0,
		DeviceTrouble:  w&0x0040 != 0,
		DeviceRestart:  w&0x0080 != 0,
		NoFuncCode:     w&0x0100 != 0,
		ObjectUnknown:  w&0x0200 != 0,
		ParameterError: w&0x0400 != 0,
		EventBufOvf:    w&0x0800 != 0,
		AlreadyExec:    w&0x1000 != 0,
		ConfigCorrupt:  w&0x2000 != 0,
	}
}

// DNP3Response is the parsed application-layer response.
type DNP3Response struct {
	Function byte
	IIN      DNP3IIN
	Raw      []byte // application payload after the 4-byte app header
}

// --- DNP3 CRC ---------------------------------------------------------
// The 256-entry CRC-16/DNP table. Polynomial 0x3D65 (reflected).

var dnp3CRCTable = [256]uint16{
	0, 0x365E, 0x6CBC, 0x5AE2, 0xD978, 0xEF26, 0xB5C4, 0x839A,
	0xCE45, 0xF81B, 0xA2F9, 0x94A7, 0x173D, 0x2163, 0x7B81, 0x4DDF,
	0x8A1A, 0xBC44, 0xE6A6, 0xD0F8, 0x5362, 0x653C, 0x3FDE, 0x0980,
	0x445F, 0x7201, 0x28E3, 0x1EBD, 0x9D27, 0xAB79, 0xF19B, 0xC7C5,
	0x1006, 0x2658, 0x7CBA, 0x4AE4, 0xC97E, 0xFF20, 0xA5C2, 0x939C,
	0xDE43, 0xE81D, 0xB2FF, 0x84A1, 0x073B, 0x3165, 0x6B87, 0x5DD9,
	0x9A1C, 0xAC42, 0xF6A0, 0xC0FE, 0x4364, 0x753A, 0x2FD8, 0x1986,
	0x5459, 0x6207, 0x38E5, 0x0EBB, 0x8D21, 0xBB7F, 0xE19D, 0xD7C3,
	0x200C, 0x1652, 0x4CB0, 0x7AEE, 0xF974, 0xCF2A, 0x95C8, 0xA396,
	0xEE49, 0xD817, 0x82F5, 0xB4AB, 0x3731, 0x016F, 0x5B8D, 0x6DD3,
	0xAA16, 0x9C48, 0xC6AA, 0xF0F4, 0x736E, 0x4530, 0x1FD2, 0x298C,
	0x6453, 0x520D, 0x08EF, 0x3EB1, 0xBD2B, 0x8B75, 0xD197, 0xE7C9,
	0x400B, 0x7655, 0x2CB7, 0x1AE9, 0x9973, 0xAF2D, 0xF5CF, 0xC391,
	0x8E4E, 0xB810, 0xE2F2, 0xD4AC, 0x5736, 0x6168, 0x3B8A, 0x0DD4,
	0xCA11, 0xFC4F, 0xA6AD, 0x90F3, 0x1369, 0x2537, 0x7FD5, 0x498B,
	0x0454, 0x320A, 0x68E8, 0x5EB6, 0xDD2C, 0xEB72, 0xB190, 0x87CE,
	0x8017, 0xB649, 0xECAB, 0xDAF5, 0x596F, 0x6F31, 0x35D3, 0x038D,
	0x4E52, 0x780C, 0x22EE, 0x14B0, 0x972A, 0xA174, 0xFBF6, 0xCBAB,
	0x0C2D, 0x3A73, 0x6091, 0x56CF, 0xD555, 0xE30B, 0xB9E9, 0x8FB7,
	0xC268, 0xF436, 0xAED4, 0x988A, 0x1B10, 0x2D4E, 0x77AC, 0x41F2,
	0xA03E, 0x9660, 0xCC82, 0xFADC, 0x7946, 0x4F18, 0x15FA, 0x23A4,
	0x6E7B, 0x5825, 0x02C7, 0x3499, 0xB703, 0x815D, 0xDBBF, 0xEDE1,
	0x2A24, 0x1C7A, 0x4698, 0x70C6, 0xF35C, 0xC502, 0x9FE0, 0xA9BE,
	0xE461, 0xD23F, 0x88DD, 0xBEA3, 0x3D39, 0x0B67, 0x5185, 0x67DB,
	0xC02E, 0xF670, 0xAC92, 0x9ACC, 0x1956, 0x2F08, 0x75EA, 0x43B4,
	0x0E6B, 0x3835, 0x62D7, 0x5489, 0xD713, 0xE14D, 0xBBAF, 0x8DF1,
	0x4A34, 0x7C6A, 0x2688, 0x10D6, 0x934C, 0xA512, 0xFFF0, 0xC9AE,
	0x8471, 0xB22F, 0xE8CD, 0xDE93, 0x5D09, 0x6B57, 0x31B5, 0x07EB,
	0xE02C, 0xD672, 0x8C90, 0xBACE, 0x3954, 0x0F0A, 0x55E8, 0x63B6,
	0x2E69, 0x1837, 0x42D5, 0x748B, 0xF711, 0xC14F, 0x9BAD, 0xADF3,
	0x6A36, 0x5C68, 0x068A, 0x30D4, 0xB34E, 0x8510, 0xDFF2, 0xE9AC,
	0xA473, 0x922D, 0xC8CF, 0xFE91, 0x7D0B, 0x4B55, 0x11B7, 0x27E9,
}

func dnp3CRC(b []byte) uint16 {
	crc := uint16(0)
	for _, x := range b {
		crc = (crc >> 8) ^ dnp3CRCTable[(crc^uint16(x))&0xFF]
	}
	return ^crc
}

func dnp3CRCPad(data []byte) []byte {
	out := make([]byte, 0, len(data)+len(data)/16*2+2)
	for i := 0; i < len(data); i += 16 {
		end := i + 16
		if end > len(data) {
			end = len(data)
		}
		chunk := data[i:end]
		out = append(out, chunk...)
		var c [2]byte
		binary.LittleEndian.PutUint16(c[:], dnp3CRC(chunk))
		out = append(out, c[:]...)
	}
	return out
}

// dnp3Link builds a link frame carrying payload under control.
func dnp3Link(dest, src uint16, control byte, payload []byte) []byte {
	crcBytes := 0
	if len(payload) > 0 {
		crcBytes = ((len(payload) + 15) / 16) * 2
	}
	length := 5 + len(payload) + crcBytes

	hdr := make([]byte, 8)
	hdr[0] = 0x05
	hdr[1] = 0x64
	hdr[2] = byte(length)
	hdr[3] = control
	binary.LittleEndian.PutUint16(hdr[4:6], dest)
	binary.LittleEndian.PutUint16(hdr[6:8], src)

	out := make([]byte, 0, 10+len(payload)+crcBytes)
	out = append(out, hdr...)
	var hc [2]byte
	binary.LittleEndian.PutUint16(hc[:], dnp3CRC(hdr))
	out = append(out, hc[:]...)
	if len(payload) > 0 {
		out = append(out, dnp3CRCPad(payload)...)
	}
	return out
}

// parseDNP3Link strips CRCs, returns payload and control byte.
func parseDNP3Link(data []byte) (payload []byte, control byte, err error) {
	if len(data) < 10 || data[0] != 0x05 || data[1] != 0x64 {
		return nil, 0, errors.New("icsgo/dnp3: bad link start")
	}
	length := int(data[2])
	if len(data) < length+2 {
		return nil, 0, errors.New("icsgo/dnp3: truncated link frame")
	}
	hdr := data[:8]
	gotCRC := binary.LittleEndian.Uint16(data[8:10])
	if dnp3CRC(hdr) != gotCRC {
		return nil, 0, errors.New("icsgo/dnp3: header CRC mismatch")
	}
	control = data[3]
	user := data[10 : length+2]
	// strip the 16-byte-chunk CRCs from user data
	out := make([]byte, 0, len(user))
	for i := 0; i < len(user); i += 18 {
		end := i + 16
		if end > len(user) {
			end = len(user)
		}
		out = append(out, user[i:end]...)
	}
	return out, control, nil
}

// DNP3Connect dials and performs a link reset.
func DNP3Connect(opts DNP3Options) (*DNP3Conn, error) {
	if opts.Host == "" {
		return nil, errors.New("icsgo/dnp3: host required")
	}
	if opts.Port == 0 {
		opts.Port = 20000
	}
	if opts.Dest == 0 {
		opts.Dest = 1
	}
	if opts.Src == 0 {
		opts.Src = 100
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("icsgo/dnp3: dial: %w", err)
	}
	c := &DNP3Conn{conn: conn, opts: opts, seq: 1}

	// link reset
	_, _ = conn.Write(dnp3Link(opts.Dest, opts.Src, DNP3LinkReset, nil))
	_ = conn.SetReadDeadline(time.Now().Add(opts.Timeout))
	_, _ = readDNP3Frame(conn)
	return c, nil
}

// Close ends the DNP3 session.
func (c *DNP3Conn) Close() error { return c.conn.Close() }

// readDNP3Frame reads one full link frame from the stream.
func readDNP3Frame(conn net.Conn) ([]byte, error) {
	head := make([]byte, 10)
	if _, err := io.ReadFull(conn, head); err != nil {
		return nil, err
	}
	if head[0] != 0x05 || head[1] != 0x64 {
		return nil, errors.New("icsgo/dnp3: desync")
	}
	length := int(head[2])
	rest := make([]byte, length+2-10)
	if rest != nil {
		if _, err := io.ReadFull(conn, rest); err != nil {
			return nil, err
		}
	}
	return append(head, rest...), nil
}

// Integrity fires a class 1+2+3+0 poll and decodes the response.
func (c *DNP3Conn) Integrity() (DNP3Response, error) {
	// objects: 60 var 1..4 all objects
	objs := []byte{
		0x3C, 0x01, 0x06,
		0x3C, 0x02, 0x06,
		0x3C, 0x03, 0x06,
		0x3C, 0x04, 0x06,
	}
	return c._read(DNP3FnRead, objs)
}

// PollClass fires a class poll for the given class (0..3).
func (c *DNP3Conn) PollClass(class uint8) (DNP3Response, error) {
	if class > 3 {
		return DNP3Response{}, errors.New("icsgo/dnp3: class 0..3")
	}
	objs := []byte{0x3C, class + 1, 0x06}
	return c._read(DNP3FnRead, objs)
}

func (c *DNP3Conn) _read(fn byte, objects []byte) (DNP3Response, error) {
	// transport: FIR=1 FIN=1 SEQ
	transport := 0xC0 | (c.seq & 0x3F)
	// app control: FIR=1 FIN=1 seq in low nibble
	appCtrl := byte(0xC0 | (c.seq & 0x0F))
	app := make([]byte, 0, 2+len(objects))
	app = append(app, appCtrl, fn)
	app = append(app, objects...)

	payload := append([]byte{transport}, app...)
	frame := dnp3Link(c.opts.Dest, c.opts.Src, DNP3LinkUserDataUnc, payload)

	_ = c.conn.SetDeadline(time.Now().Add(c.opts.Timeout))
	if _, err := c.conn.Write(frame); err != nil {
		return DNP3Response{}, err
	}
	raw, err := readDNP3Frame(c.conn)
	if err != nil {
		return DNP3Response{}, err
	}
	parsed, _, err := parseDNP3Link(raw)
	if err != nil {
		return DNP3Response{}, err
	}
	if len(parsed) < 4 {
		return DNP3Response{}, errors.New("icsgo/dnp3: short app")
	}
	// skip transport byte
	app = parsed[1:]
	resp := DNP3Response{
		Function: app[1],
		IIN:      decodeIIN(binary.LittleEndian.Uint16(app[2:4])),
	}
	if len(app) > 4 {
		resp.Raw = append([]byte(nil), app[4:]...)
	}
	return resp, nil
}
