package icsgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"
)

// BACnet/IP — UDP/47808 (0xBAC0). Building automation protocol. No auth on
// the base spec; BACnet/SC adds TLS but is rarely deployed. Any device on
// the segment accepts whatever a same-subnet peer sends.
//
// BACnet/IP frame:
//   BVLC header (4 bytes):
//     type (1)    0x81 = BACnet/IP
//     function (1)  0x0A = Original-Unicast, 0x0B = Original-Broadcast,
//                   0x04 = Forwarded-NPDU
//     length (2 BE) total message length including BVLC
//   NPDU:
//     version (1)  0x01
//     control (1)  bit 7 = Network Layer Message, bit 5 = DNET/DLEN/DADR present,
//                  bit 3 = DNET is broadcast
//     [DNET (2), DLEN (1), DADR (DLEN)] if DNET present
//     [hop count (1)] if DNET is broadcast
//     [APDU] if not a network-layer message
//   APDU:
//     PDU type (1)    0x00 = Confirmed-Request, 0x10 = Unconfirmed-Request,
//                     0x20 = SimpleACK, 0x30 = ComplexACK, 0x50 = Error, 0x60 = Reject
//     [invoke id (1), service choice (1) for confirmed]  — for unconfirmed,
//                        only service choice follows
//     service parameters
//
// Services used here:
//   0x0C  ReadProperty
//   0x0F  WriteProperty
//   0x08  Who-Is (unconfirmed, broadcasts for device discovery)
//   0x00  I-Am (response to Who-Is)
//   0x0E  Who-Has / 0x01 I-Have (object discovery by name)

// BACnet BVLC constants
const (
	BacnetPort          = 47808
	BacnetBVLCType      = 0x81
	BacnetFuncUnicast   = 0x0A
	BacnetFuncBroadcast = 0x0B
	BacnetFuncForwarded = 0x04
)

// BACnet APDU PDU types
const (
	BacnetConfirmedReq = 0x00
	BacnetUnconfirmed  = 0x10
	BacnetSimpleACK    = 0x20
	BacnetComplexACK   = 0x30
	BacnetSegmentACK   = 0x40
	BacnetError        = 0x50
	BacnetReject       = 0x60
	BacnetAbort        = 0x70
)

// BACnet Confirmed-Request service choices
const (
	BacnetSvcAckAlarm          = 0x00
	BacnetSvcReadProperty      = 0x0C
	BacnetSvcWriteProperty     = 0x0F
	BacnetSvcReadPropertyMulti = 0x0E
	BacnetSvcAtomicReadFile    = 0x06
	BacnetSvcAtomicWriteFile   = 0x07
	BacnetSvcDeviceCommControl = 0x11
	BacnetSvcReinitialize      = 0x14
)

// BACnet Unconfirmed-Request service choices
const (
	BacnetSvcWhoIs       = 0x08
	BacnetSvcIAm         = 0x00
	BacnetSvcWhoHas      = 0x07
	BacnetSvcIHave       = 0x01
	BacnetSvcTimeSync    = 0x06
	BacnetSvcUTCTimeSync = 0x09
	BacnetSvcWriteGroup  = 0x0A
)

// Object types (standard). Full list is in ASHRAE 135.
const (
	BacnetObjAnalogInput   = 0
	BacnetObjAnalogOutput  = 1
	BacnetObjAnalogValue   = 2
	BacnetObjBinaryInput   = 3
	BacnetObjBinaryOutput  = 4
	BacnetObjBinaryValue   = 5
	BacnetObjDevice        = 8
	BacnetObjMultiStateIn  = 13
	BacnetObjMultiStateOut = 14
	BacnetObjMultiStateVal = 19
)

// Property IDs
const (
	BacnetPropObjectIdentifier = 75
	BacnetPropObjectName       = 77
	BacnetPropObjectType       = 79
	BacnetPropPresentValue     = 85
	BacnetPropStatusFlags      = 111
	BacnetPropUnits            = 117
	BacnetPropDescription      = 28
)

// BACnetOptions controls a BACnet/IP interaction.
type BACnetOptions struct {
	Host    string
	Port    int           // 47808 default
	Timeout time.Duration // per request
}

func bacnetDefault(opts BACnetOptions) BACnetOptions {
	if opts.Port == 0 {
		opts.Port = BacnetPort
	}
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	return opts
}

// bvlcWrap wraps a payload in a BVLC header (Original-Unicast).
func bvlcWrap(payload []byte, function byte) []byte {
	out := make([]byte, 4+len(payload))
	out[0] = BacnetBVLCType
	out[1] = function
	binary.BigEndian.PutUint16(out[2:4], uint16(4+len(payload)))
	copy(out[4:], payload)
	return out
}

// npduWrap wraps an APDU in a minimal NPDU (no routing — global broadcast).
func npduWrap(apdu []byte, isNetworkLayer bool) []byte {
	ctrl := byte(0x00)
	if isNetworkLayer {
		ctrl |= 0x80
	}
	out := make([]byte, 2+len(apdu))
	out[0] = 0x01 // version
	out[1] = ctrl
	copy(out[2:], apdu)
	return out
}

// WhoIs builds a Who-Is unconfirmed request. Range limits of 0x0000..0xFFFF
// scan every device ID; pass distinct lo/hi to narrow.
func WhoIs(lo, hi uint32) []byte {
	apdu := make([]byte, 0, 6)
	apdu = append(apdu, BacnetUnconfirmed, BacnetSvcWhoIs)
	// context tags for optional device id range
	if lo != 0 || hi != 0 {
		apdu = append(apdu, bacnetContextUint(0, lo)...)
		apdu = append(apdu, bacnetContextUint(1, hi)...)
	}
	npdu := npduWrap(apdu, false)
	return bvlcWrap(npdu, BacnetFuncBroadcast)
}

// IAm builds the response form used in tests.
func IAm(deviceInstance uint32, maxAPDU uint32, segmentation byte, vendorID uint16) []byte {
	apdu := []byte{BacnetUnconfirmed, BacnetSvcIAm}
	apdu = append(apdu, bacnetAppUint(deviceInstance)...)
	apdu = append(apdu, bacnetAppUint(maxAPDU)...)
	apdu = append(apdu, segmentation)
	apdu = append(apdu, bacnetAppUint(uint32(vendorID))...)
	npdu := npduWrap(apdu, false)
	return bvlcWrap(npdu, BacnetFuncBroadcast)
}

// ReadProperty builds a Confirmed-Request ReadProperty APDU.
func ReadProperty(invokeID byte, objType uint16, objInstance uint32, propertyID uint16) []byte {
	apdu := []byte{BacnetConfirmedReq, invokeID, BacnetSvcReadProperty}
	// object identifier: context tag 0, 4 bytes: (objType << 22) | objInstance
	objID := (uint32(objType) << 22) | (objInstance & 0x3FFFFF)
	apdu = append(apdu, bacnetContextUint(0, objID)...)
	// property identifier: context tag 1, 1..4 bytes
	apdu = append(apdu, bacnetContextUint(1, uint32(propertyID))...)
	npdu := npduWrap(apdu, false)
	return bvlcWrap(npdu, BacnetFuncUnicast)
}

// WriteProperty builds a Confirmed-Request WriteProperty APDU. The value is
// an application-encoded blob the caller assembles (typically 0x44 0xXX for
// a real, 0x91 0xNN for an enumerated/boolean).
func WriteProperty(invokeID byte, objType uint16, objInstance uint32, propertyID uint16, value []byte) []byte {
	apdu := []byte{BacnetConfirmedReq, invokeID, BacnetSvcWriteProperty}
	objID := (uint32(objType) << 22) | (objInstance & 0x3FFFFF)
	apdu = append(apdu, bacnetContextUint(0, objID)...)
	apdu = append(apdu, bacnetContextUint(1, uint32(propertyID))...)
	// opening tag 3 (value), then the value bytes, then closing tag 3
	apdu = append(apdu, 0x3E)
	apdu = append(apdu, value...)
	apdu = append(apdu, 0x3F)
	npdu := npduWrap(apdu, false)
	return bvlcWrap(npdu, BacnetFuncUnicast)
}

// --- encoding helpers for BACnet context / application tags ---

// bacnetContextUint encodes a context-tagged unsigned integer of minimum bytes.
func bacnetContextUint(tag byte, v uint32) []byte {
	// encode minimum number of bytes
	var nb int
	switch {
	case v == 0:
		nb = 0
	case v <= 0xFF:
		nb = 1
	case v <= 0xFFFF:
		nb = 2
	case v <= 0xFFFFFF:
		nb = 3
	default:
		nb = 4
	}
	out := []byte{0x08 | tag<<4 | byte(nb)} // 0x08 = context tag marker in the high nibble meaning, length in low
	for i := nb - 1; i >= 0; i-- {
		out = append(out, byte((v>>(8*uint(i)))&0xFF))
	}
	return out
}

// bacnetAppUint encodes an application-tagged Unsigned Integer (tag 2).
func bacnetAppUint(v uint32) []byte {
	var nb int
	switch {
	case v <= 0xFF:
		nb = 1
	case v <= 0xFFFF:
		nb = 2
	case v <= 0xFFFFFF:
		nb = 3
	default:
		nb = 4
	}
	out := []byte{0x20 | byte(nb)} // application tag 2 (Unsigned), length in low nibble
	for i := nb - 1; i >= 0; i-- {
		out = append(out, byte((v>>(8*uint(i)))&0xFF))
	}
	return out
}

// --- operations ---

// BACnetWhoIs sends a broadcast Who-Is and collects I-Am responses until
// the timeout. Returns one DeviceInfo per responding device.
type DeviceInfo struct {
	Addr           string
	DeviceInstance uint32
	VendorID       uint16
	Raw            []byte
}

// WhoIsScan sends a Who-Is to the broadcast address and listens for I-Am.
// Uses the same UDP socket for send and receive so the responses land back
// on the correct port.
func WhoIsScan(opts BACnetOptions, lo, hi uint32) ([]DeviceInfo, error) {
	opts = bacnetDefault(opts)
	if opts.Host == "" {
		return nil, errors.New("icsgo/bacnet: host required (broadcast address)")
	}
	addr := &net.UDPAddr{IP: net.ParseIP(opts.Host), Port: opts.Port}
	if addr.IP == nil {
		return nil, fmt.Errorf("icsgo/bacnet: bad host %q", opts.Host)
	}

	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	pkt := WhoIs(lo, hi)
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: write: %w", err)
	}

	var results []DeviceInfo
	buf := make([]byte, 4096)
	for {
		n, from, err := conn.ReadFromUDP(buf)
		if err != nil {
			break // timeout ends the scan
		}
		info, ok := parseIAm(buf[:n])
		if !ok {
			continue
		}
		info.Addr = from.String()
		info.Raw = append([]byte(nil), buf[:n]...)
		results = append(results, info)
	}
	return results, nil
}

// parseIAm extracts device-instance and vendor-id from an I-Am response.
func parseIAm(pkt []byte) (DeviceInfo, bool) {
	if len(pkt) < 4 {
		return DeviceInfo{}, false
	}
	if pkt[0] != BacnetBVLCType {
		return DeviceInfo{}, false
	}
	// BVLC(4) + NPDU(2) + APDU
	apdu := pkt[6:]
	if len(apdu) < 2 {
		return DeviceInfo{}, false
	}
	if apdu[0] != BacnetUnconfirmed || apdu[1] != BacnetSvcIAm {
		return DeviceInfo{}, false
	}
	// parse app-uint at apdu[2:] — tag is 0x2X
	off := 2
	devID, off := bacnetReadAppUint(apdu, off)
	_, off = bacnetReadAppUint(apdu, off) // max APDU
	if off < len(apdu) {
		off++ // segmentation support byte
	}
	vendor, _ := bacnetReadAppUint(apdu, off)
	return DeviceInfo{DeviceInstance: devID, VendorID: uint16(vendor)}, true
}

// bacnetReadAppUint parses one application-tagged unsigned integer.
func bacnetReadAppUint(b []byte, off int) (uint32, int) {
	if off >= len(b) {
		return 0, off
	}
	tag := b[off]
	if tag>>4 != 2 { // application tag 2 = Unsigned Integer
		return 0, off + 1
	}
	l := int(tag & 0x0F)
	off++
	if off+l > len(b) {
		l = len(b) - off
	}
	var v uint32
	for i := 0; i < l; i++ {
		v = (v << 8) | uint32(b[off+i])
	}
	return v, off + l
}

// ReadPropertyValue sends a ReadProperty request and returns the raw
// ComplexACK or Error response. Full APDU decoding is the operator's job —
// BACnet's encoding is exhaustive and most operators know the shape they
// are looking at.
func ReadPropertyValue(opts BACnetOptions, objType uint16, objInstance uint32, propertyID uint16) ([]byte, error) {
	opts = bacnetDefault(opts)
	if opts.Host == "" {
		return nil, errors.New("icsgo/bacnet: host required")
	}
	addr := &net.UDPAddr{IP: net.ParseIP(opts.Host), Port: opts.Port}
	if addr.IP == nil {
		return nil, fmt.Errorf("icsgo/bacnet: bad host %q", opts.Host)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	pkt := ReadProperty(1, objType, objInstance, propertyID)
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: write: %w", err)
	}
	buf := make([]byte, 8192)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: read: %w", err)
	}
	return append([]byte(nil), buf[:n]...), nil
}

// BACnetWriteRaw sends a Confirmed-Request WriteProperty with the raw
// application-encoded value bytes (as produced by the operator's own
// encoder for the specific data type).
func BACnetWriteRaw(opts BACnetOptions, objType uint16, objInstance uint32, propertyID uint16, rawValue []byte) ([]byte, error) {
	opts = bacnetDefault(opts)
	if opts.Host == "" {
		return nil, errors.New("icsgo/bacnet: host required")
	}
	addr := &net.UDPAddr{IP: net.ParseIP(opts.Host), Port: opts.Port}
	if addr.IP == nil {
		return nil, fmt.Errorf("icsgo/bacnet: bad host %q", opts.Host)
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: dial: %w", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))

	pkt := WriteProperty(1, objType, objInstance, propertyID, rawValue)
	if _, err := conn.Write(pkt); err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: write: %w", err)
	}
	buf := make([]byte, 4096)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("icsgo/bacnet: read: %w", err)
	}
	return append([]byte(nil), buf[:n]...), nil
}
