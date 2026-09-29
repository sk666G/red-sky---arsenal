package icsgo

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math"
)

// BACnet APDU decoder. The base spec has ~30 application data types and a
// context-tag scheme that lets those types be nested inside each other.
// This file covers the types that show up in ReadProperty / WriteProperty
// responses for real building-automation objects.
//
// Application tag summary (high nibble = type, low nibble = length unless 5):
//   0  Null                1  Boolean (length is value)
//   2  Unsigned Integer    3  Signed Integer
//   4  Real (IEEE 754)     5  Double
//   6  Octet String        7  Character String
//   8  Bit String          9  Enumerated
//   10 Date               11  Time
//   12 Object Identifier  13 Reserved
//   14 Reserved           15 Reserved
//
// Context tags: high nibble 8..15 means tag numbers 0..7 respectively, and
// low nibble = 0..4 is length, or 5 means "opening tag" (followed by a
// closing tag 0xXF to end the nested value).

// BACnetValue is a decoded value with a type label.
type BACnetValue struct {
	Type  string      // "real", "unsigned", "enumerated", "object-id", "string", ...
	Value interface{} // float64, int64, uint64, string, BACnetObjectID, []byte, bool
}

// BACnetObjectID is the classic 4-byte packed object identifier.
type BACnetObjectID struct {
	ObjectType uint16
	Instance   uint32
}

func (o BACnetObjectID) String() string {
	return fmt.Sprintf("%d:%d", o.ObjectType, o.Instance)
}

// BACnetDecodeResult is the outcome of decoding a ComplexACK payload.
type BACnetDecodeResult struct {
	ObjectID   BACnetObjectID
	PropertyID uint32
	Value      BACnetValue
	Raw        []byte // unparsed remainder (nested / extended values)
}

// DecodeReadPropertyACK parses the body of a ComplexACK response to a
// ReadProperty request. Expected layout (post-BVLC, post-NPDU, post-APDU
// header, i.e. after the 0x30 invoke-id service-ack bytes):
//
//	context 0 (Object Identifier)   — the object being read
//	context 1 (Property Identifier) — the property being read
//	[context 2 (Array Index)]       — optional
//	context 3 (opening tag)         — the value block
//	<value>
//	context 3 (closing tag)
func DecodeReadPropertyACK(apdu []byte) (BACnetDecodeResult, error) {
	var res BACnetDecodeResult
	if len(apdu) < 6 {
		return res, errors.New("icsgo/bacnet: apdu too short")
	}
	// caller supplies the APDU starting at the PDU type byte (0x30 for
	// ComplexACK). we skip past: PDU type(1) + invoke id(1) + service(1) + object-type(1) ... in fact
	// the caller has already stripped those; here we want the property read
	// payload. this function accepts a slice that starts at the object
	// identifier context tag.
	off := 0

	// optional: skip PDU type if present
	if apdu[0] == BacnetComplexACK {
		off += 3 // PDU type + invoke id + service choice
		// service choice 0x0C read-property — could be others
	}

	// context 0: object id
	objID, n, err := bacnetContextObjectID(apdu, off)
	if err != nil {
		return res, fmt.Errorf("icsgo/bacnet: object id: %w", err)
	}
	off += n
	res.ObjectID = objID

	// context 1: property identifier
	propID, n, err := bacnetContextUnsigned(apdu, off)
	if err != nil {
		return res, fmt.Errorf("icsgo/bacnet: property id: %w", err)
	}
	off += n
	res.PropertyID = propID

	// optional context 2: array index — skip if present
	if off < len(apdu) && (apdu[off]>>4) == 0x8+2 {
		_, n, err := bacnetContextUnsigned(apdu, off)
		if err == nil {
			off += n
		}
	}

	// context 3 opening tag
	if off >= len(apdu) || apdu[off] != (0x8+3)<<4|5 {
		// not the standard opening tag — try decoding as a bare value
		val, _, err := bacnetDecodeValue(apdu, off)
		if err != nil {
			return res, fmt.Errorf("icsgo/bacnet: value: %w", err)
		}
		res.Value = val
		res.Raw = apdu[off:]
		return res, nil
	}
	off++ // skip opening tag
	val, consumed, err := bacnetDecodeValue(apdu, off)
	if err != nil {
		return res, fmt.Errorf("icsgo/bacnet: value: %w", err)
	}
	off += consumed
	res.Value = val
	res.Raw = apdu[off:]
	return res, nil
}

// --- individual decoders ---

// bacnetContextUnsigned reads a context-tagged unsigned integer (tags 0..7).
func bacnetContextUnsigned(b []byte, off int) (uint32, int, error) {
	if off >= len(b) {
		return 0, 0, errors.New("eof")
	}
	t := b[off]
	high := t >> 4
	if high < 8 || high > 15 {
		return 0, 0, fmt.Errorf("not a context tag: 0x%02x", t)
	}
	l := int(t & 0x0F)
	if l >= 5 {
		return 0, 0, errors.New("context tag with non-numeric length")
	}
	off++
	if off+l > len(b) {
		return 0, 0, errors.New("truncated")
	}
	var v uint32
	for i := 0; i < l; i++ {
		v = (v << 8) | uint32(b[off+i])
	}
	return v, 1 + l, nil
}

// bacnetContextObjectID reads a context 0 tag that wraps a 4-byte object id.
func bacnetContextObjectID(b []byte, off int) (BACnetObjectID, int, error) {
	if off >= len(b) {
		return BACnetObjectID{}, 0, errors.New("eof")
	}
	t := b[off]
	if (t >> 4) != 8 {
		return BACnetObjectID{}, 0, fmt.Errorf("expected context 0, got 0x%02x", t)
	}
	l := int(t & 0x0F)
	if l != 4 {
		return BACnetObjectID{}, 0, fmt.Errorf("object id tag length must be 4, got %d", l)
	}
	off++
	raw := binary.BigEndian.Uint32(b[off : off+4])
	return BACnetObjectID{
		ObjectType: uint16(raw >> 22),
		Instance:   raw & 0x3FFFFF,
	}, 5, nil
}

// bacnetDecodeValue decodes one application-tagged value starting at off.
// Returns the decoded value and the number of bytes consumed.
func bacnetDecodeValue(b []byte, off int) (BACnetValue, int, error) {
	if off >= len(b) {
		return BACnetValue{}, 0, errors.New("eof at value")
	}
	tag := b[off]
	high := tag >> 4
	low := tag & 0x0F

	switch high {
	case 0: // Null
		return BACnetValue{Type: "null"}, 1, nil

	case 1: // Boolean — length is the value (0 or 1)
		return BACnetValue{Type: "boolean", Value: low == 1}, 1, nil

	case 2: // Unsigned Integer
		if low > 8 {
			return BACnetValue{}, 0, fmt.Errorf("unsigned tag length %d", low)
		}
		off++
		if off+int(low) > len(b) {
			return BACnetValue{}, 0, errors.New("truncated unsigned")
		}
		var v uint64
		for i := 0; i < int(low); i++ {
			v = (v << 8) | uint64(b[off+i])
		}
		return BACnetValue{Type: "unsigned", Value: v}, 1 + int(low), nil

	case 3: // Signed Integer
		if low > 8 {
			return BACnetValue{}, 0, fmt.Errorf("signed tag length %d", low)
		}
		off++
		if off+int(low) > len(b) {
			return BACnetValue{}, 0, errors.New("truncated signed")
		}
		// assemble the raw magnitude, then sign-extend based on the top bit
		var raw uint64
		for i := 0; i < int(low); i++ {
			raw = (raw << 8) | uint64(b[off+i])
		}
		bits := uint(low) * 8
		var v int64
		if low > 0 && b[off]&0x80 != 0 {
			// negative — sign-extend by setting all bits above `bits`
			v = int64(raw) | ^((int64(1) << bits) - 1)
		} else {
			v = int64(raw)
		}
		return BACnetValue{Type: "signed", Value: v}, 1 + int(low), nil

	case 4: // Real (IEEE 754 single)
		if low != 4 {
			return BACnetValue{}, 0, fmt.Errorf("real tag length must be 4, got %d", low)
		}
		off++
		if off+4 > len(b) {
			return BACnetValue{}, 0, errors.New("truncated real")
		}
		bits := binary.BigEndian.Uint32(b[off : off+4])
		return BACnetValue{Type: "real", Value: float64(math.Float32frombits(bits))}, 5, nil

	case 5: // Double
		if low != 8 {
			return BACnetValue{}, 0, fmt.Errorf("double tag length must be 8, got %d", low)
		}
		off++
		if off+8 > len(b) {
			return BACnetValue{}, 0, errors.New("truncated double")
		}
		bits := binary.BigEndian.Uint64(b[off : off+8])
		return BACnetValue{Type: "double", Value: math.Float64frombits(bits)}, 9, nil

	case 6: // Octet String
		off++
		if off+int(low) > len(b) {
			return BACnetValue{}, 0, errors.New("truncated octet string")
		}
		v := append([]byte(nil), b[off:off+int(low)]...)
		return BACnetValue{Type: "octet-string", Value: v}, 1 + int(low), nil

	case 7: // Character String
		if low < 1 {
			return BACnetValue{}, 0, errors.New("char string tag needs encoding byte")
		}
		off++
		if off+int(low) > len(b) {
			return BACnetValue{}, 0, errors.New("truncated char string")
		}
		// first byte of the payload is the encoding (0 = UTF-8 / ANSI)
		enc := b[off]
		_ = enc // we assume UTF-8/ANSI
		s := string(b[off+1 : off+int(low)])
		return BACnetValue{Type: "string", Value: s}, 1 + int(low), nil

	case 8: // Bit String
		off++
		if off+int(low) > len(b) {
			return BACnetValue{}, 0, errors.New("truncated bit string")
		}
		// first payload byte is the unused-bit count
		_, unused := b[off], 0
		_ = unused
		v := append([]byte(nil), b[off:off+int(low)]...)
		return BACnetValue{Type: "bit-string", Value: v}, 1 + int(low), nil

	case 9: // Enumerated
		off++
		if off+int(low) > len(b) {
			return BACnetValue{}, 0, errors.New("truncated enum")
		}
		var v uint64
		for i := 0; i < int(low); i++ {
			v = (v << 8) | uint64(b[off+i])
		}
		return BACnetValue{Type: "enumerated", Value: v}, 1 + int(low), nil

	case 10: // Date (4 bytes)
		off++
		if off+4 > len(b) {
			return BACnetValue{}, 0, errors.New("truncated date")
		}
		year := int(b[off]) + 1900
		month := b[off+1]
		day := b[off+2]
		dow := b[off+3]
		return BACnetValue{
			Type:  "date",
			Value: fmt.Sprintf("%04d-%02d-%02d (dow=%d)", year, month, day, dow),
		}, 5, nil

	case 11: // Time (4 bytes)
		off++
		if off+4 > len(b) {
			return BACnetValue{}, 0, errors.New("truncated time")
		}
		h, m, s, h100 := b[off], b[off+1], b[off+2], b[off+3]
		return BACnetValue{
			Type:  "time",
			Value: fmt.Sprintf("%02d:%02d:%02d.%02d", h, m, s, h100),
		}, 5, nil

	case 12: // Object Identifier
		if low != 4 {
			return BACnetValue{}, 0, fmt.Errorf("object-id tag length must be 4, got %d", low)
		}
		off++
		raw := binary.BigEndian.Uint32(b[off : off+4])
		obj := BACnetObjectID{
			ObjectType: uint16(raw >> 22),
			Instance:   raw & 0x3FFFFF,
		}
		return BACnetValue{Type: "object-id", Value: obj}, 5, nil

	default:
		return BACnetValue{}, 0, fmt.Errorf("unsupported application tag %d", high)
	}
}

// BACnetFormatValue is a short pretty-printer for decoded values.
func BACnetFormatValue(v BACnetValue) string {
	switch v.Type {
	case "real", "double":
		if f, ok := v.Value.(float64); ok {
			return fmt.Sprintf("%g", f)
		}
	case "unsigned", "enumerated":
		return fmt.Sprintf("%v", v.Value)
	case "signed":
		return fmt.Sprintf("%v", v.Value)
	case "string":
		return fmt.Sprintf("%q", v.Value)
	case "boolean":
		return fmt.Sprintf("%v", v.Value)
	case "object-id":
		return v.Value.(BACnetObjectID).String()
	case "octet-string", "bit-string":
		return fmt.Sprintf("%x", v.Value)
	}
	return fmt.Sprintf("%v", v.Value)
}
