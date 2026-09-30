package adgo

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Minimal DER (Distinguished Encoding Rules) encoder for ASN.1 structures.
// Kerberos messages are ASN.1 DER-encoded; this file provides the
// tag/length/content primitives to build them by hand.
//
// ASN.1 tag byte:
//   bits 7-6  class:      00 = universal, 01 = application, 10 = context, 11 = private
//   bit 5     constructed: 1 = the content is a sequence of TLV values
//   bits 4-0  tag number (0..30)
//
// Length encoding:
//   short form: 0x00-0x7F — the length is that byte
//   0x80       — indefinite length (not used in DER)
//   0x81 NN    — one byte of length follows
//   0x82 NN NN — two bytes
//   etc.

// DERClass identifies the ASN.1 tag class.
type DERClass byte

const (
	ClassUniversal   DERClass = 0x00
	ClassApplication DERClass = 0x40
	ClassContext     DERClass = 0x80
	ClassPrivate     DERClass = 0xC0
)

// Universal tag numbers.
const (
	TagBoolean     = 1
	TagInteger     = 2
	TagBitString   = 3
	TagOctetString = 4
	TagNull        = 5
	TagOID         = 6
	TagUTF8String  = 12
	TagSequence    = 16
	TagSet         = 17
	TagPrintable   = 19
	TagIA5String   = 22
	TagUTCTime     = 23
	TagGeneralTime = 24
)

// Tag builds a DER tag byte for a class + tag number + constructed flag.
func Tag(class DERClass, constructed bool, num byte) byte {
	b := byte(class)
	if constructed {
		b |= 0x20
	}
	b |= num & 0x1F
	return b
}

// Len encodes a DER length. Returns the length bytes only.
func Len(n int) []byte {
	if n < 0 {
		n = 0
	}
	if n < 0x80 {
		return []byte{byte(n)}
	}
	// long form
	if n < 0x100 {
		return []byte{0x81, byte(n)}
	}
	if n < 0x10000 {
		return []byte{0x82, byte(n >> 8), byte(n)}
	}
	if n < 0x1000000 {
		return []byte{0x83, byte(n >> 16), byte(n >> 8), byte(n)}
	}
	return []byte{0x84, byte(n >> 24), byte(n >> 16), byte(n >> 8), byte(n)}
}

// TLV wraps content in a tag-length-value.
func TLV(tag byte, content []byte) []byte {
	out := []byte{tag}
	out = append(out, Len(len(content))...)
	out = append(out, content...)
	return out
}

// --- primitive encoders ---

// DERInteger encodes an int as an ASN.1 INTEGER. Handles the two's
// complement form DER requires — leading 0x00 to keep the sign bit
// clear for positive values that would otherwise set it.
func DERInteger(v int64) []byte {
	if v == 0 {
		return TLV(Tag(ClassUniversal, false, TagInteger), []byte{0x00})
	}
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], uint64(v))
	// find the first significant byte
	i := 0
	if v > 0 {
		// skip leading 0x00
		for i < 8 && buf[i] == 0x00 {
			i++
		}
		// if the top bit of the first sig byte is set, prepend 0x00 to
		// keep it positive
		if buf[i]&0x80 != 0 {
			return TLV(Tag(ClassUniversal, false, TagInteger), append([]byte{0x00}, buf[i:]...))
		}
		return TLV(Tag(ClassUniversal, false, TagInteger), buf[i:])
	}
	// negative: skip leading 0xFF but keep the last one if the next byte
	// also has the top bit set
	for i < 7 && buf[i] == 0xFF && (buf[i+1]&0x80) != 0 {
		i++
	}
	return TLV(Tag(ClassUniversal, false, TagInteger), buf[i:])
}

// DERIntegerBig encodes a big-endian byte slice as an ASN.1 INTEGER.
// Useful for large integers where int64 isn't enough (e.g., some Kerberos
// fields).
func DERIntegerBig(b []byte) []byte {
	// strip leading zeros but keep at least one byte
	i := 0
	for i < len(b)-1 && b[i] == 0x00 {
		i++
	}
	b = b[i:]
	// if top bit is set, prepend a zero byte
	if len(b) > 0 && b[0]&0x80 != 0 {
		b = append([]byte{0x00}, b...)
	}
	return TLV(Tag(ClassUniversal, false, TagInteger), b)
}

// DEROctetString wraps bytes as an OCTET STRING.
func DEROctetString(b []byte) []byte {
	return TLV(Tag(ClassUniversal, false, TagOctetString), b)
}

// DERNull is the NULL value.
func DERNull() []byte {
	return []byte{Tag(ClassUniversal, false, TagNull), 0x00}
}

// DERBoolean encodes a BOOLEAN (0xFF for true, 0x00 for false, per DER).
func DERBoolean(v bool) []byte {
	if v {
		return []byte{Tag(ClassUniversal, false, TagBoolean), 0x01, 0xFF}
	}
	return []byte{Tag(ClassUniversal, false, TagBoolean), 0x01, 0x00}
}

// DERSequence wraps content in a SEQUENCE (constructed).
func DERSequence(content []byte) []byte {
	return TLV(Tag(ClassUniversal, true, TagSequence), content)
}

// DERSet wraps content in a SET (constructed).
func DERSet(content []byte) []byte {
	return TLV(Tag(ClassUniversal, true, TagSet), content)
}

// DERContextTag wraps content in a context tag (class 10, given number).
// If constructed is true, the content is a nested TLV structure. If false,
// the content is treated as raw bytes (implicit tagging).
func DERContextTag(num byte, constructed bool, content []byte) []byte {
	return TLV(Tag(ClassContext, constructed, num), content)
}

// DERApplicationTag is the same idea for the application class.
func DERApplicationTag(num byte, constructed bool, content []byte) []byte {
	return TLV(Tag(ClassApplication, constructed, num), content)
}

// DERGeneralString wraps text in a GeneralString (tag 27 — used in
// Kerberos for realm names and principal components).
func DERGeneralString(s string) []byte {
	return TLV(Tag(ClassUniversal, false, 27), []byte(s))
}

// DERIA5String wraps ASCII in an IA5String (tag 22).
func DERIA5String(s string) []byte {
	return TLV(Tag(ClassUniversal, false, TagIA5String), []byte(s))
}

// DERGeneralizedTime wraps a timestamp in the generalized time format
// Kerberos requires: YYYYMMDDHHMMSSZ.
func DERGeneralizedTime(t string) []byte {
	// caller formats the string; we just wrap it
	return TLV(Tag(ClassUniversal, false, TagGeneralTime), []byte(t))
}

// --- high-level helpers for Kerberos ---

// KerbPrincipal builds a Kerberos PrincipalName:
//
//	PrincipalName ::= SEQUENCE {
//	    name-type    [0] Int32,
//	    name-string  [1] SEQUENCE OF KerberosString
//	}
func KerbPrincipal(nameType int, components []string) []byte {
	typeEnc := DERContextTag(0, false, DERInteger(int64(nameType)))
	var stringSeq []byte
	for _, s := range components {
		stringSeq = append(stringSeq, DERGeneralString(s)...)
	}
	stringSeqEnc := DERContextTag(1, true, stringSeq)
	return DERSequence(append(typeEnc, stringSeqEnc...))
}

// KerbTime wraps a KerberosTime (GeneralizedTime) as a context tag.
func KerbTime(num byte, t string) []byte {
	return DERContextTag(num, false, DERGeneralizedTime(t))
}

// --- decoding ---

// DERReader is a minimal DER decoder.
type DERReader struct {
	b   []byte
	off int
}

// NewDERReader creates a reader over a DER-encoded blob.
func NewDERReader(b []byte) *DERReader {
	return &DERReader{b: b}
}

// ReadTLV reads the next tag + content. Returns the tag byte and the
// content slice (without the tag/length).
func (r *DERReader) ReadTLV() (byte, []byte, error) {
	if r.off >= len(r.b) {
		return 0, nil, errors.New("adgo/der: eof")
	}
	tag := r.b[r.off]
	r.off++
	length, err := r.readLength()
	if err != nil {
		return 0, nil, err
	}
	if r.off+length > len(r.b) {
		return 0, nil, errors.New("adgo/der: content overruns buffer")
	}
	content := r.b[r.off : r.off+length]
	r.off += length
	return tag, content, nil
}

func (r *DERReader) readLength() (int, error) {
	if r.off >= len(r.b) {
		return 0, errors.New("adgo/der: eof in length")
	}
	first := r.b[r.off]
	r.off++
	if first&0x80 == 0 {
		return int(first), nil
	}
	n := int(first & 0x7F)
	if n == 0 {
		return 0, errors.New("adgo/der: indefinite length not supported in DER")
	}
	if n > 4 {
		return 0, errors.New("adgo/der: length > 4 bytes")
	}
	if r.off+n > len(r.b) {
		return 0, errors.New("adgo/der: length overruns buffer")
	}
	var v int
	for i := 0; i < n; i++ {
		v = (v << 8) | int(r.b[r.off+i])
	}
	r.off += n
	return v, nil
}

// TagClass returns the class of a tag byte.
func TagClass(tag byte) DERClass {
	return DERClass(tag & 0xC0)
}

// TagNumber returns the tag number of a tag byte.
func TagNumber(tag byte) byte {
	return tag & 0x1F
}

// IsConstructed returns whether the tag has the constructed bit set.
func IsConstructed(tag byte) bool {
	return tag&0x20 != 0
}

// DecodeInteger reads a DER INTEGER content and returns its value as
// int64. Returns an error for integers larger than 8 bytes.
func DecodeInteger(content []byte) (int64, error) {
	if len(content) == 0 {
		return 0, nil
	}
	if len(content) > 8 {
		return 0, fmt.Errorf("adgo/der: integer too large (%d bytes)", len(content))
	}
	var v int64
	if content[0]&0x80 != 0 {
		// negative — sign-extend
		v = -1
	}
	for _, b := range content {
		v = (v << 8) | int64(b)
	}
	return v, nil
}

var _ = errors.New
