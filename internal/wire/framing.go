// Package wire handles framing for the Red Sky agent protocol.
//
// Frame layout:
//
//	[2] magic   0x52 0x53  ("RS")
//	[1] version 0x03
//	[1] flags   bit0 compressed, bit1 encrypted, bit2 last-chunk
//	[4] length  uint32 BE, length of payload after this header
//	[N] payload
package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	Magic0  = 0x52
	Magic1  = 0x53
	Version = 0x03

	FlagCompressed = 1 << 0
	FlagEncrypted  = 1 << 1
	FlagLastChunk  = 1 << 2

	HeaderSize = 8
	MaxPayload = 32 * 1024 * 1024
)

var (
	ErrBadMagic   = errors.New("wire: bad magic")
	ErrBadVersion = errors.New("wire: unsupported version")
	ErrTooLarge   = errors.New("wire: payload too large")
)

// Frame is a decoded wire frame.
type Frame struct {
	Flags   byte
	Payload []byte
}

// WriteFrame writes one framed payload to w.
func WriteFrame(w io.Writer, flags byte, payload []byte) error {
	if len(payload) > MaxPayload {
		return ErrTooLarge
	}
	hdr := [HeaderSize]byte{
		Magic0, Magic1,
		Version,
		flags,
		0, 0, 0, 0,
	}
	binary.BigEndian.PutUint32(hdr[4:8], uint32(len(payload)))
	if _, err := w.Write(hdr[:]); err != nil {
		return err
	}
	_, err := w.Write(payload)
	return err
}

// ReadFrame reads exactly one frame from r.
func ReadFrame(r io.Reader) (*Frame, error) {
	var hdr [HeaderSize]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	if hdr[0] != Magic0 || hdr[1] != Magic1 {
		return nil, ErrBadMagic
	}
	if hdr[2] != Version {
		return nil, ErrBadVersion
	}
	flags := hdr[3]
	length := binary.BigEndian.Uint32(hdr[4:8])
	if length > MaxPayload {
		return nil, ErrTooLarge
	}
	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return &Frame{Flags: flags, Payload: payload}, nil
}
