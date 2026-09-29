//go:build !linux

package capturer

import (
	"context"
	"errors"
	"time"
)

// Frame is a captured packet (stub).
type Frame struct {
	TS      time.Time
	Data    []byte
	OrigLen int
}

// Options controls a capture session (stub).
type Options struct {
	Iface   string
	Snaplen int
	Timeout time.Duration
}

// Capture is not implemented on non-Linux platforms.
func Capture(ctx context.Context, opts Options, onFrame func(Frame)) error {
	return errors.New("capturer: raw packet capture is Linux-only in this build")
}

// Supported returns false on non-Linux.
func Supported() bool { return false }
