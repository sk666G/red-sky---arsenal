//go:build !linux

package wireless

import (
	"context"
	"errors"
	"time"
)

type Frame struct {
	TS   time.Time
	Data []byte
}

type Options struct {
	Iface   string
	Channel int
	Timeout time.Duration
}

func Capture(ctx context.Context, opts Options, onFrame func(Frame)) error {
	return errors.New("wireless: 802.11 capture is Linux-only in this build")
}

func Supported() bool { return false }
