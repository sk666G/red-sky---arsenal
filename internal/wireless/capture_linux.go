//go:build linux

// Package wireless implements 802.11 frame capture on Linux via AF_PACKET
// on a monitor-mode interface. Needs CAP_NET_RAW and a wifi adapter that
// supports monitor mode.
package wireless

import (
	"context"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Frame is one captured 802.11 frame.
type Frame struct {
	TS   time.Time
	Data []byte
}

// Options controls a wireless capture.
type Options struct {
	Iface   string
	Channel int
	Timeout time.Duration
}

// Capture enables monitor mode if needed, sets the channel if given, and
// streams 802.11 frames to onFrame until ctx is done or Timeout elapses.
func Capture(ctx context.Context, opts Options, onFrame func(Frame)) error {
	if opts.Iface == "" {
		return fmt.Errorf("wireless: iface required")
	}

	if !isMonitorMode(opts.Iface) {
		if err := enableMonitor(opts.Iface); err != nil {
			return fmt.Errorf("wireless: enable monitor: %w", err)
		}
	}

	if opts.Channel > 0 {
		_ = exec.Command("iw", "dev", opts.Iface, "set", "channel",
			fmt.Sprintf("%d", opts.Channel)).Run()
	}

	ifi, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("wireless: iface lookup: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("wireless: socket: %w", err)
	}
	defer syscall.Close(fd)

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		return fmt.Errorf("wireless: bind: %w", err)
	}

	stop := make(chan struct{})
	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			close(stop)
			syscall.Shutdown(fd, syscall.SHUT_RD)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
			return
		}
		shutdown()
	}()
	if opts.Timeout > 0 {
		go func() {
			select {
			case <-time.After(opts.Timeout):
				shutdown()
			case <-stop:
			}
		}()
	}

	buf := make([]byte, 65536)
	start := time.Now()
	for {
		select {
		case <-stop:
			return nil
		default:
		}
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EBADF || err == syscall.EINVAL || err == syscall.ENOTCONN {
				return nil
			}
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("wireless: recvfrom: %w", err)
		}
		if n == 0 {
			continue
		}
		onFrame(Frame{TS: time.Now(), Data: append([]byte(nil), buf[:n]...)})
		if opts.Timeout > 0 && time.Since(start) > opts.Timeout {
			return nil
		}
	}
}

func isMonitorMode(iface string) bool {
	out, err := exec.Command("iw", "dev", iface, "info").Output()
	if err != nil {
		return false
	}
	return strings.Contains(string(out), "type monitor")
}

func enableMonitor(iface string) error {
	if err := exec.Command("ip", "link", "set", iface, "down").Run(); err != nil {
		return err
	}
	if err := exec.Command("iw", "dev", iface, "set", "type", "monitor").Run(); err != nil {
		_ = exec.Command("ip", "link", "set", iface, "up").Run()
		return err
	}
	return exec.Command("ip", "link", "set", iface, "up").Run()
}

func htons(v uint16) uint16 {
	return (v<<8)&0xFF00 | (v>>8)&0x00FF
}

// Supported reports whether this platform can do wireless capture.
func Supported() bool { return true }
