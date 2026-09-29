//go:build linux

// Package capturer implements raw Ethernet frame capture on Linux via the
// AF_PACKET socket family. No libpcap dependency. Requires CAP_NET_RAW on
// the agent (root, or the cap set on the binary).
package capturer

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"sync"
	"syscall"
	"time"
	"unsafe"
)

// Frame is one captured Ethernet frame with a timestamp.
type Frame struct {
	TS      time.Time
	Data    []byte // full L2 frame (Ethernet header included)
	OrigLen int    // original length on the wire before snaplen truncation
}

// Options controls a capture session.
type Options struct {
	Iface   string        // interface name; empty = pick the first non-loopback
	Snaplen int           // bytes to capture per frame; 0 = full frame (max 65536)
	Timeout time.Duration // total capture duration; 0 = run until ctx cancelled
}

// Capture opens the raw socket on iface, delivers frames to onFrame, and
// blocks until ctx is cancelled or the timeout elapses.
func Capture(ctx context.Context, opts Options, onFrame func(Frame)) error {
	iface := opts.Iface
	if iface == "" {
		iface = pickDefaultIface()
		if iface == "" {
			return fmt.Errorf("no suitable interface found")
		}
	}
	ifi, err := net.InterfaceByName(iface)
	if err != nil {
		return fmt.Errorf("interface %s: %w", iface, err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(syscall.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("socket(AF_PACKET): %w (need CAP_NET_RAW)", err)
	}
	defer syscall.Close(fd)

	// bind to the specific interface index
	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(syscall.ETH_P_ALL),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		return fmt.Errorf("bind: %w", err)
	}

	snaplen := opts.Snaplen
	if snaplen <= 0 || snaplen > 65536 {
		snaplen = 65536
	}

	// read loop with a deadline so we can honor ctx cancels
	buf := make([]byte, snaplen)
	var total int
	start := time.Now()

	// watcher goroutine for ctx / timeout
	stop := make(chan struct{})
	var stopOnce sync.Once
	cancelRead := func() {
		stopOnce.Do(func() {
			close(stop)
			// force the blocked Read to return
			syscall.Shutdown(fd, syscall.SHUT_RD)
		})
	}
	go func() {
		select {
		case <-ctx.Done():
		case <-stop:
			return
		}
		cancelRead()
	}()
	if opts.Timeout > 0 {
		go func() {
			select {
			case <-time.After(opts.Timeout):
				cancelRead()
			case <-stop:
			}
		}()
	}

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
			return fmt.Errorf("recvfrom: %w", err)
		}
		if n == 0 {
			continue
		}
		frame := Frame{
			TS:      time.Now(),
			Data:    append([]byte(nil), buf[:n]...),
			OrigLen: n,
		}
		total++
		onFrame(frame)
		if opts.Timeout > 0 && time.Since(start) > opts.Timeout {
			return nil
		}
	}
}

func pickDefaultIface() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return ""
	}
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		if i.Flags&net.FlagUp == 0 {
			continue
		}
		// prefer eth*/en* names
		name := i.Name
		if len(name) > 2 && (name[:2] == "en" || name[:2] == "et" || name[:2] == "wl" || name[:2] == "wa") {
			return name
		}
	}
	// fallback to first non-loopback up
	for _, i := range ifaces {
		if i.Flags&net.FlagLoopback == 0 && i.Flags&net.FlagUp != 0 {
			return i.Name
		}
	}
	return ""
}

// htons converts a uint16 from host to network byte order.
func htons(v uint16) uint16 {
	var b [2]byte
	binary.BigEndian.PutUint16(b[:], v)
	return *(*uint16)(unsafe.Pointer(&b[0]))
}

// Supported returns true if raw capture is available on this platform.
func Supported() bool { return os.Geteuid() == 0 || hasCapNetRaw() }

// hasCapNetRaw checks the effective capability set for CAP_NET_RAW (bit 13).
func hasCapNetRaw() bool {
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return false
	}
	for _, line := range splitLines(data) {
		if len(line) > 8 && line[:8] == "CapEff:\t" {
			// crude parse; assume hex
			var cap uint64
			if _, err := fmt.Sscanf(line[8:], "%x", &cap); err == nil {
				return cap&(1<<13) != 0
			}
		}
	}
	return false
}

func splitLines(b []byte) []string {
	var out []string
	start := 0
	for i, c := range b {
		if c == '\n' {
			out = append(out, string(b[start:i]))
			start = i + 1
		}
	}
	if start < len(b) {
		out = append(out, string(b[start:]))
	}
	return out
}
