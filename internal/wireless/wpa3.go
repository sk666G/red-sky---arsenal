//go:build linux

// Package wireless — WPA3 observation and transition-mode abuse.
//
// Two things live here:
//
//   1. SAE frame observation.
//      WPA3 replaces the 4-way handshake PSK with SAE (Simultaneous
//      Authentication of Equals), an auth frame subtype 0xB carrying
//      authentication algorithm 3. SAE commit and confirm frames are
//      observable on the air and reveal which clients in range support
//      WPA3, plus per-client capability sets. No PMKID escapes from a
//      pure SAE handshake — the key is never pre-derived — so this is
//      mostly inventory, not crack material.
//
//   2. Transition-mode downgrade detection.
//      An AP that advertises WPA3 but also accepts WPA2 (transition mode,
//      RSN IE shows AKM suites 2 and 8) can be forced into a WPA2
//      handshake with a targeted disassoc during the SAE exchange. Once
//      the client falls back to WPA2 the standard pmkid.go path (34b)
//      applies. We detect the transition-mode flag and emit a hint so the
//      operator can chain deauth + pmkid.
//
// This file is observation + detection. The disassoc itself is 34a.
package wireless

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"syscall"
	"time"
)

// SAEHit is an observed SAE authentication frame.
type SAEHit struct {
	TS      time.Time
	BSSID   net.HardwareAddr
	Station net.HardwareAddr
	// Status: 0 = commit, 1 = confirm (from the sequence/status field).
	// We use the auth transaction sequence number at bytes 2-3 of the
	// auth frame body: 1 = commit, 2 = confirm.
	Seq     uint16
	GroupID uint16 // SAE group id from the commit frame (19 = NIST P-256)
}

// TransitionHit marks an AP advertising both WPA2 and WPA3 (downgrade
// candidate). Emitted once per BSSID per run.
type TransitionHit struct {
	TS    time.Time
	BSSID net.HardwareAddr
	SSID  string
}

// WPA3Options controls a WPA3 observation run.
type WPA3Options struct {
	Iface    string        // monitor-mode iface
	Channel  int           // set before capture if > 0
	Duration time.Duration // total run; 0 = until ctx done
}

// WPA3 observes SAE and beacon frames. onSAE fires for every SAE auth
// frame; onTransition fires once per BSSID seen advertising mixed WPA2+WPA3.
func WPA3(ctx context.Context, opts WPA3Options, onSAE func(SAEHit), onTransition func(TransitionHit)) error {
	if opts.Iface == "" {
		return fmt.Errorf("wpa3: iface required")
	}
	if !isMonitorMode(opts.Iface) {
		if err := enableMonitor(opts.Iface); err != nil {
			return fmt.Errorf("wpa3: enable monitor: %w", err)
		}
	}
	if opts.Channel > 0 {
		setChannel(opts.Iface, opts.Channel)
	}

	ifi, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("wpa3: iface lookup: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("wpa3: socket: %w", err)
	}
	defer syscall.Close(fd)

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		return fmt.Errorf("wpa3: bind: %w", err)
	}

	stop := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			syscall.Shutdown(fd, syscall.SHUT_RD)
		case <-stop:
		}
	}()
	if opts.Duration > 0 {
		go func() {
			select {
			case <-time.After(opts.Duration):
				syscall.Shutdown(fd, syscall.SHUT_RD)
			case <-stop:
			}
		}()
	}
	defer close(stop)

	seenTransition := make(map[string]bool)
	buf := make([]byte, 65536)
	for {
		n, _, err := syscall.Recvfrom(fd, buf, 0)
		if err != nil {
			if err == syscall.EBADF || err == syscall.EINVAL || err == syscall.ENOTCONN {
				return nil
			}
			if err == syscall.EINTR {
				continue
			}
			return fmt.Errorf("wpa3: recvfrom: %w", err)
		}
		if n < 24 {
			continue
		}
		rtLen := int(binary.LittleEndian.Uint16(buf[2:4]))
		if rtLen < 8 || rtLen > n-24 {
			continue
		}
		frame := buf[rtLen:n]
		if len(frame) < 24 {
			continue
		}
		fc := frame[0]
		stype := fc & 0x0C
		subtype := (fc >> 4) & 0x0F

		// SAE auth frame: mgmt (0x00), subtype 0xB
		if stype == 0x00 && subtype == 0x0B && len(frame) >= 24+6 {
			hit, ok := parseSAE(frame)
			if ok && onSAE != nil {
				onSAE(hit)
			}
			continue
		}

		// beacon: mgmt, subtype 0x08
		if stype == 0x00 && subtype == 0x08 && len(frame) >= 24+12 {
			bssid := append(net.HardwareAddr(nil), frame[16:22]...)
			key := bssid.String()
			if seenTransition[key] {
				continue
			}
			ssid, mixed, ok := parseBeaconRSN(frame)
			if !ok || !mixed {
				continue
			}
			seenTransition[key] = true
			if onTransition != nil {
				onTransition(TransitionHit{TS: time.Now(), BSSID: bssid, SSID: ssid})
			}
		}
	}
}

// parseSAE pulls BSSID, station, transaction sequence and group id out of
// an SAE auth frame.
//
// Layout after the 24-byte mgmt header (auth frame body):
//   algorithm (2) = 3 for SAE
//   transaction sequence (2) = 1 commit, 2 confirm
//   status code (2) = 0
//   for commit: group id (2), then scalar + element (opaque)
func parseSAE(frame []byte) (SAEHit, bool) {
	if len(frame) < 24+6 {
		return SAEHit{}, false
	}
	alg := binary.LittleEndian.Uint16(frame[24:26])
	if alg != 3 {
		return SAEHit{}, false
	}
	seq := binary.LittleEndian.Uint16(frame[26:28])
	bssid := append(net.HardwareAddr(nil), frame[16:22]...)
	station := append(net.HardwareAddr(nil), frame[10:16]...)

	var group uint16
	if seq == 1 && len(frame) >= 24+8 {
		group = binary.LittleEndian.Uint16(frame[30:32])
	}
	return SAEHit{
		TS:      time.Now(),
		BSSID:   bssid,
		Station: station,
		Seq:     seq,
		GroupID: group,
	}, true
}

// parseBeaconRSN scans a beacon frame's IEs for the RSN information
// element and decides whether the AP advertises mixed WPA2+WPA3.
//
// RSN IE layout (after tag+len):
//   version (2)
//   group cipher (4)
//   pairwise count (2) + pairwise suites (4 each)
//   AKM count (2) + AKM suites (4 each) — this is where we look
//   ...
//
// AKM suite 00:0F:AC:02 = PSK (WPA2)
// AKM suite 00:0F:AC:08 = SAE (WPA3)
// A beacon advertising both is transition mode.
func parseBeaconRSN(frame []byte) (string, bool, bool) {
	// fixed fields: 12 bytes after 24-byte hdr
	if len(frame) < 24+12 {
		return "", false, false
	}
	ies := frame[24+12:]
	ssid := ""
	mixed := false
	i := 0
	for i+2 <= len(ies) {
		tag := ies[i]
		length := int(ies[i+1])
		if i+2+length > len(ies) {
			break
		}
		body := ies[i+2 : i+2+length]
		if tag == 0x00 {
			ssid = string(body)
		}
		if tag == 0x30 { // RSN IE
			if hasMixedAKM(body) {
				mixed = true
			}
		}
		i += 2 + length
	}
	return ssid, mixed, true
}

// hasMixedAKM walks the RSN IE body and returns true if both PSK (2) and
// SAE (8) AKM suites are present.
func hasMixedAKM(rsn []byte) bool {
	if len(rsn) < 2+4 {
		return false
	}
	i := 2            // skip version
	i += 4            // skip group cipher
	if i+2 > len(rsn) {
		return false
	}
	pwCount := int(binary.LittleEndian.Uint16(rsn[i : i+2]))
	i += 2
	i += pwCount * 4
	if i+2 > len(rsn) {
		return false
	}
	akmCount := int(binary.LittleEndian.Uint16(rsn[i : i+2]))
	i += 2
	hasPSK := false
	hasSAE := false
	for k := 0; k < akmCount; k++ {
		if i+4 > len(rsn) {
			break
		}
		// AKM suite is OUI(3) + type(1); PSK type=2, SAE type=8
		if rsn[i] == 0x00 && rsn[i+1] == 0x0F && rsn[i+2] == 0xAC {
			switch rsn[i+3] {
			case 0x02:
				hasPSK = true
			case 0x08:
				hasSAE = true
			}
		}
		i += 4
	}
	return hasPSK && hasSAE
}
