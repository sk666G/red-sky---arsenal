package rfgo

import (
	"context"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// BLE advertisement parsing. Advertisements are the passive BLE surface —
// every device that's on and advertising broadcasts its flags, its local
// name (sometimes), its service UUIDs, and often its manufacturer data.
// No connection required, no pairing, no auth.
//
// We capture advertisements via bluetoothctl's scan output, which prints
// them as lines of hex after "Advertisement data:". Parsing that gives us
// the AD structure:
//
//   AD element = length (1) | type (1) | data (length-1)
//
// Common AD types:
//   0x01  Flags
//   0x02  16-bit Service UUID (incomplete list)
//   0x03  16-bit Service UUID (complete list)
//   0x06  128-bit Service UUID (incomplete)
//   0x07  128-bit Service UUID (complete)
//   0x08  Shortened Local Name
//   0x09  Complete Local Name
//   0x0A  TX Power Level
//   0x16  Service Data — 16-bit UUID
//   0x19  Appearance
//   0xFF  Manufacturer Specific Data (first 2 bytes = company ID)

// BLEAdvertisement is one parsed advertisement.
type BLEAdvertisement struct {
	Address          string   `json:"address"`
	Name             string   `json:"name,omitempty"` // from local name AD
	Flags            uint8    `json:"flags,omitempty"`
	TxPower          int8     `json:"tx_power,omitempty"`
	Appearance       uint16   `json:"appearance,omitempty"`
	ServiceUUIDs16   []string `json:"service_uuids_16,omitempty"`
	ServiceUUIDs128  []string `json:"service_uuids_128,omitempty"`
	ManufacturerID   uint16   `json:"manufacturer_id,omitempty"` // BLE SIG company id
	ManufacturerName string   `json:"manufacturer_name,omitempty"`
	ManufacturerData []byte   `json:"manufacturer_data,omitempty"`
	RSSI             int      `json:"rssi,omitempty"`
	Raw              []byte   `json:"raw,omitempty"`
}

// BLEOptions controls an advertisement capture.
type BLEOptions struct {
	Duration time.Duration
	Timeout  time.Duration
}

func bleDefault(opts BLEOptions) BLEOptions {
	if opts.Duration == 0 {
		opts.Duration = 10 * time.Second
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return opts
}

// advLineRe matches bluetoothctl's advertisement data lines.
// Example:
//
//	Advertisement data: 02 01 06 03 03 aa fe 17 16 aa fe 00 ff 4c 00 10 05 0a 01 18 00
var advLineRe = regexp.MustCompile(`Advertisement data:\s*([0-9a-fA-F ]+)`)

// rssiLineRe matches the RSSI printed by bluetoothctl.
var rssiLineRe = regexp.MustCompile(`RSSI:\s*(-?\d+)`)

// CaptureAdvertisements runs a scan and returns every parsed BLE
// advertisement. Devices that appear multiple times are deduped by MAC.
func CaptureAdvertisements(ctx context.Context, opts BLEOptions) ([]BLEAdvertisement, error) {
	opts = bleDefault(opts)
	if err := checkBlueZ(); err != nil {
		return nil, err
	}
	go func() {
		_ = exec.Command("bluetoothctl", "scan", "on").Start()
	}()
	time.Sleep(opts.Duration)
	out, err := runBluetoothctl(ctx, []string{"scan", "off"}, opts.Timeout)
	if err != nil {
		return nil, err
	}
	return parseAdvertisementOutput(out), nil
}

// parseAdvertisementOutput walks the bluetoothctl output. Between each
// "Device XX:XX..." line and the next, we look for Advertisement data
// lines and RSSI lines, and build a BLEAdvertisement per device.
func parseAdvertisementOutput(out string) []BLEAdvertisement {
	var ads []BLEAdvertisement
	seen := map[string]bool{}

	var curAddr string
	var curRSSI int
	var curAdvData []byte

	flush := func() {
		if curAddr == "" {
			return
		}
		// if we saw advertising data, parse the AD structure
		if len(curAdvData) > 0 {
			ad := parseADStructure(curAdvData)
			ad.Address = curAddr
			ad.RSSI = curRSSI
			ad.Raw = append([]byte(nil), curAdvData...)
			if !seen[curAddr] {
				seen[curAddr] = true
				ads = append(ads, ad)
			}
		}
		curAddr = ""
		curRSSI = 0
		curAdvData = nil
	}

	sc := newScannerLines(out)
	for _, line := range sc {
		// check for device marker
		if m := deviceRe.FindStringSubmatch(line); len(m) > 1 {
			flush()
			curAddr = strings.ToLower(m[1])
			continue
		}
		// advertisement data
		if m := advLineRe.FindStringSubmatch(line); len(m) > 1 {
			curAdvData = hexToBytesSimple(m[1])
			continue
		}
		// RSSI
		if m := rssiLineRe.FindStringSubmatch(line); len(m) > 1 {
			curRSSI = atoiSafe(m[1])
			continue
		}
	}
	flush()
	return ads
}

// newScannerLines splits a blob on newlines. Simple helper.
func newScannerLines(s string) []string {
	return strings.Split(s, "\n")
}

// hexToBytesSimple is a lenient hex parser (space-separated or packed).
func hexToBytesSimple(s string) []byte {
	s = strings.ReplaceAll(s, " ", "")
	s = strings.ReplaceAll(s, ":", "")
	if len(s)%2 != 0 {
		return nil
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi := hexNibble(s[i*2])
		lo := hexNibble(s[i*2+1])
		if hi < 0 || lo < 0 {
			return nil
		}
		out[i] = byte(hi<<4 | lo)
	}
	return out
}

// parseADStructure walks the length-type-value AD structure.
func parseADStructure(b []byte) BLEAdvertisement {
	var ad BLEAdvertisement
	i := 0
	for i < len(b) {
		length := int(b[i])
		if length == 0 || i+1+length > len(b) {
			break
		}
		adType := b[i+1]
		data := b[i+2 : i+1+length]
		i += 1 + length

		switch adType {
		case 0x01: // Flags
			if len(data) >= 1 {
				ad.Flags = data[0]
			}
		case 0x02, 0x03: // 16-bit Service UUID
			for j := 0; j+1 < len(data); j += 2 {
				u := uint16(data[j]) | uint16(data[j+1])<<8
				ad.ServiceUUIDs16 = append(ad.ServiceUUIDs16, uuid16ToString(u))
			}
		case 0x06, 0x07: // 128-bit Service UUID
			for j := 0; j+15 < len(data); j += 16 {
				ad.ServiceUUIDs128 = append(ad.ServiceUUIDs128, formatUUID128(data[j:j+16]))
			}
		case 0x08, 0x09: // Local Name
			ad.Name = string(data)
		case 0x0A: // TX Power
			if len(data) >= 1 {
				ad.TxPower = int8(data[0])
			}
		case 0x19: // Appearance
			if len(data) >= 2 {
				ad.Appearance = uint16(data[0]) | uint16(data[1])<<8
			}
		case 0xFF: // Manufacturer Specific Data
			if len(data) >= 2 {
				ad.ManufacturerID = uint16(data[0]) | uint16(data[1])<<8
				ad.ManufacturerName = CompanyName(ad.ManufacturerID)
				ad.ManufacturerData = append([]byte(nil), data[2:]...)
			}
		}
	}
	return ad
}

// uuid16ToString renders a 16-bit UUID as a full BLE SIG UUID string.
func uuid16ToString(u uint16) string {
	const base = "00000000-0000-1000-8000-00805f9b34fb"
	// splice the four hex chars at positions 4..8
	hex := []byte{
		"0123456789abcdef"[(u>>12)&0xF],
		"0123456789abcdef"[(u>>8)&0xF],
		"0123456789abcdef"[(u>>4)&0xF],
		"0123456789abcdef"[u&0xF],
	}
	out := []byte(base)
	copy(out[4:8], hex)
	return string(out)
}

// formatUUID128 renders a 16-byte UUID (little-endian AD format) as a
// standard string.
func formatUUID128(b []byte) string {
	// AD encodes 128-bit UUIDs little-endian
	reversed := make([]byte, 16)
	for i := 0; i < 16; i++ {
		reversed[15-i] = b[i]
	}
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 36)
	pos := 0
	for i := 0; i < 16; i++ {
		if i == 4 || i == 6 || i == 8 || i == 10 {
			out[pos] = '-'
			pos++
		}
		out[pos] = hexdigits[reversed[i]>>4]
		out[pos+1] = hexdigits[reversed[i]&0xF]
		pos += 2
	}
	return string(out)
}

// CompanyName returns the BLE SIG assigned company name for a manufacturer
// ID, or "" if unknown. Small curated subset.
func CompanyName(id uint16) string {
	m := map[uint16]string{
		0x004C: "Apple",
		0x0006: "Microsoft",
		0x00E0: "Google",
		0x0075: "Samsung",
		0x000F: "Broadcom",
		0x0001: "Nokia",
		0x0002: "Intel",
		0x000D: "Texas Instruments",
		0x0059: "Nordic Semiconductor",
		0x02E5: "Espressif",
		0x038F: "Xiaomi",
		0x0087: "Garmin",
		0x0157: "Amazon",
		0x0499: "Ruuvi",
		0x0822: "Adafruit",
		0x02FF: "Anker",
		0x027D: "Huawei",
		0x0224: "Sonos",
		0x0171: "Tile",
	}
	return m[id]
}
