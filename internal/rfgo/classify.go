package rfgo

import (
	"fmt"
	"strings"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// ClassifiedBluetoothVuln is a heuristic finding derived from a
// Bluetooth module response. BluetoothData carries no Action field —
// the action lives on BluetoothStart. So the classifier infers what
// happened from which fields are populated.
//
// Inferred shapes:
//   - Notifies non-empty      → live notification stream captured, info
//   - GATTHex non-empty       → GATT read returned data, medium
//   - Chars non-empty with writable flag → GATT attack surface, medium
//   - Chars non-empty, no writable       → GATT enumeration, skip
//   - Services non-empty (no Chars)      → service discovery, skip
//   - AdvName / MfgHex non-empty         → BLE advertisement, skip
//   - Address + Name + RSSI only         → scan result, skip
//   - Paired / Trusted device            → info (already-trusted device)
type ClassifiedBluetoothVuln struct {
	Name     string
	Severity string
	Evidence string
}

// ClassifyBluetooth turns a Bluetooth module response into a classified
// vuln. Pure function — no side effects, no DB, no logging. The sink
// owns the write.
func ClassifyBluetooth(d proto.BluetoothData) []ClassifiedBluetoothVuln {
	if d.Done || d.Error != "" {
		return nil
	}

	addr := d.Address
	if addr == "" {
		addr = "unknown"
	}

	// Live notification stream — data flowing from a remote device
	// right now. Observation, not attack, but worth an info row.
	if len(d.Notifies) > 0 {
		preview := d.Notifies[0]
		if len(preview) > 64 {
			preview = preview[:64] + "…"
		}
		return []ClassifiedBluetoothVuln{{
			Name:     "Bluetooth notification stream captured",
			Severity: "info",
			Evidence: fmt.Sprintf("%s %d notification(s) first=%q", addr, len(d.Notifies), preview),
		}}
	}

	// GATT read returned data — unencrypted characteristic.
	if d.GATTHex != "" {
		preview := d.GATTHex
		if len(preview) > 64 {
			preview = preview[:64] + "…"
		}
		return []ClassifiedBluetoothVuln{{
			Name:     "Bluetooth GATT read returned data — unencrypted characteristic",
			Severity: "medium",
			Evidence: fmt.Sprintf("%s hex=%s", addr, preview),
		}}
	}

	// GATT enumeration — count writable characteristics from the
	// formatted Chars strings: "service_uuid|handle|uuid|flags".
	if len(d.Chars) > 0 {
		writable := 0
		var writableUUIDs []string
		for _, c := range d.Chars {
			parts := strings.Split(c, "|")
			if len(parts) < 4 {
				continue
			}
			uuid := parts[2]
			flags := strings.ToLower(parts[3])
			if strings.Contains(flags, "write") {
				writable++
				writableUUIDs = append(writableUUIDs, uuid)
			}
		}
		if writable > 0 {
			preview := strings.Join(writableUUIDs, ",")
			if len(preview) > 120 {
				preview = preview[:120] + "…"
			}
			return []ClassifiedBluetoothVuln{{
				Name:     fmt.Sprintf("Bluetooth GATT exposes %d writable characteristic(s)", writable),
				Severity: "medium",
				Evidence: fmt.Sprintf("%s writable=[%s]", addr, preview),
			}}
		}
	}

	return nil
}
