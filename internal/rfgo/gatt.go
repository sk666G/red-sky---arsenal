package rfgo

import (
	"context"
	"regexp"
	"strings"
	"time"
)

// BLE GATT service / characteristic enumeration. Drives bluetoothctl's
// `menu gatt` sub-shell to list services and their characteristics.
//
// bluetoothctl's GATT menu is driven by sending commands in sequence:
//   menu gatt
//   list-attributes <device MAC>
//   (prints primary services and their characteristics)
//   back
//   quit
//
// Output format (BlueZ 5.x):
//   Primary Service (Handle 0x0001)
//     UUID: 00001800-0000-1000-8000-00805f9b34fb
//     Vendor: Bluetooth SIG
//     (various other fields)
//   Characteristic (Handle 0x0002)
//     UUID: 00002a00-0000-1000-8000-00805f9b34fb
//     ...
//
// GATTEnum returns the services with their characteristics attached.

// GATTService is one primary service with its characteristics.
type GATTService struct {
	Handle          string           `json:"handle,omitempty"`
	UUID            string           `json:"uuid"`
	Vendor          string           `json:"vendor,omitempty"`
	Characteristics []GATTCharacteristic `json:"characteristics,omitempty"`
}

// GATTCharacteristic is one characteristic on a service.
type GATTCharacteristic struct {
	Handle      string   `json:"handle,omitempty"`
	UUID        string   `json:"uuid"`
	Flags       []string `json:"flags,omitempty"`
	Descriptors []string `json:"descriptors,omitempty"`
}

// GATTEnumResult is the full enumeration of one device.
type GATTEnumResult struct {
	Address  string        `json:"address"`
	Services []GATTService `json:"services"`
}

// uuidRe matches a 128-bit UUID line.
var uuidRe = regexp.MustCompile(`[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`)

// handleRe matches "(Handle 0xNNNN)".
var handleRe = regexp.MustCompile(`\(Handle\s+0x([0-9a-fA-F]+)\)`)

// GATTEnum connects to the device, waits for services to resolve, then
// drives bluetoothctl's gatt menu to list attributes.
//
// The connect step is necessary — BlueZ will only resolve the GATT tree
// for a device while it is currently connected.
func GATTEnum(ctx context.Context, addr string, opts BTOptions) (GATTEnumResult, error) {
	opts = btDefault(opts)
	out := GATTEnumResult{Address: addr}

	// 1. connect (bluetoothctl treats "connect" as blocking until the
	//    service resolution completes or times out — we use a short run)
	_, _ = runBluetoothctl(ctx, []string{
		"connect " + addr,
	}, opts.Timeout)

	// small settle window for BlueZ to publish its services
	time.Sleep(2 * time.Second)

	// 2. list attributes
	raw, err := runBluetoothctl(ctx, []string{
		"menu gatt",
		"list-attributes " + addr,
		"back",
	}, opts.Timeout)
	if err != nil {
		return out, err
	}

	out.Services = parseGATTAttributes(raw)

	// 3. disconnect (be polite — many devices only serve one central)
	_, _ = runBluetoothctl(ctx, []string{"disconnect " + addr}, opts.Timeout)

	return out, nil
}

// parseGATTAttributes walks the bluetoothctl output and builds the service
// tree. The parser keys off the "Primary Service" and "Characteristic"
// markers and the indentation of the fields underneath.
func parseGATTAttributes(raw string) []GATTService {
	var services []GATTService
	var cur *GATTService
	var curChar *GATTCharacteristic
	flushService := func() {
		if cur != nil {
			services = append(services, *cur)
			cur = nil
			curChar = nil
		}
	}
	flushChar := func() {
		if cur != nil && curChar != nil {
			cur.Characteristics = append(cur.Characteristics, *curChar)
			curChar = nil
		}
	}

	for _, line := range strings.Split(raw, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		// service marker
		if strings.HasPrefix(trimmed, "Primary Service") {
			flushChar()
			flushService()
			cur = &GATTService{}
			if m := handleRe.FindStringSubmatch(trimmed); len(m) > 1 {
				cur.Handle = "0x" + m[1]
			}
			continue
		}

		// characteristic marker
		if strings.HasPrefix(trimmed, "Characteristic") {
			flushChar()
			if cur == nil {
				continue
			}
			curChar = &GATTCharacteristic{}
			if m := handleRe.FindStringSubmatch(trimmed); len(m) > 1 {
				curChar.Handle = "0x" + m[1]
			}
			continue
		}

		// descriptor marker (inside a characteristic)
		if strings.HasPrefix(trimmed, "Descriptor") {
			if curChar != nil {
				curChar.Descriptors = append(curChar.Descriptors, trimmed)
			}
			continue
		}

		// field lines
		if strings.HasPrefix(trimmed, "UUID:") {
			u := strings.TrimSpace(strings.TrimPrefix(trimmed, "UUID:"))
			if m := uuidRe.FindString(u); m != "" {
				u = strings.ToLower(m)
			}
			if curChar != nil {
				curChar.UUID = u
			} else if cur != nil {
				cur.UUID = u
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Vendor:") {
			v := strings.TrimSpace(strings.TrimPrefix(trimmed, "Vendor:"))
			if cur != nil && curChar == nil {
				cur.Vendor = v
			}
			continue
		}
		if strings.HasPrefix(trimmed, "Flags:") {
			f := strings.TrimSpace(strings.TrimPrefix(trimmed, "Flags:"))
			if curChar != nil {
				curChar.Flags = strings.Split(f, ",")
				for i := range curChar.Flags {
					curChar.Flags[i] = strings.TrimSpace(curChar.Flags[i])
				}
			}
			continue
		}
	}
	flushChar()
	flushService()

	return services
}

// KnownUUIDs maps the well-known GATT UUIDs to their human names. Only the
// most common ones — full coverage is the Bluetooth SIG assigned numbers.
var KnownUUIDs = map[string]string{
	"00001800-0000-1000-8000-00805f9b34fb": "Generic Access",
	"00001801-0000-1000-8000-00805f9b34fb": "Generic Attribute",
	"00001802-0000-1000-8000-00805f9b34fb": "Immediate Alert",
	"00001803-0000-1000-8000-00805f9b34fb": "Link Loss",
	"00001804-0000-1000-8000-00805f9b34fb": "Tx Power",
	"0000180a-0000-1000-8000-00805f9b34fb": "Device Information",
	"0000180f-0000-1000-8000-00805f9b34fb": "Battery Service",
	"00001812-0000-1000-8000-00805f9b34fb": "Human Interface Device",
	"0000180d-0000-1000-8000-00805f9b34fb": "Heart Rate",
	"00001810-0000-1000-8000-00805f9b34fb": "Blood Pressure",
	"00001816-0000-1000-8000-00805f9b34fb": "Cycling Speed and Cadence",
	"0000181a-0000-1000-8000-00805f9b34fb": "Environmental Sensing",
	"00002a00-0000-1000-8000-00805f9b34fb": "Device Name",
	"00002a01-0000-1000-8000-00805f9b34fb": "Appearance",
	"00002a19-0000-1000-8000-00805f9b34fb": "Battery Level",
	"00002a24-0000-1000-8000-00805f9b34fb": "Model Number",
	"00002a25-0000-1000-8000-00805f9b34fb": "Serial Number",
	"00002a26-0000-1000-8000-00805f9b34fb": "Firmware Revision",
	"00002a27-0000-1000-8000-00805f9b34fb": "Hardware Revision",
	"00002a28-0000-1000-8000-00805f9b34fb": "Software Revision",
	"00002a29-0000-1000-8000-00805f9b34fb": "Manufacturer Name",
	"00002a37-0000-1000-8000-00805f9b34fb": "Heart Rate Measurement",
}

// DescribeUUID returns the friendly name for a well-known GATT UUID, or "".
func DescribeUUID(u string) string {
	return KnownUUIDs[strings.ToLower(u)]
}
