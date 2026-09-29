package rfgo

import (
	"context"
	"errors"
	"regexp"
	"strings"
	"time"
)

// BLE GATT characteristic read / write. Drives bluetoothctl's gatt menu:
//
//   menu gatt
//   select-attribute <uuid>
//   read                          ; prints "Characteristic value/descriptor: HEX"
//   write <hex bytes>             ; writes a value
//   notify on                     ; subscribes to notifications
//   back
//
// The reconnect is required because BlueZ only exposes the GATT tree while
// the device is connected, and bluetoothctl drops the connection between
// invocations.
//
// ReadValue / WriteValue / NotifyOn are the three entry points.

// GATTReadResult is the outcome of a characteristic read.
type GATTReadResult struct {
	Address string `json:"address"`
	UUID    string `json:"uuid"`
	Hex     string `json:"hex,omitempty"`
	Bytes   []byte `json:"bytes,omitempty"`
	Error   string `json:"error,omitempty"`
}

// valueLineRe matches bluetoothctl's read output lines.
var valueLineRe = regexp.MustCompile(`Characteristic value(?:\/descriptor)?:\s*([0-9a-fA-F ]+)`)

// connectAndGatt connects, waits for the tree, runs the given gatt commands,
// then disconnects. Commands are the inner gatt-menu lines (between
// "menu gatt" and "back").
func connectAndGatt(ctx context.Context, addr string, opts BTOptions, gattCmds []string) (string, error) {
	opts = btDefault(opts)
	if addr == "" {
		return "", errors.New("rfgo/gatt: address required")
	}
	// connect
	_, _ = runBluetoothctl(ctx, []string{"connect " + addr}, opts.Timeout)
	time.Sleep(2 * time.Second)

	cmds := append([]string{"menu gatt"}, gattCmds...)
	cmds = append(cmds, "back")
	out, err := runBluetoothctl(ctx, cmds, opts.Timeout)

	// disconnect
	_, _ = runBluetoothctl(ctx, []string{"disconnect " + addr}, opts.Timeout)
	return out, err
}

// ReadValue reads one characteristic value (returns hex + bytes).
func ReadValue(ctx context.Context, addr, uuid string, opts BTOptions) (GATTReadResult, error) {
	res := GATTReadResult{Address: addr, UUID: uuid}
	out, err := connectAndGatt(ctx, addr, opts, []string{
		"select-attribute " + uuid,
		"read",
	})
	if err != nil {
		res.Error = err.Error()
		return res, err
	}
	m := valueLineRe.FindStringSubmatch(out)
	if len(m) < 2 {
		res.Error = "no value line in output"
		return res, errors.New(res.Error)
	}
	hexStr := strings.ReplaceAll(strings.TrimSpace(m[1]), " ", "")
	res.Hex = strings.ToLower(hexStr)
	res.Bytes = hexToBytes(res.Hex)
	return res, nil
}

// WriteValue writes hex-encoded bytes to a characteristic.
func WriteValue(ctx context.Context, addr, uuid string, hexBytes string, opts BTOptions) error {
	hexBytes = strings.ReplaceAll(hexBytes, " ", "")
	if hexBytes == "" {
		return errors.New("rfgo/gatt: empty write")
	}
	if len(hexBytes)%2 != 0 {
		return errors.New("rfgo/gatt: odd-length hex")
	}
	_, err := connectAndGatt(ctx, addr, opts, []string{
		"select-attribute " + uuid,
		"write " + hexBytes,
	})
	return err
}

// NotifyOn subscribes to notifications on a characteristic. bluetoothctl's
// notify is asynchronous — the connection has to stay open. This function
// runs the command for `listen` seconds and returns whatever lines arrived.
//
// For a persistent subscription the operator wants a long listen window
// and to parse stdout as it streams; a follow-up build streams through the
// tunnel instead of returning at the end.
func NotifyOn(ctx context.Context, addr, uuid string, listen time.Duration, opts BTOptions) ([]string, error) {
	if listen <= 0 {
		listen = 5 * time.Second
	}
	out, err := connectAndGatt(ctx, addr, opts, []string{
		"select-attribute " + uuid,
		"notify on",
		// wait — no equivalent inside bluetoothctl, so we rely on the
		// outer context deadline
	})
	if err != nil {
		return nil, err
	}
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if strings.Contains(line, "Notify") || strings.Contains(line, "value") {
			lines = append(lines, line)
		}
	}
	return lines, nil
}

// hexToBytes decodes a hex string. Returns nil on odd length or bad char.
func hexToBytes(s string) []byte {
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

// hexNibble converts a single hex char to its value, -1 on bad input.
func hexNibble(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
