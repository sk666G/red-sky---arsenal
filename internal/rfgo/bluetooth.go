// Package rfgo implements RF-protocol primitives on the agent — Bluetooth
// and (soon) 802.15.4 / LoRa. Kept separate from the `wireless` package
// (which is 802.11) because the tooling and the RF bands are different.
//
// Bluetooth via BlueZ over the `bluetoothctl` command-line tool. The
// alternative is the D-Bus API, which needs a dependency (muka/go-bluetooth
// or godbus/dbus). Wrapping the CLI keeps this package stdlib-only —
// `bluetoothctl` ships with every distro that has BlueZ.
package rfgo

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
)

// BTDevice describes one discovered device.
type BTDevice struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
	RSSI    int    `json:"rssi,omitempty"`
	Paired  bool   `json:"paired,omitempty"`
	Trusted bool   `json:"trusted,omitempty"`
}

// BTOptions controls a scan / interaction.
type BTOptions struct {
	Duration time.Duration // scan time; default 10s
	Timeout  time.Duration // per bluetoothctl invocation
}

func btDefault(opts BTOptions) BTOptions {
	if opts.Duration == 0 {
		opts.Duration = 10 * time.Second
	}
	if opts.Timeout == 0 {
		opts.Timeout = 30 * time.Second
	}
	return opts
}

// checkBlueZ returns an error if bluetoothctl is not on PATH.
func checkBlueZ() error {
	if _, err := exec.LookPath("bluetoothctl"); err != nil {
		return errors.New("rfgo/bluetooth: bluetoothctl not found (apt install bluez)")
	}
	return nil
}

// runBluetoothctl feeds commands to bluetoothctl on stdin and returns
// combined output. The final "quit" is appended automatically.
func runBluetoothctl(ctx context.Context, commands []string, timeout time.Duration) (string, error) {
	if err := checkBlueZ(); err != nil {
		return "", err
	}
	cmdCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// bluetoothctl accepts -- separator and reads commands from stdin
	cmd := exec.CommandContext(cmdCtx, "bluetoothctl", "--timeout", "30")
	full := append([]string{}, commands...)
	full = append(full, "quit")
	cmd.Stdin = strings.NewReader(strings.Join(full, "\n") + "\n")
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	// bluetoothctl returns non-zero on some scans even when it succeeded —
	// we return output regardless and only error on context cancellation.
	if err != nil && cmdCtx.Err() != nil {
		return buf.String(), cmdCtx.Err()
	}
	return buf.String(), nil
}

// deviceRe matches the "Device XX:XX:XX:XX:XX:XX Name" lines.
var deviceRe = regexp.MustCompile(`Device ([0-9A-Fa-f:]{17})(?:\s+(.*))?`)

// rssiRe matches "RSSI: -NN" lines that appear in info output.
var rssiRe = regexp.MustCompile(`RSSI:\s*(-?\d+)`)

// Scan runs `bluetoothctl scan on` for Duration, then `devices` to list
// what was seen. Returns every unique device.
func Scan(ctx context.Context, opts BTOptions) ([]BTDevice, error) {
	opts = btDefault(opts)

	// power on first
	_, _ = runBluetoothctl(ctx, []string{"power", "on"}, opts.Timeout)

	// start scan in a separate call, wait, then stop and list
	scanCtx, scanCancel := context.WithTimeout(ctx, opts.Duration+2*time.Second)
	defer scanCancel()
	_ = scanCtx

	// do it manually: send scan on, sleep, scan off, devices
	go func() {
		_ = exec.Command("bluetoothctl", "scan", "on").Start()
	}()
	time.Sleep(opts.Duration)
	out, err := runBluetoothctl(ctx, []string{"scan", "off", "devices"}, opts.Timeout)
	if err != nil {
		return nil, err
	}

	// parse
	seen := map[string]BTDevice{}
	for _, line := range strings.Split(out, "\n") {
		m := deviceRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		addr := strings.ToLower(m[1])
		d := BTDevice{Address: addr}
		if len(m) > 2 {
			d.Name = strings.TrimSpace(m[2])
		}
		seen[addr] = d
	}
	var devices []BTDevice
	for _, d := range seen {
		devices = append(devices, d)
	}
	return devices, nil
}

// Info runs `bluetoothctl info <addr>` for one device and parses the
// response, including RSSI if present.
func Info(ctx context.Context, addr string, opts BTOptions) (BTDevice, error) {
	opts = btDefault(opts)
	out, err := runBluetoothctl(ctx, []string{"info", addr}, opts.Timeout)
	if err != nil {
		return BTDevice{}, err
	}
	d := BTDevice{Address: addr}
	sc := bufio.NewScanner(strings.NewReader(out))
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case strings.HasPrefix(line, "Name:"):
			d.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
		case strings.HasPrefix(line, "Paired:"):
			d.Paired = strings.Contains(line, "yes")
		case strings.HasPrefix(line, "Trusted:"):
			d.Trusted = strings.Contains(line, "yes")
		case strings.HasPrefix(line, "RSSI:"):
			if m := rssiRe.FindStringSubmatch(line); len(m) > 1 {
				d.RSSI = atoiSafe(m[1])
			}
		}
	}
	return d, nil
}

// LowEnergy variants: send `menu gatt` to bluetoothctl, list services,
// and list characteristics. Full BLE support is a follow-up.

// LEScan starts a low-energy scan and lists devices. Returns whatever
// bluetoothctl's discovery output produced.
func LEScan(ctx context.Context, opts BTOptions) ([]BTDevice, error) {
	opts = btDefault(opts)
	go func() {
		_ = exec.Command("bluetoothctl", "scan", "on").Start()
	}()
	time.Sleep(opts.Duration)
	out, err := runBluetoothctl(ctx, []string{"scan", "off", "devices"}, opts.Timeout)
	if err != nil {
		return nil, err
	}
	seen := map[string]BTDevice{}
	for _, line := range strings.Split(out, "\n") {
		m := deviceRe.FindStringSubmatch(line)
		if len(m) < 2 {
			continue
		}
		addr := strings.ToLower(m[1])
		d := BTDevice{Address: addr}
		if len(m) > 2 {
			d.Name = strings.TrimSpace(m[2])
		}
		seen[addr] = d
	}
	var out2 []BTDevice
	for _, d := range seen {
		out2 = append(out2, d)
	}
	return out2, nil
}

// atoiSafe parses a possibly-signed integer, returning 0 on error.
func atoiSafe(s string) int {
	neg := false
	if strings.HasPrefix(s, "-") {
		neg = true
		s = s[1:]
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	if neg {
		n = -n
	}
	return n
}

// MustBluetoothctl is a thin diagnostic — returns an error if bluetoothctl
// is not reachable, otherwise nil. Useful as a first check.
func MustBluetoothctl() error {
	if err := checkBlueZ(); err != nil {
		return err
	}
	out, err := exec.Command("bluetoothctl", "--version").Output()
	if err != nil {
		return fmt.Errorf("rfgo/bluetooth: version: %w", err)
	}
	_ = out
	return nil
}
