// Package recon2 implements small host-side reconnaissance primitives on
// the agent — the local-information gathering that runs before any network
// activity. Go analogue of Program/ipgrab/ and Program/geoip/.
package recon2

import (
	"encoding/json"
	"net"
	"os"
	"runtime"
	"sort"
	"strings"
)

// IfaceInfo describes one network interface.
type IfaceInfo struct {
	Name         string   `json:"name"`
	Index        int      `json:"index"`
	MTU          int      `json:"mtu"`
	HardwareAddr string   `json:"mac,omitempty"`
	Flags        []string `json:"flags"`
	Addrs        []string `json:"addrs"`
}

// HostInfo is the whole local picture.
type HostInfo struct {
	Hostname  string            `json:"hostname"`
	GOOS      string            `json:"goos"`
	GOARCH    string            `json:"goarch"`
	Interfaces []IfaceInfo      `json:"interfaces"`
	Gateway   string            `json:"gateway,omitempty"`
	DNSServers []string         `json:"dns_servers,omitempty"`
	Routes    []RouteEntry      `json:"routes,omitempty"`
}

// RouteEntry is one route from the local routing table.
type RouteEntry struct {
	Destination string `json:"destination"`
	Gateway     string `json:"gateway,omitempty"`
	Interface   string `json:"interface,omitempty"`
}

// Grab returns the local interface + address + route picture.
func Grab() (HostInfo, error) {
	var h HostInfo
	hostname, _ := os.Hostname()
	h.Hostname = hostname
	h.GOOS = runtime.GOOS
	h.GOARCH = runtime.GOARCH

	ifaces, err := net.Interfaces()
	if err != nil {
		return h, err
	}
	for _, ifc := range ifaces {
		info := IfaceInfo{
			Name:  ifc.Name,
			Index: ifc.Index,
			MTU:   ifc.MTU,
		}
		if len(ifc.HardwareAddr) > 0 {
			info.HardwareAddr = ifc.HardwareAddr.String()
		}
		for _, f := range []struct {
			flag net.Flags
			name string
		}{
			{net.FlagUp, "up"},
			{net.FlagBroadcast, "broadcast"},
			{net.FlagLoopback, "loopback"},
			{net.FlagMulticast, "multicast"},
			{net.FlagPointToPoint, "pointtopoint"},
		} {
			if ifc.Flags&f.flag != 0 {
				info.Flags = append(info.Flags, f.name)
			}
		}
		addrs, err := ifc.Addrs()
		if err == nil {
			for _, a := range addrs {
				info.Addrs = append(info.Addrs, a.String())
			}
		}
		h.Interfaces = append(h.Interfaces, info)
	}

	// DNS servers from the resolver config file
	h.DNSServers = readDNSServers()

	// Gateway via the routing table — best-effort, not always available
	h.Gateway = readDefaultGateway()

	return h, nil
}

// readDNSServers parses /etc/resolv.conf (linux / macos) or falls back to
// an empty list. On Windows the caller should use ipconfig instead.
func readDNSServers() []string {
	if runtime.GOOS == "windows" {
		return nil
	}
	b, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return nil
	}
	var out []string
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				out = append(out, parts[1])
			}
		}
	}
	return out
}

// readDefaultGateway parses /proc/net/route on Linux. Returns "" if the
// file is not readable or no default route is present.
func readDefaultGateway() string {
	if runtime.GOOS != "linux" {
		return ""
	}
	b, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	for i, line := range strings.Split(string(b), "\n") {
		if i == 0 {
			continue // header
		}
		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}
		// default route: destination = 00000000
		if fields[1] == "00000000" {
			// gateway is little-endian hex
			gw := fields[2]
			if len(gw) == 8 {
				b0, b1, b2, b3 := gw[6:8], gw[4:6], gw[2:4], gw[0:2]
				return parseHexPair(b0) + "." + parseHexPair(b1) + "." + parseHexPair(b2) + "." + parseHexPair(b3)
			}
		}
	}
	return ""
}

// parseHexPair converts a 2-char hex string to a decimal octet string.
func parseHexPair(s string) string {
	if len(s) != 2 {
		return "0"
	}
	var v int
	for _, c := range s {
		v *= 16
		switch {
		case c >= '0' && c <= '9':
			v += int(c - '0')
		case c >= 'a' && c <= 'f':
			v += int(c-'a') + 10
		case c >= 'A' && c <= 'F':
			v += int(c-'A') + 10
		}
	}
	return itoa(v)
}

// itoa is a tiny int-to-string to avoid pulling strconv.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// MarshalJSON is the canonical JSON encoder — kept here so callers that
// want a blob to ship have one form to use.
func (h HostInfo) MarshalJSONBlob() ([]byte, error) {
	// stable ordering for easy diffing
	sort.Slice(h.Interfaces, func(i, j int) bool {
		return h.Interfaces[i].Index < h.Interfaces[j].Index
	})
	sort.Strings(h.DNSServers)
	return json.MarshalIndent(h, "", "  ")
}
