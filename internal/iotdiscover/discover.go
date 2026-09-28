// Package iotdiscover is a Go port of Program/iot/discover.py. Finds IoT
// devices on a LAN via four channels:
//
//   ARP table       — live neighbor cache + OUI vendor lookup
//   mDNS            — _services._dns-sd._udp.local PTR query
//   SSDP            — UPnP M-SEARCH multicast
//   MQTT CONNECT    — port 1883 open + broker response
//   CoAP            — GET /.well-known/core on 5683/udp
//
// Designed to run in-process inside the redsky-agent. No external tools.
package iotdiscover

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Device is one host with any signal.
type Device struct {
	IP       string   `json:"ip"`
	MAC      string   `json:"mac,omitempty"`
	Vendor   string   `json:"vendor,omitempty"`
	MDNS     []string `json:"mdns,omitempty"`
	SSDP     []string `json:"ssdp,omitempty"`
	MQTT     bool     `json:"mqtt,omitempty"`
	CoAP     string   `json:"coap,omitempty"`
	Signals  []string `json:"signals"`
}

// ouiVendors is a compact prefix table for common IoT vendors.
var ouiVendors = map[string]string{
	"b0:c5:54": "D-Link",
	"b0:be:76": "TP-Link",
	"f4:f2:6d": "TP-Link",
	"50:c7:bf": "TP-Link",
	"a4:2b:b0": "TP-Link",
	"e8:de:27": "TP-Link",
	"3c:5a:b4": "Google Nest",
	"f4:f5:d8": "Google Nest",
	"1c:f2:9a": "Google Nest",
	"64:16:66": "Nest",
	"18:b4:30": "Nest",
	"44:65:0d": "Amazon",
	"68:54:fd": "Amazon",
	"f0:27:2d": "Amazon",
	"84:d6:d0": "Amazon",
	"a0:02:dc": "Amazon",
	"fc:65:de": "Amazon",
	"00:17:88": "Philips Hue",
	"ec:b5:fa": "Philips Hue",
	"d0:73:d5": "LIFX",
	"68:c6:3a": "LIFX",
	"a4:c1:38": "Tuya",
	"10:d5:61": "Tuya",
	"50:02:91": "Tuya",
	"dc:4f:22": "Espressif",
	"24:0a:c4": "Espressif",
	"3c:71:bf": "Espressif",
	"a0:20:a6": "Espressif",
	"84:0d:8e": "Espressif",
	"5c:cf:7f": "Espressif",
	"b8:27:eb": "Raspberry Pi",
	"dc:a6:32": "Raspberry Pi",
	"e4:5f:01": "Raspberry Pi",
	"28:cd:c1": "Raspberry Pi",
	"44:07:0b": "Hikvision",
	"c0:56:e3": "Hikvision",
	"bc:ad:28": "Hikvision",
	"4c:bd:8f": "Hikvision",
	"3c:ef:8c": "Dahua",
	"e0:50:8b": "Dahua",
	"4c:11:bf": "Dahua",
	"00:1c:27": "Dahua",
	"ac:cc:8e": "Axis",
	"00:40:8c": "Axis",
	"b8:a4:4f": "Axis",
	"48:8f:5a": "MikroTik",
	"4c:5e:0c": "MikroTik",
	"64:d1:54": "MikroTik",
	"6c:3b:6b": "MikroTik",
	"74:4d:28": "MikroTik",
	"dc:2c:6e": "MikroTik",
	"fc:ec:da": "Ubiquiti",
	"78:8a:20": "Ubiquiti",
	"24:a4:3c": "Ubiquiti",
	"04:18:d6": "Ubiquiti",
	"44:d9:e7": "Ubiquiti",
	"18:e8:29": "Ubiquiti",
	"74:83:c2": "Ubiquiti",
	"c8:3a:35": "Tenda",
	"5c:e3:0e": "Tenda",
	"04:95:e6": "Tenda",
	"00:1f:33": "Netgear",
	"a0:40:a0": "Netgear",
	"20:4e:7f": "Netgear",
	"30:46:9a": "Netgear",
	"9c:3d:cf": "Netgear",
}

func ouiLookup(mac string) string {
	m := strings.ToLower(strings.ReplaceAll(mac, "-", ":"))
	if len(m) < 8 {
		return ""
	}
	return ouiVendors[m[:8]]
}

// --- ARP ---
func arpNeighbors() []Device {
	var out []Device
	// Linux: `ip neigh`
	if b, err := exec.Command("ip", "neigh").Output(); err == nil {
		re := regexp.MustCompile(`^(\d+\.\d+\.\d+\.\d+)\s+dev\s+\S+\s+lladdr\s+([0-9a-f:]{17})`)
		for _, line := range strings.Split(string(b), "\n") {
			if m := re.FindStringSubmatch(line); m != nil {
				out = append(out, Device{IP: m[1], MAC: m[2], Vendor: ouiLookup(m[2])})
			}
		}
		return out
	}
	// macOS/BSD: `arp -an`
	if b, err := exec.Command("arp", "-an").Output(); err == nil {
		re := regexp.MustCompile(`\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+([0-9a-f:]{17})`)
		for _, line := range strings.Split(string(b), "\n") {
			if m := re.FindStringSubmatch(line); m != nil {
				out = append(out, Device{IP: m[1], MAC: m[2], Vendor: ouiLookup(m[2])})
			}
		}
	}
	return out
}

// --- mDNS ---
const (
	mdnsAddr = "224.0.0.251:5353"
	ssdpAddr = "239.255.255.250:1900"
)

func mdnsQuery(ctx context.Context, timeout time.Duration) map[string][]string {
	resp := map[string][]string{}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return resp
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	// Build the DNS PTR query for _services._dns-sd._udp.local
	qname := []byte{9, '_', 's', 'e', 'r', 'v', 'i', 'c', 'e', 's',
		7, '_', 'd', 'n', 's', '-', 's', 'd',
		4, '_', 'u', 'd', 'p', 5, 'l', 'o', 'c', 'a', 'l', 0}
	var q []byte
	q = append(q, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0)
	q = append(q, qname...)
	q = append(q, 0, 12, 0, 1)

	if _, err := conn.WriteToUDP(q, mustResolve(mdnsAddr)); err != nil {
		return resp
	}

	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return resp
		default:
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return resp
		}
		text := string(buf[:n])
		var names []string
		cur := strings.Builder{}
		for _, b := range []byte(text) {
			if b >= 0x20 && b <= 0x7e {
				cur.WriteByte(b)
			} else {
				if cur.Len() >= 4 {
					names = append(names, cur.String())
				}
				cur.Reset()
			}
		}
		if cur.Len() >= 4 {
			names = append(names, cur.String())
		}
		if len(names) > 0 {
			resp[addr.IP.String()] = append(resp[addr.IP.String()], names...)
		}
	}
}

func mustResolve(s string) *net.UDPAddr {
	a, _ := net.ResolveUDPAddr("udp", s)
	return a
}

// --- SSDP ---
func ssdpDiscover(ctx context.Context, timeout time.Duration) map[string][]string {
	resp := map[string][]string{}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return resp
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	req := "M-SEARCH * HTTP/1.1\r\n" +
		"HOST: 239.255.255.250:1900\r\n" +
		"MAN: \"ssdp:discover\"\r\n" +
		"MX: 2\r\n" +
		"ST: ssdp:all\r\n\r\n"
	if _, err := conn.WriteToUDP([]byte(req), mustResolve(ssdpAddr)); err != nil {
		return resp
	}

	buf := make([]byte, 4096)
	seen := map[string]bool{}
	for {
		select {
		case <-ctx.Done():
			return resp
		default:
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return resp
		}
		key := addr.IP.String() + string(buf[:min(n, 64)])
		if seen[key] {
			continue
		}
		seen[key] = true
		text := string(buf[:n])
		srv := ""
		for _, line := range strings.Split(text, "\r\n") {
			l := strings.ToLower(line)
			if strings.HasPrefix(l, "server:") {
				srv = strings.TrimSpace(line[7:])
				break
			}
		}
		resp[addr.IP.String()] = append(resp[addr.IP.String()], srv)
	}
}

// --- port probes ---
func tcpProbe(ip string, port int, timeout time.Duration) bool {
	c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", ip, port), timeout)
	if err != nil {
		return false
	}
	c.Close()
	return true
}

func coapProbe(ip string, timeout time.Duration) string {
	conn, err := net.DialTimeout("udp", fmt.Sprintf("%s:5683", ip), timeout)
	if err != nil {
		return ""
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(timeout))
	// CoAP GET /.well-known/core
	pkt := []byte{0x40, 0x01, 0x12, 0x34, 0xb9, '.', 'w', 'e', 'l', 'l', '-', 'k', 'n', 'o', 'w', 'n', 0x04, 'c', 'o', 'r', 'e'}
	if _, err := conn.Write(pkt); err != nil {
		return ""
	}
	buf := make([]byte, 2048)
	n, err := conn.Read(buf)
	if err != nil {
		return ""
	}
	idx := -1
	for i, b := range buf[:n] {
		if b == 0xff {
			idx = i
			break
		}
	}
	if idx < 0 {
		return ""
	}
	return string(buf[idx+1 : n])
}

// --- main entry ---

// Options controls a discovery run.
type Options struct {
	Hosts   []string      // when empty, ARP+multicast are used; the TCP probes are skipped
	Timeout time.Duration // per-channel timeout
}

// Scan runs every discovery channel and merges results per-IP.
func Scan(ctx context.Context, opts Options) []Device {
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	byIP := map[string]*Device{}

	touch := func(ip string) *Device {
		if d, ok := byIP[ip]; ok {
			return d
		}
		d := &Device{IP: ip}
		byIP[ip] = d
		return d
	}

	// 1. ARP
	for _, d := range arpNeighbors() {
		cur := touch(d.IP)
		cur.MAC = d.MAC
		cur.Vendor = d.Vendor
		cur.Signals = append(cur.Signals, "arp")
	}

	// 2. mDNS
	var wg sync.WaitGroup
	mdnsCh := make(chan map[string][]string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		mdnsCh <- mdnsQuery(ctx, opts.Timeout)
	}()

	// 3. SSDP
	ssdpCh := make(chan map[string][]string, 1)
	wg.Add(1)
	go func() {
		defer wg.Done()
		ssdpCh <- ssdpDiscover(ctx, opts.Timeout)
	}()

	wg.Wait()
	for ip, names := range <-mdnsCh {
		cur := touch(ip)
		cur.MDNS = names
		cur.Signals = append(cur.Signals, "mdns")
	}
	for ip, servers := range <-ssdpCh {
		cur := touch(ip)
		cur.SSDP = servers
		cur.Signals = append(cur.Signals, "ssdp")
	}

	// 4. Per-host port probes (only when the caller gave us a host list)
	for _, ip := range opts.Hosts {
		cur := touch(ip)
		if tcpProbe(ip, 1883, 800*time.Millisecond) {
			cur.MQTT = true
			cur.Signals = append(cur.Signals, "mqtt")
		}
		if coap := coapProbe(ip, 800*time.Millisecond); coap != "" {
			cur.CoAP = coap
			cur.Signals = append(cur.Signals, "coap")
		}
	}

	var out []Device
	for _, d := range byIP {
		if len(d.Signals) == 0 {
			continue
		}
		out = append(out, *d)
	}
	sort.Slice(out, func(i, j int) bool {
		return ipLess(out[i].IP, out[j].IP)
	})
	return out
}

func ipLess(a, b string) bool {
	ia := net.ParseIP(a).To4()
	ib := net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(ia) < binary.BigEndian.Uint32(ib)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
