// Package icsdiscover is a Go port of the ICS portion of Program/ics_scada.
// Finds industrial control systems on a network via five protocol channels:
//
//	Modbus/TCP    (502)      read device identification
//	EtherNet/IP   (44818)    CIP ListIdentity
//	Profinet DCP  (34964/udp) Identify-All
//	OPC-UA        (4840)     Hello handshake
//	BACnet/IP     (47808/udp) Who-Is broadcast
//
// Discovery-only. No writes, no state changes, no control commands.
package icsdiscover

import (
	"context"
	"encoding/binary"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Device is one host that responded to any ICS protocol.
type Device struct {
	IP        string   `json:"ip"`
	Protocols []string `json:"protocols"`
	Details   []string `json:"details"`
}

// Well-known ICS ports to probe.
var icsPorts = []struct {
	port     int
	protocol string
}{
	{502, "modbus"},
	{44818, "ethernet-ip"},
	{4840, "opc-ua"},
	{2404, "iec-104"},
	{102, "s7comm"},
	{20000, "dnp3"},
}

// Options controls a discovery run.
type Options struct {
	Hosts   []string
	Timeout time.Duration
}

// Scan runs every channel and merges results by IP.
func Scan(ctx context.Context, opts Options) []Device {
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}
	byIP := map[string]*Device{}
	mu := sync.Mutex{}

	touch := func(ip string) *Device {
		mu.Lock()
		defer mu.Unlock()
		if d, ok := byIP[ip]; ok {
			return d
		}
		d := &Device{IP: ip}
		byIP[ip] = d
		return d
	}
	addSignal := func(ip, proto, detail string) {
		d := touch(ip)
		mu.Lock()
		defer mu.Unlock()
		found := false
		for _, p := range d.Protocols {
			if p == proto {
				found = true
				break
			}
		}
		if !found {
			d.Protocols = append(d.Protocols, proto)
		}
		if detail != "" {
			d.Details = append(d.Details, fmt.Sprintf("%s: %s", proto, detail))
		}
	}

	var wg sync.WaitGroup
	sem := make(chan struct{}, 200)

	// 1. TCP port sweep on each host for the known ICS ports.
	for _, host := range opts.Hosts {
		for _, entry := range icsPorts {
			wg.Add(1)
			sem <- struct{}{}
			go func(h string, port int, proto string) {
				defer wg.Done()
				defer func() { <-sem }()
				c, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", h, port), opts.Timeout)
				if err != nil {
					return
				}
				c.Close()
				addSignal(h, proto, fmt.Sprintf("port %d open", port))
			}(host, entry.port, entry.protocol)
		}
	}
	wg.Wait()

	// 2. EtherNet/IP ListIdentity on hosts that had 44818 open.
	for _, d := range snapshot(byIP, &mu) {
		if !hasProto(d, "ethernet-ip") {
			continue
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			detail := enipListIdentity(ip, opts.Timeout)
			if detail != "" {
				addSignal(ip, "ethernet-ip", detail)
			}
		}(d.IP)
	}

	// 3. OPC-UA Hello on hosts with 4840 open.
	for _, d := range snapshot(byIP, &mu) {
		if !hasProto(d, "opc-ua") {
			continue
		}
		wg.Add(1)
		go func(ip string) {
			defer wg.Done()
			detail := opcuaHello(ip, opts.Timeout)
			if detail != "" {
				addSignal(ip, "opc-ua", detail)
			}
		}(d.IP)
	}

	// 4. BACnet/IP Who-Is multicast.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ip, detail := range bacnetWhoIs(ctx, opts.Timeout) {
			addSignal(ip, "bacnet", detail)
		}
	}()

	// 5. Profinet DCP Identify-All multicast.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for ip, detail := range profinetIdentify(ctx, opts.Timeout) {
			addSignal(ip, "profinet", detail)
		}
	}()

	wg.Wait()

	var out []Device
	mu.Lock()
	for _, d := range byIP {
		out = append(out, *d)
	}
	mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return ipLess(out[i].IP, out[j].IP) })
	return out
}

func snapshot(m map[string]*Device, mu *sync.Mutex) []Device {
	mu.Lock()
	defer mu.Unlock()
	out := make([]Device, 0, len(m))
	for _, d := range m {
		out = append(out, *d)
	}
	return out
}

func hasProto(d Device, p string) bool {
	for _, x := range d.Protocols {
		if x == p {
			return true
		}
	}
	return false
}

// --- EtherNet/IP ---
func enipListIdentity(ip string, timeout time.Duration) string {
	c, err := net.DialTimeout("tcp", ip+":44818", timeout)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))

	// ENIP encapsulation: cmd(2) len(2) session(4) status(4) context(8) options(4)
	req := make([]byte, 24)
	binary.LittleEndian.PutUint16(req[0:2], 0x0063) // ListIdentity
	// len 0
	if _, err := c.Write(req); err != nil {
		return ""
	}
	buf := make([]byte, 4096)
	n, err := c.Read(buf)
	if err != nil || n < 24 {
		return ""
	}
	// Look for vendor strings in the payload
	body := buf[24:n]
	vendor := extractString(body)
	if vendor != "" {
		return "vendor=" + vendor
	}
	return fmt.Sprintf("%d byte response", len(body))
}

func extractString(b []byte) string {
	var cur strings.Builder
	for _, c := range b {
		if c >= 0x20 && c <= 0x7e {
			cur.WriteByte(c)
		} else {
			if cur.Len() >= 4 {
				return cur.String()
			}
			cur.Reset()
		}
	}
	if cur.Len() >= 4 {
		return cur.String()
	}
	return ""
}

// --- OPC-UA ---
func opcuaHello(ip string, timeout time.Duration) string {
	c, err := net.DialTimeout("tcp", ip+":4840", timeout)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(timeout))

	endpoint := "opc.tcp://" + ip + ":4840"
	// HEL message: 'HEL' + 'F' + size(4) + ver(4) recv(4) send(4) maxmsg(4) maxchunk(4) strlen(4) url
	body := make([]byte, 0, 64)
	body = append(body, 0, 0, 0, 0)       // ver
	body = append(body, 0xff, 0xff, 0, 0) // recv
	body = append(body, 0xff, 0xff, 0, 0) // send
	body = append(body, 0, 0, 0, 0)       // maxmsg
	body = append(body, 0, 0, 0, 0)       // maxchunk
	sl := make([]byte, 4)
	binary.LittleEndian.PutUint32(sl, uint32(len(endpoint)))
	body = append(body, sl...)
	body = append(body, endpoint...)
	size := make([]byte, 4)
	binary.LittleEndian.PutUint32(size, uint32(8+len(body)))
	pkt := append([]byte{'H', 'E', 'L', 'F'}, size...)
	pkt = append(pkt, body...)
	if _, err := c.Write(pkt); err != nil {
		return ""
	}
	rbuf := make([]byte, 1024)
	n, err := c.Read(rbuf)
	if err != nil || n < 3 {
		return ""
	}
	if string(rbuf[:3]) == "ACK" {
		return "ACK received"
	}
	return fmt.Sprintf("%d byte response", n)
}

// --- BACnet/IP ---
func bacnetWhoIs(ctx context.Context, timeout time.Duration) map[string]string {
	out := map[string]string{}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return out
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	// BVLC-Result / broadcast + NPDU + Unconfirmed-Request Who-Is
	pkt := []byte{0x81, 0x0b, 0x00, 0x0c,
		0x01, 0x20,
		0x10, 0x08, 0x00, 0xff, 0x00, 0xff}
	dst, _ := net.ResolveUDPAddr("udp", "255.255.255.255:47808")
	if _, err := conn.WriteToUDP(pkt, dst); err != nil {
		return out
	}
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		out[addr.IP.String()] = fmt.Sprintf("%d byte response", n)
	}
}

// --- Profinet ---
func profinetIdentify(ctx context.Context, timeout time.Duration) map[string]string {
	out := map[string]string{}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4zero, Port: 0})
	if err != nil {
		return out
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(timeout))

	// DCP Identify-All request
	pkt := []byte{
		0xfe, 0xff, // service ID
		0x05, 0x00, // service type + XID
		0x01, 0x02, 0x03, 0x04,
		0xff, 0xff, // option
		0xff, 0xff, // suboption
		0x00, 0x00, // block length
	}
	dst, _ := net.ResolveUDPAddr("udp", "255.255.255.255:34964")
	if _, err := conn.WriteToUDP(pkt, dst); err != nil {
		return out
	}
	buf := make([]byte, 2048)
	for {
		select {
		case <-ctx.Done():
			return out
		default:
		}
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return out
		}
		out[addr.IP.String()] = fmt.Sprintf("%d byte DCP response", n)
	}
}

// ipLess sorts dotted-quad IPs numerically.
func ipLess(a, b string) bool {
	ia := net.ParseIP(a).To4()
	ib := net.ParseIP(b).To4()
	if ia == nil || ib == nil {
		return a < b
	}
	return binary.BigEndian.Uint32(ia) < binary.BigEndian.Uint32(ib)
}

// ParsePorts is a light wrapper for want of a common helper in this package.
func ParsePorts(spec string) ([]int, error) {
	var out []int
	for _, p := range strings.Split(spec, ",") {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, err
		}
		out = append(out, n)
	}
	return out, nil
}
