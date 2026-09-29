package iotcreds

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// TelnetOptions controls a telnet spray.
type TelnetOptions struct {
	Host      string
	Port      int           // 23 default
	Timeout   time.Duration // per-attempt
	StopFirst bool
}

// sprayTelnet connects, waits for a login banner, sends user then pass,
// then checks for shell markers (# $ > busybox welcome). Deny markers
// (incorrect / denied / fail) always win.
func sprayTelnet(ctx context.Context, opts TelnetOptions, onAttempt func(i int, c Cred, ok bool)) ([]Hit, error) {
	if opts.Host == "" {
		return nil, errors.New("iotcreds/telnet: host required")
	}
	if opts.Port == 0 {
		opts.Port = 23
	}
	if opts.Timeout == 0 {
		opts.Timeout = 6 * time.Second
	}
	addr := fmt.Sprintf("%s:%d", opts.Host, opts.Port)

	var hits []Hit
	for i, c := range BuiltinCreds {
		select {
		case <-ctx.Done():
			return hits, ctx.Err()
		default:
		}
		ok := telnetOne(ctx, addr, c, opts.Timeout)
		if onAttempt != nil {
			onAttempt(i, c, ok)
		}
		if ok {
			hits = append(hits, Hit{
				Host: opts.Host, Port: opts.Port, Protocol: "telnet",
				Vendor: c.Vendor, User: c.User, Pass: c.Pass,
			})
			if opts.StopFirst {
				return hits, nil
			}
		}
	}
	return hits, nil
}

func telnetOne(ctx context.Context, addr string, c Cred, timeout time.Duration) bool {
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()
	deadline := time.Now().Add(timeout)
	_ = conn.SetDeadline(deadline)

	banner := readSome(conn, 2048, 400*time.Millisecond)
	lowBanner := strings.ToLower(string(banner))

	// if no login/username/password prompt yet, nudge with a blank line
	if !strings.Contains(lowBanner, "login") &&
		!strings.Contains(lowBanner, "username") &&
		!strings.Contains(lowBanner, "password") {
		_, _ = conn.Write([]byte("\r\n"))
		more := readSome(conn, 2048, 400*time.Millisecond)
		banner = append(banner, more...)
		lowBanner = strings.ToLower(string(banner))
	}
	if !strings.Contains(lowBanner, "login") &&
		!strings.Contains(lowBanner, "username") &&
		!strings.Contains(lowBanner, "password") {
		return false
	}

	if strings.Contains(lowBanner, "login") || strings.Contains(lowBanner, "username") {
		_, _ = conn.Write([]byte(c.User + "\r\n"))
		_ = readSome(conn, 1024, 300*time.Millisecond)
	}
	_, _ = conn.Write([]byte(c.Pass + "\r\n"))
	time.Sleep(600 * time.Millisecond)

	resp := readSome(conn, 4096, 600*time.Millisecond)
	low := strings.ToLower(string(resp))

	if strings.Contains(low, "incorrect") || strings.Contains(low, "denied") || strings.Contains(low, "fail") {
		return false
	}
	for _, m := range []string{"#", "$", ">", "welcome", "busybox"} {
		if strings.Contains(low, m) {
			return true
		}
	}
	return false
}

// readSome reads up to max bytes, waiting at most wait, ignoring timeouts.
func readSome(conn net.Conn, max int, wait time.Duration) []byte {
	buf := make([]byte, 0, 1024)
	tmp := make([]byte, 1024)
	deadline := time.Now().Add(wait)
	_ = conn.SetReadDeadline(deadline)
	for len(buf) < max {
		_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		n, err := conn.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
		if time.Now().After(deadline) {
			break
		}
	}
	return buf
}
