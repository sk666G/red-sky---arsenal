package recon2

import (
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

// SOCKS5 chain builder. Given a list of SOCKS5 endpoints, dial the first,
// then CONNECT through it to the second, then through that to the third,
// and so on. The result is a single net.Conn that represents the whole
// chain — everything written to it exits through the last hop.
//
// Used to pivot: the agent is on one network, the target is on another,
// and the operator has a collection of SOCKS endpoints that reach the
// second. Chaining them through the agent's tunnel means the operator's
// own IP is never in the packet path.
//
// SOCKS5 CONNECT (RFC 1928):
//   client: 05 NMETHODS METHODS...    ; version 5, n methods
//   server: 05 METHOD                ; chosen method (0 = no auth)
//   client: 05 01 00 ATYP ADDR PORT  ; connect request, version 5, CMD=connect, RSV=0
//   server: 05 00 00 ATYP ADDR PORT  ; reply
//
// Auth: no-auth (0x00) implemented. Username/password (0x02) is a
// follow-up — many internal proxies allow no-auth on the LAN side.

// ProxyHop describes one SOCKS5 endpoint.
type ProxyHop struct {
	Host     string
	Port     int
	User     string // empty = no auth
	Pass     string
}

// ChainOptions controls chain dialing.
type ChainOptions struct {
	Hops    []ProxyHop
	Timeout time.Duration
	// Target is the final endpoint to reach. Passed to the last hop's
	// CONNECT. If empty, the caller drives the last hop directly (used
	// for tunneling).
	Target string
}

// ChainDial opens a connection through every hop in opts.Hops, ending at
// opts.Target. Returns the fully chained net.Conn.
func ChainDial(opts ChainOptions) (net.Conn, error) {
	if len(opts.Hops) == 0 {
		return nil, errors.New("recon2: at least one hop required")
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}

	// dial the first hop directly
	first := opts.Hops[0]
	d := net.Dialer{Timeout: opts.Timeout}
	conn, err := d.Dial("tcp", first.Host+":"+itoa(first.Port))
	if err != nil {
		return nil, fmt.Errorf("recon2: dial first hop: %w", err)
	}
	_ = conn.SetDeadline(time.Now().Add(opts.Timeout))
	if err := socks5Handshake(conn, first.User, first.Pass); err != nil {
		conn.Close()
		return nil, fmt.Errorf("recon2: handshake hop 0: %w", err)
	}

	// for each subsequent hop: CONNECT to the next hop's address
	for i := 1; i < len(opts.Hops); i++ {
		next := opts.Hops[i]
		target := next.Host + ":" + itoa(next.Port)
		if err := socks5Connect(conn, target); err != nil {
			conn.Close()
			return nil, fmt.Errorf("recon2: connect hop %d: %w", i, err)
		}
		if err := socks5Handshake(conn, next.User, next.Pass); err != nil {
			conn.Close()
			return nil, fmt.Errorf("recon2: handshake hop %d: %w", i, err)
		}
	}

	// final CONNECT to the real target
	if opts.Target != "" {
		if err := socks5Connect(conn, opts.Target); err != nil {
			conn.Close()
			return nil, fmt.Errorf("recon2: connect to target: %w", err)
		}
	}

	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

// socks5Handshake performs the version + method negotiation. Only no-auth
// (0x00) and user/pass (0x02) are supported.
func socks5Handshake(conn net.Conn, user, pass string) error {
	var methods []byte
	if user != "" {
		methods = []byte{0x00, 0x02} // try no-auth first, then user/pass
	} else {
		methods = []byte{0x00}
	}
	req := append([]byte{0x05, byte(len(methods))}, methods...)
	if _, err := conn.Write(req); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("not socks5 (version %d)", resp[0])
	}
	switch resp[1] {
	case 0x00:
		return nil // no auth
	case 0x02:
		if user == "" {
			return errors.New("server wants user/pass, none supplied")
		}
		return socks5UserPass(conn, user, pass)
	case 0xFF:
		return errors.New("no acceptable methods")
	}
	return fmt.Errorf("unsupported method 0x%02x", resp[1])
}

// socks5UserPass performs the RFC 1929 username/password sub-negotiation.
func socks5UserPass(conn net.Conn, user, pass string) error {
	if len(user) > 255 || len(pass) > 255 {
		return errors.New("user/pass too long")
	}
	buf := append([]byte{0x01, byte(len(user))}, []byte(user)...)
	buf = append(buf, byte(len(pass)))
	buf = append(buf, []byte(pass)...)
	if _, err := conn.Write(buf); err != nil {
		return err
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[1] != 0x00 {
		return errors.New("auth rejected")
	}
	return nil
}

// socks5Connect sends the CONNECT command for target (host:port).
func socks5Connect(conn net.Conn, target string) error {
	host, portStr, err := net.SplitHostPort(target)
	if err != nil {
		return err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return err
	}

	var req []byte
	req = append(req, 0x05, 0x01, 0x00) // version, cmd=connect, rsv

	ip := net.ParseIP(host)
	if ip == nil {
		// domain name — ATYP 0x03
		if len(host) > 255 {
			return errors.New("domain too long")
		}
		req = append(req, 0x03, byte(len(host)))
		req = append(req, []byte(host)...)
	} else if ip4 := ip.To4(); ip4 != nil {
		req = append(req, 0x01) // ATYP 0x01 = IPv4
		req = append(req, ip4...)
	} else {
		req = append(req, 0x04) // ATYP 0x04 = IPv6
		req = append(req, ip.To16()...)
	}
	req = append(req, byte(port>>8), byte(port&0xFF))

	if _, err := conn.Write(req); err != nil {
		return err
	}
	// read reply: VER REP RSV ATYP BND.ADDR BND.PORT
	resp := make([]byte, 4)
	if _, err := io.ReadFull(conn, resp); err != nil {
		return err
	}
	if resp[0] != 0x05 {
		return fmt.Errorf("bad version %d in reply", resp[0])
	}
	if resp[1] != 0x00 {
		return fmt.Errorf("socks5 reply code 0x%02x", resp[1])
	}
	// consume the bound address based on ATYP
	var skip int
	switch resp[3] {
	case 0x01:
		skip = 4 + 2
	case 0x03:
		l := make([]byte, 1)
		if _, err := io.ReadFull(conn, l); err != nil {
			return err
		}
		skip = int(l[0]) + 2
	case 0x04:
		skip = 16 + 2
	default:
		return fmt.Errorf("unknown ATYP 0x%02x", resp[3])
	}
	if skip > 0 {
		discard := make([]byte, skip)
		if _, err := io.ReadFull(conn, discard); err != nil {
			return err
		}
	}
	return nil
}

// ParseProxyChain parses a chain spec like "host1:1080,host2:9050,host3:1080"
// into ProxyHop entries.
func ParseProxyChain(spec string) ([]ProxyHop, error) {
	var out []ProxyHop
	parts := splitCSV(spec)
	for _, p := range parts {
		if p == "" {
			continue
		}
		host, portStr, err := net.SplitHostPort(p)
		if err != nil {
			return nil, fmt.Errorf("recon2: bad hop %q: %w", p, err)
		}
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, err
		}
		out = append(out, ProxyHop{Host: host, Port: port})
	}
	if len(out) == 0 {
		return nil, errors.New("recon2: no hops parsed")
	}
	return out, nil
}

// splitCSV splits on commas, trims whitespace.
func splitCSV(s string) []string {
	var out []string
	var cur []byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ',' {
			out = append(out, trimSpace(string(cur)))
			cur = nil
			continue
		}
		cur = append(cur, c)
	}
	out = append(out, trimSpace(string(cur)))
	return out
}

// trimSpace trims ASCII whitespace.
func trimSpace(s string) string {
	i, j := 0, len(s)
	for i < j && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r') {
		i++
	}
	for j > i && (s[j-1] == ' ' || s[j-1] == '\t' || s[j-1] == '\n' || s[j-1] == '\r') {
		j--
	}
	return s[i:j]
}
