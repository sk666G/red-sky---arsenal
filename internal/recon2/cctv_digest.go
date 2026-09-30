package recon2

import (
	"crypto/md5"
	"encoding/hex"
	"fmt"
	"regexp"
	"strings"
)

// RTSP Digest authentication. Many IP cameras (Dahua in particular, some
// Axis) require Digest auth on the RTSP endpoint instead of Basic. The
// code path is nearly identical to Basic — the difference is the
// Authorization header.
//
// Digest (RFC 2617 / RFC 7616) response:
//
//   HA1 = MD5(username:realm:password)
//   HA2 = MD5(method:uri)
//   response = MD5(HA1:nonce:HA2)                       (no qop)
//   response = MD5(HA1:nonce:nc:cnonce:qop:HA2)         (qop present)
//
// The server sends the nonce (and often qop) in the WWW-Authenticate
// challenge. The client responds with the computed response.

// DigestChallenge is a parsed WWW-Authenticate header.
type DigestChallenge struct {
	Realm     string
	Nonce     string
	Opaque    string
	QOP       string // "auth" if present
	Algorithm string // MD5, MD5-sess, SHA-256
	Stale     bool
}

// authHeaderRe extracts key="value" pairs from a header.
var authHeaderRe = regexp.MustCompile(`([a-zA-Z]+)\s*=\s*(?:"([^"]*)"|([^,\s]+))`)

// ParseDigestChallenge parses a WWW-Authenticate header. Returns the
// challenge or (DigestChallenge{}, false) if the header isn't Digest.
func ParseDigestChallenge(header string) (DigestChallenge, bool) {
	header = strings.TrimSpace(header)
	if !strings.HasPrefix(strings.ToLower(header), "digest ") {
		return DigestChallenge{}, false
	}
	rest := header[len("digest "):]
	ch := DigestChallenge{Algorithm: "MD5"}
	for _, m := range authHeaderRe.FindAllStringSubmatch(rest, -1) {
		key := strings.ToLower(m[1])
		val := m[2]
		if val == "" {
			val = m[3]
		}
		switch key {
		case "realm":
			ch.Realm = val
		case "nonce":
			ch.Nonce = val
		case "opaque":
			ch.Opaque = val
		case "qop":
			ch.QOP = val
		case "algorithm":
			ch.Algorithm = val
		case "stale":
			ch.Stale = strings.EqualFold(val, "true")
		}
	}
	if ch.Nonce == "" {
		return DigestChallenge{}, false
	}
	return ch, true
}

// DigestResponse computes the RFC 7616 digest response.
//
//	cnonce is a client-generated nonce (only used if qop is set)
//	nc is the request counter as 8 hex digits ("00000001" for the first)
func DigestResponse(username, password, method, uri string, ch DigestChallenge, cnonce, nc string) string {
	h := func(s string) string {
		sum := md5.Sum([]byte(s))
		return hex.EncodeToString(sum[:])
	}
	ha1 := h(username + ":" + ch.Realm + ":" + password)
	ha2 := h(method + ":" + uri)
	if strings.Contains(ch.QOP, "auth") {
		return h(ha1 + ":" + ch.Nonce + ":" + nc + ":" + cnonce + ":auth:" + ha2)
	}
	return h(ha1 + ":" + ch.Nonce + ":" + ha2)
}

// BuildDigestAuthorization returns the value for the Authorization header
// given a parsed challenge.
func BuildDigestAuthorization(username, password, method, uri string, ch DigestChallenge, cnonce, nc string) string {
	response := DigestResponse(username, password, method, uri, ch, cnonce, nc)
	var parts []string
	parts = append(parts, `username="`+username+`"`)
	parts = append(parts, `realm="`+ch.Realm+`"`)
	parts = append(parts, `nonce="`+ch.Nonce+`"`)
	parts = append(parts, `uri="`+uri+`"`)
	parts = append(parts, `response="`+response+`"`)
	if ch.Algorithm != "" && !strings.EqualFold(ch.Algorithm, "MD5") {
		parts = append(parts, `algorithm=`+ch.Algorithm)
	}
	if ch.Opaque != "" {
		parts = append(parts, `opaque="`+ch.Opaque+`"`)
	}
	if strings.Contains(ch.QOP, "auth") {
		parts = append(parts, `qop=auth`)
		parts = append(parts, `nc=`+nc)
		parts = append(parts, `cnonce="`+cnonce+`"`)
	}
	return "Digest " + strings.Join(parts, ", ")
}

// FakeCnonce returns a deterministic cnonce for testing — the caller
// should generate a real random one in production.
func FakeCnonce(seed uint32) string {
	return fmt.Sprintf("%08x", seed)
}
