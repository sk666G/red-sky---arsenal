package recon2

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// CCTV / IP camera reconnaissance. Two checks:
//
//   ProbeRTSP   dial an RTSP endpoint and check the DESCRIBE response.
//               Unauthenticated returns 200 + SDP; authed returns 401.
//               Combined with default creds this identifies live cameras.
//
//   RTSPOptions sends an OPTIONS request — the most benign check. Returns
//               the Server header if present, which often names the vendor.
//
// RTSP is a text protocol (RFC 2326) at its core — REQUEST / RESPONSE
// lines with CSeq, and a set of headers. The method we care about is
// OPTIONS (no session needed) and DESCRIBE (returns SDP, needs the target).
//
// The common RTSP URLs on IP cameras:
//   rtsp://<host>:554/                       root path
//   rtsp://<host>:554/Streaming/Channels/101 (Hikvision)
//   rtsp://<host>:554/cam/realmonitor?channel=1&subtype=0 (Dahua)
//   rtsp://<host>:554/axis-media/media.amp   (Axis)
//   rtsp://<host>:554/onvif1                 (ONVIF generic)
//   rtsp://<host>:554/h264Preview_01_main    (Reolink)
//   rtsp://<host>:554/mpeg4                  (some generic)
//   rtsp://<host>:554/live/ch0               (some generic)

// CCTVCred is one username/password pair.
type CCTVCred struct {
	User string
	Pass string
	Note string
}

// CCTVCreds is a curated default-credential list for IP cameras.
var CCTVCreds = []CCTVCred{
	{"admin", "admin", "universal"},
	{"admin", "", "universal blank"},
	{"admin", "12345", "Hikvision"},
	{"admin", "password", "universal"},
	{"admin", "1234", "universal"},
	{"admin", "123456", "universal"},
	{"root", "root", "universal"},
	{"root", "pass", "universal"},
	{"root", "12345", "universal"},
	{"root", "admin", "universal"},
	{"root", "", "universal blank"},
	{"user", "user", "universal"},
	{"admin", "admin12345", "many"},
	{"admin", "password123", "many"},
	{"admin", "instar", "Instar"},
	{"admin", "system", "some"},
	{"admin", "camera", "some"},
	{"admin", "camera1", "some"},
	{"service", "service", "some"},
	{"admin", "9999", "some"},
}

// RTSPPaths is the common URL path list to try against a camera.
var RTSPPaths = []string{
	"/",
	"/Streaming/Channels/101",
	"/Streaming/Channels/102",
	"/cam/realmonitor?channel=1&subtype=0",
	"/axis-media/media.amp",
	"/onvif1",
	"/h264Preview_01_main",
	"/mpeg4",
	"/live/ch0",
	"/video1",
	"/img/video.mjpeg",
	"/1",
	"/12",
	"/user=admin_password=_channel=1_stream=0.sdp",
}

// CCTVOptions controls a probe.
type CCTVOptions struct {
	Timeout time.Duration
}

// RTSPResult is the outcome of one probe.
type RTSPResult struct {
	URL       string `json:"url"`
	OK        bool   `json:"ok"`
	Status    int    `json:"status"` // HTTP-style code
	Server    string `json:"server,omitempty"`
	AuthRealm string `json:"auth_realm,omitempty"`
	Note      string `json:"note,omitempty"`
}

// rtspRequest sends one RTSP method to a URL and returns the response head.
func rtspRequest(ctx context.Context, rtspURL, method string, cseq int, creds *CCTVCred, timeout time.Duration) (int, string, error) {
	u, err := url.Parse(rtspURL)
	if err != nil {
		return 0, "", err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":554"
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// request line + headers
	var req strings.Builder
	req.WriteString(method + " " + u.RequestURI() + " RTSP/1.0\r\n")
	req.WriteString("CSeq: " + strconv.Itoa(cseq) + "\r\n")
	req.WriteString("User-Agent: redsky-recon\r\n")
	if creds != nil {
		// Basic auth is the common RTSP auth on cameras
		req.WriteString("Authorization: Basic " + base64Encode(creds.User+":"+creds.Pass) + "\r\n")
	}
	req.WriteString("\r\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		return 0, "", err
	}

	// read response head (up to blank line)
	br := bufio.NewReader(conn)
	head := strings.Builder{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		head.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}

	resp := head.String()
	lines := strings.Split(resp, "\r\n")
	if len(lines) == 0 {
		return 0, resp, errors.New("empty response")
	}
	// status line: RTSP/1.0 <code> <reason>
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return 0, resp, errors.New("bad status line")
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, resp, err
	}
	return code, resp, nil
}

// ProbeRTSP sends OPTIONS (unauthenticated) then DESCRIBE (with creds if
// supplied). Returns a CCTVRResult with the discovered Server header.
func ProbeRTSP(ctx context.Context, rtspURL string, creds *CCTVCred, opts CCTVOptions) RTSPResult {
	if opts.Timeout == 0 {
		opts.Timeout = 5 * time.Second
	}
	res := RTSPResult{URL: rtspURL}

	// OPTIONS first — no auth
	code, head, err := rtspRequest(ctx, rtspURL, "OPTIONS", 1, nil, opts.Timeout)
	if err != nil {
		res.Note = err.Error()
		return res
	}
	res.Status = code
	for _, line := range strings.Split(head, "\r\n") {
		low := strings.ToLower(line)
		switch {
		case strings.HasPrefix(low, "server:"):
			res.Server = strings.TrimSpace(line[len("server:"):])
		case strings.HasPrefix(low, "www-authenticate:"):
			res.AuthRealm = strings.TrimSpace(line)
		}
	}

	if code == 200 {
		res.OK = true
		res.Note = "options accepted (no auth)"
		return res
	}
	if code != 401 {
		res.Note = fmt.Sprintf("options returned %d", code)
		return res
	}

	// needs auth — try creds if supplied
	if creds == nil {
		res.Note = "auth required, no creds supplied"
		return res
	}

	// prefer Basic if the challenge asked for it; try Digest if the
	// challenge was a Digest form. Some cameras accept either.
	challengeLower := strings.ToLower(res.AuthRealm)
	useDigest := strings.Contains(challengeLower, "digest")

	if useDigest {
		ch, ok := ParseDigestChallenge(res.AuthRealm)
		if !ok {
			res.Note = "digest challenge unparseable"
			return res
		}
		// compute the Authorization header for the DESCRIBE request
		cnonce := FakeCnonce(uint32(0xDEADBEEF))
		uri := "/"
		if u, err := url.Parse(rtspURL); err == nil && u.RequestURI() != "" {
			uri = u.RequestURI()
		}
		auth := BuildDigestAuthorization(creds.User, creds.Pass, "DESCRIBE", uri, ch, cnonce, "00000001")
		code, head, err = rtspRequestDigest(ctx, rtspURL, "DESCRIBE", 2, auth, opts.Timeout)
	} else {
		code, head, err = rtspRequest(ctx, rtspURL, "DESCRIBE", 2, creds, opts.Timeout)
	}

	if err != nil {
		res.Note = err.Error()
		return res
	}
	res.Status = code
	for _, line := range strings.Split(head, "\r\n") {
		low := strings.ToLower(line)
		if strings.HasPrefix(low, "server:") {
			res.Server = strings.TrimSpace(line[len("server:"):])
		}
	}
	if code == 200 {
		res.OK = true
		authKind := "basic"
		if useDigest {
			authKind = "digest"
		}
		res.Note = "authenticated (" + authKind + ") with " + creds.User + ":" + creds.Pass
	} else {
		res.Note = fmt.Sprintf("describe returned %d", code)
	}
	return res
}

// rtspRequestDigest is like rtspRequest but takes a pre-computed
// Authorization header (typically the value produced by
// BuildDigestAuthorization).
func rtspRequestDigest(ctx context.Context, rtspURL, method string, cseq int, authHeader string, timeout time.Duration) (int, string, error) {
	u, err := url.Parse(rtspURL)
	if err != nil {
		return 0, "", err
	}
	host := u.Host
	if !strings.Contains(host, ":") {
		host += ":554"
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.DialContext(ctx, "tcp", host)
	if err != nil {
		return 0, "", err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	var req strings.Builder
	req.WriteString(method + " " + u.RequestURI() + " RTSP/1.0\r\n")
	req.WriteString("CSeq: " + strconv.Itoa(cseq) + "\r\n")
	req.WriteString("User-Agent: redsky-recon\r\n")
	req.WriteString("Authorization: " + authHeader + "\r\n")
	req.WriteString("\r\n")

	if _, err := conn.Write([]byte(req.String())); err != nil {
		return 0, "", err
	}
	br := bufio.NewReader(conn)
	head := strings.Builder{}
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			break
		}
		head.WriteString(line)
		if line == "\r\n" || line == "\n" {
			break
		}
	}
	resp := head.String()
	lines := strings.Split(resp, "\r\n")
	if len(lines) == 0 {
		return 0, resp, errors.New("empty response")
	}
	parts := strings.SplitN(lines[0], " ", 3)
	if len(parts) < 2 {
		return 0, resp, errors.New("bad status line")
	}
	code, err := strconv.Atoi(parts[1])
	if err != nil {
		return 0, resp, err
	}
	return code, resp, nil
}

// ProbeCamera finds a working RTSP URL on a host. Walks RTSPPaths and
// returns the first that returns 200 (either unauthenticated or with
// the supplied creds).
func ProbeCamera(ctx context.Context, host string, creds *CCTVCred, opts CCTVOptions) []RTSPResult {
	var out []RTSPResult
	for _, p := range RTSPPaths {
		u := "rtsp://" + host + p
		r := ProbeRTSP(ctx, u, creds, opts)
		if r.OK {
			out = append(out, r)
			break
		}
	}
	return out
}

// ScanCreds walks the credential list against one RTSP URL, returning the
// first that returns 200.
func ScanCreds(ctx context.Context, rtspURL string, opts CCTVOptions) *CCTVCred {
	for i := range CCTVCreds {
		c := CCTVCreds[i]
		r := ProbeRTSP(ctx, rtspURL, &c, opts)
		if r.OK {
			return &c
		}
	}
	return nil
}

// base64Encode is a self-contained base64 (no import).
func base64Encode(s string) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var b strings.Builder
	data := []byte(s)
	for i := 0; i < len(data); i += 3 {
		var chunk [3]byte
		n := copy(chunk[:], data[i:])
		b.WriteByte(alphabet[chunk[0]>>2])
		b.WriteByte(alphabet[((chunk[0]&0x03)<<4)|(chunk[1]>>4)])
		if n >= 2 {
			b.WriteByte(alphabet[((chunk[1]&0x0F)<<2)|(chunk[2]>>6)])
		} else {
			b.WriteByte('=')
		}
		if n >= 3 {
			b.WriteByte(alphabet[chunk[2]&0x3F])
		} else {
			b.WriteByte('=')
		}
	}
	return b.String()
}
