package webgo

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Raw HTTP request driver. Not net/http — deliberately raw socket so the
// operator can send malformed requests, override Host, use non-standard
// methods, smuggle request boundaries, and observe the byte-level response.
//
// This is the piece the SSRF/SSTI/XXE/XSS payload kits were missing: the
// actual delivery. Payloads come out of those modules as strings; WebReq
// sends them.

// WebReqOptions controls one request.
type WebReqOptions struct {
	URL     string
	Method  string // default GET
	Headers map[string]string
	Body    []byte
	Timeout time.Duration
	// UseTLS is inferred from URL scheme unless explicitly set.
	UseTLS bool
	// SkipTLSVerify mirrors SSRF — internal hosts usually have self-signed certs.
	SkipTLSVerify bool
	// RawRequest, when set, is the entire request bytes and URL scheme/host
	// are ignored for parsing but still used for connect.
	RawRequest []byte
}

// WebReqResult is the raw response.
type WebReqResult struct {
	Status      int
	StatusLine  string
	Headers     map[string]string
	HeaderOrder []string
	Body        []byte
	Raw         []byte
	DurationMs  int64
	Error       string
}

// WebReq sends one raw HTTP request and returns the response.
func WebReq(ctx context.Context, opts WebReqOptions) WebReqResult {
	start := time.Now()
	var res WebReqResult

	if opts.URL == "" {
		res.Error = "url required"
		return res
	}
	u, err := url.Parse(opts.URL)
	if err != nil {
		res.Error = err.Error()
		return res
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		res.Error = "url scheme must be http or https"
		return res
	}
	if opts.Timeout == 0 {
		opts.Timeout = 15 * time.Second
	}
	if opts.Method == "" {
		opts.Method = "GET"
	}

	// dial
	hostport := u.Host
	if !strings.Contains(hostport, ":") {
		if u.Scheme == "https" {
			hostport += ":443"
		} else {
			hostport += ":80"
		}
	}
	d := net.Dialer{Timeout: opts.Timeout}
	rawConn, err := d.DialContext(ctx, "tcp", hostport)
	if err != nil {
		res.Error = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer rawConn.Close()
	_ = rawConn.SetDeadline(time.Now().Add(opts.Timeout))

	var conn net.Conn = rawConn
	if u.Scheme == "https" || opts.UseTLS {
		tlsCfg := &tls.Config{
			ServerName:         u.Hostname(),
			InsecureSkipVerify: opts.SkipTLSVerify,
		}
		tlsConn := tls.Client(rawConn, tlsCfg)
		if err := tlsConn.Handshake(); err != nil {
			res.Error = "tls: " + err.Error()
			res.DurationMs = time.Since(start).Milliseconds()
			return res
		}
		conn = tlsConn
	}

	// build request bytes
	req := opts.RawRequest
	if len(req) == 0 {
		req = buildHTTPRequest(u, opts)
	}
	if _, err := conn.Write(req); err != nil {
		res.Error = "write: " + err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}

	// read response head + body
	br := bufio.NewReader(conn)
	respBytes, _ := io.ReadAll(io.LimitReader(br, 1<<20))
	res.Raw = respBytes
	res.DurationMs = time.Since(start).Milliseconds()

	// parse head/body split
	idx := bytes.Index(respBytes, []byte("\r\n\r\n"))
	if idx < 0 {
		idx = bytes.Index(respBytes, []byte("\n\n"))
	}
	if idx < 0 {
		res.Error = "no header/body separator in response"
		return res
	}
	head := respBytes[:idx]
	res.Body = respBytes[idx+4:]
	if idx >= len(respBytes) {
		res.Body = nil
	}

	// parse status line + headers
	lines := strings.Split(string(head), "\n")
	if len(lines) == 0 {
		res.Error = "empty response head"
		return res
	}
	res.StatusLine = strings.TrimRight(lines[0], "\r\n")
	parts := strings.SplitN(res.StatusLine, " ", 3)
	if len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			res.Status = code
		}
	}
	res.Headers = map[string]string{}
	for _, line := range lines[1:] {
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon <= 0 {
			continue
		}
		k := strings.TrimSpace(line[:colon])
		v := strings.TrimSpace(line[colon+1:])
		lk := strings.ToLower(k)
		res.HeaderOrder = append(res.HeaderOrder, lk)
		if prev, ok := res.Headers[lk]; ok {
			res.Headers[lk] = prev + ", " + v
		} else {
			res.Headers[lk] = v
		}
	}
	return res
}

// buildHTTPRequest renders the request line + headers + body for a URL.
func buildHTTPRequest(u *url.URL, opts WebReqOptions) []byte {
	var b bytes.Buffer
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	b.WriteString(opts.Method + " " + path + " HTTP/1.1\r\n")
	// Host is required unless the operator overrides it
	if _, ok := opts.Headers["Host"]; !ok {
		b.WriteString("Host: " + u.Host + "\r\n")
	}
	if _, ok := opts.Headers["User-Agent"]; !ok {
		b.WriteString("User-Agent: Mozilla/5.0\r\n")
	}
	if _, ok := opts.Headers["Accept"]; !ok {
		b.WriteString("Accept: */*\r\n")
	}
	if _, ok := opts.Headers["Connection"]; !ok {
		b.WriteString("Connection: close\r\n")
	}
	for k, v := range opts.Headers {
		b.WriteString(k + ": " + v + "\r\n")
	}
	if len(opts.Body) > 0 {
		if _, ok := opts.Headers["Content-Length"]; !ok {
			b.WriteString("Content-Length: " + strconv.Itoa(len(opts.Body)) + "\r\n")
		}
	}
	b.WriteString("\r\n")
	if len(opts.Body) > 0 {
		b.Write(opts.Body)
	}
	return b.Bytes()
}

// SendSSRF builds a WebReqOptions for the standard SSRF probe — GET with
// optional IMDS headers.
func SendSSRF(url string, imdsv2Token string, timeout time.Duration) WebReqResult {
	opts := WebReqOptions{
		URL:           url,
		Method:        "GET",
		Timeout:       timeout,
		SkipTLSVerify: true,
	}
	if imdsv2Token != "" {
		opts.Headers = map[string]string{"X-aws-ec2-metadata-token": imdsv2Token}
	}
	return WebReq(context.Background(), opts)
}

// SendSSTI sends an SSTI payload as a query parameter, following the
// common "?name=<payload>" shape.
func SendSSTI(baseURL, param, payload string, timeout time.Duration) WebReqResult {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	url := baseURL + sep + param + "=" + url.QueryEscape(payload)
	return WebReq(context.Background(), WebReqOptions{
		URL:           url,
		Method:        "GET",
		Timeout:       timeout,
		SkipTLSVerify: true,
	})
}

// SendXXE posts an XML body with the Content-Type header set to text/xml.
// The response body is the target's parsed response.
func SendXXE(url, xmlBody string, timeout time.Duration) WebReqResult {
	return WebReq(context.Background(), WebReqOptions{
		URL:           url,
		Method:        "POST",
		Timeout:       timeout,
		SkipTLSVerify: true,
		Headers:       map[string]string{"Content-Type": "text/xml"},
		Body:          []byte(xmlBody),
	})
}

// SendXSS probes a URL with an XSS payload in a named parameter.
func SendXSS(baseURL, param, payload string, timeout time.Duration) WebReqResult {
	sep := "?"
	if strings.Contains(baseURL, "?") {
		sep = "&"
	}
	u := baseURL + sep + param + "=" + url.QueryEscape(payload)
	return WebReq(context.Background(), WebReqOptions{
		URL:           u,
		Method:        "GET",
		Timeout:       timeout,
		SkipTLSVerify: true,
	})
}

// RequestSmuggle takes two requests separated by the CL.TE / TE.CL boundary
// markers and sends them as one TCP write. This is the low-level smuggling
// primitive that the caller layers the actual payload onto.
//
// The function returns the response bytes as-is — smuggling detection is
// the operator's job.
func RequestSmuggle(host, port string, rawBytes []byte, timeout time.Duration) ([]byte, error) {
	if host == "" || port == "" {
		return nil, errors.New("webgo: host and port required")
	}
	d := net.Dialer{Timeout: timeout}
	conn, err := d.Dial("tcp", host+":"+port)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if _, err := conn.Write(rawBytes); err != nil {
		return nil, err
	}
	out, _ := io.ReadAll(io.LimitReader(conn, 1<<20))
	return out, nil
}

var _ = fmt.Sprintf
