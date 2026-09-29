package webgo

import (
	"bytes"
	"context"
	"strings"
	"testing"
	"time"
)

// TestDefaultProbesShape confirms every default probe has a label and URL.
func TestDefaultProbesShape(t *testing.T) {
	if len(DefaultProbes) == 0 {
		t.Fatal("no default probes")
	}
	for _, p := range DefaultProbes {
		if p.Label == "" {
			t.Fatalf("probe missing label: %+v", p)
		}
		if p.URL == "" {
			t.Fatalf("probe missing URL: %+v", p)
		}
		if !strings.HasPrefix(p.URL, "http") && !strings.HasPrefix(p.URL, "file") {
			t.Fatalf("probe URL has unexpected scheme: %q", p.URL)
		}
	}
}

// TestDefaultSSRFClient confirms defaults are sane.
func TestDefaultSSRFClient(t *testing.T) {
	c := DefaultSSRFClient()
	if c.Timeout == 0 {
		t.Fatal("default timeout is zero")
	}
	if c.MaxBodyBytes == 0 {
		t.Fatal("default max body size is zero")
	}
	if !c.AllowInsecure {
		t.Fatal("SSRF client should allow self-signed by default")
	}
}

// TestProbeAllPopulatesResults confirms that ProbeAll with an empty list
// uses DefaultProbes and produces one result per probe.
func TestProbeAllPopulatesResults(t *testing.T) {
	c := DefaultSSRFClient()
	// shrink timeout so this test is fast even if it tries to reach IMDS
	c.Timeout = 500 * time.Millisecond
	c.MaxBodyBytes = 1024

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// limit to a few obvious non-routable probes so we test the shape
	// without hammering the network
	probes := []SSRFProbe{
		{Label: "unroutable", URL: "http://192.0.2.1/", Method: "GET"},
		{Label: "bogus-host", URL: "http://this-host-does-not-resolve.invalid/", Method: "GET"},
	}
	results := c.ProbeAll(ctx, probes, 2, nil)
	if len(results) != 2 {
		t.Fatalf("expected 2 results, got %d", len(results))
	}
	// each result must name the probe it came from
	labels := map[string]bool{}
	for _, r := range results {
		labels[r.Probe] = true
	}
	for _, p := range probes {
		if !labels[p.Label] {
			t.Fatalf("result for probe %q missing", p.Label)
		}
	}
}

// TestProbeOnBadURL confirms a malformed URL produces a clean error.
func TestProbeOnBadURL(t *testing.T) {
	c := DefaultSSRFClient()
	c.Timeout = 500 * time.Millisecond

	ctx := context.Background()
	res := c.Probe(ctx, SSRFProbe{Label: "bad", URL: "http://[invalid"})
	if res.Err == "" {
		t.Fatalf("expected error for bad URL, got result %+v", res)
	}
	if res.OK {
		t.Fatalf("bad URL marked OK")
	}
}

// TestProbeOnUnreachableHost confirms network errors land in the result
// without panicking.
func TestProbeOnUnreachableHost(t *testing.T) {
	c := DefaultSSRFClient()
	c.Timeout = 500 * time.Millisecond

	ctx := context.Background()
	res := c.Probe(ctx, SSRFProbe{
		Label: "unreachable",
		URL:   "http://192.0.2.1/", // TEST-NET-1, never routable
	})
	if res.OK {
		t.Fatalf("192.0.2.1 reachable (unexpected)")
	}
	// error should be set, or status should be 0
	if res.Err == "" && res.Status != 0 {
		t.Fatalf("no error and status set: %+v", res)
	}
}

// TestGopherRedisInfoShape checks the gopher payload strings.
func TestGopherRedisInfoShape(t *testing.T) {
	got := GopherRedisInfo()
	if !strings.HasSuffix(got, "\r\n") {
		t.Fatalf("gopher redis INFO should end with CRLF: %q", got)
	}
	if !strings.Contains(got, "INFO") {
		t.Fatalf("gopher redis INFO missing INFO: %q", got)
	}
	if !strings.Contains(got, "QUIT") {
		t.Fatalf("gopher redis INFO missing QUIT: %q", got)
	}
}

// TestGopherRedisWrite confirms the SET command encoding.
func TestGopherRedisWrite(t *testing.T) {
	got := GopherRedisWrite("key1", "value1")
	want := "SET key1 value1\r\nQUIT\r\n"
	if got != want {
		t.Fatalf("gopher redis SET:\n  got  %q\n  want %q", got, want)
	}
}

// TestGopherRedisWriteStripsCRLF confirms CRLF is stripped so the payload
// cannot form a second command. The only CRLF pairs in the output must be
// the two the format inserts (SET terminator + QUIT terminator).
func TestGopherRedisWriteStripsCRLF(t *testing.T) {
	// if CRLF were not stripped, this would produce 6 CRLF pairs (the two
	// we insert plus four from the two injected \r\n pairs)
	got := GopherRedisWrite("k\r\nINJECT", "v\r\nINJECT")
	crlfCount := strings.Count(got, "\r\n")
	if crlfCount != 2 {
		t.Fatalf("expected 2 CRLF separators, got %d: %q", crlfCount, got)
	}
	// and no bare CR or LF
	if strings.ContainsAny(got, "\r\n") {
		// there ARE CRLFs (the two legit ones), so this check should
		// verify no bare CR or bare LF outside the two pairs — count chars
		r := strings.Count(got, "\r")
		n := strings.Count(got, "\n")
		if r != 2 || n != 2 {
			t.Fatalf("bare CR=%d LF=%d (want 2/2): %q", r, n, got)
		}
	}
}

// TestFileProbesShape confirms the file probe list is well-formed.
func TestFileProbesShape(t *testing.T) {
	if len(FileProbes) == 0 {
		t.Fatal("no file probes")
	}
	for _, p := range FileProbes {
		if p.Label == "" || p.URL == "" {
			t.Fatalf("file probe malformed: %+v", p)
		}
		if !strings.HasPrefix(p.URL, "file://") {
			t.Fatalf("file probe URL not file://: %q", p.URL)
		}
	}
}

// TestInsecureTLSIsInsecure verifies the helper actually disables
// verification (intentional).
func TestInsecureTLSIsInsecure(t *testing.T) {
	cfg := insecureTLS()
	if !cfg.InsecureSkipVerify {
		t.Fatalf("insecureTLS did not set InsecureSkipVerify")
	}
}

// TestBuildFCGIRequestEmpty confirms a valid FastCGI request is
// produced for a basic invocation.
func TestBuildFCGIRequestEmpty(t *testing.T) {
	req := buildFCGIRequest("/var/www/html/index.php", nil)
	if len(req) < 16 {
		t.Fatalf("FastCGI request too short: %d bytes", len(req))
	}
	// first byte is version 1
	if req[0] != 1 {
		t.Fatalf("FastCGI version byte %d, want 1", req[0])
	}
}

// TestBuildFCGIWithParams confirms custom params make it into the request.
func TestBuildFCGIWithParams(t *testing.T) {
	params := map[string]string{
		"SCRIPT_FILENAME": "/index.php",
		"QUERY_STRING":    "a=b",
	}
	req := buildFCGIRequest("/index.php", params)
	// the params blob should contain the key strings
	body := string(req)
	if !strings.Contains(body, "SCRIPT_FILENAME") {
		t.Fatalf("SCRIPT_FILENAME missing from FastCGI request")
	}
	if !strings.Contains(body, "/index.php") {
		t.Fatalf("script path missing from FastCGI request")
	}
	if !strings.Contains(body, "QUERY_STRING") {
		t.Fatalf("QUERY_STRING missing from FastCGI request")
	}
}

// TestEncodeLengthNibbles exercises the length encoder used by FastCGI.
func TestEncodeLengthNibbles(t *testing.T) {
	var b bytes.Buffer
	writeLen(&b, 5)
	if b.Len() != 1 || b.Bytes()[0] != 5 {
		t.Fatalf("short length wrong: %v", b.Bytes())
	}
	b.Reset()
	writeLen(&b, 300)
	if b.Len() != 4 {
		t.Fatalf("long length should be 4 bytes, got %d", b.Len())
	}
	// top bit should be set
	if b.Bytes()[0]&0x80 == 0 {
		t.Fatalf("long length missing top bit: %v", b.Bytes())
	}
}
