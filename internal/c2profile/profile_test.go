package c2profile

import (
	"os"
	"path/filepath"
	"testing"
)

func writeProfile(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, "profile.json")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadMinimalDefaults(t *testing.T) {
	p := writeProfile(t, `{}`)
	prof, err := Load(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if prof.UserAgent != DefaultUserAgent {
		t.Fatalf("UA not defaulted: %q", prof.UserAgent)
	}
	if prof.SleepMS != DefaultSleepMS {
		t.Fatalf("sleep not defaulted: %d", prof.SleepMS)
	}
	if prof.JitterPct != DefaultJitterPct {
		t.Fatalf("jitter not defaulted: %d", prof.JitterPct)
	}
	if len(prof.URIs) != 1 || prof.URIs[0] != "/" {
		t.Fatalf("uris not defaulted: %v", prof.URIs)
	}
	if prof.BodyEncoding != "none" {
		t.Fatalf("encoding not defaulted: %q", prof.BodyEncoding)
	}
}

func TestLoadFull(t *testing.T) {
	body := `{
		"name": "test",
		"useragent": "curl/8.0",
		"uris": ["/api/v1/sync/{id}", "/static/app.js"],
		"headers": {"Host": "example.com"},
		"sleep_ms": 30000,
		"jitter_pct": 50,
		"padding_min": 32,
		"padding_max": 128,
		"body_encoding": "base64"
	}`
	prof, err := Load(writeProfile(t, body))
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if prof.UserAgent != "curl/8.0" {
		t.Fatalf("UA: %q", prof.UserAgent)
	}
	if prof.SleepMS != 30000 || prof.JitterPct != 50 {
		t.Fatalf("sleep/jitter: %d/%d", prof.SleepMS, prof.JitterPct)
	}
	if len(prof.URIs) != 2 {
		t.Fatalf("uris: %v", prof.URIs)
	}
	if prof.Headers["Host"] != "example.com" {
		t.Fatalf("headers: %v", prof.Headers)
	}
	if prof.BodyEncoding != "base64" {
		t.Fatalf("encoding: %q", prof.BodyEncoding)
	}
}

func TestRenderURI(t *testing.T) {
	if got := RenderURI("/api/{id}/sync", "abc123"); got != "/api/abc123/sync" {
		t.Fatalf("render: %q", got)
	}
	if got := RenderURI("/static/x.js", "abc"); got != "/static/x.js" {
		t.Fatalf("no token: %q", got)
	}
	if got := RenderURI("/api/{id}", ""); got != "/api/{id}" {
		t.Fatalf("empty id: %q", got)
	}
}

func TestEncodeDecodeRoundtrip(t *testing.T) {
	raw := []byte(`{"envelope":"test","payload":{"cmd":"whoami"}}`)
	for _, enc := range []string{"none", "base64", "hex"} {
		p := &Profile{BodyEncoding: enc}
		e, err := p.EncodeBody(raw)
		if err != nil {
			t.Fatalf("%s encode: %v", enc, err)
		}
		d, err := p.DecodeBody(e)
		if err != nil {
			t.Fatalf("%s decode: %v", enc, err)
		}
		if string(d) != string(raw) {
			t.Fatalf("%s roundtrip: %q != %q", enc, d, raw)
		}
	}
}

func TestPadStripRoundtrip(t *testing.T) {
	p := &Profile{PaddingMin: 32, PaddingMax: 64}
	raw := []byte(`{"payload":"data"}`)
	padded := p.PadBody(raw)
	if len(padded) <= len(raw) {
		t.Fatalf("no padding added: len %d", len(padded))
	}
	stripped := StripPadding(padded)
	if string(stripped) != string(raw) {
		t.Fatalf("stripped: %q != %q", stripped, raw)
	}
}

func TestSleepJitterRange(t *testing.T) {
	p := &Profile{SleepMS: 1000, JitterPct: 50}
	for i := 0; i < 100; i++ {
		ms := p.SleepJitterMS()
		if ms < 500 || ms > 1500 {
			t.Fatalf("out of range: %d", ms)
		}
	}
}

func TestLoadBadJSON(t *testing.T) {
	if _, err := Load(writeProfile(t, `{not json}`)); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load("/nonexistent/path/profile.json"); err == nil {
		t.Fatal("expected missing-file error")
	}
}

func TestValidateBadEncoding(t *testing.T) {
	p := writeProfile(t, `{"body_encoding":"rot13"}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected encoding validation error")
	}
}

func TestValidateBadURI(t *testing.T) {
	p := writeProfile(t, `{"uris":["api/v1/no-leading-slash"]}`)
	if _, err := Load(p); err == nil {
		t.Fatal("expected URI validation error")
	}
}
