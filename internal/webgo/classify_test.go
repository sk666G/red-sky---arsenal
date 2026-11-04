package webgo

import (
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

func TestClassifySSRF_IMDS(t *testing.T) {
	got := ClassifySSRF(proto.WebSSRFData{
		URL:     "http://169.254.169.254/latest/meta-data/ami-id",
		OK:      true,
		Status:  200,
		Body:    "ami-id\ninstance-id\nsecurity-credentials",
		BodyLen: 42,
	})
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].Severity != "critical" {
		t.Fatalf("severity: %q", got[0].Severity)
	}
}

func TestClassifySSRF_AdminPanel(t *testing.T) {
	got := ClassifySSRF(proto.WebSSRFData{
		URL:    "http://127.0.0.1:8080/server-status",
		OK:     true,
		Status: 200,
		Body:   "server status page",
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

func TestClassifySSRF_NonMatch(t *testing.T) {
	got := ClassifySSRF(proto.WebSSRFData{
		URL:    "http://target.com/hello",
		OK:     true,
		Status: 200,
		Body:   "hello world",
	})
	if len(got) != 1 || got[0].Severity != "info" {
		t.Fatalf("want 1 info, got %+v", got)
	}
}

func TestClassifySSRF_SkippedOnError(t *testing.T) {
	if got := ClassifySSRF(proto.WebSSRFData{
		URL:    "http://target.com",
		OK:     false,
		Status: 0,
		Err:    "connection refused",
	}); len(got) != 0 {
		t.Fatalf("failed probe should skip, got %+v", got)
	}
}

func TestClassifyWebReq_200(t *testing.T) {
	got := ClassifyWebReq(proto.WebReqData{
		Status:     200,
		StatusLine: "200 OK",
		BodyLen:    1024,
	})
	if len(got) != 1 || got[0].Severity != "info" {
		t.Fatalf("want 1 info, got %+v", got)
	}
}

func TestClassifyWebReq_ServerError(t *testing.T) {
	got := ClassifyWebReq(proto.WebReqData{
		Status:     500,
		StatusLine: "500 Internal Server Error",
	})
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if !contains(got[0].Name, "500") {
		t.Fatalf("name should mention status: %q", got[0].Name)
	}
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(s) > 0 && (s[:len(sub)] == sub || contains(s[1:], sub)))
}
