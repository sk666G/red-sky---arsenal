package recon2

import (
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

func TestClassifyCCTV_CredsCaptured(t *testing.T) {
	got := ClassifyCCTV(proto.CCTVData{
		URL:  "rtsp://10.0.0.5:554/stream",
		OK:   true,
		User: "admin",
		Pass: "admin",
		Note: "scan_creds match",
	})
	if len(got) != 1 || got[0].Severity != "critical" {
		t.Fatalf("want 1 critical, got %+v", got)
	}
}

func TestClassifyCCTV_AuthRealm(t *testing.T) {
	got := ClassifyCCTV(proto.CCTVData{
		URL:       "rtsp://10.0.0.5:554/",
		OK:        true,
		Status:    401,
		AuthRealm: "IP Camera",
	})
	if len(got) != 1 || got[0].Severity != "medium" {
		t.Fatalf("want 1 medium, got %+v", got)
	}
}

func TestClassifyCCTV_Unauthenticated(t *testing.T) {
	got := ClassifyCCTV(proto.CCTVData{
		URL:    "rtsp://10.0.0.5:554/stream1",
		OK:     true,
		Status: 200,
		Server: "Hikvision",
	})
	if len(got) != 1 || got[0].Severity != "high" {
		t.Fatalf("want 1 high, got %+v", got)
	}
}

func TestClassifyCCTV_NoCredsMatched(t *testing.T) {
	if got := ClassifyCCTV(proto.CCTVData{
		URL:  "rtsp://10.0.0.5:554/",
		OK:   false,
		Note: "no creds matched",
	}); len(got) != 0 {
		t.Fatalf("no-creds-match should skip, got %+v", got)
	}
}

func TestClassifyCCTV_ErrorSkipped(t *testing.T) {
	if got := ClassifyCCTV(proto.CCTVData{
		Error: "connection timeout",
	}); len(got) != 0 {
		t.Fatalf("error should skip, got %+v", got)
	}
}

func TestClassifyCCTV_DoneSkipped(t *testing.T) {
	if got := ClassifyCCTV(proto.CCTVData{
		Done: true,
		OK:   true,
		User: "u", Pass: "p",
	}); len(got) != 0 {
		t.Fatalf("done should skip, got %+v", got)
	}
}
