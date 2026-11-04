package recon2

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/sk666G/red-sky---arsenal/internal/engagement"
)

func isolateDB(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	_ = os.MkdirAll(filepath.Join(dir, ".redsky", "engagements"), 0o755)
}

func TestReportFromDB_Empty(t *testing.T) {
	isolateDB(t)
	db, err := engagement.Open("test-report-eng")
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	defer db.Close()

	r, err := ReportFromDB(db, "Test", "op", "test-report-eng")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(r.Findings) != 0 {
		t.Fatalf("expected 0 findings on empty DB, got %d", len(r.Findings))
	}
	if r.Meta.Title != "Test" {
		t.Fatalf("title: %q", r.Meta.Title)
	}
}

func TestReportFromDB_HostWithServicesOnly(t *testing.T) {
	isolateDB(t)
	db, err := engagement.Open("test-report-eng")
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	defer db.Close()

	hostID, _ := db.UpsertHost(engagement.Host{IP: "10.0.0.1"})
	if _, err := db.UpsertService(engagement.Service{HostID: hostID, Port: 22, Protocol: "tcp", State: "open"}); err != nil {
		t.Fatalf("service: %v", err)
	}
	if _, err := db.UpsertService(engagement.Service{HostID: hostID, Port: 80, Protocol: "tcp", State: "open"}); err != nil {
		t.Fatalf("service: %v", err)
	}

	r, err := ReportFromDB(db, "Test", "op", "test-report-eng")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 informational finding, got %d", len(r.Findings))
	}
	if r.Findings[0].Target != "10.0.0.1" {
		t.Fatalf("target: %q", r.Findings[0].Target)
	}
	if r.Findings[0].Severity != SeverityInfo {
		t.Fatalf("severity: %q", r.Findings[0].Severity)
	}
}

func TestReportFromDB_HostWithVulns(t *testing.T) {
	isolateDB(t)
	db, err := engagement.Open("test-report-eng")
	if err != nil {
		t.Fatalf("db open: %v", err)
	}
	defer db.Close()

	hostID, _ := db.UpsertHost(engagement.Host{IP: "10.0.0.5"})
	svcID, _ := db.UpsertService(engagement.Service{HostID: hostID, Port: 445, Protocol: "tcp", State: "open"})
	if _, err := db.AddVuln(engagement.Vuln{
		HostID: hostID, ServiceID: svcID, Name: "MS17-010", Severity: "critical", Evidence: "smb sig",
	}); err != nil {
		t.Fatalf("vuln: %v", err)
	}

	r, err := ReportFromDB(db, "Test", "op", "test-report-eng")
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if len(r.Findings) != 1 {
		t.Fatalf("expected 1 finding, got %d", len(r.Findings))
	}
	if r.Findings[0].Title != "MS17-010" {
		t.Fatalf("title: %q", r.Findings[0].Title)
	}
	if r.Findings[0].Severity != SeverityCritical {
		t.Fatalf("severity: %q", r.Findings[0].Severity)
	}
}
