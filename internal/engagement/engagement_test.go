package engagement

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// isolate redirects HOME so the test never touches the real ~/.redsky.
func isolate(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CACHE_HOME", filepath.Join(dir, ".cache"))
}

func TestOpenCreatesFile(t *testing.T) {
	isolate(t)
	db, err := Open("test-eng")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()
	if _, err := os.Stat(db.Path()); err != nil {
		t.Fatalf("db file missing: %v", err)
	}
}

func TestOpenEmptyName(t *testing.T) {
	isolate(t)
	if _, err := Open(""); err == nil {
		t.Fatal("empty name accepted")
	}
}

func TestUpsertHostIdempotent(t *testing.T) {
	isolate(t)
	db, err := Open("test-eng")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	id1, err := db.UpsertHost(Host{IP: "10.0.0.1", Hostname: "host1"})
	if err != nil {
		t.Fatalf("first upsert: %v", err)
	}
	id2, err := db.UpsertHost(Host{IP: "10.0.0.1", OS: "linux"})
	if err != nil {
		t.Fatalf("second upsert: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("ids differ: %d vs %d", id1, id2)
	}
	hosts, err := db.Hosts()
	if err != nil {
		t.Fatalf("Hosts: %v", err)
	}
	if len(hosts) != 1 {
		t.Fatalf("want 1 host, got %d", len(hosts))
	}
	if hosts[0].Hostname != "host1" {
		t.Fatalf("Hostname lost on update: %q", hosts[0].Hostname)
	}
	if hosts[0].OS != "linux" {
		t.Fatalf("OS not set on update: %q", hosts[0].OS)
	}
}

func TestServicesAndVulnsAndCreds(t *testing.T) {
	isolate(t)
	db, err := Open("test-eng")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	h, _ := db.UpsertHost(Host{IP: "10.0.0.5"})
	svc, err := db.UpsertService(Service{HostID: h, Port: 22, Protocol: "tcp", Banner: "OpenSSH_9.0"})
	if err != nil {
		t.Fatalf("service: %v", err)
	}
	if _, err := db.AddVuln(Vuln{HostID: h, ServiceID: svc, Name: "CVE-2024-6387", Severity: "high", Evidence: "banner match"}); err != nil {
		t.Fatalf("vuln: %v", err)
	}
	if _, err := db.AddCred(Cred{HostID: h, Service: "ssh", User: "root", Pass: "toor", Source: "spray"}); err != nil {
		t.Fatalf("cred: %v", err)
	}

	services, _ := db.Services(h)
	if len(services) != 1 || services[0].Port != 22 {
		t.Fatalf("services: %+v", services)
	}
	vulns, _ := db.Vulns(h)
	if len(vulns) != 1 || vulns[0].Name != "CVE-2024-6387" {
		t.Fatalf("vulns: %+v", vulns)
	}
	creds, _ := db.Creds(h)
	if len(creds) != 1 || creds[0].User != "root" {
		t.Fatalf("creds: %+v", creds)
	}
}

func TestFindingJSONRoundTrip(t *testing.T) {
	isolate(t)
	db, err := Open("test-eng")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	payload := map[string]any{"url": "https://x", "status": 200}
	raw, _ := json.Marshal(payload)
	if _, err := db.AddFinding(Finding{Module: "webreq", Kind: "response", Data: raw}); err != nil {
		t.Fatalf("finding: %v", err)
	}
	out, err := db.Findings("webreq")
	if err != nil {
		t.Fatalf("Findings: %v", err)
	}
	if len(out) != 1 {
		t.Fatalf("want 1 finding, got %d", len(out))
	}
	var got map[string]any
	if err := json.Unmarshal(out[0].Data, &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if got["url"] != "https://x" {
		t.Fatalf("roundtrip lost url: %+v", got)
	}
}

func TestReopenPersists(t *testing.T) {
	isolate(t)
	db, err := Open("persist-eng")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	id, _ := db.UpsertHost(Host{IP: "192.168.1.1"})
	if _, err := db.AddCred(Cred{HostID: id, User: "admin", Pass: "admin"}); err != nil {
		t.Fatalf("cred: %v", err)
	}
	db.Close()

	db2, err := Open("persist-eng")
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer db2.Close()
	hosts, _ := db2.Hosts()
	if len(hosts) != 1 || hosts[0].IP != "192.168.1.1" {
		t.Fatalf("host lost on reopen: %+v", hosts)
	}
	creds, _ := db2.Creds(hosts[0].ID)
	if len(creds) != 1 {
		t.Fatalf("creds lost on reopen: %+v", creds)
	}
}
