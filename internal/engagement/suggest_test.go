package engagement

import "testing"

func TestSuggestCredsLateral(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	db.AddEdge(Edge{FromID: a, ToID: b, Kind: "trust"})
	db.AddCred(Cred{HostID: a, Service: "smb", User: "admin", Pass: "hash", Source: "kerberoast"})
	sugs, err := db.Suggest(0)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	found := false
	for _, s := range sugs {
		if s.Rule == "creds-lateral" && s.FromID == a && s.ToID == b {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected creds-lateral, got %+v", sugs)
	}
}

func TestSuggestEscalateReach(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	db.AddEdge(Edge{FromID: a, ToID: b, Kind: "reach"})
	db.AddVuln(Vuln{HostID: a, Name: "CVE-2024-0001", Severity: "critical"})
	sugs, err := db.Suggest(0)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	found := false
	for _, s := range sugs {
		if s.Rule == "escalate-reach" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected escalate-reach, got %+v", sugs)
	}
}

func TestSuggestOrphanCreds(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	db.AddCred(Cred{HostID: a, User: "u", Pass: "p"})
	sugs, err := db.Suggest(0)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	found := false
	for _, s := range sugs {
		if s.Rule == "orphan-creds" && s.FromID == a {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected orphan-creds, got %+v", sugs)
	}
}

func TestSuggestOrphanTrust(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	db.AddEdge(Edge{FromID: a, ToID: b, Kind: "trust"})
	sugs, err := db.Suggest(0)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	found := false
	for _, s := range sugs {
		if s.Rule == "orphan-trust" && s.FromID == a {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected orphan-trust, got %+v", sugs)
	}
}

func TestSuggestHub(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	c := mkHost(t, db, "10.0.0.3")
	d := mkHost(t, db, "10.0.0.4")
	db.AddEdge(Edge{FromID: a, ToID: b, Kind: "reach"})
	db.AddEdge(Edge{FromID: a, ToID: c, Kind: "reach"})
	db.AddEdge(Edge{FromID: a, ToID: d, Kind: "reach"})
	sugs, err := db.Suggest(0)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	found := false
	for _, s := range sugs {
		if s.Rule == "hub" && s.FromID == a {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected hub, got %+v", sugs)
	}
}

func TestSuggestFilterByHost(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	db.AddCred(Cred{HostID: a, User: "u", Pass: "p"})
	db.AddEdge(Edge{FromID: b, ToID: a, Kind: "reach"})
	sugs, err := db.Suggest(b)
	if err != nil {
		t.Fatalf("suggest: %v", err)
	}
	for _, s := range sugs {
		if s.FromID != b {
			t.Fatalf("filter leaked: %+v", s)
		}
	}
}
