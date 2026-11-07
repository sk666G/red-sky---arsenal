package engagement

import (
	"testing"
)

func freshDB(t *testing.T) *DB {
	t.Helper()
	t.Setenv("HOME", t.TempDir())
	db, err := Open("chaintest")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func mkHost(t *testing.T, db *DB, ip string) int64 {
	t.Helper()
	id, err := db.UpsertHost(Host{IP: ip})
	if err != nil {
		t.Fatalf("upsert %s: %v", ip, err)
	}
	return id
}

func TestWalkLinearChain(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	c := mkHost(t, db, "10.0.0.3")
	db.AddEdge(Edge{FromID: a, ToID: b, Kind: "creds"})
	db.AddEdge(Edge{FromID: b, ToID: c, Kind: "trust"})
	root, err := db.WalkFrom(a, 6)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if root.HostID != a || len(root.Children) != 1 {
		t.Fatalf("root: %+v", root)
	}
	if root.Children[0].HostID != b || len(root.Children[0].Children) != 1 {
		t.Fatalf("depth1: %+v", root.Children[0])
	}
	if root.Children[0].Children[0].HostID != c {
		t.Fatalf("depth2: %+v", root.Children[0].Children[0])
	}
}

func TestWalkCycle(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	db.AddEdge(Edge{FromID: a, ToID: b, Kind: "creds"})
	db.AddEdge(Edge{FromID: b, ToID: a, Kind: "trust"})
	root, err := db.WalkFrom(a, 6)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(root.Children) != 1 {
		t.Fatalf("expected one child, got %d", len(root.Children))
	}
	back := root.Children[0].Children[0]
	if !back.Cycle {
		t.Fatalf("expected Cycle, got %+v", back)
	}
	if len(back.Children) != 0 {
		t.Fatalf("cycle node must not expand")
	}
}

func TestWalkDepthCap(t *testing.T) {
	db := freshDB(t)
	ids := make([]int64, 6)
	for i := range ids {
		ids[i] = mkHost(t, db, "10.0.0."+string(rune('1'+i)))
	}
	for i := 0; i < len(ids)-1; i++ {
		db.AddEdge(Edge{FromID: ids[i], ToID: ids[i+1], Kind: "reach"})
	}
	root, err := db.WalkFrom(ids[0], 2)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	depth := 0
	n := root
	for len(n.Children) > 0 {
		n = n.Children[0]
		depth++
	}
	if depth > 2 {
		t.Fatalf("depth cap violated: %d", depth)
	}
}

func TestWalkDiamond(t *testing.T) {
	db := freshDB(t)
	a := mkHost(t, db, "10.0.0.1")
	b := mkHost(t, db, "10.0.0.2")
	c := mkHost(t, db, "10.0.0.3")
	d := mkHost(t, db, "10.0.0.4")
	db.AddEdge(Edge{FromID: a, ToID: b, Kind: "reach"})
	db.AddEdge(Edge{FromID: a, ToID: c, Kind: "reach"})
	db.AddEdge(Edge{FromID: b, ToID: d, Kind: "trust"})
	db.AddEdge(Edge{FromID: c, ToID: d, Kind: "trust"})
	root, err := db.WalkFrom(a, 6)
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(root.Children) != 2 {
		t.Fatalf("expected two arms, got %d", len(root.Children))
	}
	for _, arm := range root.Children {
		if len(arm.Children) != 1 || arm.Children[0].HostID != d {
			t.Fatalf("arm %d: %+v", arm.HostID, arm)
		}
		if arm.Children[0].Cycle {
			t.Fatalf("diamond false cycle")
		}
	}
}

func TestWalkUnknownRoot(t *testing.T) {
	db := freshDB(t)
	if _, err := db.WalkFrom(999, 6); err == nil {
		t.Fatal("expected error on missing host")
	}
}
