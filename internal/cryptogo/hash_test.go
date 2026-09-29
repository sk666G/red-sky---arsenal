package cryptogo

import (
	"os"
	"path/filepath"
	"testing"
)

// Known NTLM hash values. NTLM of "password" is 8846f7eaee8fb117ad06bdd830b7586c
// — the classic NT hash every pentest cheat sheet has.
func TestNTLMKnownVector(t *testing.T) {
	got := NTLMHex([]byte("password"))
	want := "8846f7eaee8fb117ad06bdd830b7586c"
	if got != want {
		t.Fatalf("NTLM(password) mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// NTLM of the empty string. MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
// and NTLM("") is MD4 over the empty UTF-16LE string, which is empty.
func TestNTLMEmpty(t *testing.T) {
	got := NTLMHex([]byte(""))
	want := "31d6cfe0d16ae931b73c59d7e0c089c0"
	if got != want {
		t.Fatalf("NTLM(empty) mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// MD4 known vectors from RFC 1320.
func TestMD4KnownVectors(t *testing.T) {
	cases := []struct{ in, out string }{
		{"", "31d6cfe0d16ae931b73c59d7e0c089c0"},
		{"a", "bde52cb31de33e46245e05fbdbd6fb24"},
		{"abc", "a448017aaf21d8525fc10ae87aa6729d"},
		{"message digest", "d9130a8164549fe818874806e1c7014b"},
		{"abcdefghijklmnopqrstuvwxyz", "d79e1c308aa5bbcdeea8ed63df412da9"},
	}
	for _, c := range cases {
		got := hexEncode(MD4([]byte(c.in)))
		if got != c.out {
			t.Fatalf("MD4(%q) mismatch:\n  got  %s\n  want %s", c.in, got, c.out)
		}
	}
}

// TestHashOneMD5 pins md5("password").
func TestHashOneMD5(t *testing.T) {
	got, err := HashOne("md5", []byte("password"))
	if err != nil {
		t.Fatal(err)
	}
	want := "5f4dcc3b5aa765d61d8327deb882cf99"
	if got != want {
		t.Fatalf("md5 mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestHashOneSHA1 pins sha1("abc").
func TestHashOneSHA1(t *testing.T) {
	got, err := HashOne("sha1", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := "a9993e364706816aba3e25717850c26c9cd0d89d"
	if got != want {
		t.Fatalf("sha1 mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestHashOneSHA256 pins sha256("abc").
func TestHashOneSHA256(t *testing.T) {
	got, err := HashOne("sha256", []byte("abc"))
	if err != nil {
		t.Fatal(err)
	}
	want := "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got != want {
		t.Fatalf("sha256 mismatch:\n  got  %s\n  want %s", got, want)
	}
}

// TestHashOneUnknown rejects bad algorithm names.
func TestHashOneUnknown(t *testing.T) {
	_, err := HashOne("not-a-hash", []byte("x"))
	if err == nil {
		t.Fatalf("expected error for unknown algo")
	}
}

// TestIdentifyHashShapes covers the well-known shapes.
func TestIdentifyHashShapes(t *testing.T) {
	cases := []struct {
		hash    string
		wantOne string
	}{
		{"5f4dcc3b5aa765d61d8327deb882cf99", "md5"},
		{"8846f7eaee8fb117ad06bdd830b7586c", "md5"}, // 32 hex ambiguous with ntlm
		{"a9993e364706816aba3e25717850c26c9cd0d89d", "sha1"},
		{"ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", "sha256"},
		{"$2b$12$abcdefghijklmnopqrstuv", "bcrypt"},
		{"$1$abc$xyz", "md5crypt"},
		{"$5$abc$xyz", "sha256crypt"},
		{"$6$abc$xyz", "sha512crypt"},
		{"$argon2id$v=19$m=4096,t=3,p=1$x$x", "argon2"},
		{"$P$abcdefghijklmnopqrstuvwxyzABCD", "phpass"},
	}
	for _, c := range cases {
		got := IdentifyHash(c.hash)
		found := false
		for _, g := range got {
			if g == c.wantOne {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("identify(%q) = %v, missing %q", c.hash, got, c.wantOne)
		}
	}
}

// TestIdentifyHashAmbiguous checks that 32-hex returns both md5 and ntlm.
func TestIdentifyHashAmbiguous(t *testing.T) {
	got := IdentifyHash("8846f7eaee8fb117ad06bdd830b7586c")
	hasMD5 := false
	hasNTLM := false
	for _, g := range got {
		if g == "md5" {
			hasMD5 = true
		}
		if g == "ntlm" {
			hasNTLM = true
		}
	}
	if !hasMD5 || !hasNTLM {
		t.Fatalf("ambiguous 32-hex should return md5+ntlm: %v", got)
	}
}

// TestCrackHash finds a known password in a wordlist.
func TestCrackHash(t *testing.T) {
	tmp := t.TempDir()
	wl := filepath.Join(tmp, "words.txt")
	if err := os.WriteFile(wl, []byte("hunter2\npassword\nadmin\nroot\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target, _ := HashOne("md5", []byte("admin"))
	res, err := CrackHash("md5", target, wl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found {
		t.Fatalf("expected to find 'admin'")
	}
	if res.Word != "admin" {
		t.Fatalf("wrong word: %q", res.Word)
	}
	if res.Tried < 3 {
		t.Fatalf("wordlist too short — tried %d", res.Tried)
	}
}

// TestCrackHashNTLM finds a NTLM hash in the same wordlist.
func TestCrackHashNTLM(t *testing.T) {
	tmp := t.TempDir()
	wl := filepath.Join(tmp, "words.txt")
	if err := os.WriteFile(wl, []byte("letmein\npassword\nadmin\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target := NTLMHex([]byte("password"))
	res, err := CrackHash("ntlm", target, wl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Found {
		t.Fatalf("ntlm crack failed")
	}
	if res.Word != "password" {
		t.Fatalf("wrong word: %q", res.Word)
	}
}

// TestCrackHashNotFound exercises the negative path.
func TestCrackHashNotFound(t *testing.T) {
	tmp := t.TempDir()
	wl := filepath.Join(tmp, "words.txt")
	if err := os.WriteFile(wl, []byte("a\nb\nc\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	target, _ := HashOne("md5", []byte("nothing-in-here"))
	res, err := CrackHash("md5", target, wl, nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.Found {
		t.Fatalf("should not have found")
	}
}

// hexEncode is a small local wrapper for the tests.
func hexEncode(b []byte) string {
	const chars = "0123456789abcdef"
	out := make([]byte, len(b)*2)
	for i, x := range b {
		out[i*2] = chars[x>>4]
		out[i*2+1] = chars[x&0x0F]
	}
	return string(out)
}
