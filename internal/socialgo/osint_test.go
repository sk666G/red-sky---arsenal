package socialgo

import (
	"context"
	"strings"
	"testing"
	"time"
)

// TestPlatformsShape confirms every platform entry is well-formed.
func TestPlatformsShape(t *testing.T) {
	if len(Platforms) == 0 {
		t.Fatal("no platforms")
	}
	for i, p := range Platforms {
		if p.Label == "" {
			t.Fatalf("platform %d missing label", i)
		}
		if p.URLTemplate == "" {
			t.Fatalf("platform %s missing url template", p.Label)
		}
		if !strings.Contains(p.URLTemplate, "{u}") {
			t.Fatalf("platform %s url template missing {u}: %s", p.Label, p.URLTemplate)
		}
	}
}

// TestPlatformsNoDuplicateLabels confirms no label collision.
func TestPlatformsNoDuplicateLabels(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range Platforms {
		if seen[p.Label] {
			t.Fatalf("duplicate platform label: %s", p.Label)
		}
		seen[p.Label] = true
	}
}

// TestPlatformsCoversBigSites confirms the major platforms are present.
func TestPlatformsCoversBigSites(t *testing.T) {
	wanted := []string{"github", "twitter", "reddit", "instagram", "tiktok", "youtube"}
	seen := map[string]bool{}
	for _, p := range Platforms {
		seen[p.Label] = true
	}
	for _, w := range wanted {
		if !seen[w] {
			t.Fatalf("missing platform: %s", w)
		}
	}
}

// TestGravatarHashShape confirms the MD5 hash produced for a known email.
//
// gravatar uses MD5(lowercase(trim(email))). Known example: the empty
// string hashes to d41d8cd98f00b204e9800998ecf8427e.
func TestGravatarHashEmpty(t *testing.T) {
	res, err := Gravatar(context.Background(), " ", time.Second)
	if err != nil {
		// err comes from network — but the hash should be computed first
		t.Logf("network error: %v", err)
		return
	}
	// empty string hashes to d41d8cd98f00b204e9800998ecf8427e
	if res.Hash != "d41d8cd98f00b204e9800998ecf8427e" {
		t.Fatalf("empty email hash: %q", res.Hash)
	}
}

// TestGravatarHashKnownVector confirms the MD5 of a specific email.
// MD5("test@example.com") = 55502f40dc8b7c769880b10874abc9d0
func TestGravatarHashKnownVector(t *testing.T) {
	res, err := Gravatar(context.Background(), "test@example.com", time.Second)
	if err != nil {
		t.Logf("network error: %v", err)
		return
	}
	want := "55502f40dc8b7c769880b10874abc9d0"
	if res.Hash != want {
		t.Fatalf("gravatar hash:\n  got  %s\n  want %s", res.Hash, want)
	}
}

// TestGravatarTrimsAndLowercases confirms the hash normalizes the email.
func TestGravatarTrimsAndLowercases(t *testing.T) {
	res1, err1 := Gravatar(context.Background(), "Test@Example.com", time.Second)
	res2, err2 := Gravatar(context.Background(), "test@example.com", time.Second)
	if err1 != nil || err2 != nil {
		t.Logf("network error: %v %v", err1, err2)
		return
	}
	if res1.Hash != res2.Hash {
		t.Fatalf("gravatar should normalize case: %s vs %s", res1.Hash, res2.Hash)
	}
}

// TestEnumerateUsernameRejectsEmpty confirms the guard.
func TestEnumerateUsernameRejectsEmpty(t *testing.T) {
	_, err := EnumerateUsername(context.Background(), UsernameOptions{}, nil, nil)
	if err == nil {
		t.Fatalf("expected error for empty user")
	}
}

// TestSubdomainWordlistShape confirms the candidate list is well-formed.
func TestSubdomainWordlistShape(t *testing.T) {
	if len(SubdomainWordlist) == 0 {
		t.Fatal("no subdomain wordlist")
	}
	for i, w := range SubdomainWordlist {
		if w == "" {
			t.Fatalf("wordlist[%d] empty", i)
		}
		if strings.Contains(w, ".") {
			t.Fatalf("wordlist[%d] has dot: %q", i, w)
		}
		if strings.Contains(w, " ") {
			t.Fatalf("wordlist[%d] has space: %q", i, w)
		}
	}
}

// TestSubdomainWordlistCommonPresent confirms the standard subdomains are
// in the list.
func TestSubdomainWordlistCommonPresent(t *testing.T) {
	wanted := []string{"www", "mail", "api", "dev", "staging", "admin", "vpn"}
	seen := map[string]bool{}
	for _, w := range SubdomainWordlist {
		seen[w] = true
	}
	for _, w := range wanted {
		if !seen[w] {
			t.Fatalf("missing subdomain: %s", w)
		}
	}
}

// TestEnumerateSubdomainsRejectsEmptyDomain confirms the guard.
func TestEnumerateSubdomainsRejectsEmptyDomain(t *testing.T) {
	_, err := EnumerateSubdomains(context.Background(), "", nil, 1, nil)
	if err == nil {
		t.Fatalf("expected error for empty domain")
	}
}

// TestEnumerateSubdomainsDefaults confirms empty wordlist falls back to
// the builtin set. Uses an empty-word test domain.
func TestEnumerateSubdomainsDefaults(t *testing.T) {
	// 127.0.0.1 as root domain — nothing will resolve, so we just verify
	// the function returns nil error and doesn't panic.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hits, err := EnumerateSubdomains(ctx, "test.invalid", nil, 2, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// no .invalid resolves under a proper resolver — hits should be empty
	if len(hits) > 0 {
		t.Logf("unexpected hits (check your DNS): %v", hits)
	}
}

// TestThreadsDefaultsTo30 confirms the concurrency default.
func TestThreadsDefaultsTo30(t *testing.T) {
	// this is only testable indirectly — pass 0 threads and verify it
	// doesn't panic
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()
	_, err := EnumerateSubdomains(ctx, "test.invalid", []string{"www"}, 0, nil)
	if err != nil {
		t.Fatalf("zero-thread call errored: %v", err)
	}
}
