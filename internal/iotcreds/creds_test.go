package iotcreds

import (
	"strings"
	"testing"
)

// TestBuiltinCredsShape confirms every credential is well-formed.
func TestBuiltinCredsShape(t *testing.T) {
	if len(BuiltinCreds) == 0 {
		t.Fatal("no credentials in the table")
	}
	for i, c := range BuiltinCreds {
		if c.Vendor == "" {
			t.Fatalf("cred %d missing vendor: %+v", i, c)
		}
		// user and pass may be empty for a few (redis, mikrotik admin)
		// but the vendor must be set
	}
}

// TestBuiltinCredsContainsClassics confirms the well-known default
// credentials are present. If somebody trims the table, these must stay.
func TestBuiltinCredsContainsClassics(t *testing.T) {
	required := []struct{ user, pass string }{
		{"admin", "admin"},
		{"admin", "password"},
		{"admin", "12345"}, // Hikvision
		{"root", "root"},
		{"root", "toor"},
		{"admin", ""}, // ubiquitous on older firmware
		{"root", ""},
		{"cisco", "cisco"},
		{"ubnt", "ubnt"},    // Ubiquiti
		{"pi", "raspberry"}, // SCADA default
		{"postgres", "postgres"},
	}
	for _, want := range required {
		found := false
		for _, c := range BuiltinCreds {
			if c.User == want.user && c.Pass == want.pass {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing required cred %s/%s", want.user, want.pass)
		}
	}
}

// TestBuiltinCredsHasVendors checks the table covers the major vendor
// families. Not exhaustive — just guarding against an accidental sweep.
func TestBuiltinCredsHasVendors(t *testing.T) {
	wanted := []string{"hikvision", "dahua", "axis", "netgear", "tp-link", "cisco", "siemens", "mqtt", "redis"}
	seen := map[string]bool{}
	for _, c := range BuiltinCreds {
		seen[strings.ToLower(c.Vendor)] = true
	}
	for _, w := range wanted {
		if !seen[w] {
			t.Fatalf("missing vendor in table: %q", w)
		}
	}
}

// TestCountMatchesLen — trivially true but the helper should stay in sync.
func TestCountMatchesLen(t *testing.T) {
	if Count() != len(BuiltinCreds) {
		t.Fatalf("Count() = %d, len(BuiltinCreds) = %d", Count(), len(BuiltinCreds))
	}
}

// TestHitStringRendering confirms the Hit String() renders the expected
// short form.
func TestHitStringRendering(t *testing.T) {
	h := Hit{Host: "192.168.1.1", Port: 80, Protocol: "http", Vendor: "generic", User: "admin", Pass: "admin"}
	got := h.String()
	if !strings.Contains(got, "192.168.1.1") || !strings.Contains(got, "admin") {
		t.Fatalf("hit string missing host/user: %q", got)
	}
	// empty password renders as "(empty)"
	h.Pass = ""
	got = h.String()
	if !strings.Contains(got, "(empty)") {
		t.Fatalf("empty password not rendered as (empty): %q", got)
	}
}

// TestSprayValidation checks that Spray rejects unknown protocols without
// hitting the network.
func TestSprayValidation(t *testing.T) {
	_, err := Spray(nil, SprayOptions{Host: "127.0.0.1", Protocol: "bogus"}, nil)
	if err == nil {
		t.Fatalf("expected error for unknown protocol")
	}
	if !strings.Contains(err.Error(), "unknown protocol") {
		t.Fatalf("error message not clear: %v", err)
	}
}

// TestSprayOnUnreachableHost confirms the HTTP spray bails cleanly when
// the target port is closed.
func TestSprayOnUnreachableHost(t *testing.T) {
	// TEST-NET-1 is never routable
	res, err := Spray(nil, SprayOptions{
		Host:     "192.0.2.1",
		Port:     80,
		Protocol: "http",
		Timeout:  1,
	}, nil)
	if err != nil {
		// error is fine — the point is it doesn't hang or panic
		return
	}
	if len(res) > 0 {
		t.Fatalf("unexpected hits against unroutable host: %v", res)
	}
}

// TestCredentialsHaveConsistentVendorCase confirms the vendor names are
// lowercase (they're the identifiers used elsewhere).
func TestCredentialsHaveConsistentVendorCase(t *testing.T) {
	for i, c := range BuiltinCreds {
		if c.Vendor != strings.ToLower(c.Vendor) {
			t.Fatalf("cred %d vendor not lowercased: %q", i, c.Vendor)
		}
	}
}

// TestNoDuplicateExactCreds confirms no exact dup (vendor+user+pass) in
// the table.
func TestNoDuplicateExactCreds(t *testing.T) {
	seen := map[string]bool{}
	for i, c := range BuiltinCreds {
		key := c.Vendor + "|" + c.User + "|" + c.Pass
		if seen[key] {
			t.Fatalf("duplicate exact cred at %d: %s/%s (vendor %s)", i, c.User, c.Pass, c.Vendor)
		}
		seen[key] = true
	}
}
