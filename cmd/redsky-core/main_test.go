package main

import "testing"

func TestDomainFromDN(t *testing.T) {
	cases := []struct {
		dn   string
		want string
	}{
		{"CN=alice,CN=Users,DC=corp,DC=local", "corp.local"},
		{"CN=Domain Admins,CN=Users,DC=corp,DC=local", "corp.local"},
		{"DC=example,DC=com", "example.com"},
		{"OU=Groups,DC=sub,DC=example,DC=org", "sub.example.org"},
		{"CN=nothing-useful", "unknown-domain"},
		{"", "unknown-domain"},
	}
	for _, tc := range cases {
		if got := domainFromDN(tc.dn); got != tc.want {
			t.Fatalf("domainFromDN(%q) = %q, want %q", tc.dn, got, tc.want)
		}
	}
}
