package adgo

import "testing"

func TestClassifyEntry_DomainAdminsMember(t *testing.T) {
	e := LDAPEntry{
		DN: "CN=Domain Admins,CN=Users,DC=corp,DC=local",
		Attrs: map[string][]string{
			"name":   {"Domain Admins"},
			"member": {"CN=alice,CN=Users,DC=corp,DC=local", "CN=bob,CN=Users,DC=corp,DC=local"},
		},
	}
	got := classifyEntry(e)
	if len(got) != 2 {
		t.Fatalf("want 2 members, got %d", len(got))
	}
	if got[0].Severity != "high" {
		t.Fatalf("severity: %q", got[0].Severity)
	}
}

func TestClassifyEntry_ASREPRoastable(t *testing.T) {
	e := LDAPEntry{
		DN: "CN=svc,CN=Users,DC=corp,DC=local",
		Attrs: map[string][]string{
			"samAccountName":     {"svc"},
			"userAccountControl": {"4260352"}, // 0x410000 | 0x20 | 0x10000
		},
	}
	got := classifyEntry(e)
	var found bool
	for _, v := range got {
		if v.Name == "AS-REP roastable user (DONT_REQ_PREAUTH)" {
			found = true
		}
	}
	if !found {
		t.Fatalf("DONT_REQ_PREAUTH not detected, got: %+v", got)
	}
}

func TestClassifyEntry_SPN(t *testing.T) {
	e := LDAPEntry{
		DN: "CN=mssql,CN=Users,DC=corp,DC=local",
		Attrs: map[string][]string{
			"samAccountName":       {"mssql"},
			"servicePrincipalName": {"MSSQLSvc/db.corp.local:1433"},
		},
	}
	got := classifyEntry(e)
	var found bool
	for _, v := range got {
		if v.Name == "Service account with SPN (Kerberoastable)" {
			found = true
			if v.Severity != "medium" {
				t.Fatalf("severity: %q", v.Severity)
			}
		}
	}
	if !found {
		t.Fatalf("SPN not detected, got: %+v", got)
	}
}

func TestClassifyEntry_OrdinaryUser(t *testing.T) {
	e := LDAPEntry{
		DN: "CN=alice,CN=Users,DC=corp,DC=local",
		Attrs: map[string][]string{
			"samAccountName":     {"alice"},
			"userAccountControl": {"512"}, // NORMAL_ACCOUNT
		},
	}
	got := classifyEntry(e)
	if len(got) != 0 {
		t.Fatalf("ordinary user should not classify, got: %+v", got)
	}
}

func TestClassifyMessage_ASREP(t *testing.T) {
	got := classifyMessage("asrep", "$krb5asrep$23$alice@CORP.LOCAL:abc123")
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].Severity != "high" {
		t.Fatalf("severity: %q", got[0].Severity)
	}
}

func TestClassifyMessage_Kerberoast(t *testing.T) {
	got := classifyMessage("kerberoast", "$krb5tgs$23$*mssql$CORP.LOCAL$...")
	if len(got) != 1 {
		t.Fatalf("want 1, got %d", len(got))
	}
	if got[0].Severity != "critical" {
		t.Fatalf("severity: %q", got[0].Severity)
	}
}
