package adgo

import (
	"strings"
	"testing"
)

// --- Test helpers ---

// mkEntry builds a minimal LDAPEntry with the given attributes.
func mkEntry(dn string, attrs map[string][]string) LDAPEntry {
	e := LDAPEntry{DN: dn, Attrs: map[string][]string{}}
	for k, v := range attrs {
		e.Attrs[strings.ToLower(k)] = v
	}
	return e
}

// --- AnalyzeTemplate ---

func TestESC1Positive(t *testing.T) {
	// ESC1: enrollee can supply subject (0x01 flag) + client-auth EKU +
	// no manager approval
	e := mkEntry("CN=User", map[string][]string{
		"cn":                          {"User"},
		"msPKI-Certificate-Name-Flag": {"1"},
		"pKIExtendedKeyUsage":         {EKUClientAuth},
	})
	r := AnalyzeTemplate(e)
	found := false
	for _, v := range r.Vulnerabilities {
		if v == "ESC1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ESC1 not detected in %v", r.Vulnerabilities)
	}
}

func TestESC1RequiresClientAuthOrAnyPurpose(t *testing.T) {
	// enrollee-supplies-subject but wrong EKU → no ESC1
	e := mkEntry("CN=User", map[string][]string{
		"cn":                          {"User"},
		"msPKI-Certificate-Name-Flag": {"1"},
		"pKIExtendedKeyUsage":         {EKUServerAuth}, // server auth only
	})
	r := AnalyzeTemplate(e)
	for _, v := range r.Vulnerabilities {
		if v == "ESC1" {
			t.Fatalf("ESC1 fired without client-auth EKU")
		}
	}
}

func TestESC1BlockedByManagerApproval(t *testing.T) {
	// enrollee-supplies-subject + client auth BUT manager approval required
	e := mkEntry("CN=User", map[string][]string{
		"cn":                          {"User"},
		"msPKI-Certificate-Name-Flag": {"1"},
		"pKIExtendedKeyUsage":         {EKUClientAuth},
		"msPKI-Enrollment-Flag":       {"2"}, // PendAllRequests
	})
	r := AnalyzeTemplate(e)
	for _, v := range r.Vulnerabilities {
		if v == "ESC1" {
			t.Fatalf("ESC1 fired despite manager approval requirement")
		}
	}
}

func TestESC1WithAnyPurposeEKU(t *testing.T) {
	// enrollee-supplies-subject + Any Purpose EKU (which subsumes client auth)
	e := mkEntry("CN=User", map[string][]string{
		"cn":                          {"User"},
		"msPKI-Certificate-Name-Flag": {"1"},
		"pKIExtendedKeyUsage":         {EKUAnyPurpose},
	})
	r := AnalyzeTemplate(e)
	found := false
	for _, v := range r.Vulnerabilities {
		if v == "ESC1" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ESC1 not detected with Any Purpose EKU: %v", r.Vulnerabilities)
	}
}

func TestESC2AnyPurpose(t *testing.T) {
	e := mkEntry("CN=Any", map[string][]string{
		"cn":                  {"Any"},
		"pKIExtendedKeyUsage": {EKUAnyPurpose},
	})
	r := AnalyzeTemplate(e)
	found := false
	for _, v := range r.Vulnerabilities {
		if v == "ESC2" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ESC2 not detected: %v", r.Vulnerabilities)
	}
}

func TestESC2EmptyEKU(t *testing.T) {
	// no pKIExtendedKeyUsage at all → ESC2
	e := mkEntry("CN=NoEKU", map[string][]string{
		"cn": {"NoEKU"},
	})
	r := AnalyzeTemplate(e)
	found := false
	for _, v := range r.Vulnerabilities {
		if v == "ESC2" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ESC2 not detected for empty EKU: %v", r.Vulnerabilities)
	}
}

func TestESC3CertRequestAgent(t *testing.T) {
	e := mkEntry("CN=Agent", map[string][]string{
		"cn":                  {"Agent"},
		"pKIExtendedKeyUsage": {EKUCertRequestAgent},
	})
	r := AnalyzeTemplate(e)
	found := false
	for _, v := range r.Vulnerabilities {
		if v == "ESC3" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ESC3 not detected: %v", r.Vulnerabilities)
	}
}

func TestTemplateWithNoRisk(t *testing.T) {
	// a well-configured template: server-auth only, no enrollee subject
	e := mkEntry("CN=WebServer", map[string][]string{
		"cn":                  {"WebServer"},
		"pKIExtendedKeyUsage": {EKUServerAuth},
	})
	r := AnalyzeTemplate(e)
	if len(r.Vulnerabilities) != 0 {
		t.Fatalf("clean template flagged: %v", r.Vulnerabilities)
	}
}

// --- AnalyzeCA ---

func TestESC6EditFlags(t *testing.T) {
	// CA with EDITF_ATTRIBUTESUBJECTALTNAME2 set: 0x00040000 = 262144
	e := mkEntry("CN=Corp-CA", map[string][]string{
		"cn":          {"Corp-CA"},
		"dNSHostName": {"ca.corp.local"},
		"editFlags":   {"262144"},
	})
	r := AnalyzeCA(e)
	found := false
	for _, v := range r.Vulnerabilities {
		if v == "ESC6" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("ESC6 not detected: %v", r.Vulnerabilities)
	}
	if r.Hostname != "ca.corp.local" {
		t.Fatalf("hostname parse: %q", r.Hostname)
	}
}

func TestESC6NotFired(t *testing.T) {
	// CA without the flag set
	e := mkEntry("CN=Corp-CA", map[string][]string{
		"cn":        {"Corp-CA"},
		"editFlags": {"0"},
	})
	r := AnalyzeCA(e)
	if len(r.Vulnerabilities) != 0 {
		t.Fatalf("clean CA flagged: %v", r.Vulnerabilities)
	}
}

// --- AnalyzeADCS composite ---

func TestAnalyzeADCSComposite(t *testing.T) {
	cas := []LDAPEntry{
		mkEntry("CN=CA", map[string][]string{
			"cn":        {"CA"},
			"editFlags": {"262144"},
		}),
	}
	tpls := []LDAPEntry{
		mkEntry("CN=T1", map[string][]string{
			"cn":                          {"T1"},
			"msPKI-Certificate-Name-Flag": {"1"},
			"pKIExtendedKeyUsage":         {EKUClientAuth},
		}),
		mkEntry("CN=T2", map[string][]string{
			"cn":                  {"T2"},
			"pKIExtendedKeyUsage": {EKUAnyPurpose},
		}),
	}
	caRisks, tplRisks := AnalyzeADCS(cas, tpls)
	if len(caRisks) != 1 {
		t.Fatalf("caRisks %d", len(caRisks))
	}
	if len(caRisks[0].Vulnerabilities) == 0 {
		t.Fatalf("CA risk not detected")
	}
	if len(tplRisks) != 2 {
		t.Fatalf("tplRisks %d", len(tplRisks))
	}
	// T1 should have ESC1; T2 should have ESC2
	t1HasESC1 := false
	for _, v := range tplRisks[0].Vulnerabilities {
		if v == "ESC1" {
			t1HasESC1 = true
		}
	}
	if !t1HasESC1 {
		t.Fatalf("T1 missing ESC1: %v", tplRisks[0].Vulnerabilities)
	}
	t2HasESC2 := false
	for _, v := range tplRisks[1].Vulnerabilities {
		if v == "ESC2" {
			t2HasESC2 = true
		}
	}
	if !t2HasESC2 {
		t.Fatalf("T2 missing ESC2: %v", tplRisks[1].Vulnerabilities)
	}
}

// --- Attribute parsing ---

func TestParseUintAttr(t *testing.T) {
	e := mkEntry("CN=x", map[string][]string{
		"num": {"65536"},
	})
	if got := parseUintAttr(e, "num"); got != 65536 {
		t.Fatalf("parseUintAttr = %d, want 65536", got)
	}
	// missing attribute → 0
	if got := parseUintAttr(e, "missing"); got != 0 {
		t.Fatalf("missing attr = %d, want 0", got)
	}
	// non-numeric tail stops cleanly
	e2 := mkEntry("CN=y", map[string][]string{
		"num": {"123abc"},
	})
	if got := parseUintAttr(e2, "num"); got != 123 {
		t.Fatalf("non-numeric tail: got %d, want 123", got)
	}
}

// --- ESC8 URL builder ---

func TestESC8CheckURL(t *testing.T) {
	got := ESC8CheckURL("ca.corp.local")
	want := "http://ca.corp.local/certsrv/"
	if got != want {
		t.Fatalf("ESC8 URL: %q, want %q", got, want)
	}
	// already-scheme'd
	got = ESC8CheckURL("http://ca.corp.local")
	if got != want {
		t.Fatalf("ESC8 URL w/ scheme: %q, want %q", got, want)
	}
	// trailing slash
	got = ESC8CheckURL("ca.corp.local/")
	if got != "http://ca.corp.local/certsrv/" {
		t.Fatalf("ESC8 URL w/ trailing slash: %q", got)
	}
	// empty host
	got = ESC8CheckURL("")
	if got != "" {
		t.Fatalf("ESC8 URL empty host: %q", got)
	}
}

// --- EKU helpers ---

func TestHasEKUCaseInsensitive(t *testing.T) {
	list := []string{EKUClientAuth}
	if !hasEKU(list, strings.ToUpper(EKUClientAuth)) {
		t.Fatalf("hasEKU should be case-insensitive")
	}
	if hasEKU(list, EKUServerAuth) {
		t.Fatalf("hasEKU should return false for non-matching")
	}
}
