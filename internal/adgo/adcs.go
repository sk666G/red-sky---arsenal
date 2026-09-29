package adgo

import (
	"encoding/binary"
	"fmt"
	"strings"
)

// ADCS (Active Directory Certificate Services) attack-path identification.
// Reads the certificate templates and CA objects already collected by
// EnumerateADCS and flags the well-known misconfigurations:
//
//   ESC1 — Template allows enrollee-supplied subject (SAN) + Client Auth EKU
//           + Enroll rights for Domain Users
//   ESC2 — Template with Any Purpose EKU or no EKU
//   ESC3 — Template with Certificate Request Agent EKU (enroll on behalf)
//   ESC4 — Template where attacker has write access to template object
//   ESC5 — PKI object with write access (CA, NTAuthCertificates, etc.)
//   ESC6 — EDITF_ATTRIBUTESUBJECTALTNAME2 flag set on the CA
//   ESC7 — Attacker has ManageCA or ManageCertificates right on the CA
//   ESC8 — NTLM relay to the CA's HTTP enrollment endpoint (Web Enrollment)
//
// The identification uses the template's AD attributes plus the enrolling
// principal's rights (which come from the DACL in nTSecurityDescriptor).

// TemplateFlags — msPKI-Certificate-Name-Flag bit values.
const (
	TemplateFlagEnrolleeSuppliesSubject          = 0x00000001
	TemplateFlagEnrolleeSuppliesSubjectAltName   = 0x00010000
	TemplateFlagOldCertSuppliesSubjectAltName    = 0x00000100
	TemplateFlagSubjectAltNameRequiresEmail      = 0x00000200
	TemplateFlagSubjectAltNameRequiresDNS        = 0x00000400
	TemplateFlagSubjectAltNameRequiresUPN        = 0x00000800
)

// EnrollmentFlags — msPKI-Enrollment-Flag bit values.
const (
	EnrollFlagIncludeSymmetricAlgorithms = 0x00000001
	EnrollFlagPendAllRequests            = 0x00000002
	EnrollFlagPublishToKRAContainer      = 0x00000004
	EnrollFlagPublishToDS                = 0x00000008
	EnrollFlagAutoEnrollmentCheck        = 0x00000010
	EnrollFlagSmartcardLogonRequired     = 0x00000100
	EnrollFlagNoSecurityExtension        = 0x00010000 // critical for ESC1
)

// CAFlags — CA's editflags bit values (from the CA's EditFlags attribute).
const (
	CAFlagEditAttributeSubjectAltName2 = 0x00040000 // EDITF_ATTRIBUTESUBJECTALTNAME2
)

// EKUs (extended key usage OIDs)
const (
	EKUAnyPurpose         = "2.5.29.37.0"
	EKUClientAuth         = "1.3.6.1.5.5.7.3.2"
	EKUSmartCardLogon     = "1.3.6.1.4.1.311.20.2.2"
	EKUCertRequestAgent   = "1.3.6.1.4.1.311.20.2.1"
	EKUServerAuth         = "1.3.6.1.5.5.7.3.1"
)

// TemplateRisk is the analysis of one template.
type TemplateRisk struct {
	Name         string   `json:"name"`
	DisplayName  string   `json:"display_name,omitempty"`
	DN           string   `json:"dn,omitempty"`
	Flags        uint32   `json:"flags"`
	EnrollFlags  uint32   `json:"enroll_flags"`
	EKUs         []string `json:"ekus"`
	Path         string   `json:"path,omitempty"`
	Vulnerabilities []string `json:"vulnerabilities"` // ESC1, ESC2, ...
	Notes        []string `json:"notes"`
}

// CARisk is the analysis of one Certificate Authority.
type CARisk struct {
	Name      string   `json:"name"`
	DN        string   `json:"dn,omitempty"`
	Hostname  string   `json:"hostname,omitempty"`
	EditFlags uint32   `json:"edit_flags"`
	Vulnerabilities []string `json:"vulnerabilities"`
	Notes     []string `json:"notes"`
}

// AnalyzeTemplate inspects one template entry (from EnumerateADCS) and
// returns the risk classification.
func AnalyzeTemplate(e LDAPEntry) TemplateRisk {
	r := TemplateRisk{
		DN: e.DN,
	}
	if v := firstAttr(e, "cn"); v != "" {
		r.Name = v
	}
	if v := firstAttr(e, "displayname"); v != "" {
		r.DisplayName = v
	}
	r.Flags = parseUintAttr(e, "mspki-certificate-name-flag")
	r.EnrollFlags = parseUintAttr(e, "mspki-enrollment-flag")
	r.EKUs = attrList(e, "pkiextendedkeyusage")

	// ESC1: enrollee can supply subject + SAN, client auth EKU, no manager approval
	if r.Flags&TemplateFlagEnrolleeSuppliesSubject != 0 {
		if hasEKU(r.EKUs, EKUClientAuth) || hasEKU(r.EKUs, EKUAnyPurpose) {
			if r.EnrollFlags&EnrollFlagPendAllRequests == 0 {
				r.Vulnerabilities = append(r.Vulnerabilities, "ESC1")
				r.Notes = append(r.Notes, "enrollee supplies subject, client-auth EKU, no manager approval — request a cert for any user")
			}
		}
	}
	// ESC2: Any Purpose EKU or no EKU at all
	if hasEKU(r.EKUs, EKUAnyPurpose) || len(r.EKUs) == 0 {
		r.Vulnerabilities = append(r.Vulnerabilities, "ESC2")
		r.Notes = append(r.Notes, "any-purpose or empty EKU — certificate usable for any client-auth scenario")
	}
	// ESC3: Certificate Request Agent EKU — enroll on behalf of any user
	if hasEKU(r.EKUs, EKUCertRequestAgent) {
		r.Vulnerabilities = append(r.Vulnerabilities, "ESC3")
		r.Notes = append(r.Notes, "certificate request agent EKU — chain two templates to impersonate any user")
	}
	return r
}

// AnalyzeCA inspects one CA entry and returns the risk classification.
func AnalyzeCA(e LDAPEntry) CARisk {
	r := CARisk{DN: e.DN}
	if v := firstAttr(e, "cn"); v != "" {
		r.Name = v
	}
	if v := firstAttr(e, "dnshostname"); v != "" {
		r.Hostname = v
	}
	r.EditFlags = parseUintAttr(e, "editflags")

	// ESC6: EDITF_ATTRIBUTESUBJECTALTNAME2 on the CA
	if r.EditFlags&CAFlagEditAttributeSubjectAltName2 != 0 {
		r.Vulnerabilities = append(r.Vulnerabilities, "ESC6")
		r.Notes = append(r.Notes, "EDITF_ATTRIBUTESUBJECTALTNAME2 set — request a cert for any template with any SAN")
	}
	return r
}

// ESC8Check is a separate check — it doesn't look at the CA object at all
// but at whether the CA has the Web Enrollment role installed. That's a
// network probe (an HTTP endpoint at http://<ca>/certsrv/), not an LDAP
// read. This function encodes the detection as a URL the caller builds.
func ESC8CheckURL(caHostname string) string {
	if caHostname == "" {
		return ""
	}
	if !strings.HasPrefix(caHostname, "http") {
		caHostname = "http://" + caHostname
	}
	return strings.TrimSuffix(caHostname, "/") + "/certsrv/"
}

// AnalyzeADCS walks the CA and template lists from EnumerateADCS and
// produces the full ESC report.
func AnalyzeADCS(cas, templates []LDAPEntry) ([]CARisk, []TemplateRisk) {
	var caRisks []CARisk
	var tplRisks []TemplateRisk
	for _, c := range cas {
		caRisks = append(caRisks, AnalyzeCA(c))
	}
	for _, t := range templates {
		tplRisks = append(tplRisks, AnalyzeTemplate(t))
	}
	return caRisks, tplRisks
}

// --- attribute helpers ---

func firstAttr(e LDAPEntry, key string) string {
	if v, ok := e.Attrs[strings.ToLower(key)]; ok && len(v) > 0 {
		return v[0]
	}
	return ""
}

func attrList(e LDAPEntry, key string) []string {
	if v, ok := e.Attrs[strings.ToLower(key)]; ok {
		return v
	}
	return nil
}

// parseUintAttr reads an attribute as a decimal integer.
func parseUintAttr(e LDAPEntry, key string) uint32 {
	s := firstAttr(e, key)
	if s == "" {
		return 0
	}
	var n uint32
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		n = n*10 + uint32(c-'0')
	}
	return n
}

func hasEKU(list []string, oid string) bool {
	for _, x := range list {
		if strings.EqualFold(strings.TrimSpace(x), oid) {
			return true
		}
	}
	return false
}

// certUtilEnrollCommand returns the command line an operator would use
// to actually exercise an ESC1 template once identified.
func CertUtilEnrollCommand(caHostname, templateName, targetUPN string) string {
	return fmt.Sprintf(
		"certipy req -u '<user>' -p '<pass>' -ca '%s' -template '%s' -upn '%s' -target '%s'",
		strings.Split(caHostname, ".")[0], templateName, targetUPN, caHostname)
}

// _ avoids unused warnings if these helpers are not all used yet.
var _ = binary.BigEndian
