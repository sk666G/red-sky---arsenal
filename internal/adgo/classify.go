package adgo

import (
	"fmt"
	"strconv"
	"strings"
)

// ClassifiedVuln is a heuristic finding derived from a raw LDAP entry
// or a streamed message. Same vocabulary as recon2.Severity so the
// report renders it consistently.
type ClassifiedVuln struct {
	Name     string
	Severity string // "critical" | "high" | "medium" | "low" | "info"
	Evidence string
}

// userAccountControl flag bits we care about.
const (
	uacPasswdNotReq   = 0x0020   // 32     PASSWD_NOTREQD
	uacDontExpirePwd  = 0x10000  // 65536  DONT_EXPIRE_PASSWORD
	uacDontReqPreauth = 0x400000 // 4194304 DONT_REQ_PREAUTH

	uacTrustedForDelegation = 0x80000 // TRUSTED_FOR_DELEGATION
)

// classifyMessage scans a free-form message for embedded hash markers.
func classifyMessage(action, msg string) []ClassifiedVuln {
	if msg == "" {
		return nil
	}
	var out []ClassifiedVuln

	if strings.Contains(msg, "$krb5asrep$") {
		out = append(out, ClassifiedVuln{
			Name:     "AS-REP roastable account — hash captured",
			Severity: "high",
			Evidence: truncateStr(msg, 200),
		})
	}
	if strings.Contains(msg, "$krb5tgs$") {
		out = append(out, ClassifiedVuln{
			Name:     "Kerberoastable service account — hash captured",
			Severity: "critical",
			Evidence: truncateStr(msg, 200),
		})
	}
	return out
}

// classifyEntry applies the standard AD heuristic set to a single
// LDAP entry. Pure function — no DB, no network, testable in isolation.
func classifyEntry(e LDAPEntry) []ClassifiedVuln {
	if e.DN == "" || len(e.Attrs) == 0 {
		return nil
	}
	var out []ClassifiedVuln

	groupName := attrFirst(e.Attrs, "name", "samAccountName")
	members := e.Attrs["member"]

	if strings.EqualFold(groupName, "Domain Admins") {
		for _, m := range members {
			out = append(out, ClassifiedVuln{
				Name:     "Domain Admins member",
				Severity: "high",
				Evidence: m,
			})
		}
	}
	if strings.EqualFold(groupName, "Enterprise Admins") {
		for _, m := range members {
			out = append(out, ClassifiedVuln{
				Name:     "Enterprise Admins member",
				Severity: "critical",
				Evidence: m,
			})
		}
	}

	if uacStr := attrFirst(e.Attrs, "userAccountControl"); uacStr != "" {
		if uac, err := strconv.Atoi(uacStr); err == nil {
			sam := attrFirst(e.Attrs, "samAccountName")
			if sam == "" {
				sam = e.DN
			}
			if uac&uacDontReqPreauth != 0 {
				out = append(out, ClassifiedVuln{
					Name:     "AS-REP roastable user (DONT_REQ_PREAUTH)",
					Severity: "high",
					Evidence: fmt.Sprintf("%s uac=0x%x", sam, uac),
				})
			}
			if uac&uacPasswdNotReq != 0 {
				out = append(out, ClassifiedVuln{
					Name:     "User with PASSWD_NOTREQD flag",
					Severity: "high",
					Evidence: fmt.Sprintf("%s uac=0x%x", sam, uac),
				})
			}
			if uac&uacDontExpirePwd != 0 {
				out = append(out, ClassifiedVuln{
					Name:     "User with password-never-expires",
					Severity: "low",
					Evidence: fmt.Sprintf("%s uac=0x%x", sam, uac),
				})
			}
		}
	}
	if spns := e.Attrs["servicePrincipalName"]; len(spns) > 0 {
		sam := attrFirst(e.Attrs, "samAccountName")
		if sam == "" {
			sam = e.DN
		}
		out = append(out, ClassifiedVuln{
			Name:     "Service account with SPN (Kerberoastable)",
			Severity: "medium",
			Evidence: fmt.Sprintf("%s spn=%s", sam, strings.Join(spns, ",")),
		})
	}
	if adminCount := attrFirst(e.Attrs, "adminCount"); adminCount == "1" {
		sam := attrFirst(e.Attrs, "samAccountName")
		if sam == "" {
			sam = e.DN
		}
		out = append(out, ClassifiedVuln{
			Name:     "Privileged account (adminCount=1)",
			Severity: "medium",
			Evidence: sam,
		})
	}

	if maq := attrFirst(e.Attrs, "ms-DS-MachineAccountQuota"); maq != "" {
		if n, err := strconv.Atoi(maq); err == nil && n > 0 {
			out = append(out, ClassifiedVuln{
				Name:     "MachineAccountQuota > 0 (any user can join computers)",
				Severity: "medium",
				Evidence: fmt.Sprintf("ms-DS-MachineAccountQuota=%d", n),
			})
		}
	}

	// Unconstrained delegation — TRUSTED_FOR_DELEGATION bit on a
	// computer account. Coerced TGT can be relayed to a DC.
	if uacStr := attrFirst(e.Attrs, "userAccountControl"); uacStr != "" {
		if uac, err := strconv.Atoi(uacStr); err == nil && uac&uacTrustedForDelegation != 0 {
			sam := attrFirst(e.Attrs, "samAccountName")
			if sam == "" {
				sam = e.DN
			}
			out = append(out, ClassifiedVuln{
				Name:     "Unconstrained delegation (TRUSTED_FOR_DELEGATION)",
				Severity: "high",
				Evidence: fmt.Sprintf("%s uac=0x%x", sam, uac),
			})
		}
	}

	// LAPS-readable — ms-Mcs-AdmPwd (or LAPS v2 variant) attribute
	// present in an entry we could read = local admin password.
	for _, attr := range []string{"ms-Mcs-AdmPwd", "msLAPS-Password", "msLAPS-EncryptedPassword"} {
		if pw := attrFirst(e.Attrs, attr); pw != "" {
			sam := attrFirst(e.Attrs, "samAccountName", "name")
			if sam == "" {
				sam = e.DN
			}
			out = append(out, ClassifiedVuln{
				Name:     "LAPS password readable (" + attr + ")",
				Severity: "high",
				Evidence: fmt.Sprintf("%s %s=%s", sam, attr, truncateStr(pw, 64)),
			})
			break
		}
	}

	// Replicating Directory Changes — DCSync rights.
	if sd := attrFirst(e.Attrs, "nTSecurityDescriptor"); sd != "" {
		if strings.Contains(sd, "Replicating Directory Changes") ||
			strings.Contains(sd, "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2") ||
			strings.Contains(sd, "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2") {
			sam := attrFirst(e.Attrs, "samAccountName", "name")
			if sam == "" {
				sam = e.DN
			}
			out = append(out, ClassifiedVuln{
				Name:     "Replicating Directory Changes (DCSync rights)",
				Severity: "critical",
				Evidence: fmt.Sprintf("%s grants DCSync", sam),
			})
		}
	}

	// ADCS template / CA risks — AnalyzeTemplate and AnalyzeCA return
	// Vulnerabilities []string (ESC1, ESC2, ...) and Notes []string.
	// Fire one vuln per ESC class.
	if objectClass := e.Attrs["objectClass"]; len(objectClass) > 0 {
		isTemplate := false
		isCA := false
		for _, c := range objectClass {
			if strings.EqualFold(c, "pKICertificateTemplate") {
				isTemplate = true
			}
			if strings.EqualFold(c, "pKIEnrollmentService") {
				isCA = true
			}
		}
		if isTemplate {
			risk := AnalyzeTemplate(e)
			for _, esc := range risk.Vulnerabilities {
				sev := "critical"
				if esc == "ESC4" || esc == "ESC5" {
					sev = "high"
				}
				notes := strings.Join(risk.Notes, "; ")
				if len(notes) > 200 {
					notes = notes[:200] + "…"
				}
				out = append(out, ClassifiedVuln{
					Name:     "ADCS template — " + esc,
					Severity: sev,
					Evidence: fmt.Sprintf("%s %s", e.DN, notes),
				})
			}
		}
		if isCA {
			caRisk := AnalyzeCA(e)
			for _, esc := range caRisk.Vulnerabilities {
				sev := "critical"
				if esc == "ESC7" || esc == "ESC8" {
					sev = "high"
				}
				notes := strings.Join(caRisk.Notes, "; ")
				if len(notes) > 200 {
					notes = notes[:200] + "…"
				}
				out = append(out, ClassifiedVuln{
					Name:     "ADCS CA — " + esc,
					Severity: sev,
					Evidence: fmt.Sprintf("%s %s", e.DN, notes),
				})
			}
		}
	}

	return out
}

// attrFirst returns the first value of the first matching attribute
// name. Different from adcs.go's firstAttr which takes a different
// signature — renamed here to avoid redeclaration.
func attrFirst(m map[string][]string, names ...string) string {
	for _, n := range names {
		if v, ok := m[n]; ok && len(v) > 0 {
			return v[0]
		}
	}
	return ""
}

func truncateStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// ClassifyEntry is the exported entry point used by the data sink.
func ClassifyEntry(action string, e LDAPEntry) []ClassifiedVuln {
	var out []ClassifiedVuln
	out = append(out, classifyEntry(e)...)
	if m := attrFirst(e.Attrs, "message"); m != "" {
		out = append(out, classifyMessage(action, m)...)
	}
	return out
}

// ClassifyMessage is the exported message classifier.
func ClassifyMessage(action, msg string) []ClassifiedVuln {
	return classifyMessage(action, msg)
}
