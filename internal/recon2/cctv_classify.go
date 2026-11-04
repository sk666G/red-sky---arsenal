package recon2

import (
	"fmt"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// ClassifiedCCTVvuln is a heuristic finding derived from a CCTV module
// response. The strongest signal is captured credentials — ScanCreds
// found a working user/pass pair. Unauthenticated cameras (OK, no auth
// realm, no creds) are also real — the stream is open.
//
// CCTVData carries no Action field — the action lives on CCTVStart. The
// classifier infers the case from which fields are populated:
//   - User + Pass + OK              → critical (credentials captured)
//   - OK, Server non-empty          → info (camera responding)
//   - OK, AuthRealm non-empty       → medium (auth-protected camera found)
//   - OK, no AuthRealm, no creds    → high (unauthenticated camera)
//   - !OK, Note "no creds matched"  → skip (scan came back empty)
//   - Error / Done                  → skip
type ClassifiedCCTVvuln struct {
	Name     string
	Severity string
	Evidence string
}

// ClassifyCCTV turns a CCTV module response into a classified vuln.
// Pure function — no side effects, no DB, no logging.
func ClassifyCCTV(d proto.CCTVData) []ClassifiedCCTVvuln {
	if d.Done || d.Error != "" {
		return nil
	}

	// Credentials captured — the strongest signal. ScanCreds found a
	// working user/pass pair against an RTSP endpoint.
	if d.OK && d.User != "" && d.Pass != "" {
		return []ClassifiedCCTVvuln{{
			Name:     "CCTV camera — valid credentials captured",
			Severity: "critical",
			Evidence: fmt.Sprintf("%s user=%s pass=%s%s", d.URL, d.User, d.Pass, noteSuffix(d.Note)),
		}}
	}

	// Auth-protected camera — realm discovered, no creds matched yet.
	if d.OK && d.AuthRealm != "" {
		return []ClassifiedCCTVvuln{{
			Name:     "CCTV camera — auth-protected, realm discovered",
			Severity: "medium",
			Evidence: fmt.Sprintf("%s realm=%q%s", d.URL, d.AuthRealm, noteSuffix(d.Note)),
		}}
	}

	// Unauthenticated camera — 200 without auth or creds. Stream open.
	if d.OK && d.AuthRealm == "" && d.User == "" {
		return []ClassifiedCCTVvuln{{
			Name:     "CCTV camera — unauthenticated stream access",
			Severity: "high",
			Evidence: fmt.Sprintf("%s status=%d server=%q%s", d.URL, d.Status, d.Server, noteSuffix(d.Note)),
		}}
	}

	return nil
}

func noteSuffix(note string) string {
	if note == "" {
		return ""
	}
	return " note=" + note
}
