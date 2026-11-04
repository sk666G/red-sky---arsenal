package webgo

import (
	"fmt"
	"strings"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// ClassifiedWebVuln is a heuristic finding derived from a web module
// response. Only SSRF and webreq produce vulns — they send real requests
// and inspect the response. SSTI/XSS/XXE render payloads for the pentester
// to paste into a proxy; that's not a proof of vuln, so no vuln row.
type ClassifiedWebVuln struct {
	Name     string
	Severity string // "critical" | "high" | "medium" | "low" | "info"
	Evidence string
}

// imdsBodySignatures are strings that appear in AWS/GCP/Azure metadata
// responses. If SSRF returns any of these, the metadata service is
// reachable from the target — credentials are one request away.
var imdsBodySignatures = []string{
	"ami-id",
	"instance-id",
	"security-credentials",
	"computeMetadata",
	"iam/security-credentials",
	"metadata/identity",
	"accessKeyId",
	"AccessKeyId",
}

// internalAdminPaths are paths that, when they return 200 to an SSRF
// probe, indicate an internal admin surface — worth flagging as high.
var internalAdminPaths = []string{
	"/admin",
	"/server-status",
	"/actuator",
	"/swagger-ui",
	"/api/v1/namespaces",
	"/version", // docker api
}

// ClassifySSRF turns an SSRF probe response into a classified vuln.
// Keyed on OK, Status, and Body. IMDS body match → critical (credential
// theft surface). Internal admin path with 200 → high. Successful probe
// with no match → info finding for the record.
func ClassifySSRF(d proto.WebSSRFData) []ClassifiedWebVuln {
	if d.Done || !d.OK {
		return nil
	}
	// Only 200 (or 2xx) responses count. 4xx/5xx from an SSRF probe
	// means the target responded but the endpoint didn't exist.
	if d.Status < 200 || d.Status >= 300 {
		return nil
	}

	target := d.URL
	if target == "" {
		target = d.Probe
	}
	evidence := fmt.Sprintf("%d %s (len=%d)", d.Status, target, d.BodyLen)

	// 1. IMDS detection — highest severity.
	lowerBody := strings.ToLower(d.Body)
	for _, sig := range imdsBodySignatures {
		if strings.Contains(lowerBody, strings.ToLower(sig)) {
			return []ClassifiedWebVuln{{
				Name:     "SSRF to cloud metadata service (IMDS reachable)",
				Severity: "critical",
				Evidence: evidence + " — body contains " + sig,
			}}
		}
	}

	// 2. Internal admin panel detection.
	lowerURL := strings.ToLower(target)
	for _, path := range internalAdminPaths {
		if strings.Contains(lowerURL, path) {
			return []ClassifiedWebVuln{{
				Name:     "SSRF to internal admin surface (" + path + ")",
				Severity: "high",
				Evidence: evidence,
			}}
		}
	}

	// 3. Everything else — successful probe, worth an info entry.
	return []ClassifiedWebVuln{{
		Name:     "SSRF probe succeeded (response received)",
		Severity: "info",
		Evidence: evidence,
	}}
}

// ClassifyWebReq turns a webreq response into a classified finding.
// webgo.WebReq sends a real HTTP request — the response tells us the
// endpoint exists. This is not a vuln by itself; the pentester needs
// to interpret what came back. Info-level for the record.
func ClassifyWebReq(d proto.WebReqData) []ClassifiedWebVuln {
	if d.Done || d.Status == 0 {
		return nil
	}
	if d.Error != "" {
		return nil
	}

	sev := "info"
	name := fmt.Sprintf("HTTP %d (endpoint reachable)", d.Status)
	if d.Status >= 200 && d.Status < 300 {
		name = fmt.Sprintf("HTTP %d OK (endpoint reachable)", d.Status)
	} else if d.Status >= 300 && d.Status < 400 {
		name = fmt.Sprintf("HTTP %d redirect (endpoint reachable)", d.Status)
	} else if d.Status >= 500 {
		name = fmt.Sprintf("HTTP %d server error (worth investigating)", d.Status)
	}

	evidence := fmt.Sprintf("%d %s", d.Status, d.StatusLine)
	if d.BodyLen > 0 {
		evidence += fmt.Sprintf(" (body len=%d)", d.BodyLen)
	}

	return []ClassifiedWebVuln{{
		Name:     name,
		Severity: sev,
		Evidence: evidence,
	}}
}
