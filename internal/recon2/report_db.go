package recon2

import (
	"fmt"

	"github.com/sk666G/red-sky---arsenal/internal/engagement"
)

// ReportFromDB builds a Report from the engagement state stored in the
// sqlite DB instead of walking the filesystem. Every host with a vuln
// becomes a Finding; every host with only services (no vulns) still
// gets one informational Finding so pure-scan output shows up.
//
// Companion to NewReport(title, operator, engagement), which takes no
// data source. Same *Report type, same Render() and Save() methods.
//
// This is the reader side of the closed state loop: scanner (and future
// modules) write to the DB via engDB, ReportFromDB reads from it, and
// the rendered report is the operator-visible artifact.
func ReportFromDB(db *engagement.DB, title, operator, engagementName string) (*Report, error) {
	if db == nil {
		return nil, fmt.Errorf("recon2: ReportFromDB: nil db")
	}
	r := NewReport(title, operator, engagementName)

	hosts, err := db.Hosts()
	if err != nil {
		return nil, fmt.Errorf("recon2: list hosts: %w", err)
	}

	for _, h := range hosts {
		services, err := db.Services(h.ID)
		if err != nil {
			return nil, fmt.Errorf("recon2: services for %s: %w", h.IP, err)
		}
		vulns, err := db.Vulns(h.ID)
		if err != nil {
			return nil, fmt.Errorf("recon2: vulns for %s: %w", h.IP, err)
		}

		if len(vulns) > 0 {
			for _, v := range vulns {
				f := Finding{
					Title:    v.Name,
					Severity: Severity(v.Severity),
					Target:   h.IP,
					Evidence: v.Evidence,
				}
				if f.Severity == "" {
					f.Severity = SeverityInfo
				}
				r.AddFinding(f)
			}
			continue
		}

		// No vulns, but services found — one informational finding per host
		// so scan-only output shows up in the report.
		if len(services) > 0 {
			ports := ""
			for i, s := range services {
				if i > 0 {
					ports += ","
				}
				ports += fmt.Sprintf("%d/%s", s.Port, s.Protocol)
			}
			r.AddFinding(Finding{
				Title:       "Host reachable — open services",
				Severity:    SeverityInfo,
				Target:      h.IP,
				Description: fmt.Sprintf("%d open TCP service(s)", len(services)),
				Evidence:    "services: " + ports,
			})
		}
	}

	return r, nil
}
