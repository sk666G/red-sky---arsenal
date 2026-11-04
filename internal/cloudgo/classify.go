package cloudgo

import (
	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// ClassifiedCloudVuln is a heuristic finding derived from a single
// CloudData response. Severity is scoped to exposure criticality of
// the *stage that succeeded*, not to a specific CVE.
type ClassifiedCloudVuln struct {
	Name     string
	Severity string // "critical" | "high" | "medium" | "low" | "info"
	Evidence string
}

// ClassifyCloudData returns zero or more ClassifiedCloudVuln derived
// from a single streamed CloudData response. Keyed on Stage (which
// identifies the action family that produced it — probe, identity,
// iam, simulate, driver) and OK.
//
// Host attribution comes from the caller (the sink knows the agent's
// peer IP via s.conn.RemoteAddr). This function is host-agnostic.
//
// Skips terminal responses (Done) and error responses (OK=false).
func ClassifyCloudData(d proto.CloudData) []ClassifiedCloudVuln {
	if d.Done || !d.OK {
		return nil
	}
	if d.Stage == "error" || d.Stage == "" {
		return nil
	}

	evidence := d.Message
	if d.Detail != "" {
		if evidence != "" {
			evidence += " — "
		}
		evidence += d.Detail
	}
	if len(evidence) > 300 {
		evidence = evidence[:300] + "..."
	}

	var name, severity string
	switch d.Stage {
	case "probe":
		name, severity = "Cloud metadata service reachable (IMDS probe)", "critical"
	case "identity":
		name, severity = "AWS STS identity resolved (live credentials)", "high"
	case "iam":
		name, severity = "Cloud IAM read access confirmed", "high"
	case "simulate":
		name, severity = "IAM policy simulation confirmed attack path", "critical"
	case "driver":
		name, severity = "Cloud privesc driver executed successfully", "critical"
	default:
		return nil
	}

	return []ClassifiedCloudVuln{{
		Name:     name,
		Severity: severity,
		Evidence: evidence,
	}}
}
