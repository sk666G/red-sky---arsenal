package cloudgo

import (
	"strings"

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
		// Probe depth: pattern-match on the body to name the specific
		// exposure. IMDS returning live credentials is a much higher
		// severity than IMDS merely answering with ami-id.
		lower := strings.ToLower(evidence)
		switch {
		case strings.Contains(evidence, "AKIA") || strings.Contains(lower, "accesskeyid"):
			name = "AWS credentials captured from IMDS"
			severity = "critical"
		case strings.Contains(lower, "service-accounts/default/token") ||
			(strings.Contains(lower, "access_token") && strings.Contains(lower, "computeMetadata")):
			name = "GCP OAuth token captured from metadata"
			severity = "critical"
		case strings.Contains(lower, "access_token") && strings.Contains(lower, "azure"):
			name = "Azure managed identity token captured"
			severity = "critical"
		case strings.Contains(lower, "security-credentials"):
			name = "AWS IMDS IAM role credential path reachable"
			severity = "high"
		case strings.Contains(lower, "ami-id") || strings.Contains(lower, "instance-id"):
			name = "AWS IMDS metadata reachable (non-credential)"
			severity = "info"
		case strings.Contains(lower, "computeMetadata"):
			name = "GCP metadata service reachable"
			severity = "info"
		default:
			name = "Cloud metadata service reachable (IMDS probe)"
			severity = "high"
		}
	case "probe-extract":
		// Auto-extract stage emits a redacted summary of a captured
		// credential — this is a cleaner signal than pattern-matching
		// the probe body, so it warrants its own severity.
		switch {
		case strings.Contains(d.Message, "AWS credentials"):
			name = "AWS credentials captured (auto-extracted)"
			severity = "critical"
		case strings.Contains(d.Message, "GCP OAuth"):
			name = "GCP OAuth token captured (auto-extracted)"
			severity = "critical"
		default:
			name = "Credential captured from cloud metadata"
			severity = "critical"
		}
	case "chain-identity":
		if strings.Contains(d.Message, "credential proved") {
			name = "Cloud credential proved via sts:GetCallerIdentity"
			severity = "critical"
		} else if strings.Contains(d.Message, "credential rejected") {
			// Rejected credential = probe succeeded but the key is dead.
			// Info only — not a real finding.
			return nil
		} else {
			// "no valid credentials found" — informational
			return nil
		}
	case "identity":
		name, severity = "AWS STS identity resolved (live credentials)", "high"
	case "iam":
		name, severity = "Cloud IAM read access confirmed", "high"
	case "simulate":
		name, severity = "IAM policy simulation confirmed attack path", "critical"
	case "driver":
		// Driver depth: name the specific primitive. Different drivers
		// mean different attacker capabilities.
		lower := strings.ToLower(d.Message + " " + d.Detail)
		switch {
		case strings.Contains(lower, "create_access_key") || strings.Contains(lower, "access key"):
			name = "Cloud persistence: access key created"
			severity = "critical"
		case strings.Contains(lower, "attach") && strings.Contains(lower, "policy"):
			name = "Cloud privilege escalation: policy attached to principal"
			severity = "critical"
		case strings.Contains(lower, "put_user_policy"):
			name = "Cloud privilege escalation: inline policy injected"
			severity = "critical"
		case strings.Contains(lower, "update_login_profile") || strings.Contains(lower, "password"):
			name = "Cloud credential modification: login profile updated"
			severity = "critical"
		case strings.Contains(lower, "assume_role") || strings.Contains(lower, "assume"):
			name = "Cloud lateral movement: role assumed"
			severity = "high"
		case strings.Contains(lower, "add_user_to_group") || strings.Contains(lower, "group"):
			name = "Cloud privilege escalation: user added to group"
			severity = "critical"
		default:
			name = "Cloud privesc driver executed successfully"
			severity = "critical"
		}
	default:
		return nil
	}

	return []ClassifiedCloudVuln{{
		Name:     name,
		Severity: severity,
		Evidence: evidence,
	}}
}
