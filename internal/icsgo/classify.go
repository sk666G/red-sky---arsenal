package icsgo

import (
	"fmt"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// ClassifiedIcsVuln is a heuristic finding derived from a single
// IcsData response. Severity is scoped to exposure criticality, not
// to exploitability — an open Modbus write means the network is
// exposed, not that a specific CVE is present.
type ClassifiedIcsVuln struct {
	Name     string
	Severity string // "critical" | "high" | "medium" | "low" | "info"
	Evidence string
}

// ClassifyIcsData returns zero or more ClassifiedIcsVuln derived from
// a single streamed IcsData response. Keyed on Protocol (from the
// IcsStart that kicked off the session — echoed through every
// response since alpha.98.6), Stage (read/write/poll/...), and OK.
//
// Skips terminal responses (Done) and error responses (OK=false).
// Empty and error stages never classify.
func ClassifyIcsData(d proto.IcsData) []ClassifiedIcsVuln {
	if d.Done || !d.OK {
		return nil
	}
	// error stage is not a vulnerability — it's a diagnostic
	if d.Stage == "error" || d.Stage == "" {
		return nil
	}

	proto_ := d.Protocol
	if proto_ == "" {
		// pre-alpha.98.6 responses won't have this. skip cleanly.
		return nil
	}

	stage := d.Stage
	host := d.Host
	if host == "" {
		host = "unknown-host"
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
	switch proto_ {
	case "modbus":
		switch stage {
		case "write":
			name, severity = "Modbus unauthenticated write accepted", "critical"
		case "read":
			name, severity = "Modbus unauthenticated read accepted", "high"
		default:
			return nil
		}
	case "s7":
		switch stage {
		case "write":
			name, severity = "S7 (Siemens) unauthenticated write accepted", "critical"
		case "read":
			name, severity = "S7 (Siemens) unauthenticated read accepted", "high"
		default:
			return nil
		}
	case "dnp3":
		switch stage {
		case "read", "poll", "integrity":
			name, severity = "DNP3 unauthenticated "+stage+" accepted", "high"
		case "write":
			name, severity = "DNP3 unauthenticated write accepted", "critical"
		default:
			return nil
		}
	case "enip":
		switch stage {
		case "write":
			name, severity = "EtherNet/IP unauthenticated write accepted", "critical"
		case "read", "list_identity":
			name, severity = "EtherNet/IP device exposure ("+stage+")", "high"
		default:
			return nil
		}
	case "bacnet":
		switch stage {
		case "write":
			name, severity = "BACnet unauthenticated write accepted", "critical"
		case "read":
			name, severity = "BACnet device exposure (read)", "medium"
		default:
			return nil
		}
	case "opcua":
		name, severity = "OPC-UA device reachable ("+stage+")", "medium"
	default:
		return nil
	}

	return []ClassifiedIcsVuln{{
		Name:     fmt.Sprintf("%s — %s", name, host),
		Severity: severity,
		Evidence: evidence,
	}}
}
