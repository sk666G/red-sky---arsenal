package planner

import (
	"context"
	"strings"
	"time"
)

// RulePlanner matches keywords in the goal and emits a canned plan.
type RulePlanner struct{}

func (RulePlanner) Plan(_ context.Context, goal string) (*Plan, error) {
	g := strings.ToLower(goal)
	var steps []Task

	addNet := func(ports string) {
		steps = append(steps, Task{
			Module: "net_scanner",
			Args:   []string{"192.168.1.0/24", ports, "2000"},
			Reason: "TCP port sweep on the local subnet",
		})
	}

	switch {
	case strings.Contains(g, "smb") || strings.Contains(g, "share") || strings.Contains(g, "windows"):
		addNet("135,139,445,3389,5985")
		steps = append(steps, Task{
			Module: "cred_harvest",
			Args:   []string{"all"},
			Reason: "grab stored credentials once reachable hosts are known",
		})
	case strings.Contains(g, "wifi") || strings.Contains(g, "wireless"):
		steps = append(steps, Task{
			Module: "wireless",
			Args:   []string{"scan"},
			Reason: "passive wireless survey",
		})
	case strings.Contains(g, "web") || strings.Contains(g, "http") || strings.Contains(g, "site"):
		addNet("80,443,8080,8443")
	case strings.Contains(g, "creds") || strings.Contains(g, "password") || strings.Contains(g, "hash"):
		steps = append(steps, Task{
			Module: "cred_harvest",
			Args:   []string{"all"},
			Reason: "harvest stored credentials and process secrets",
		})
	case strings.Contains(g, "ics") || strings.Contains(g, "scada") || strings.Contains(g, "modbus") || strings.Contains(g, "plc"):
		steps = append(steps, Task{
			Module: "ics_scada",
			Args:   []string{"scan", "192.168.1.0/24"},
			Reason: "ICS protocol sweep across the subnet",
		})
	case strings.Contains(g, "iot") || strings.Contains(g, "smart"):
		steps = append(steps, Task{
			Module: "iot",
			Args:   []string{"discover", "scan", "192.168.1.0/24"},
			Reason: "IoT device discovery on the LAN",
		})
	default:
		addNet("1-1024")
		steps = append(steps, Task{
			Module: "report",
			Args:   []string{"findings", "stats"},
			Reason: "summarize what was found",
		})
	}

	return &Plan{
		Goal:    goal,
		Backend: "rule",
		Steps:   steps,
		Created: time.Now(),
	}, nil
}
