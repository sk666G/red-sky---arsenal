// Package planner turns a natural-language goal into a sequence of framework
// tasks. Three backends: Ollama (local), OpenAI-compatible (remote), and a
// deterministic rule engine that requires no LLM.
package planner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Task is one planned step.
type Task struct {
	Module string   `json:"module"`
	Args   []string `json:"args"`
	Reason string   `json:"reason,omitempty"`
}

// Plan is an ordered list of tasks with the goal that produced it.
type Plan struct {
	Goal     string    `json:"goal"`
	Backend  string    `json:"backend"`
	Steps    []Task    `json:"steps"`
	Created  time.Time `json:"created"`
	RawReply string    `json:"raw_reply,omitempty"`
}

// Planner is the interface all backends implement.
type Planner interface {
	// Plan takes a natural-language goal and returns an ordered plan.
	Plan(ctx context.Context, goal string) (*Plan, error)
}

// SystemPrompt is the same for every LLM backend.
const SystemPrompt = `You are a Red Sky framework planner. The user gives a goal in plain English.
Output ONLY a JSON array of tasks. Each task is an object:
  {"module": "...", "args": ["..."], "reason": "..."}

Available modules and their subcommand shapes:
  net_scanner     args: cidr ports threads
  ics_scada       args: scan cidr
  iot             args: discover scan cidr
  cred_harvest    args: browsers | lsass | all
  wireless        args: scan | deauth | evil_twin
  report          args: findings stats | findings score | exec generate
  dns             args: check domain

Rules:
- Emit ONLY a JSON array of OBJECTS. Not strings. Each element must have "module" and "args" fields.
- Example: [{"module":"net_scanner","args":["192.168.1.0/24","445","2000"],"reason":"smb scan"}]
- No prose, no markdown fences.
- 5 tasks maximum.
- Use the actual subnet when one is implied (default 192.168.1.0/24).
- If the goal is unclear, emit [].

Goal: %s`

// ErrNoPlan is returned when the backend refuses to produce anything usable.
var ErrNoPlan = errors.New("planner: no plan produced")

// extractJSONArray finds the first top-level JSON array in a string. Handles
// models that wrap the array in prose or markdown fences.
func extractJSONArray(s string) (string, error) {
	s = strings.TrimSpace(s)
	// strip markdown fences
	s = strings.ReplaceAll(s, "```json", "")
	s = strings.ReplaceAll(s, "```", "")
	s = strings.TrimSpace(s)
	start := strings.IndexByte(s, '[')
	if start < 0 {
		return "", ErrNoPlan
	}
	depth := 0
	for i := start; i < len(s); i++ {
		switch s[i] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return s[start : i+1], nil
			}
		}
	}
	return "", ErrNoPlan
}

// parseTasks converts the extracted JSON into a []Task, dropping any tasks
// with unknown modules. Handles two shapes: proper objects, and a bare list
// of "module arg1 arg2" strings (some models prefer this).
func parseTasks(raw string) ([]Task, error) {
	raw = strings.TrimSpace(raw)

	// Case 1: array of objects.
	var tasks []Task
	if err := json.Unmarshal([]byte(raw), &tasks); err == nil {
		return filterTasks(tasks), nil
	}

	// Case 2: single object.
	var single Task
	if err := json.Unmarshal([]byte(raw), &single); err == nil && single.Module != "" {
		return filterTasks([]Task{single}), nil
	}

	// Case 3: array of strings.
	var strs []string
	if err := json.Unmarshal([]byte(raw), &strs); err == nil {
		var out []Task
		for _, s := range strs {
			fields := strings.Fields(s)
			if len(fields) == 0 {
				continue
			}
			out = append(out, Task{
				Module: fields[0],
				Args:   fields[1:],
				Reason: "parsed from model string form",
			})
		}
		return filterTasks(out), nil
	}

	// Case 4: object with a "tasks" key.
	var wrapped struct {
		Tasks []Task `json:"tasks"`
	}
	if err := json.Unmarshal([]byte(raw), &wrapped); err == nil && len(wrapped.Tasks) > 0 {
		return filterTasks(wrapped.Tasks), nil
	}

	return nil, fmt.Errorf("parse tasks: unrecognized shape: %s", raw[:min(120, len(raw))])
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func filterTasks(tasks []Task) []Task {
	// Filter out obviously bogus entries.
	known := map[string]bool{
		"net_scanner":  true,
		"ics_scada":    true,
		"iot":          true,
		"cred_harvest": true,
		"wireless":     true,
		"report":       true,
		"dns":          true,
	}
	var out []Task
	for _, t := range tasks {
		if !known[t.Module] {
			continue
		}
		out = append(out, t)
	}
	return out
}
