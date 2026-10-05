// Package agentfw is the agent-side framework dispatcher. Given a Task with
// Kind="framework", it routes to a Go-native implementation of that module.
// Modules not yet ported to Go return an explicit error, so the operator sees
// the gap instead of a silent failure.
package agentfw

import (
	"context"
	"fmt"
	"sort"
)

// Module is anything that runs a framework task on the agent.
type Module interface {
	// Name is the wire name — matches Task.Cmd from the core.
	Name() string
	// Run executes the module. args are the wire Args, unmodified.
	Run(ctx context.Context, args []string) Result
}

var modules = map[string]Module{}

// Register adds a module to the dispatcher table. Called from init() in
// the module's own file, so adding a module means adding a file.
func Register(m Module) {
	if m == nil {
		panic("agentfw: Register(nil)")
	}
	name := m.Name()
	if name == "" {
		panic("agentfw: Register with empty Name")
	}
	if _, dup := modules[name]; dup {
		panic(fmt.Sprintf("agentfw: duplicate module registration: %s", name))
	}
	modules[name] = m
}

// Names returns every registered module name, sorted — for -h output.
func Names() []string {
	out := make([]string, 0, len(modules))
	for n := range modules {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}
