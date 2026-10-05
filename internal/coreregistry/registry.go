// Package coreregistry is the core-side module dispatcher — the mirror of
// internal/agentfw for the operator box. Every core-side dispatcher in
// cmd/redsky-core/main.go registers itself here under a stable name, so the
// operator can drive it with a single flag:
//
//	redsky-core -module cloud -args '{"action":"imds_probe","provider":"aws"}'
//
// The legacy per-module flags keep working — the registry is an additional
// door into the same functions, not a replacement.
package coreregistry

import (
	"encoding/json"
	"fmt"
	"sort"
	"sync"

	"github.com/sk666G/red-sky---arsenal/internal/session"
)

// Module is anything the core can dispatch to.
type Module struct {
	// Name is the wire name — what the operator types after -module.
	Name string
	// Help is the one-liner shown by -h.
	Help string
	// Run executes the module. rawArgs is the JSON blob passed via -args.
	// Implementations decode into their own typed args struct and then call
	// the existing runXxxDispatch.
	Run func(mgr *session.Manager, rawArgs []byte) error
}

var (
	mu      sync.RWMutex
	modules = map[string]Module{}
)

// Register adds a module to the core dispatcher table. Called from init()
// in each module's own file. Duplicates panic — a name is a name.
func Register(m Module) {
	mu.Lock()
	defer mu.Unlock()
	if m.Name == "" {
		panic("coreregistry: Register with empty Name")
	}
	if m.Run == nil {
		panic(fmt.Sprintf("coreregistry: Register(%s) with nil Run", m.Name))
	}
	if _, dup := modules[m.Name]; dup {
		panic(fmt.Sprintf("coreregistry: duplicate module registration: %s", m.Name))
	}
	modules[m.Name] = m
}

// Lookup returns the module by name, or false.
func Lookup(name string) (Module, bool) {
	mu.RLock()
	defer mu.RUnlock()
	m, ok := modules[name]
	return m, ok
}

// Names returns every registered module name, sorted — for -h output.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]string, 0, len(modules))
	for n := range modules {
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// Help renders a name-tab-help table for -h output.
func Help() string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(modules))
	for n := range modules {
		names = append(names, n)
	}
	sort.Strings(names)
	var out []byte
	for _, n := range names {
		out = append(out, []byte(fmt.Sprintf("  %-20s %s\n", n, modules[n].Help))...)
	}
	return string(out)
}

// DecodeArgs is a helper for module adapters. Empty input decodes to a
// zero struct; malformed input returns the JSON error verbatim so the
// operator sees what's wrong.
func DecodeArgs(raw []byte, dst any) error {
	if len(raw) == 0 {
		return nil
	}
	return json.Unmarshal(raw, dst)
}
