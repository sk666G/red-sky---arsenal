// Package plugin bridges the existing Python modules into the Go core.
//
// Phase 3: local plugin bridge only. Each plugin is invoked by shelling out
// to `python3 redsky.py <module> <args...>` and capturing stdout. Slow (~200ms
// Python startup per call) but simple and works with the existing CLI as-is.
// Phase 4 will convert to a long-lived JSON-RPC server.
package plugin

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"time"
)

// LocalPlugin describes a Python-side module that runs on the operator box.
type LocalPlugin struct {
	Name    string
	Side    string // "local" or "remote"
	Command string // what to run: python3 redsky.py <name>
}

// Invoke runs a local plugin with the given subcommand + args and returns the
// combined stdout. Errors from the plugin process are returned as part of the
// output — the caller decides what to do with them.
func Invoke(ctx context.Context, repoRoot, module string, args []string, timeout time.Duration) (string, error) {
	if timeout == 0 {
		timeout = 5 * time.Minute
	}
	py := "python3"
	redsky := filepath.Join(repoRoot, "redsky.py")

	if _, err := exec.LookPath(py); err != nil {
		return "", fmt.Errorf("python3 not found: %w", err)
	}

	cmdArgs := append([]string{redsky, module}, args...)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	cmd := exec.CommandContext(cctx, py, cmdArgs...)
	cmd.Dir = repoRoot
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	out := stdout.String()
	if err != nil {
		// include stderr in the returned text so the operator sees the real error
		if stderr.Len() > 0 {
			out += "\n--- stderr ---\n" + stderr.String()
		}
		return out, err
	}
	return out, nil
}
