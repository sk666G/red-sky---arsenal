package agentfw

import (
	"context"
	"fmt"
)

// Result is what a framework task returns.
type Result struct {
	Output   string
	Err      error
	ExitCode int
}

// Dispatch runs a framework task by name. Modules self-register via
// Register() from their own init(). Unknown names return an explicit error
// (ExitCode 127) so the operator sees the gap instead of a silent no-op.
func Dispatch(ctx context.Context, module string, args []string) Result {
	m, ok := modules[module]
	if !ok {
		return Result{
			Err:      fmt.Errorf("framework module not implemented on agent: %s", module),
			ExitCode: 127,
		}
	}
	return m.Run(ctx, args)
}
