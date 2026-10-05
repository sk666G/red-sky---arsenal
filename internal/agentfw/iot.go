package agentfw

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/iotdiscover"
	"github.com/sk666G/red-sky---arsenal/internal/scanner"
)

type iotModule struct{}

func init() { Register(iotModule{}) }

func (iotModule) Name() string { return "iot" }

func (iotModule) Run(ctx context.Context, args []string) Result {
	var hosts []string
	if len(args) >= 2 && args[0] == "scan" {
		if h, err := scanner.ParseCIDR(args[1]); err == nil {
			hosts = h
		}
	}
	devices := iotdiscover.Scan(ctx, iotdiscover.Options{
		Hosts:   hosts,
		Timeout: 3 * time.Second,
	})
	var b strings.Builder
	fmt.Fprintf(&b, "iot discover -> %d device(s)\n", len(devices))
	for _, d := range devices {
		fmt.Fprintf(&b, "  %s", d.IP)
		if d.Vendor != "" {
			fmt.Fprintf(&b, "  vendor=%s", d.Vendor)
		}
		if d.MAC != "" {
			fmt.Fprintf(&b, "  mac=%s", d.MAC)
		}
		if len(d.Signals) > 0 {
			fmt.Fprintf(&b, "  signals=%s", strings.Join(d.Signals, ","))
		}
		b.WriteString("\n")
	}
	return Result{Output: b.String(), ExitCode: 0}
}
