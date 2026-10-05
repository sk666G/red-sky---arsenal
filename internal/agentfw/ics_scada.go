package agentfw

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/icsdiscover"
	"github.com/sk666G/red-sky---arsenal/internal/scanner"
)

type icsScadaModule struct{}

func init() { Register(icsScadaModule{}) }

func (icsScadaModule) Name() string { return "ics_scada" }

func (icsScadaModule) Run(ctx context.Context, args []string) Result {
	var hosts []string
	if len(args) >= 2 && args[0] == "scan" {
		if h, err := scanner.ParseCIDR(args[1]); err == nil {
			hosts = h
		}
	}
	if len(hosts) == 0 {
		return Result{Err: fmt.Errorf("ics_scada needs a cidr: ics_scada scan 10.0.0.0/24"), ExitCode: 2}
	}
	devices := icsdiscover.Scan(ctx, icsdiscover.Options{
		Hosts:   hosts,
		Timeout: 2 * time.Second,
	})
	var b strings.Builder
	fmt.Fprintf(&b, "ics_scada scan %s -> %d device(s)\n", args[1], len(devices))
	for _, d := range devices {
		fmt.Fprintf(&b, "  %s  protocols=%s\n", d.IP, strings.Join(d.Protocols, ","))
		for _, det := range d.Details {
			fmt.Fprintf(&b, "      %s\n", det)
		}
	}
	if len(devices) == 0 {
		b.WriteString("  (no ICS devices found)\n")
	}
	return Result{Output: b.String(), ExitCode: 0}
}
