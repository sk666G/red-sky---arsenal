package agentfw

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/scanner"
)

type netScannerModule struct{}

func init() { Register(netScannerModule{}) }

func (netScannerModule) Name() string { return "net_scanner" }

func (netScannerModule) Run(ctx context.Context, args []string) Result {
	// args = [cidr, ports, threads?]
	if len(args) < 2 {
		return Result{Err: fmt.Errorf("net_scanner needs <cidr> <ports> [threads]"), ExitCode: 2}
	}
	cidr := args[0]
	portSpec := args[1]
	threads := 1000
	if len(args) >= 3 {
		if n, err := strconv.Atoi(args[2]); err == nil && n > 0 {
			threads = n
		}
	}

	hosts, err := scanner.ParseCIDR(cidr)
	if err != nil {
		return Result{Err: err, ExitCode: 2}
	}
	ports, err := scanner.ParsePorts(portSpec)
	if err != nil {
		return Result{Err: err, ExitCode: 2}
	}

	live := scanner.DiscoverAlive(ctx, hosts, nil, 500, 800*time.Millisecond, func(string) {})
	if len(live) == 0 {
		return Result{Output: fmt.Sprintf("net_scanner %s: no live hosts\n", cidr)}
	}

	var lines []string
	lines = append(lines, fmt.Sprintf("net_scanner %s -> %d live host(s)", cidr, len(live)))
	err = scanner.Scan(ctx, scanner.ScanOptions{
		Hosts:   live,
		Ports:   ports,
		Threads: threads,
		Timeout: 2 * time.Second,
	}, func(r scanner.Result) {
		lines = append(lines, fmt.Sprintf("%s:%d open", r.Host, r.Port))
	})
	if err != nil {
		return Result{Err: err, ExitCode: 1}
	}
	out := ""
	for _, l := range lines {
		out += l + "\n"
	}
	if len(lines) == 1 {
		out += "(no open ports)\n"
	}
	return Result{Output: out}
}
