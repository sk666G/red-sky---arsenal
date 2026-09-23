package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"path/filepath"
	"sort"
	"sync"
	"time"
)

// Result is one open port found on a host.
type Result struct {
	Host string `json:"host"`
	Port int    `json:"port"`
}

// ScanOptions controls one scan run.
type ScanOptions struct {
	Hosts   []string
	Ports   []int
	Threads int
	Timeout time.Duration
}

// Scan walks every (host, port) pair with the given worker count and returns
// the open ports found. Results stream to the returned channel as they arrive
// and the scan terminates when the channel closes.
func Scan(ctx context.Context, opts ScanOptions, onResult func(Result)) error {
	if opts.Threads <= 0 {
		opts.Threads = 2000
	}
	if opts.Timeout == 0 {
		opts.Timeout = 2 * time.Second
	}

	type probe struct {
		host string
		port int
	}

	jobs := make(chan probe, opts.Threads*4)
	var wg sync.WaitGroup

	worker := func() {
		defer wg.Done()
		dialer := &net.Dialer{Timeout: opts.Timeout}
		for p := range jobs {
			select {
			case <-ctx.Done():
				return
			default:
			}
			addr := fmt.Sprintf("%s:%d", p.host, p.port)
			conn, err := dialer.DialContext(ctx, "tcp", addr)
			if err == nil {
				conn.Close()
				onResult(Result{Host: p.host, Port: p.port})
			}
		}
	}

	for i := 0; i < opts.Threads; i++ {
		wg.Add(1)
		go worker()
	}

	// Feed jobs
	go func() {
		defer close(jobs)
		for _, h := range opts.Hosts {
			for _, p := range opts.Ports {
				select {
				case <-ctx.Done():
					return
				case jobs <- probe{host: h, port: p}:
				}
			}
		}
	}()

	wg.Wait()
	return nil
}

// WriteJSON dumps the collected results to disk under Output/scanner/.
func WriteJSON(results []Result) (string, error) {
	dir := filepath.Join("Output", "scanner")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(dir, fmt.Sprintf("scan_%d.json", time.Now().Unix()))
	// sort by host then port for stable output
	sort.Slice(results, func(i, j int) bool {
		if results[i].Host == results[j].Host {
			return results[i].Port < results[j].Port
		}
		return results[i].Host < results[j].Host
	})
	data, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return "", err
	}
	return path, nil
}


// DiscoverAlive probes each host on a small set of common ports with a short
// timeout to find which ones are reachable. Returns only the live hosts.
// Use this to prune the target list before a full port scan.
func DiscoverAlive(ctx context.Context, hosts []string, probePorts []int,
	threads int, timeout time.Duration, onAlive func(string)) []string {
	if threads <= 0 {
		threads = 500
	}
	if timeout == 0 {
		timeout = 800 * time.Millisecond
	}
	if len(probePorts) == 0 {
		probePorts = []int{80, 443, 22, 445}
	}

	type job struct{ host string }
	jobs := make(chan job, threads*4)
	var wg sync.WaitGroup
	var mu sync.Mutex
	alive := map[string]bool{}

	worker := func() {
		defer wg.Done()
		d := &net.Dialer{Timeout: timeout}
		for j := range jobs {
			found := false
			for _, prt := range probePorts {
				conn, err := d.DialContext(ctx, "tcp", fmt.Sprintf("%s:%d", j.host, prt))
				if err == nil {
					conn.Close()
					found = true
					break
				}
				// ECONNREFUSED means host is up but port closed — still alive
				if isConnRefused(err) {
					found = true
					break
				}
			}
			if found {
				mu.Lock()
				if !alive[j.host] {
					alive[j.host] = true
					mu.Unlock()
					onAlive(j.host)
				} else {
					mu.Unlock()
				}
			}
		}
	}

	for i := 0; i < threads; i++ {
		wg.Add(1)
		go worker()
	}
	go func() {
		defer close(jobs)
		for _, h := range hosts {
			select {
			case <-ctx.Done():
				return
			case jobs <- job{host: h}:
			}
		}
	}()
	wg.Wait()

	out := make([]string, 0, len(alive))
	for h := range alive {
		out = append(out, h)
	}
	sort.Strings(out)
	return out
}

func isConnRefused(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "connection refused")
}
