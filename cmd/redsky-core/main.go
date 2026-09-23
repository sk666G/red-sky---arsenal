// redsky-core — the framework.
// Phase 5: persistent sessions + TUI.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/plugin"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/scanner"
	"github.com/sk666G/red-sky---arsenal/internal/session"
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
	"github.com/sk666G/red-sky---arsenal/internal/tui"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
)

func main() {
	bind := flag.String("bind", "0.0.0.0", "listen address")
	port := flag.Int("port", 4444, "listen port")
	eng := flag.String("engagement", "default", "engagement name")
	pluginFlag := flag.String("plugin", "", "run a local plugin instead of listening")
	pluginTimeout := flag.Duration("plugin-timeout", 5*time.Minute, "plugin execution timeout")
	scanCIDR := flag.String("scan-cidr", "", "fast TCP scan: cidr or single ip")
	scanPorts := flag.String("scan-ports", "1-1024", "fast TCP scan: port spec")
	scanThreads := flag.Int("scan-threads", 2000, "fast TCP scan: worker count")
	scanTimeout := flag.Duration("scan-timeout", 2*time.Second, "fast TCP scan: dial timeout")
	headless := flag.Bool("headless", false, "log-only mode, no TUI")
	flag.Parse()

	if *pluginFlag != "" {
		runPlugin(*pluginFlag, *pluginTimeout)
		return
	}

	if *scanCIDR != "" {
		runScanner(*scanCIDR, *scanPorts, *scanThreads, *scanTimeout)
		return
	}

	root, _ := os.UserHomeDir()
	paths := rsTLS.Paths(filepath.Join(root, ".redsky"), *eng)
	if err := paths.EnsureCA([]string{"127.0.0.1", "localhost"}); err != nil {
		log.Fatalf("ensure CA: %v", err)
	}
	fp, err := paths.CAFingerprint()
	if err != nil {
		log.Fatalf("ca fingerprint: %v", err)
	}
	tlsCfg, err := paths.ServerTLSConfig()
	if err != nil {
		log.Fatalf("tls config: %v", err)
	}

	mgr := session.NewManager()

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	tlsLn := rsTLS.NewTLSListener(ln, tlsCfg)

	fmt.Printf("redsky-core listening on %s (TLS)\n", addr)
	fmt.Printf("engagement dir: %s\n", paths.Dir)
	fmt.Printf("CA fingerprint: %s\n", fp)
	fmt.Printf("agent flag: -ca-fingerprint '%s'\n\n", fp)

	go acceptLoop(tlsLn, mgr)

	if *headless {
		for ev := range mgr.Events {
			fmt.Printf("[%s] %s: %s\n", ev.Kind, ev.AgentID, ev.Text)
		}
		return
	}

	p := tea.NewProgram(tui.New(mgr), tea.WithAltScreen())
	if _, err := p.Run(); err != nil {
		log.Fatalf("tui: %v", err)
	}
}

func acceptLoop(ln net.Listener, mgr *session.Manager) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			continue
		}
		go handleConn(conn, mgr)
	}
}

func runPlugin(spec string, timeout time.Duration) {
	parts := strings.Fields(spec)
	if len(parts) == 0 {
		log.Fatalf("-plugin needs at least a module name")
	}
	repo := findRepoRoot()
	if repo == "" {
		log.Fatalf("could not find repo root (expected redsky.py)")
	}
	out, err := plugin.Invoke(context.Background(), repo, parts[0], parts[1:], timeout)
	if out != "" {
		fmt.Print(out)
	}
	if err != nil {
		log.Printf("plugin exited with error: %v", err)
		os.Exit(1)
	}
}

func findRepoRoot() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	dir := cwd
	for {
		if _, err := os.Stat(filepath.Join(dir, "redsky.py")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return ""
		}
		dir = parent
	}
}

func handleConn(conn net.Conn, mgr *session.Manager) {
	remote := conn.RemoteAddr().String()
	defer func() {
		if r := recover(); r != nil {
			log.Printf("%s: panic: %v", remote, r)
			conn.Close()
		}
	}()

	// The listener already wrapped conn in TLS; but we haven't forced the
	// handshake yet. Do it now.
	if tlsConn, ok := conn.(*tls.Conn); ok {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
		if err := tlsConn.Handshake(); err != nil {
			conn.Close()
			return
		}
		conn.SetDeadline(time.Time{})
	}

	coreKey, err := crypto.GenerateEphemeralKey()
	if err != nil {
		conn.Close()
		return
	}
	hello := map[string]string{
		"type":    "ecdh_hello",
		"pubkey":  base64.StdEncoding.EncodeToString(coreKey.PublicKey().Bytes()),
		"version": "3",
	}
	helloRaw, _ := json.Marshal(hello)
	if err := wire.WriteFrame(conn, 0, helloRaw); err != nil {
		conn.Close()
		return
	}

	frame, err := wire.ReadFrame(conn)
	if err != nil {
		conn.Close()
		return
	}
	var reply map[string]string
	if err := json.Unmarshal(frame.Payload, &reply); err != nil {
		conn.Close()
		return
	}
	if reply["type"] != "ecdh_reply" {
		conn.Close()
		return
	}
	agentPub, err := base64.StdEncoding.DecodeString(reply["pubkey"])
	if err != nil {
		conn.Close()
		return
	}
	key, err := crypto.DeriveKey(coreKey, agentPub)
	if err != nil {
		conn.Close()
		return
	}
	cs, err := crypto.NewSession(key)
	if err != nil {
		conn.Close()
		return
	}

	// Read beacon.
	frame, err = wire.ReadFrame(conn)
	if err != nil {
		conn.Close()
		return
	}
	beaconRaw, err := cs.Decrypt(frame.Payload)
	if err != nil {
		conn.Close()
		return
	}
	var env proto.Envelope
	if err := json.Unmarshal(beaconRaw, &env); err != nil {
		conn.Close()
		return
	}
	var beacon proto.Beacon
	if err := json.Unmarshal(env.Payload, &beacon); err != nil {
		conn.Close()
		return
	}
	mgr.Register(beacon.AgentID, beacon.Info, conn, cs)
}


// runScanner is the fast Go port scanner (Phase 6 + discovery).
func runScanner(cidr, ports string, threads int, timeout time.Duration) {
	allHosts, err := scanner.ParseCIDR(cidr)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	portList, err := scanner.ParsePorts(ports)
	if err != nil {
		log.Fatalf("scan: %v", err)
	}
	ctx := context.Background()
	t0 := time.Now()

	// Stage 1: fast host discovery.
	fmt.Printf("discovering live hosts in %s (%d hosts)...\n", cidr, len(allHosts))
	live := scanner.DiscoverAlive(ctx, allHosts, nil, 500, 800*time.Millisecond, func(h string) {
		fmt.Printf("[live] %s\n", h)
	})
	fmt.Printf("discovery: %d/%d hosts alive in %s\n\n",
		len(live), len(allHosts), time.Since(t0).Truncate(time.Millisecond))

	if len(live) == 0 {
		fmt.Println("no live hosts found")
		return
	}

	// Stage 2: full port scan on live hosts only.
	fmt.Printf("scanning %d live hosts x %d ports (%d probes) with %d workers\n",
		len(live), len(portList), len(live)*len(portList), threads)

	var results []scanner.Result
	var mu sync.Mutex

	err = scanner.Scan(ctx, scanner.ScanOptions{
		Hosts:   live,
		Ports:   portList,
		Threads: threads,
		Timeout: timeout,
	}, func(r scanner.Result) {
		mu.Lock()
		results = append(results, r)
		mu.Unlock()
		fmt.Printf("[+] %s:%d\n", r.Host, r.Port)
	})
	if err != nil {
		log.Fatalf("scan: %v", err)
	}

	elapsed := time.Since(t0)
	fmt.Printf("\n%d open port(s) in %s\n", len(results), elapsed.Truncate(time.Millisecond))
	if len(results) > 0 {
		path, err := scanner.WriteJSON(results)
		if err != nil {
			log.Printf("write results: %v", err)
		} else {
			fmt.Printf("saved: %s\n", path)
		}
	}
}
