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
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/plugin"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
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
	headless := flag.Bool("headless", false, "log-only mode, no TUI")
	flag.Parse()

	if *pluginFlag != "" {
		runPlugin(*pluginFlag, *pluginTimeout)
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
