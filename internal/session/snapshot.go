package session

import (
	"sort"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// ManagerSnapshot is a deep-copy view of the manager's session table.
// The TUI reads this instead of poking live *Session pointers, so the
// run loop never races a readerLoop mutating a session's Info or LastSeen.
type ManagerSnapshot struct {
	TS       time.Time
	Sessions []SessionSnapshot
}

// SessionSnapshot is one session's readable state. No live pointers, no
// mutexes, no channels, no net.Conn — everything a view needs and
// nothing a view can accidentally mutate.
type SessionSnapshot struct {
	AgentID   string
	Info      proto.AgentInfo
	Joined    time.Time
	LastSeen  time.Time
	Connected bool
	Tasks     []TaskSnapshot
}

// TaskSnapshot is one task's state, a copy of the fields the TUI draws.
type TaskSnapshot struct {
	ID        string
	Kind      string
	Cmd       string
	Args      []string
	Timeout   int
	State     TaskState
	Enqueued  time.Time
	Completed time.Time
	Error     string
	// Result stays a pointer — it's written exactly once when the task
	// completes and never mutated after, so a shallow copy is safe.
	Result *proto.Result
}

// Snapshot returns a consistent deep-copy of the manager's state at a
// single point in time. Sessions are ordered by LastSeen descending,
// ties broken by AgentID — deterministic so the TUI doesn't wobble.
func (m *Manager) Snapshot() ManagerSnapshot {
	m.mu.RLock()
	sessions := make([]*Session, 0, len(m.sessions))
	for _, s := range m.sessions {
		sessions = append(sessions, s)
	}
	m.mu.RUnlock()

	out := ManagerSnapshot{
		TS:       time.Now(),
		Sessions: make([]SessionSnapshot, 0, len(sessions)),
	}
	for _, s := range sessions {
		out.Sessions = append(out.Sessions, s.snapshot())
	}
	sort.SliceStable(out.Sessions, func(i, j int) bool {
		a, b := out.Sessions[i], out.Sessions[j]
		if !a.LastSeen.Equal(b.LastSeen) {
			return a.LastSeen.After(b.LastSeen)
		}
		return a.AgentID < b.AgentID
	})
	return out
}

// snapshot returns a copy of this session's readable state. Holds s.mu
// for the whole read so the beacon handler's write to Info/LastSeen can't
// interleave. Tasks are copied under the same lock.
func (s *Session) snapshot() SessionSnapshot {
	s.mu.Lock()
	defer s.mu.Unlock()

	tasks := make([]TaskSnapshot, 0, len(s.tasks))
	for _, t := range s.tasks {
		tasks = append(tasks, TaskSnapshot{
			ID:        t.ID,
			Kind:      t.Kind,
			Cmd:       t.Cmd,
			Args:      append([]string(nil), t.Args...),
			Timeout:   t.Timeout,
			State:     t.State,
			Enqueued:  t.Enqueued,
			Completed: t.Completed,
			Error:     t.Error,
			Result:    t.Result,
		})
	}
	sort.SliceStable(tasks, func(i, j int) bool {
		return tasks[i].Enqueued.Before(tasks[j].Enqueued)
	})

	return SessionSnapshot{
		AgentID:   s.AgentID,
		Info:      s.Info,
		Joined:    s.Joined,
		LastSeen:  s.LastSeen,
		Connected: !s.closed,
		Tasks:     tasks,
	}
}
