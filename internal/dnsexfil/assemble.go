package dnsexfil

import (
	"sync"
	"time"
)

// Session reassembles chunks arriving out of order.
type Session struct {
	ID        string
	Total     int
	chunks    map[int][]byte
	started   time.Time
	completed bool
	bytes     int64
	mu        sync.Mutex
}

// Reassembler tracks all live exfil sessions by session ID.
type Reassembler struct {
	mu       sync.Mutex
	sessions map[string]*Session
	// OnComplete fires when a session's chunks are all present.
	OnComplete func(sessionID string, payload []byte, bytes int64)
}

// NewReassembler builds an empty reassembler.
func NewReassembler() *Reassembler {
	return &Reassembler{sessions: map[string]*Session{}}
}

// Feed adds one chunk. When the session is complete, it fires OnComplete.
func (r *Reassembler) Feed(sessionID string, seq, total int, payload []byte) bool {
	r.mu.Lock()
	s, ok := r.sessions[sessionID]
	if !ok {
		s = &Session{
			ID:      sessionID,
			Total:   total,
			chunks:  make(map[int][]byte),
			started: time.Now(),
		}
		r.sessions[sessionID] = s
	}
	s.mu.Lock()
	if _, dup := s.chunks[seq]; !dup {
		s.chunks[seq] = append([]byte(nil), payload...)
		s.bytes += int64(len(payload))
	}
	ready := len(s.chunks) == s.Total
	if ready && !s.completed {
		s.completed = true
	}
	s.mu.Unlock()
	r.mu.Unlock()

	if ready && r.OnComplete != nil {
		// Reassemble in order
		full := make([]byte, 0, s.bytes)
		for i := 0; i < s.Total; i++ {
			full = append(full, s.chunks[i]...)
		}
		r.OnComplete(sessionID, full, s.bytes)
		r.mu.Lock()
		delete(r.sessions, sessionID)
		r.mu.Unlock()
		return true
	}
	return false
}

// Active returns the count of in-flight sessions.
func (r *Reassembler) Active() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.sessions)
}
