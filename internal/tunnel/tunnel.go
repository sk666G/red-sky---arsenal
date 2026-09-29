// Package tunnel implements the core-side of agent-backed network tunnels.
//
// A local SOCKS5 listener on the operator box (default 127.0.0.1:1080)
// accepts application connections, opens a corresponding tunnel to a
// selected agent, and pipes bytes back and forth. From the operator's
// perspective, they have a SOCKS5 proxy whose exit node is the agent.
package tunnel

import (
	"errors"
	"io"
	"sync"
)

// Tunnel is one active stream through an agent.
type Tunnel struct {
	ID     string
	host   string
	port   int

	// fromAgent carries bytes received from the agent to whoever is reading
	// this tunnel on the core side.
	fromAgent *pipe
	// toAgent carries bytes the core wants to send through the tunnel.
	toAgent   *pipe

	closed chan struct{}
	once   sync.Once
}

// pipe is a simple in-memory byte pipe with a close signal.
type pipe struct {
	mu     sync.Mutex
	buf    []byte
	cond   *sync.Cond
	closed bool
	err    error
}

func newPipe() *pipe {
	p := &pipe{}
	p.cond = sync.NewCond(&p.mu)
	return p
}

// Write appends to the pipe. Returns io.ErrClosedPipe if closed.
func (p *pipe) Write(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return 0, io.ErrClosedPipe
	}
	p.buf = append(p.buf, b...)
	p.cond.Broadcast()
	return len(b), nil
}

// Read blocks until data is available or the pipe closes.
func (p *pipe) Read(b []byte) (int, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.buf) == 0 && !p.closed {
		p.cond.Wait()
	}
	if len(p.buf) == 0 {
		if p.err != nil {
			return 0, p.err
		}
		return 0, io.EOF
	}
	n := copy(b, p.buf)
	p.buf = p.buf[n:]
	return n, nil
}

// Close closes the pipe with an optional error reason.
func (p *pipe) Close(err error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return
	}
	p.closed = true
	p.err = err
	p.cond.Broadcast()
}

// --- Tunnel manager ---

// Manager tracks every open tunnel by ID.
type Manager struct {
	mu      sync.RWMutex
	tunnels map[string]*Tunnel
}

// NewManager creates an empty tunnel manager.
func NewManager() *Manager {
	return &Manager{tunnels: map[string]*Tunnel{}}
}

// Register creates a new tunnel with the given ID.
func (m *Manager) Register(id, host string, port int) *Tunnel {
	t := &Tunnel{
		ID:        id,
		host:      host,
		port:      port,
		fromAgent: newPipe(),
		toAgent:   newPipe(),
		closed:    make(chan struct{}),
	}
	m.mu.Lock()
	m.tunnels[id] = t
	m.mu.Unlock()
	return t
}

// Get returns the tunnel with the given ID.
func (m *Manager) Get(id string) (*Tunnel, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	t, ok := m.tunnels[id]
	return t, ok
}

// Remove drops a tunnel from the manager.
func (m *Manager) Remove(id string) {
	m.mu.Lock()
	delete(m.tunnels, id)
	m.mu.Unlock()
}

// --- Tunnel ---

// FeedFromAgent is called when a tunnel_data message arrives. It pushes the
// bytes into the fromAgent pipe so the SOCKS-side reader sees them.
func (t *Tunnel) FeedFromAgent(data []byte, eof bool) {
	if len(data) > 0 {
		t.fromAgent.Write(data)
	}
	if eof {
		t.fromAgent.Close(nil)
	}
}

// ReadFromAgent reads bytes coming from the agent toward the local SOCKS client.
func (t *Tunnel) ReadFromAgent(b []byte) (int, error) {
	return t.fromAgent.Read(b)
}

// WriteToAgent queues bytes to be sent to the agent.
func (t *Tunnel) WriteToAgent(b []byte) (int, error) {
	return t.toAgent.Write(b)
}

// ReadForAgent reads bytes queued for the agent side.
func (t *Tunnel) ReadForAgent(b []byte) (int, error) {
	return t.toAgent.Read(b)
}

// FailFromAgent signals the tunnel is dead.
func (t *Tunnel) FailFromAgent(err error) {
	t.fromAgent.Close(err)
	t.once.Do(func() {
		close(t.closed)
	})
}

// Close tears the tunnel down.
func (t *Tunnel) Close() {
	t.once.Do(func() {
		close(t.closed)
	})
	t.fromAgent.Close(errors.New("tunnel closed"))
	t.toAgent.Close(errors.New("tunnel closed"))
}

// Done returns a channel that closes when the tunnel is dead.
func (t *Tunnel) Done() <-chan struct{} { return t.closed }

// Host returns the tunnel's target host:port.
func (t *Tunnel) Host() (string, int) { return t.host, t.port }
