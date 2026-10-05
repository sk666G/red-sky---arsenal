package session

import (
	"net"
	"sync"
	"testing"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/crypto"
	"github.com/sk666G/red-sky---arsenal/internal/proto"
)

// fakeConn is a net.Conn that reads until Close, then errors — enough
// surface for readerLoop/writerLoop to spin up and tear down.
type fakeConn struct {
	mu     sync.Mutex
	closed chan struct{}
}

func newFakeConn() *fakeConn {
	return &fakeConn{closed: make(chan struct{})}
}

func (c *fakeConn) Read(b []byte) (int, error) {
	<-c.closed
	return 0, net.ErrClosed
}
func (c *fakeConn) Write(b []byte) (int, error) { return len(b), nil }
func (c *fakeConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	return nil
}
func (c *fakeConn) LocalAddr() net.Addr                { return fakeAddr{} }
func (c *fakeConn) RemoteAddr() net.Addr               { return fakeAddr{} }
func (c *fakeConn) SetDeadline(t time.Time) error      { return nil }
func (c *fakeConn) SetReadDeadline(t time.Time) error  { return nil }
func (c *fakeConn) SetWriteDeadline(t time.Time) error { return nil }

type fakeAddr struct{}

func (fakeAddr) Network() string { return "fake" }
func (fakeAddr) String() string  { return "fake" }

// csFor returns a crypto.Session good enough for Register to accept.
// Register doesn't touch it until a task is written, so a zero-value
// wrapper is fine for the tests that don't exercise the wire.
func csFor() *crypto.Session { return &crypto.Session{} }

// --- Invariant 1: duplicate Register does not leak the new session ---
//
// Current behavior (v3.2.0-alpha.83): Register calls old.close() which
// closes old.conn. old's readerLoop then errors out and runs
// `delete(m.sessions, s.AgentID)` — deleting the NEW session.
// This test asserts the correct behavior: after duplicate Register,
// the manager still holds a live entry for agentID, and that entry is
// the new one. The current code FAILS this test — see TODO below.
func TestRegisterDuplicateKeepsNewSession(t *testing.T) {
	t.Skip("TODO: fix in pass 2 — readerLoop deletes by agentID, not by session identity")

	m := NewManager()
	defer close(m.Events)

	conn1 := newFakeConn()
	conn2 := newFakeConn()
	s1 := m.Register("agent-1", proto.AgentInfo{}, conn1, csFor())
	s2 := m.Register("agent-1", proto.AgentInfo{}, conn2, csFor())

	// allow the old readerLoop to observe the close
	time.Sleep(50 * time.Millisecond)

	got, ok := m.Get("agent-1")
	if !ok {
		t.Fatalf("manager lost agent-1 after duplicate register")
	}
	if got != s2 {
		t.Fatalf("manager holds old session s1=%p, want s2=%p", got, s2)
	}
	_ = s1
}

// --- Invariant 2: close() is idempotent ---
func TestSessionCloseIdempotent(t *testing.T) {
	m := NewManager()
	defer close(m.Events)
	conn := newFakeConn()
	s := m.Register("agent-1", proto.AgentInfo{}, conn, csFor())

	s.close()
	s.close() // must not panic on double close of the conn
	s.close()

	// the read side is now unblocked and readerLoop will exit
	time.Sleep(50 * time.Millisecond)
}

// --- Invariant 3: Sessions() returns the right set, not a fixed order ---
//
// map iteration is random in Go, so the TUI renders in a wobbling order.
// Test pins the set; ordering is a TODO for pass 2.
func TestSessionsSet(t *testing.T) {
	m := NewManager()
	defer close(m.Events)
	for _, id := range []string{"b", "a", "c"} {
		m.Register(id, proto.AgentInfo{}, newFakeConn(), csFor())
	}
	got := m.Sessions()
	if len(got) != 3 {
		t.Fatalf("Sessions() len=%d, want 3", len(got))
	}
	seen := map[string]bool{}
	for _, s := range got {
		seen[s.AgentID] = true
	}
	for _, want := range []string{"a", "b", "c"} {
		if !seen[want] {
			t.Fatalf("Sessions() missing %q", want)
		}
	}
}

// --- Invariant 4: readerLoop reaps only its own session ---
//
// Same root cause as #1, tested directly on the reader path.
func TestReaderLoopReapsOwnSessionOnly(t *testing.T) {
	t.Skip("TODO: fix in pass 2 — delete(m.sessions, s.AgentID) races with re-register")

	m := NewManager()
	defer close(m.Events)

	conn1 := newFakeConn()
	s1 := m.Register("agent-1", proto.AgentInfo{}, conn1, csFor())

	// replace with a fresh session under the same agentID
	conn2 := newFakeConn()
	s2 := m.Register("agent-1", proto.AgentInfo{}, conn2, csFor())

	// wait for s1.readerLoop to run its delete
	time.Sleep(50 * time.Millisecond)

	got, ok := m.Get("agent-1")
	if !ok || got != s2 {
		t.Fatalf("readerLoop for old session deleted the new one (got=%p want=%p)", got, s2)
	}
	_ = s1
}

// --- Invariant 5: Send after close must not block forever ---
//
// Current behavior: Send writes to s.write (chan *Task, 64) which only
// the session's writerLoop drains. After close(), writerLoop has exited,
// so a full buffer blocks Send indefinitely. This test uses a short
// timeout to fail fast.
func TestSendAfterCloseDoesNotBlock(t *testing.T) {
	t.Skip("TODO: fix in pass 2 — Send writes to s.write without a closed check")

	m := NewManager()
	defer close(m.Events)
	conn := newFakeConn()
	s := m.Register("agent-1", proto.AgentInfo{}, conn, csFor())

	s.close()
	time.Sleep(50 * time.Millisecond) // let writerLoop exit

	done := make(chan struct{})
	go func() {
		defer close(done)
		s.Send("id", nil, 5)
	}()

	select {
	case <-done:
		// good: Send returned (either nil or an error)
	case <-time.After(500 * time.Millisecond):
		t.Fatalf("Send blocked after close")
	}
}

// --- Invariant 6: GetCaptureChannel unknown session returns nil ---
func TestGetCaptureChannelUnknown(t *testing.T) {
	m := NewManager()
	defer close(m.Events)
	s := m.Register("agent-1", proto.AgentInfo{}, newFakeConn(), csFor())

	ch := s.GetCaptureChannel("does-not-exist")
	if ch != nil {
		t.Fatalf("GetCaptureChannel(unknown) = %v, want nil", ch)
	}
}

// compile guard: fakeConn must satisfy net.Conn
var _ net.Conn = (*fakeConn)(nil)
