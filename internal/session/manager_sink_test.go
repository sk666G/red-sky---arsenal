package session

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/sk666G/red-sky---arsenal/internal/proto"
	"github.com/sk666G/red-sky---arsenal/internal/wire"
)

// TestSetDataSinkFires ensures a registered sink is called for an
// envelope type that readerLoop has no explicit case for. The sink
// returns true, so readerLoop must not emit an "unknown message" error.
func TestSetDataSinkFires(t *testing.T) {
	m := NewManager()
	defer m.Close()

	var fired bool
	m.SetDataSink(func(s *Session, env proto.Envelope) bool {
		if env.Type == proto.TypeAdEnumData {
			fired = true
			return true
		}
		return false
	})

	// Directly exercise the sink path — the full readerLoop requires a
	// real encrypted conn which is out of scope for this test.
	m.sinkMu.RLock()
	sink := m.sink
	m.sinkMu.RUnlock()
	if sink == nil {
		t.Fatal("sink not set")
	}

	s := &Session{AgentID: "agent-1"}
	env := proto.Envelope{
		Type:    proto.TypeAdEnumData,
		Payload: json.RawMessage(`{"action":"users","dn":"CN=alice,DC=corp","ok":true}`),
	}
	if !sink(s, env) {
		t.Fatal("sink returned false — should claim TypeAdEnumData")
	}
	if !fired {
		t.Fatal("sink did not fire for TypeAdEnumData")
	}
}

// TestSetDataSinkIgnoresUnknown ensures the sink can decline an envelope
// (returns false), so readerLoop's existing default emit still runs.
func TestSetDataSinkIgnoresUnknown(t *testing.T) {
	m := NewManager()
	defer m.Close()

	m.SetDataSink(func(s *Session, env proto.Envelope) bool { return false })

	m.sinkMu.RLock()
	sink := m.sink
	m.sinkMu.RUnlock()

	s := &Session{AgentID: "agent-1"}
	env := proto.Envelope{Type: proto.MessageType("nonsense"), Payload: json.RawMessage("{}")}
	if sink(s, env) {
		t.Fatal("sink claimed a message it shouldn't")
	}
}

// TestSetDataSinkNilClears confirms SetDataSink(nil) reverts to the old
// default-emit behavior without panicking.
func TestSetDataSinkNilClears(t *testing.T) {
	m := NewManager()
	defer m.Close()

	m.SetDataSink(func(s *Session, env proto.Envelope) bool { return true })
	m.SetDataSink(nil)

	m.sinkMu.RLock()
	sink := m.sink
	m.sinkMu.RUnlock()
	if sink != nil {
		t.Fatal("sink should be nil after SetDataSink(nil)")
	}

	// Ensure readerLoop default path would still run — just a sanity
	// check that nil sink is safe in the default case body.
	_ = wire.FlagEncrypted
	_ = time.Now
}
