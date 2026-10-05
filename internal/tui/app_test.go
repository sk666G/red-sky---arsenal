package tui

import (
	"testing"
	"time"

	tea "github.com/charmbracelet/bubbletea"

	"github.com/sk666G/red-sky---arsenal/internal/session"
)

// --- Invariant 1: New() returns a sane model ---
func TestNewModelDefaults(t *testing.T) {
	mgr := session.NewManager()
	defer close(mgr.Events)

	m := New(mgr, "test-engagement", 4444, nil)

	if m.mgr != mgr {
		t.Fatalf("mgr not wired")
	}
	if m.engagement != "test-engagement" {
		t.Fatalf("engagement=%q", m.engagement)
	}
	if m.width == 0 || m.height == 0 {
		// New should set sensible defaults before the first WindowSizeMsg
		t.Fatalf("width/height not initialized: %d x %d", m.width, m.height)
	}
}

// --- Invariant 2: tick with an empty event channel returns fast ---
//
// Regression guard: a blocking receive on m.mgr.Events inside Update
// would hang the whole tea loop. Assert a single tickMsg round-trips
// in well under the tick interval.
func TestTickDoesNotBlock(t *testing.T) {
	mgr := session.NewManager()
	defer close(mgr.Events)

	m := New(mgr, "test", 4444, nil)
	m.width, m.height = 80, 24

	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = m.Update(tickMsg(time.Now()))
	}()

	select {
	case <-done:
	case <-time.After(100 * time.Millisecond):
		t.Fatalf("Update(tickMsg) blocked longer than 100ms with empty event channel")
	}
}

// --- Invariant 3: printable keys accumulate into the input buffer ---
func TestKeyRunesGoIntoInput(t *testing.T) {
	mgr := session.NewManager()
	defer close(mgr.Events)

	m := New(mgr, "test", 4444, nil)
	m.width, m.height = 80, 24

	m2, _ := m.Update(tea.KeyMsg{Type: tea.KeyRunes, Runes: []rune("whoami")})
	got := m2.(Model)
	if got.input != "whoami" {
		t.Fatalf("input=%q, want whoami", got.input)
	}
}
