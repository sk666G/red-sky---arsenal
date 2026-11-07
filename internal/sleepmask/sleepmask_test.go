package sleepmask

import (
	"bytes"
	"testing"
)

func TestMaskUnmaskRoundtrip(t *testing.T) {
	m := &Masker{}
	a := []byte("agent-id-0001")
	b := []byte("0123456789abcdef0123456789abcdef")
	origA := append([]byte(nil), a...)
	origB := append([]byte(nil), b...)
	key, err := m.Mask(a, b)
	if err != nil {
		t.Fatalf("mask: %v", err)
	}
	if len(key) != 32 {
		t.Fatalf("key len %d", len(key))
	}
	if bytes.Equal(a, origA) || bytes.Equal(b, origB) {
		t.Fatal("regions not masked")
	}
	if err := m.Unmask(key, a, b); err != nil {
		t.Fatalf("unmask: %v", err)
	}
	if !bytes.Equal(a, origA) || !bytes.Equal(b, origB) {
		t.Fatal("regions not restored")
	}
}

func TestKeysRotate(t *testing.T) {
	m := &Masker{}
	buf := []byte("0123456789abcdef")
	k1, err := m.Mask(buf)
	if err != nil {
		t.Fatalf("mask 1: %v", err)
	}
	if err := m.Unmask(k1, buf); err != nil {
		t.Fatalf("unmask 1: %v", err)
	}
	k2, err := m.Mask(buf)
	if err != nil {
		t.Fatalf("mask 2: %v", err)
	}
	if bytes.Equal(k1, k2) {
		t.Fatal("keys should rotate between cycles")
	}
}

func TestEmptyKeyRefused(t *testing.T) {
	m := &Masker{}
	if err := m.Unmask(nil, []byte("x")); err == nil {
		t.Fatal("expected empty key error")
	}
}
