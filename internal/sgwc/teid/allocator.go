// Package teid provides TEID allocation for SGW-C control-plane endpoints.
// TEIDs are allocated using crypto/rand to avoid predictable sequences.
package teid

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
)

// Allocator allocates 32-bit TEIDs with collision detection.
type Allocator struct {
	mu   sync.Mutex
	used map[uint32]struct{}
}

// NewAllocator creates a ready-to-use TEID allocator.
func NewAllocator() *Allocator {
	return &Allocator{used: make(map[uint32]struct{})}
}

// Alloc allocates a new unique non-zero TEID.
// Returns an error only if the allocator is exhausted (practically impossible).
func (a *Allocator) Alloc() (uint32, error) {
	a.mu.Lock()
	defer a.mu.Unlock()

	for attempts := 0; attempts < 1024; attempts++ {
		t, err := randomU32()
		if err != nil {
			return 0, fmt.Errorf("teid: rand read: %w", err)
		}
		if t == 0 {
			continue
		}
		if _, exists := a.used[t]; !exists {
			a.used[t] = struct{}{}
			return t, nil
		}
	}
	return 0, fmt.Errorf("teid: allocator exhausted after 1024 attempts")
}

// Free releases a previously allocated TEID back to the pool.
func (a *Allocator) Free(t uint32) {
	if t == 0 {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.used, t)
}

// Len returns the number of currently allocated TEIDs.
func (a *Allocator) Len() int {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.used)
}

func randomU32() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint32(b[:]), nil
}
