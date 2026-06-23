// Package recovery manages the SGW-C restart counter per TS 29.274 Section 7.1.
// The counter is incremented on each process start and sent in Recovery IEs.
// The value is persisted to stable storage so peers can detect node restarts.
package recovery

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
)

// Counter holds the GTPv2-C restart counter for this SGW-C instance.
// The value is a uint8 that wraps at 255 per TS 29.274 Section 8.2.
type Counter struct {
	val atomic.Uint32
}

// New creates a Counter initialised to initial+1.
// Every process start is a restart per TS 29.274 Rel-15 §7.1.1; the counter
// must increase each time so peers can detect loss of local context.
// Prefer LoadOrInit to ensure the value is persisted across restarts.
func New(initial uint8) *Counter {
	c := &Counter{}
	c.val.Store(uint32((initial + 1) & 0xFF))
	return c
}

// LoadOrInit loads the persisted restart counter from path, increments it,
// writes the new value back, and returns a ready Counter.
// Per TS 29.274 Rel-15 §7.1.1/§7.1.2 and TS 23.007: the counter must change
// on each node restart so peers detect loss of local context.
// If path does not exist (first boot), the counter starts from 0 → 1.
func LoadOrInit(path string) (*Counter, error) {
	var prev uint8
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read recovery counter %q: %w", path, err)
	}
	if err == nil && len(data) >= 1 {
		prev = data[0]
	}

	c := New(prev)

	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return nil, fmt.Errorf("create state dir for recovery counter: %w", err)
	}
	if err := os.WriteFile(path, []byte{c.Value()}, 0644); err != nil {
		return nil, fmt.Errorf("write recovery counter %q: %w", path, err)
	}
	return c, nil
}

// Value returns the current restart counter value.
func (c *Counter) Value() uint8 {
	return uint8(c.val.Load() & 0xFF)
}

// Increment advances the counter by one, wrapping at 255.
func (c *Counter) Increment() uint8 {
	for {
		old := c.val.Load()
		next := (old + 1) & 0xFF
		if c.val.CompareAndSwap(old, next) {
			return uint8(next)
		}
	}
}
