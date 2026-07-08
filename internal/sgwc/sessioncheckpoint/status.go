package sessioncheckpoint

import (
	"sync"
	"time"
)

type RuntimeConfig struct {
	Enabled                   bool   `json:"enabled"`
	Backend                   string `json:"backend"`
	SQLitePath                string `json:"sqlite_path,omitempty"`
	RestoreOnStartup          bool   `json:"restore_on_startup"`
	ReconcileOnStartup        bool   `json:"reconcile_on_startup"`
	CheckpointIntervalSeconds int    `json:"checkpoint_interval_seconds"`
}

type RuntimeStatus struct {
	RuntimeConfig
	SessionsLoaded        int       `json:"sessions_loaded"`
	SessionsRestored      int       `json:"sessions_restored"`
	SessionsSkipped       int       `json:"sessions_skipped"`
	ReservedS11TEIDs      int       `json:"reserved_s11_teids"`
	PeerSnapshotsLoaded   int       `json:"peer_snapshots_loaded"`
	GTPCPeersRestored     int       `json:"gtpc_peers_restored"`
	PFCPPeersRestored     int       `json:"pfcp_peers_restored"`
	Flushes               uint64    `json:"flushes"`
	FlushFailures         uint64    `json:"flush_failures"`
	SessionSaves          uint64    `json:"session_saves"`
	SessionDeletes        uint64    `json:"session_deletes"`
	PeerSaves             uint64    `json:"peer_saves"`
	LastFlushAt           time.Time `json:"last_flush_at,omitempty"`
	LastFlushError        string    `json:"last_flush_error,omitempty"`
	LastFlushErrorAt      time.Time `json:"last_flush_error_at,omitempty"`
	LastSuccessfulFlushAt time.Time `json:"last_successful_flush_at,omitempty"`
}

type StatusTracker struct {
	mu     sync.RWMutex
	status RuntimeStatus
}

func NewStatusTracker(cfg RuntimeConfig) *StatusTracker {
	return &StatusTracker{status: RuntimeStatus{RuntimeConfig: cfg}}
}

func (t *StatusTracker) Status() RuntimeStatus {
	if t == nil {
		return RuntimeStatus{}
	}
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.status
}

func (t *StatusTracker) RecordSessionRestore(loaded, restored, skippedDeleted, skippedInvalid, reservedS11TEIDs int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.SessionsLoaded = loaded
	t.status.SessionsRestored = restored
	t.status.SessionsSkipped = skippedDeleted + skippedInvalid
	t.status.ReservedS11TEIDs = reservedS11TEIDs
}

func (t *StatusTracker) RecordPeerSnapshotsLoaded(count int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.PeerSnapshotsLoaded = count
}

func (t *StatusTracker) RecordGTPCPeersRestored(count int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.GTPCPeersRestored = count
}

func (t *StatusTracker) RecordPFCPPeersRestored(count int) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.PFCPPeersRestored = count
}

func (t *StatusTracker) RecordSessionSave() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.SessionSaves++
}

func (t *StatusTracker) RecordSessionDelete() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.SessionDeletes++
}

func (t *StatusTracker) RecordPeerSave() {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.PeerSaves++
}

func (t *StatusTracker) RecordFlush(err error, at time.Time) {
	if t == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.status.Flushes++
	t.status.LastFlushAt = at
	if err != nil {
		t.status.FlushFailures++
		t.status.LastFlushError = err.Error()
		t.status.LastFlushErrorAt = at
		return
	}
	t.status.LastSuccessfulFlushAt = at
	t.status.LastFlushError = ""
	t.status.LastFlushErrorAt = time.Time{}
}
