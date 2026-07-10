package bearerinactivity

import (
	"sync"
	"time"

	"vectorcore-sgw/internal/sgwc/session"
)

type RuntimeSnapshot struct {
	LastScanAt       time.Time
	LastResult       CleanupResult
	Scans            uint64
	Planned          uint64
	Skipped          uint64
	Cleaned          uint64
	Failed           uint64
	DeniedDefault    uint64
	MissingRules     uint64
	LastActionCounts map[DecisionAction]int
}

type Snapshot struct {
	Runtime      RuntimeSnapshot
	Decisions    []Decision
	ActionCounts map[DecisionAction]int
}

type Status struct {
	mu               sync.RWMutex
	lastScanAt       time.Time
	lastResult       CleanupResult
	scans            uint64
	planned          uint64
	skipped          uint64
	cleaned          uint64
	failed           uint64
	deniedDefault    uint64
	missingRules     uint64
	lastActionCounts map[DecisionAction]int
}

func NewStatus() *Status {
	return &Status{}
}

func (s *Status) RecordScan(at time.Time, result CleanupResult, decisions []Decision) {
	if s == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	actionCounts := countActions(decisions)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lastScanAt = at
	s.lastResult = result
	s.scans++
	s.planned += uint64(result.Planned)
	s.skipped += uint64(result.Skipped)
	s.cleaned += uint64(result.Cleaned)
	s.failed += uint64(result.Failed)
	s.deniedDefault += uint64(result.DeniedDefault)
	s.missingRules += uint64(result.MissingRules)
	s.lastActionCounts = actionCounts
}

func (s *Status) Snapshot() RuntimeSnapshot {
	if s == nil {
		return RuntimeSnapshot{LastActionCounts: map[DecisionAction]int{}}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return RuntimeSnapshot{
		LastScanAt:       s.lastScanAt,
		LastResult:       s.lastResult,
		Scans:            s.scans,
		Planned:          s.planned,
		Skipped:          s.skipped,
		Cleaned:          s.cleaned,
		Failed:           s.failed,
		DeniedDefault:    s.deniedDefault,
		MissingRules:     s.missingRules,
		LastActionCounts: copyActionCounts(s.lastActionCounts),
	}
}

type Reporter struct {
	Sessions  *session.Manager
	Evaluator Evaluator
	Status    *Status
	Now       func() time.Time
}

func (r Reporter) Snapshot() Snapshot {
	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	decisions := r.Evaluator.EvaluateManager(r.Sessions, now)
	return Snapshot{
		Runtime:      r.Status.Snapshot(),
		Decisions:    decisions,
		ActionCounts: countActions(decisions),
	}
}

func countActions(decisions []Decision) map[DecisionAction]int {
	out := make(map[DecisionAction]int)
	for _, decision := range decisions {
		out[decision.Action]++
	}
	return out
}

func copyActionCounts(in map[DecisionAction]int) map[DecisionAction]int {
	out := make(map[DecisionAction]int, len(in))
	for action, count := range in {
		out[action] = count
	}
	return out
}
