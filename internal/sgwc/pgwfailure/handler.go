package pgwfailure

import (
	"log/slog"
	"sort"
	"sync"
	"time"

	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/session"
)

type Config struct {
	Enabled                bool
	MarkSessionsOnPathDown bool
	MarkSessionsOnRestart  bool
}

type Handler struct {
	mu       sync.RWMutex
	sessions *session.Manager
	cfg      Config
	log      *slog.Logger
	pgws     map[string]*pgwState
}

type Snapshot struct {
	PGWAddr           string
	State             session.PGWPathState
	LastStateChange   time.Time
	RecoverySeen      bool
	RecoveryCounter   uint8
	RestartDetectedAt time.Time
	AffectedSessions  int
	Restarts          uint64
	PathDownEvents    uint64
}

type pgwState struct {
	addr              string
	state             session.PGWPathState
	lastStateChange   time.Time
	recoverySeen      bool
	recoveryCounter   uint8
	restartDetectedAt time.Time
	affectedSessions  int
	restarts          uint64
	pathDownEvents    uint64
}

func NewHandler(sessions *session.Manager, cfg Config, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{
		sessions: sessions,
		cfg:      cfg,
		log:      log,
		pgws:     make(map[string]*pgwState),
	}
}

func (h *Handler) OnPeerStateChange(event peerhealth.StateChangeEvent) {
	if h == nil || h.sessions == nil || !h.cfg.Enabled || !h.cfg.MarkSessionsOnPathDown {
		return
	}
	if event.Role != peerhealth.RolePGW {
		return
	}
	state := pgwPathState(event.NewState)
	affected := h.sessions.MarkPGWPathState(event.Addr, state, event.At)
	h.recordStateChange(event, state, affected)
	h.log.Info("PGW path state changed",
		"pgw", event.Addr,
		"old_state", event.OldState,
		"new_state", event.NewState,
		"session_state", state,
		"reason", event.Reason,
		"affected_sessions", affected)
}

func (h *Handler) OnPeerRestart(event peerhealth.RestartEvent) {
	if h == nil || h.sessions == nil || !h.cfg.Enabled || !h.cfg.MarkSessionsOnRestart {
		return
	}
	if event.Role != peerhealth.RolePGW {
		return
	}
	affected := h.sessions.MarkPGWRestart(event.Addr, event.NewRecovery, event.At)
	h.recordRestart(event, affected)
	h.log.Warn("PGW restart marked on sessions",
		"pgw", event.Addr,
		"old_recovery", event.OldRecovery,
		"new_recovery", event.NewRecovery,
		"affected_sessions", affected)
}

func pgwPathState(state peerhealth.State) session.PGWPathState {
	switch state {
	case peerhealth.StateUp:
		return session.PGWPathStateUp
	case peerhealth.StateDegraded:
		return session.PGWPathStateDegraded
	case peerhealth.StateSuspect:
		return session.PGWPathStateSuspect
	case peerhealth.StateDown:
		return session.PGWPathStateDown
	default:
		return session.PGWPathStateUnknown
	}
}

func (h *Handler) Snapshot() []Snapshot {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Snapshot, 0, len(h.pgws))
	for _, state := range h.pgws {
		out = append(out, Snapshot{
			PGWAddr:           state.addr,
			State:             state.state,
			LastStateChange:   state.lastStateChange,
			RecoverySeen:      state.recoverySeen,
			RecoveryCounter:   state.recoveryCounter,
			RestartDetectedAt: state.restartDetectedAt,
			AffectedSessions:  state.affectedSessions,
			Restarts:          state.restarts,
			PathDownEvents:    state.pathDownEvents,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].PGWAddr < out[j].PGWAddr
	})
	return out
}

func (h *Handler) recordStateChange(event peerhealth.StateChangeEvent, state session.PGWPathState, affected int) {
	canonical := session.CanonicalGTPCEndpoint(event.Addr)
	if canonical == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	pgw := h.getOrCreateLocked(canonical)
	if event.At.IsZero() {
		event.At = time.Now()
	}
	if pgw.state != state {
		if state == session.PGWPathStateDown {
			pgw.pathDownEvents++
		}
		pgw.lastStateChange = event.At
	}
	pgw.state = state
	pgw.affectedSessions = affected
}

func (h *Handler) recordRestart(event peerhealth.RestartEvent, affected int) {
	canonical := session.CanonicalGTPCEndpoint(event.Addr)
	if canonical == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	pgw := h.getOrCreateLocked(canonical)
	if event.At.IsZero() {
		event.At = time.Now()
	}
	pgw.state = session.PGWPathStateRestarted
	pgw.recoverySeen = true
	pgw.recoveryCounter = event.NewRecovery
	pgw.restartDetectedAt = event.At
	pgw.lastStateChange = event.At
	pgw.affectedSessions = affected
	pgw.restarts++
}

func (h *Handler) getOrCreateLocked(addr string) *pgwState {
	state := h.pgws[addr]
	if state != nil {
		return state
	}
	state = &pgwState{
		addr:  addr,
		state: session.PGWPathStateUnknown,
	}
	h.pgws[addr] = state
	return state
}
