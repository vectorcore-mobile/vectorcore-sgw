// Package peerhealth tracks passive GTPv2-C peer health state for SGW-C.
package peerhealth

import (
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"

	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

const GTPControlPort = 2123

type Role string

const (
	RoleMME Role = "mme"
	RolePGW Role = "pgw"
)

type State string

const (
	StateUnknown  State = "unknown"
	StateUp       State = "up"
	StateDegraded State = "degraded"
	StateSuspect  State = "suspect"
	StateDown     State = "down"
)

type Key struct {
	Role Role
	Addr string
}

type Snapshot struct {
	Role               Role
	Addr               string
	State              State
	LastStateChange    time.Time
	LastSeenAt         time.Time
	LastMessageType    uint8
	LastSequenceNumber uint32
	LastEchoSentAt     time.Time
	LastEchoResponseAt time.Time
	LastRTT            time.Duration
	SmoothedRTT        time.Duration
	MaxRTT             time.Duration
	ConsecutiveMisses  int
	EchoSent           uint64
	EchoResponses      uint64
	EchoTimeouts       uint64
	RecoverySeen       bool
	RecoveryCounter    uint8
	RestartDetectedAt  time.Time
	Restarts           uint64
}

type StateChangeEvent struct {
	Role     Role
	Addr     string
	OldState State
	NewState State
	Reason   string
	At       time.Time
}

type RestartEvent struct {
	Role        Role
	Addr        string
	OldRecovery uint8
	NewRecovery uint8
	At          time.Time
}

type EventHandler interface {
	OnPeerStateChange(StateChangeEvent)
	OnPeerRestart(RestartEvent)
}

type CheckpointSink interface {
	SavePeerSnapshot(sessioncheckpoint.PeerSnapshot)
}

// MultiHandler fans peerhealth events out to multiple handlers.
type MultiHandler []EventHandler

func (m MultiHandler) OnPeerStateChange(event StateChangeEvent) {
	for _, h := range m {
		if h != nil {
			h.OnPeerStateChange(event)
		}
	}
}

func (m MultiHandler) OnPeerRestart(event RestartEvent) {
	for _, h := range m {
		if h != nil {
			h.OnPeerRestart(event)
		}
	}
}

type Target struct {
	Role Role
	Addr string
}

type ProbeConfig struct {
	SuspectAfterMissed int
	DownAfterMissed    int
	DegradedRTT        time.Duration
}

type peer struct {
	key Key

	state           State
	lastStateChange time.Time
	lastSeenAt      time.Time
	lastMsgType     uint8
	lastSeq         uint32

	lastEchoSentAt     time.Time
	lastEchoResponseAt time.Time
	lastRTT            time.Duration
	smoothedRTT        time.Duration
	maxRTT             time.Duration
	consecutiveMisses  int
	echoSent           uint64
	echoResponses      uint64
	echoTimeouts       uint64

	recoverySeen      bool
	recoveryCounter   uint8
	restartDetectedAt time.Time
	restarts          uint64
}

func (t *Table) ProbeTargets(probeMME, probePGW bool) []Target {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]Target, 0, len(t.peers))
	for key := range t.peers {
		if key.Role == RoleMME && !probeMME {
			continue
		}
		if key.Role == RolePGW && !probePGW {
			continue
		}
		out = append(out, Target{Role: key.Role, Addr: key.Addr})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

func (t *Table) MarkEchoSent(role Role, addr string, seq uint32) {
	if t == nil || addr == "" {
		return
	}
	addr = NormalizeEndpoint(addr)
	now := t.now()
	key := Key{Role: role, Addr: addr}
	t.mu.Lock()
	p := t.getOrCreateLocked(key, now)
	p.lastEchoSentAt = now
	p.lastSeq = seq
	p.echoSent++
	checkpoint := t.checkpointSnapshotLocked(p, now)
	sink := t.checkpointSink
	t.mu.Unlock()
	emitPeerCheckpoint(sink, checkpoint)
}

func (t *Table) MarkEchoResponse(role Role, addr string, seq uint32, rtt time.Duration, recovery *uint8, cfg ProbeConfig) {
	if t == nil || addr == "" {
		return
	}
	addr = NormalizeEndpoint(addr)
	now := t.now()
	key := Key{Role: role, Addr: addr}

	t.mu.Lock()
	p := t.getOrCreateLocked(key, now)
	oldState := p.state
	p.state = StateUp
	p.lastStateChange = stateChangeTime(p.lastStateChange, oldState, StateUp, now)
	p.lastSeenAt = now
	p.lastEchoResponseAt = now
	p.lastSeq = seq
	p.lastRTT = rtt
	if p.smoothedRTT == 0 {
		p.smoothedRTT = rtt
	} else {
		p.smoothedRTT = (p.smoothedRTT*7 + rtt) / 8
	}
	if rtt > p.maxRTT {
		p.maxRTT = rtt
	}
	p.consecutiveMisses = 0
	p.echoResponses++
	if cfg.DegradedRTT > 0 && rtt > cfg.DegradedRTT {
		p.state = StateDegraded
		p.lastStateChange = stateChangeTime(p.lastStateChange, oldState, StateDegraded, now)
	}
	restartLog := t.applyRecoveryLocked(p, recovery, now)
	newState := p.state
	handler := t.eventHandler
	checkpoint := t.checkpointSnapshotLocked(p, now)
	sink := t.checkpointSink
	t.mu.Unlock()

	emitPeerCheckpoint(sink, checkpoint)
	t.logStateChange(role, addr, oldState, newState, "echo_response")
	t.logRestart(role, addr, restartLog)
	t.notifyStateChange(handler, StateChangeEvent{
		Role:     role,
		Addr:     addr,
		OldState: oldState,
		NewState: newState,
		Reason:   "echo_response",
		At:       now,
	})
	t.notifyRestart(handler, role, addr, restartLog, now)
}

func (t *Table) MarkEchoTimeout(role Role, addr string, seq uint32, cfg ProbeConfig) {
	if t == nil || addr == "" {
		return
	}
	addr = NormalizeEndpoint(addr)
	now := t.now()
	key := Key{Role: role, Addr: addr}

	t.mu.Lock()
	p := t.getOrCreateLocked(key, now)
	oldState := p.state
	p.lastSeq = seq
	p.consecutiveMisses++
	p.echoTimeouts++
	switch {
	case cfg.DownAfterMissed > 0 && p.consecutiveMisses >= cfg.DownAfterMissed:
		p.state = StateDown
	case cfg.SuspectAfterMissed > 0 && p.consecutiveMisses >= cfg.SuspectAfterMissed:
		p.state = StateSuspect
	default:
		p.state = StateDegraded
	}
	p.lastStateChange = stateChangeTime(p.lastStateChange, oldState, p.state, now)
	newState := p.state
	misses := p.consecutiveMisses
	handler := t.eventHandler
	checkpoint := t.checkpointSnapshotLocked(p, now)
	sink := t.checkpointSink
	t.mu.Unlock()

	emitPeerCheckpoint(sink, checkpoint)
	t.logStateChange(role, addr, oldState, newState, "echo_timeout", "missed_echo", misses)
	t.notifyStateChange(handler, StateChangeEvent{
		Role:     role,
		Addr:     addr,
		OldState: oldState,
		NewState: newState,
		Reason:   "echo_timeout",
		At:       now,
	})
}

type Table struct {
	mu             sync.RWMutex
	log            *slog.Logger
	peers          map[Key]*peer
	now            func() time.Time
	eventHandler   EventHandler
	checkpointSink CheckpointSink
}

func NewTable(log *slog.Logger) *Table {
	if log == nil {
		log = slog.Default()
	}
	return &Table{
		log:   log,
		peers: make(map[Key]*peer),
		now:   time.Now,
	}
}

func (t *Table) SetEventHandler(handler EventHandler) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.eventHandler = handler
}

func (t *Table) SetCheckpointSink(sink CheckpointSink) {
	if t == nil {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	t.checkpointSink = sink
}

func (t *Table) Observe(role Role, addr *net.UDPAddr, msgType uint8, seq uint32, recovery *uint8) {
	if t == nil || addr == nil {
		return
	}
	t.observe(role, NormalizeUDPAddr(addr), msgType, seq, recovery)
}

func (t *Table) ObserveAddr(role Role, addr string, msgType uint8, seq uint32, recovery *uint8) {
	if t == nil || addr == "" {
		return
	}
	addr = NormalizeEndpoint(addr)
	t.observe(role, addr, msgType, seq, recovery)
}

func (t *Table) State(role Role, addr string) (State, bool) {
	if t == nil || addr == "" {
		return StateUnknown, false
	}
	addr = NormalizeEndpoint(addr)
	t.mu.RLock()
	defer t.mu.RUnlock()
	p := t.peers[Key{Role: role, Addr: addr}]
	if p == nil {
		return StateUnknown, false
	}
	return p.state, true
}

func NormalizeUDPAddr(addr *net.UDPAddr) string {
	if addr == nil {
		return ""
	}
	return net.JoinHostPort(addr.IP.String(), strconv.Itoa(GTPControlPort))
}

func NormalizeEndpoint(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil || host == "" {
		return addr
	}
	return net.JoinHostPort(host, strconv.Itoa(GTPControlPort))
}

func (t *Table) observe(role Role, addr string, msgType uint8, seq uint32, recovery *uint8) {
	now := t.now()
	key := Key{Role: role, Addr: addr}

	t.mu.Lock()
	p := t.getOrCreateLocked(key, now)
	oldState := p.state
	if p.state != StateUp {
		p.state = StateUp
		p.lastStateChange = now
	}
	p.lastSeenAt = now
	p.lastMsgType = msgType
	p.lastSeq = seq

	restartLog := t.applyRecoveryLocked(p, recovery, now)
	handler := t.eventHandler
	checkpoint := t.checkpointSnapshotLocked(p, now)
	sink := t.checkpointSink
	t.mu.Unlock()

	emitPeerCheckpoint(sink, checkpoint)
	t.logStateChange(role, addr, oldState, StateUp, "valid_gtpc_message")
	t.logRestart(role, addr, restartLog)
	t.notifyStateChange(handler, StateChangeEvent{
		Role:     role,
		Addr:     addr,
		OldState: oldState,
		NewState: StateUp,
		Reason:   "valid_gtpc_message",
		At:       now,
	})
	t.notifyRestart(handler, role, addr, restartLog, now)
}

type restartChange struct {
	old uint8
	new uint8
}

func (t *Table) getOrCreateLocked(key Key, now time.Time) *peer {
	p := t.peers[key]
	if p != nil {
		return p
	}
	p = &peer{
		key:             key,
		state:           StateUnknown,
		lastStateChange: now,
	}
	t.peers[key] = p
	return p
}

func (t *Table) applyRecoveryLocked(p *peer, recovery *uint8, now time.Time) *restartChange {
	if recovery == nil {
		return nil
	}
	var restartLog *restartChange
	if p.recoverySeen && p.recoveryCounter != *recovery {
		restartLog = &restartChange{old: p.recoveryCounter, new: *recovery}
		p.restartDetectedAt = now
		p.restarts++
	}
	p.recoverySeen = true
	p.recoveryCounter = *recovery
	return restartLog
}

func stateChangeTime(oldTime time.Time, oldState, newState State, now time.Time) time.Time {
	if oldState != newState {
		return now
	}
	return oldTime
}

func (t *Table) logStateChange(role Role, addr string, oldState, newState State, reason string, attrs ...any) {
	if oldState == newState {
		return
	}
	base := []any{
		"role", role,
		"peer", addr,
		"old_state", oldState,
		"new_state", newState,
		"reason", reason,
	}
	base = append(base, attrs...)
	t.log.Info("GTP-C peer state changed", base...)
}

func (t *Table) logRestart(role Role, addr string, change *restartChange) {
	if change == nil {
		return
	}
	t.log.Warn("GTP-C peer restart detected",
		"role", role,
		"peer", addr,
		"old_recovery", change.old,
		"new_recovery", change.new)
}

func (t *Table) notifyStateChange(handler EventHandler, event StateChangeEvent) {
	if handler == nil || event.OldState == event.NewState {
		return
	}
	handler.OnPeerStateChange(event)
}

func (t *Table) notifyRestart(handler EventHandler, role Role, addr string, change *restartChange, at time.Time) {
	if handler == nil || change == nil {
		return
	}
	handler.OnPeerRestart(RestartEvent{
		Role:        role,
		Addr:        addr,
		OldRecovery: change.old,
		NewRecovery: change.new,
		At:          at,
	})
}

func (t *Table) Snapshot() []Snapshot {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	out := make([]Snapshot, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, Snapshot{
			Role:               p.key.Role,
			Addr:               p.key.Addr,
			State:              p.state,
			LastStateChange:    p.lastStateChange,
			LastSeenAt:         p.lastSeenAt,
			LastMessageType:    p.lastMsgType,
			LastSequenceNumber: p.lastSeq,
			LastEchoSentAt:     p.lastEchoSentAt,
			LastEchoResponseAt: p.lastEchoResponseAt,
			LastRTT:            p.lastRTT,
			SmoothedRTT:        p.smoothedRTT,
			MaxRTT:             p.maxRTT,
			ConsecutiveMisses:  p.consecutiveMisses,
			EchoSent:           p.echoSent,
			EchoResponses:      p.echoResponses,
			EchoTimeouts:       p.echoTimeouts,
			RecoverySeen:       p.recoverySeen,
			RecoveryCounter:    p.recoveryCounter,
			RestartDetectedAt:  p.restartDetectedAt,
			Restarts:           p.restarts,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

func (t *Table) CheckpointSnapshots() []sessioncheckpoint.PeerSnapshot {
	if t == nil {
		return nil
	}
	t.mu.RLock()
	defer t.mu.RUnlock()

	now := t.now()
	out := make([]sessioncheckpoint.PeerSnapshot, 0, len(t.peers))
	for _, p := range t.peers {
		out = append(out, t.checkpointSnapshotLocked(p, now))
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Role != out[j].Role {
			return out[i].Role < out[j].Role
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}

func (t *Table) RestoreCheckpointSnapshots(snapshots []sessioncheckpoint.PeerSnapshot) int {
	if t == nil {
		return 0
	}
	now := t.now()
	restored := 0
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, snapshot := range snapshots {
		role := Role(snapshot.Role)
		if (role != RoleMME && role != RolePGW) || snapshot.Addr == "" {
			continue
		}
		key := Key{Role: role, Addr: NormalizeEndpoint(snapshot.Addr)}
		p := t.getOrCreateLocked(key, now)
		p.state = State(snapshot.State)
		if p.state == "" {
			p.state = StateUnknown
		}
		p.lastStateChange = snapshot.UpdatedAt
		if p.lastStateChange.IsZero() {
			p.lastStateChange = now
		}
		p.recoverySeen = snapshot.RecoverySeen
		p.recoveryCounter = snapshot.RecoveryCounter
		p.restartDetectedAt = snapshot.RestartDetectedAt
		p.restarts = snapshot.Restarts
		restored++
	}
	return restored
}

func (t *Table) checkpointSnapshotLocked(p *peer, now time.Time) sessioncheckpoint.PeerSnapshot {
	updatedAt := p.lastSeenAt
	if updatedAt.IsZero() {
		updatedAt = now
	}
	return sessioncheckpoint.PeerSnapshot{
		Role:              string(p.key.Role),
		Addr:              p.key.Addr,
		State:             string(p.state),
		RecoverySeen:      p.recoverySeen,
		RecoveryCounter:   p.recoveryCounter,
		RestartDetectedAt: p.restartDetectedAt,
		Restarts:          p.restarts,
		UpdatedAt:         updatedAt,
	}
}

func emitPeerCheckpoint(sink CheckpointSink, snapshot sessioncheckpoint.PeerSnapshot) {
	if sink == nil || snapshot.Role == "" || snapshot.Addr == "" {
		return
	}
	sink.SavePeerSnapshot(snapshot)
}
