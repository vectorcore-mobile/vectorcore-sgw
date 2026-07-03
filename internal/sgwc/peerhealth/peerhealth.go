// Package peerhealth tracks passive GTPv2-C peer health state for SGW-C.
package peerhealth

import (
	"log/slog"
	"net"
	"sort"
	"strconv"
	"sync"
	"time"
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
	t.mu.Unlock()
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
	t.mu.Unlock()

	t.logStateChange(role, addr, oldState, newState, "echo_response")
	t.logRestart(role, addr, restartLog)
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
	t.mu.Unlock()

	t.logStateChange(role, addr, oldState, newState, "echo_timeout", "missed_echo", misses)
}

type Table struct {
	mu    sync.RWMutex
	log   *slog.Logger
	peers map[Key]*peer
	now   func() time.Time
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
	t.mu.Unlock()

	t.logStateChange(role, addr, oldState, StateUp, "valid_gtpc_message")
	t.logRestart(role, addr, restartLog)
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
