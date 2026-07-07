// Package ddncontrol holds SGW-C state for Downlink Data Notification
// throttling and priority paging. Phase 1 intentionally models state only;
// later phases use this package to make and enforce send/delay/suppress
// decisions before S11 DDN transmission.
package ddncontrol

import (
	"sort"
	"strings"
	"sync"
	"time"
)

type PriorityClass string

const (
	PriorityUnknown PriorityClass = "unknown"
	PriorityHigh    PriorityClass = "high"
	PriorityNormal  PriorityClass = "normal"
	PriorityLow     PriorityClass = "low"
)

type DecisionAction string

const (
	ActionSendNow  DecisionAction = "send_now"
	ActionDelay    DecisionAction = "delay"
	ActionSuppress DecisionAction = "suppress"
)

type Config struct {
	Enabled                       bool
	PerMMERateLimitPerSecond      int
	PerMMEBurst                   int
	PerUESuppression              time.Duration
	HonorMMELowPriorityThrottling bool
	LowPriorityThrottle           time.Duration
	HighPriorityBypass            bool
	HighPriority                  []PriorityRule
	LowPriority                   []PriorityRule
}

// PriorityRule classifies DDN candidates. Zero values are wildcards. ARP
// priority follows LTE convention: 1 is highest.
type PriorityRule struct {
	APN            string
	QCI            uint8
	ARPPriorityMin uint8
	ARPPriorityMax uint8
	Reason         string
}

type Candidate struct {
	MMEAddr     string
	IMSI        string
	APN         string
	EBI         uint8
	QCI         uint8
	ARPPriority uint8
}

type Decision struct {
	Action       DecisionAction
	Priority     PriorityClass
	Reason       string
	RetryAfter   time.Duration
	Bypass       bool
	MMEAddr      string
	IMSI         string
	APN          string
	EBI          uint8
	QCI          uint8
	ARPPriority  uint8
	TokensBefore int
	TokensAfter  int
}

type MMEState struct {
	MMEAddr                     string
	Tokens                      int
	Burst                       int
	RateLimitPerSecond          int
	LastRefillAt                time.Time
	LowPriorityThrottledUntil   time.Time
	LowPriorityThrottleReceived time.Time
	LowPriorityThrottleReason   string
	Sent                        uint64
	Delayed                     uint64
	Suppressed                  uint64
	HighPriorityBypassed        uint64
}

type UEState struct {
	IMSI         string
	LastDDNAt    time.Time
	LastMMEAddr  string
	LastAPN      string
	LastEBI      uint8
	LastPriority PriorityClass
	Suppressed   uint64
	Delayed      uint64
	Sent         uint64
}

type Snapshot struct {
	MMEs []MMEState
	UEs  []UEState
}

type State struct {
	mu   sync.RWMutex
	cfg  Config
	mmes map[string]*MMEState
	ues  map[string]*UEState
}

func NewState(cfg Config) *State {
	return &State{
		cfg:  cfg,
		mmes: make(map[string]*MMEState),
		ues:  make(map[string]*UEState),
	}
}

func (s *State) Config() Config {
	if s == nil {
		return Config{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.cfg
}

func (s *State) Classify(c Candidate) (PriorityClass, string) {
	if s == nil {
		return PriorityNormal, "default-normal"
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, rule := range s.cfg.HighPriority {
		if rule.matches(c) {
			return PriorityHigh, priorityReason(rule, "high-priority-rule")
		}
	}
	for _, rule := range s.cfg.LowPriority {
		if rule.matches(c) {
			return PriorityLow, priorityReason(rule, "low-priority-rule")
		}
	}
	return PriorityNormal, "default-normal"
}

func (s *State) Decide(c Candidate, at time.Time) Decision {
	if at.IsZero() {
		at = time.Now()
	}
	if s == nil {
		return Decision{
			Action:      ActionSendNow,
			Priority:    PriorityNormal,
			Reason:      "ddn-control-unavailable",
			MMEAddr:     c.MMEAddr,
			IMSI:        c.IMSI,
			APN:         c.APN,
			EBI:         c.EBI,
			QCI:         c.QCI,
			ARPPriority: c.ARPPriority,
		}
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	priority, reason := s.classifyLocked(c)
	base := Decision{
		Priority:    priority,
		Reason:      reason,
		MMEAddr:     c.MMEAddr,
		IMSI:        c.IMSI,
		APN:         c.APN,
		EBI:         c.EBI,
		QCI:         c.QCI,
		ARPPriority: c.ARPPriority,
	}
	if !s.cfg.Enabled {
		base.Action = ActionSendNow
		base.Reason = "ddn-control-disabled"
		s.recordSentLocked(c, priority, at)
		return base
	}

	mme := s.mmeLocked(c.MMEAddr, at)
	s.refillMMELocked(mme, at)
	ue := s.ueLocked(c.IMSI)
	base.TokensBefore = mme.Tokens

	if priority != PriorityHigh && s.cfg.PerUESuppression > 0 && !ue.LastDDNAt.IsZero() {
		until := ue.LastDDNAt.Add(s.cfg.PerUESuppression)
		if at.Before(until) {
			base.Action = ActionSuppress
			base.Reason = "per-ue-suppression"
			base.RetryAfter = until.Sub(at)
			base.TokensAfter = mme.Tokens
			s.recordSuppressedLocked(c, priority)
			return base
		}
	}

	if priority == PriorityLow &&
		s.cfg.HonorMMELowPriorityThrottling &&
		!mme.LowPriorityThrottledUntil.IsZero() &&
		at.Before(mme.LowPriorityThrottledUntil) {
		base.Action = ActionSuppress
		base.Reason = "mme-low-priority-throttling"
		base.RetryAfter = mme.LowPriorityThrottledUntil.Sub(at)
		base.TokensAfter = mme.Tokens
		s.recordSuppressedLocked(c, priority)
		return base
	}

	if mme.Tokens > 0 {
		mme.Tokens--
		base.Action = ActionSendNow
		base.TokensAfter = mme.Tokens
		s.recordSentLocked(c, priority, at)
		return base
	}

	if priority == PriorityHigh && s.cfg.HighPriorityBypass {
		base.Action = ActionSendNow
		base.Bypass = true
		base.Reason = "high-priority-bypass"
		base.TokensAfter = mme.Tokens
		s.recordSentLocked(c, priority, at)
		return base
	}

	base.Action = ActionDelay
	base.Reason = "per-mme-rate-limit"
	base.RetryAfter = s.nextTokenDelayLocked(mme)
	base.TokensAfter = mme.Tokens
	s.recordDelayedLocked(c, priority)
	return base
}

func (s *State) RecordSent(c Candidate, priority PriorityClass, at time.Time) {
	if s == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.recordSentLocked(c, priority, at)
}

func (s *State) RecordSuppressed(c Candidate, priority PriorityClass, at time.Time) {
	if s == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mmeLocked(c.MMEAddr, at)
	s.recordSuppressedLocked(c, priority)
}

func (s *State) RecordDelayed(c Candidate, priority PriorityClass, at time.Time) {
	if s == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mmeLocked(c.MMEAddr, at)
	s.recordDelayedLocked(c, priority)
}

func (s *State) MarkMMELowPriorityThrottled(mmeAddr, reason string, until, at time.Time) {
	if s == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	mme := s.mmeLocked(mmeAddr, at)
	mme.LowPriorityThrottledUntil = until
	mme.LowPriorityThrottleReceived = at
	mme.LowPriorityThrottleReason = reason
}

func (s *State) Snapshot() Snapshot {
	if s == nil {
		return Snapshot{}
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := Snapshot{
		MMEs: make([]MMEState, 0, len(s.mmes)),
		UEs:  make([]UEState, 0, len(s.ues)),
	}
	for _, mme := range s.mmes {
		out.MMEs = append(out.MMEs, *mme)
	}
	for _, ue := range s.ues {
		out.UEs = append(out.UEs, *ue)
	}
	sort.Slice(out.MMEs, func(i, j int) bool { return out.MMEs[i].MMEAddr < out.MMEs[j].MMEAddr })
	sort.Slice(out.UEs, func(i, j int) bool { return out.UEs[i].IMSI < out.UEs[j].IMSI })
	return out
}

func (s *State) mmeLocked(addr string, at time.Time) *MMEState {
	mme := s.mmes[addr]
	if mme == nil {
		mme = &MMEState{
			MMEAddr:            addr,
			Tokens:             s.cfg.PerMMEBurst,
			Burst:              s.cfg.PerMMEBurst,
			RateLimitPerSecond: s.cfg.PerMMERateLimitPerSecond,
			LastRefillAt:       at,
		}
		s.mmes[addr] = mme
	}
	return mme
}

func (s *State) classifyLocked(c Candidate) (PriorityClass, string) {
	for _, rule := range s.cfg.HighPriority {
		if rule.matches(c) {
			return PriorityHigh, priorityReason(rule, "high-priority-rule")
		}
	}
	for _, rule := range s.cfg.LowPriority {
		if rule.matches(c) {
			return PriorityLow, priorityReason(rule, "low-priority-rule")
		}
	}
	return PriorityNormal, "default-normal"
}

func (s *State) refillMMELocked(mme *MMEState, at time.Time) {
	if mme == nil {
		return
	}
	rate := s.cfg.PerMMERateLimitPerSecond
	if rate <= 0 {
		rate = 1
	}
	burst := s.cfg.PerMMEBurst
	if burst <= 0 {
		burst = rate
	}
	if mme.Burst <= 0 {
		mme.Burst = burst
	}
	if mme.RateLimitPerSecond <= 0 {
		mme.RateLimitPerSecond = rate
	}
	if mme.Tokens > mme.Burst {
		mme.Tokens = mme.Burst
	}
	if mme.LastRefillAt.IsZero() {
		mme.LastRefillAt = at
		return
	}
	if !at.After(mme.LastRefillAt) {
		return
	}
	elapsed := at.Sub(mme.LastRefillAt)
	add := int(elapsed.Seconds() * float64(rate))
	if add <= 0 {
		return
	}
	mme.Tokens += add
	if mme.Tokens > mme.Burst {
		mme.Tokens = mme.Burst
	}
	mme.LastRefillAt = mme.LastRefillAt.Add(time.Duration(add) * time.Second / time.Duration(rate))
}

func (s *State) nextTokenDelayLocked(mme *MMEState) time.Duration {
	rate := s.cfg.PerMMERateLimitPerSecond
	if mme != nil && mme.RateLimitPerSecond > 0 {
		rate = mme.RateLimitPerSecond
	}
	if rate <= 0 {
		rate = 1
	}
	return time.Second / time.Duration(rate)
}

func (s *State) recordSentLocked(c Candidate, priority PriorityClass, at time.Time) {
	mme := s.mmeLocked(c.MMEAddr, at)
	mme.Sent++
	if priority == PriorityHigh && s.cfg.HighPriorityBypass {
		mme.HighPriorityBypassed++
	}
	ue := s.ueLocked(c.IMSI)
	ue.LastDDNAt = at
	ue.LastMMEAddr = c.MMEAddr
	ue.LastAPN = c.APN
	ue.LastEBI = c.EBI
	ue.LastPriority = priority
	ue.Sent++
}

func (s *State) recordSuppressedLocked(c Candidate, priority PriorityClass) {
	s.mmeLocked(c.MMEAddr, time.Now()).Suppressed++
	ue := s.ueLocked(c.IMSI)
	ue.LastMMEAddr = c.MMEAddr
	ue.LastAPN = c.APN
	ue.LastEBI = c.EBI
	ue.LastPriority = priority
	ue.Suppressed++
}

func (s *State) recordDelayedLocked(c Candidate, priority PriorityClass) {
	s.mmeLocked(c.MMEAddr, time.Now()).Delayed++
	ue := s.ueLocked(c.IMSI)
	ue.LastMMEAddr = c.MMEAddr
	ue.LastAPN = c.APN
	ue.LastEBI = c.EBI
	ue.LastPriority = priority
	ue.Delayed++
}

func (s *State) ueLocked(imsi string) *UEState {
	ue := s.ues[imsi]
	if ue == nil {
		ue = &UEState{IMSI: imsi}
		s.ues[imsi] = ue
	}
	return ue
}

func (r PriorityRule) matches(c Candidate) bool {
	if r.APN != "" && !strings.EqualFold(r.APN, c.APN) {
		return false
	}
	if r.QCI != 0 && r.QCI != c.QCI {
		return false
	}
	if r.ARPPriorityMin != 0 || r.ARPPriorityMax != 0 {
		minPriority, maxPriority := r.ARPPriorityMin, r.ARPPriorityMax
		if minPriority == 0 {
			minPriority = 1
		}
		if maxPriority == 0 {
			maxPriority = 15
		}
		if minPriority > maxPriority {
			return false
		}
		if c.ARPPriority < minPriority || c.ARPPriority > maxPriority {
			return false
		}
	}
	return true
}

func priorityReason(rule PriorityRule, fallback string) string {
	if rule.Reason != "" {
		return rule.Reason
	}
	return fallback
}
