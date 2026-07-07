package mmerestoration

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"sync"
	"time"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/sgwc/ddncontrol"
	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/session"
)

type Config struct {
	Enabled                bool
	MarkSessionsOnPathDown bool
	MarkSessionsOnRestart  bool
	EnforceDeletePolicy    bool
	TriggerDDN             bool
	CleanupTimeout         time.Duration
	DelayedQueueMax        int
	DelayedQueuePerMME     int
	DelayedMaxAge          time.Duration
	Preserve               []PolicyRule
	Delete                 []PolicyRule
	DefaultAction          session.MMERestorationPolicyAction
}

type S5CDeleter interface {
	DeleteSession(ctx context.Context, sess *session.SGWSession) (uint8, error)
}

type PFCPDeleter interface {
	DeleteSessionOnPeer(ctx context.Context, peerAddr string, cpSEID, upSEID uint64) error
}

type DDNSender interface {
	SendDownlinkDataNotification(ctx context.Context, sess *session.SGWSession) (uint32, error)
}

// PolicyRule matches one PDN session for MME restoration policy evaluation.
// Zero values are wildcards. ARP priority follows LTE convention: 1 is highest.
type PolicyRule struct {
	APN            string
	QCI            uint8
	ARPPriorityMin uint8
	ARPPriorityMax uint8
	Reason         string
}

type Handler struct {
	mu       sync.RWMutex
	sessions *session.Manager
	s5c      S5CDeleter
	pfcp     PFCPDeleter
	ddn      DDNSender
	ddnCtl   *ddncontrol.State
	cfg      Config
	log      *slog.Logger
	mmes     map[string]*mmeState
	queueMu  sync.Mutex
	queue    map[string]*delayedDDN
	queueMME map[string]int
}

type Snapshot struct {
	MMEAddr           string
	State             session.MMERestorationState
	LastStateChange   time.Time
	RecoverySeen      bool
	RecoveryCounter   uint8
	RestartDetectedAt time.Time
	AffectedSessions  int
	Restarts          uint64
	PathDownEvents    uint64
}

type mmeState struct {
	addr              string
	state             session.MMERestorationState
	lastStateChange   time.Time
	recoverySeen      bool
	recoveryCounter   uint8
	restartDetectedAt time.Time
	affectedSessions  int
	restarts          uint64
	pathDownEvents    uint64
}

type delayedDDN struct {
	sessionID  string
	mmeAddr    string
	enqueuedAt time.Time
	fireAt     time.Time
	attempts   int
	timer      *time.Timer
}

func NewHandler(sessions *session.Manager, cfg Config, log *slog.Logger) *Handler {
	return NewHandlerWithCleanup(sessions, cfg, nil, nil, log)
}

func NewHandlerWithCleanup(sessions *session.Manager, cfg Config, s5c S5CDeleter, pfcp PFCPDeleter, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{
		sessions: sessions,
		s5c:      s5c,
		pfcp:     pfcp,
		cfg:      cfg,
		log:      log,
		mmes:     make(map[string]*mmeState),
		queue:    make(map[string]*delayedDDN),
		queueMME: make(map[string]int),
	}
}

func (h *Handler) SetDDNSender(sender DDNSender) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ddn = sender
}

func (h *Handler) SetDDNControl(state *ddncontrol.State) {
	if h == nil {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.ddnCtl = state
}

func (h *Handler) OnPeerStateChange(event peerhealth.StateChangeEvent) {
	if h == nil || h.sessions == nil || !h.cfg.Enabled || !h.cfg.MarkSessionsOnPathDown {
		return
	}
	if event.Role != peerhealth.RoleMME {
		return
	}
	state := mmePathState(event.NewState)
	affected := h.sessions.MarkMMEPathState(event.Addr, state, event.At)
	h.recordStateChange(event, state, affected)
	h.log.Info("MME path state changed",
		"mme", event.Addr,
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
	if event.Role != peerhealth.RoleMME {
		return
	}
	affected := h.sessions.MarkMMERestart(event.Addr, event.NewRecovery, event.At)
	preserve, deleteCount := h.applyPolicy(event)
	enforced, failed := h.enforceDeletePolicy(event)
	ddnSent, ddnFailed := h.triggerDDNForPreservedSessions(event)
	h.recordRestart(event, affected)
	h.log.Warn("MME restart marked for restoration",
		"mme", event.Addr,
		"old_recovery", event.OldRecovery,
		"new_recovery", event.NewRecovery,
		"affected_sessions", affected,
		"policy_preserve_sessions", preserve,
		"policy_delete_sessions", deleteCount,
		"delete_policy_enforced_sessions", enforced,
		"delete_policy_failed_sessions", failed,
		"ddn_sent_sessions", ddnSent,
		"ddn_failed_sessions", ddnFailed)
}

func (h *Handler) Snapshot() []Snapshot {
	if h == nil {
		return nil
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	out := make([]Snapshot, 0, len(h.mmes))
	for _, state := range h.mmes {
		out = append(out, Snapshot{
			MMEAddr:           state.addr,
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
		return out[i].MMEAddr < out[j].MMEAddr
	})
	return out
}

func mmePathState(state peerhealth.State) session.MMERestorationState {
	switch state {
	case peerhealth.StateUp:
		return session.MMERestorationStateUp
	case peerhealth.StateDegraded:
		return session.MMERestorationStateDegraded
	case peerhealth.StateSuspect:
		return session.MMERestorationStateSuspect
	case peerhealth.StateDown:
		return session.MMERestorationStateDown
	default:
		return session.MMERestorationStateUnknown
	}
}

func (h *Handler) applyPolicy(event peerhealth.RestartEvent) (preserve, deleteCount int) {
	sessions := h.sessions.FindByMME(event.Addr)
	if event.At.IsZero() {
		event.At = time.Now()
	}
	for _, sess := range sessions {
		action, reason := h.evaluatePolicy(sess)
		sess.SetMMERestorationPolicy(action, reason, event.At)
		switch action {
		case session.MMERestorationPolicyDelete:
			deleteCount++
		default:
			preserve++
		}
		h.log.Info("MME restoration policy evaluated",
			"mme", event.Addr,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"action", action,
			"reason", reason)
	}
	return preserve, deleteCount
}

func (h *Handler) enforceDeletePolicy(event peerhealth.RestartEvent) (enforced, failed int) {
	if !h.cfg.EnforceDeletePolicy {
		return 0, 0
	}
	sessions := h.sessions.FindByMME(event.Addr)
	for _, sess := range sessions {
		status := sess.MMERestorationSnapshot()
		if status.PolicyAction != session.MMERestorationPolicyDelete {
			continue
		}
		if err := h.deleteSessionForRestoration(event, sess, status.PolicyReason); err != nil {
			failed++
			sess.SetMMERestorationPolicy(session.MMERestorationPolicyDelete, fmt.Sprintf("%s; enforcement failed: %v", status.PolicyReason, err), event.At)
			h.log.Warn("MME restoration delete policy enforcement failed",
				"mme", event.Addr,
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"default_ebi", sess.DefaultBearerID,
				"reason", status.PolicyReason,
				"error", err)
			continue
		}
		enforced++
		h.log.Info("MME restoration delete policy enforced",
			"mme", event.Addr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"reason", status.PolicyReason)
	}
	return enforced, failed
}

func (h *Handler) triggerDDNForPreservedSessions(event peerhealth.RestartEvent) (sent, failed int) {
	if !h.cfg.TriggerDDN {
		return 0, 0
	}
	sender := h.ddnSender()
	if sender == nil {
		sessions := h.sessions.FindByMME(event.Addr)
		for _, sess := range sessions {
			status := sess.MMERestorationSnapshot()
			if status.PolicyAction == session.MMERestorationPolicyPreserve {
				failed++
				sess.MarkMMERestorationDDNFailed("DDN sender unavailable", event.At)
			}
		}
		if failed > 0 {
			h.log.Warn("MME restoration DDN trigger skipped; sender unavailable",
				"mme", event.Addr,
				"sessions", failed)
		}
		return 0, failed
	}

	sessions := h.sessions.FindByMME(event.Addr)
	for _, sess := range sessions {
		status := sess.MMERestorationSnapshot()
		if status.PolicyAction != session.MMERestorationPolicyPreserve {
			continue
		}
		if status.DDNTriggered {
			continue
		}
		decision := h.decideDDN(event.Addr, sess, event.At)
		if decision.Action != "" {
			sess.MarkMMERestorationDDNControlDecision(string(decision.Action), string(decision.Priority), decision.Reason, decision.RetryAfter, event.At)
			if decision.Action != ddncontrol.ActionSendNow {
				if decision.Action == ddncontrol.ActionDelay && h.enqueueDelayedDDN(event.Addr, sess, decision, event.At) {
					h.log.Info("MME restoration DDN delayed",
						"mme", event.Addr,
						"session_id", sess.SessionID,
						"imsi", sess.IMSI,
						"apn", sess.APN,
						"default_ebi", sess.DefaultBearerID,
						"priority", decision.Priority,
						"reason", decision.Reason,
						"retry_after_ms", decision.RetryAfter.Milliseconds())
					continue
				}
				failed++
				h.log.Info("MME restoration DDN controlled",
					"mme", event.Addr,
					"session_id", sess.SessionID,
					"imsi", sess.IMSI,
					"apn", sess.APN,
					"default_ebi", sess.DefaultBearerID,
					"action", decision.Action,
					"priority", decision.Priority,
					"reason", decision.Reason,
					"retry_after_ms", decision.RetryAfter.Milliseconds())
				continue
			}
		}
		if err := h.sendDDNNow(event.Addr, sess, decision, event.At); err != nil {
			failed++
			sess.MarkMMERestorationDDNFailed(err.Error(), event.At)
			h.log.Warn("MME restoration DDN trigger failed",
				"mme", event.Addr,
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"default_ebi", sess.DefaultBearerID,
				"error", err)
			continue
		}
		sent++
	}
	return sent, failed
}

func (h *Handler) enqueueDelayedDDN(mmeAddr string, sess *session.SGWSession, decision ddncontrol.Decision, at time.Time) bool {
	if h == nil || sess == nil || decision.RetryAfter <= 0 {
		return false
	}
	if at.IsZero() {
		at = time.Now()
	}
	maxAge := h.cfg.DelayedMaxAge
	if maxAge <= 0 {
		maxAge = 30 * time.Second
	}
	if decision.RetryAfter > maxAge {
		sess.MarkMMERestorationDDNFailed("DDN delayed retry exceeds max age", at)
		return false
	}
	maxGlobal := h.cfg.DelayedQueueMax
	if maxGlobal <= 0 {
		maxGlobal = 1000
	}
	maxPerMME := h.cfg.DelayedQueuePerMME
	if maxPerMME <= 0 {
		maxPerMME = 200
	}

	h.queueMu.Lock()
	defer h.queueMu.Unlock()
	if old := h.queue[sess.SessionID]; old != nil {
		old.timer.Stop()
		if h.queueMME[old.mmeAddr] > 0 {
			h.queueMME[old.mmeAddr]--
		}
	} else if len(h.queue) >= maxGlobal || h.queueMME[mmeAddr] >= maxPerMME {
		sess.MarkMMERestorationDDNFailed("DDN delayed queue full", at)
		return false
	}

	entry := &delayedDDN{
		sessionID:  sess.SessionID,
		mmeAddr:    mmeAddr,
		enqueuedAt: at,
		fireAt:     at.Add(decision.RetryAfter),
	}
	entry.timer = time.AfterFunc(decision.RetryAfter, func() {
		h.fireDelayedDDN(sess.SessionID)
	})
	h.queue[sess.SessionID] = entry
	h.queueMME[mmeAddr]++
	return true
}

func (h *Handler) fireDelayedDDN(sessionID string) {
	if h == nil {
		return
	}
	h.queueMu.Lock()
	entry := h.queue[sessionID]
	if entry == nil {
		h.queueMu.Unlock()
		return
	}
	delete(h.queue, sessionID)
	if h.queueMME[entry.mmeAddr] > 0 {
		h.queueMME[entry.mmeAddr]--
	}
	h.queueMu.Unlock()

	sess := h.sessions.Find(sessionID)
	if sess == nil {
		return
	}
	status := sess.MMERestorationSnapshot()
	if status.PolicyAction != session.MMERestorationPolicyPreserve || status.DDNTriggered {
		return
	}
	now := time.Now()
	maxAge := h.cfg.DelayedMaxAge
	if maxAge <= 0 {
		maxAge = 30 * time.Second
	}
	if now.Sub(entry.enqueuedAt) > maxAge {
		sess.MarkMMERestorationDDNFailed("DDN delayed queue entry expired", now)
		return
	}
	decision := h.decideDDN(entry.mmeAddr, sess, now)
	sess.MarkMMERestorationDDNControlDecision(string(decision.Action), string(decision.Priority), decision.Reason, decision.RetryAfter, now)
	if decision.Action == ddncontrol.ActionDelay && decision.RetryAfter > 0 && now.Add(decision.RetryAfter).Sub(entry.enqueuedAt) <= maxAge {
		h.enqueueDelayedDDN(entry.mmeAddr, sess, decision, now)
		return
	}
	if decision.Action != "" && decision.Action != ddncontrol.ActionSendNow {
		sess.MarkMMERestorationDDNFailed("DDN delayed send suppressed: "+decision.Reason, now)
		h.log.Info("MME restoration delayed DDN controlled",
			"mme", entry.mmeAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"action", decision.Action,
			"priority", decision.Priority,
			"reason", decision.Reason,
			"retry_after_ms", decision.RetryAfter.Milliseconds())
		return
	}
	if err := h.sendDDNNow(entry.mmeAddr, sess, decision, now); err != nil {
		sess.MarkMMERestorationDDNFailed(err.Error(), now)
		h.log.Warn("MME restoration delayed DDN trigger failed",
			"mme", entry.mmeAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"error", err)
	}
}

func (h *Handler) sendDDNNow(mmeAddr string, sess *session.SGWSession, decision ddncontrol.Decision, at time.Time) error {
	sender := h.ddnSender()
	if sender == nil {
		return fmt.Errorf("DDN sender unavailable")
	}
	timeout := h.cfg.CleanupTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	seq, err := sender.SendDownlinkDataNotification(ctx, sess)
	cancel()
	if err != nil {
		return err
	}
	sess.MarkMMERestorationDDNTriggered(seq, at)
	h.log.Info("MME restoration DDN triggered",
		"mme", mmeAddr,
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"default_ebi", sess.DefaultBearerID,
		"ddn_control_action", decision.Action,
		"ddn_control_priority", decision.Priority,
		"ddn_control_reason", decision.Reason,
		"seq", seq)
	return nil
}

func (h *Handler) decideDDN(mmeAddr string, sess *session.SGWSession, at time.Time) ddncontrol.Decision {
	ctl := h.ddnControl()
	if ctl == nil || sess == nil {
		return ddncontrol.Decision{}
	}
	candidate := ddncontrol.Candidate{
		MMEAddr: mmeAddr,
		IMSI:    sess.IMSI,
		APN:     sess.APN,
		EBI:     sess.DefaultBearerID,
	}
	if b := sess.GetBearer(sess.DefaultBearerID); b != nil {
		candidate.QCI = b.QCI
		candidate.ARPPriority = b.ARP.PriorityLevel
	}
	return ctl.Decide(candidate, at)
}

func (h *Handler) ddnSender() DDNSender {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ddn
}

func (h *Handler) ddnControl() *ddncontrol.State {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.ddnCtl
}

func (h *Handler) deleteSessionForRestoration(event peerhealth.RestartEvent, sess *session.SGWSession, reason string) error {
	if sess == nil {
		return nil
	}
	timeout := h.cfg.CleanupTimeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	if h.s5c == nil {
		return fmt.Errorf("S5/S8-C deleter unavailable")
	}
	cause, err := h.s5c.DeleteSession(ctx, sess)
	if err != nil {
		return fmt.Errorf("S5/S8-C Delete Session failed: %w", err)
	}
	if cause != ie.CauseRequestAccepted {
		return fmt.Errorf("PGW rejected Delete Session: cause=%d", cause)
	}

	if sess.PFCP.Established && sess.PFCP.SGWUFSEID.SEID != 0 {
		if h.pfcp == nil {
			return fmt.Errorf("PFCP deleter unavailable for established PFCP session")
		}
		if err := h.pfcp.DeleteSessionOnPeer(ctx, sess.PFCP.SGWUAddr, sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID); err != nil {
			h.log.Warn("MME restoration PFCP Session Deletion failed after PGW accepted delete; releasing SGW-C state",
				"mme", event.Addr,
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"reason", reason,
				"error", err)
		}
	}

	h.sessions.Delete(sess.SessionID)
	return nil
}

func (h *Handler) evaluatePolicy(sess *session.SGWSession) (session.MMERestorationPolicyAction, string) {
	if sess == nil {
		return defaultPolicyAction(h.cfg.DefaultAction), "nil-session"
	}
	for _, rule := range h.cfg.Preserve {
		if rule.matches(sess) {
			return session.MMERestorationPolicyPreserve, policyReason(rule, "preserve-rule")
		}
	}
	for _, rule := range h.cfg.Delete {
		if rule.matches(sess) {
			return session.MMERestorationPolicyDelete, policyReason(rule, "delete-rule")
		}
	}
	action := defaultPolicyAction(h.cfg.DefaultAction)
	return action, "default-" + string(action)
}

func defaultPolicyAction(action session.MMERestorationPolicyAction) session.MMERestorationPolicyAction {
	switch action {
	case session.MMERestorationPolicyDelete:
		return session.MMERestorationPolicyDelete
	default:
		return session.MMERestorationPolicyPreserve
	}
}

func (r PolicyRule) matches(sess *session.SGWSession) bool {
	if sess == nil {
		return false
	}
	if r.APN != "" && !strings.EqualFold(r.APN, sess.APN) {
		return false
	}
	if r.QCI != 0 {
		b := sess.GetBearer(sess.DefaultBearerID)
		if b == nil || b.QCI != r.QCI {
			return false
		}
	}
	if r.ARPPriorityMin != 0 || r.ARPPriorityMax != 0 {
		b := sess.GetBearer(sess.DefaultBearerID)
		if b == nil {
			return false
		}
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
		if b.ARP.PriorityLevel < minPriority || b.ARP.PriorityLevel > maxPriority {
			return false
		}
	}
	return true
}

func policyReason(rule PolicyRule, fallback string) string {
	if rule.Reason != "" {
		return rule.Reason
	}
	return fallback
}

func (h *Handler) recordStateChange(event peerhealth.StateChangeEvent, state session.MMERestorationState, affected int) {
	canonical := session.CanonicalGTPCEndpoint(event.Addr)
	if canonical == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	mme := h.getOrCreateLocked(canonical)
	if event.At.IsZero() {
		event.At = time.Now()
	}
	if mme.state != state {
		if state == session.MMERestorationStateDown {
			mme.pathDownEvents++
		}
		mme.lastStateChange = event.At
	}
	mme.state = state
	mme.affectedSessions = affected
}

func (h *Handler) recordRestart(event peerhealth.RestartEvent, affected int) {
	canonical := session.CanonicalGTPCEndpoint(event.Addr)
	if canonical == "" {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	mme := h.getOrCreateLocked(canonical)
	if event.At.IsZero() {
		event.At = time.Now()
	}
	mme.state = session.MMERestorationStateRestorationPending
	mme.recoverySeen = true
	mme.recoveryCounter = event.NewRecovery
	mme.restartDetectedAt = event.At
	mme.lastStateChange = event.At
	mme.affectedSessions = affected
	mme.restarts++
}

func (h *Handler) getOrCreateLocked(addr string) *mmeState {
	state := h.mmes[addr]
	if state != nil {
		return state
	}
	state = &mmeState{
		addr:  addr,
		state: session.MMERestorationStateUnknown,
	}
	h.mmes[addr] = state
	return state
}
