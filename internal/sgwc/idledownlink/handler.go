package idledownlink

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/sgwc/ddncontrol"
	"vectorcore-sgw/internal/sgwc/session"
)

type DDNSender interface {
	SendDownlinkDataNotification(ctx context.Context, sess *session.SGWSession) (uint32, error)
}

type Handler struct {
	sessions *session.Manager
	ddn      DDNSender
	ddnCtl   *ddncontrol.State
	cfg      Config
	log      *slog.Logger

	mu         sync.Mutex
	lastReport map[string]time.Time

	reports    atomic.Uint64
	suppressed atomic.Uint64
	throttled  atomic.Uint64
	ddnSent    atomic.Uint64
	ddnFailed  atomic.Uint64
}

type Config struct {
	Enabled                  bool
	TriggerDDN               bool
	ReportThrottle           time.Duration
	RequireReleaseAccessDrop bool
	HighPriority             []ddncontrol.PriorityRule
	Suppress                 []ddncontrol.PriorityRule
}

type Snapshot struct {
	Enabled        bool   `json:"enabled"`
	TriggerDDN     bool   `json:"trigger_ddn"`
	Reports        uint64 `json:"reports"`
	Suppressed     uint64 `json:"suppressed"`
	Throttled      uint64 `json:"throttled"`
	DDNSent        uint64 `json:"ddn_sent"`
	DDNFailed      uint64 `json:"ddn_failed"`
	TrackedBearers int    `json:"tracked_bearers"`
}

func New(sessions *session.Manager, cfg Config, log *slog.Logger) *Handler {
	if log == nil {
		log = slog.Default()
	}
	return &Handler{sessions: sessions, cfg: cfg, log: log, lastReport: make(map[string]time.Time)}
}

func ConfigFromSGWC(cfg sgwcconfig.IdleDownlinkConfig) Config {
	return Config{
		Enabled:                  cfg.Enabled,
		TriggerDDN:               cfg.TriggerDDN,
		ReportThrottle:           time.Duration(cfg.ReportThrottleSeconds) * time.Second,
		RequireReleaseAccessDrop: cfg.RequireReleaseAccessDrop,
		HighPriority:             priorityRules(cfg.HighPriority),
		Suppress:                 priorityRules(cfg.Suppress),
	}
}

func priorityRules(rules []sgwcconfig.DDNControlPriorityRuleConfig) []ddncontrol.PriorityRule {
	out := make([]ddncontrol.PriorityRule, 0, len(rules))
	for _, rule := range rules {
		out = append(out, ddncontrol.PriorityRule{
			APN:            rule.APN,
			QCI:            rule.QCI,
			ARPPriorityMin: rule.ARPPriorityMin,
			ARPPriorityMax: rule.ARPPriorityMax,
			Reason:         rule.Reason,
		})
	}
	return out
}

func (h *Handler) SetDDNSender(sender DDNSender) {
	h.ddn = sender
}

func (h *Handler) SetDDNControl(state *ddncontrol.State) {
	h.ddnCtl = state
}

func (h *Handler) Snapshot() Snapshot {
	if h == nil {
		return Snapshot{}
	}
	h.mu.Lock()
	tracked := len(h.lastReport)
	h.mu.Unlock()
	return Snapshot{
		Enabled:        h.cfg.Enabled,
		TriggerDDN:     h.cfg.TriggerDDN,
		Reports:        h.reports.Load(),
		Suppressed:     h.suppressed.Load(),
		Throttled:      h.throttled.Load(),
		DDNSent:        h.ddnSent.Load(),
		DDNFailed:      h.ddnFailed.Load(),
		TrackedBearers: tracked,
	}
}

func (h *Handler) HandleReport(peerAddr string, report pfcpie.VectorCoreIdleDownlinkReport) {
	if h == nil || !h.cfg.Enabled {
		return
	}
	h.reports.Add(1)
	if h.cfg.RequireReleaseAccessDrop && report.DropReason != pfcpie.VectorCoreIdleDownlinkDropReleaseAccessBearers {
		h.suppressed.Add(1)
		h.log.Info("Idle downlink report suppressed: drop reason is not Release Access Bearers",
			"sgwu", peerAddr,
			"cp_seid", report.CPSEID,
			"up_seid", report.UPSEID,
			"drop_reason", report.DropReason)
		return
	}
	sess := h.sessions.FindByPFCPSEID(report.CPSEID, report.UPSEID)
	if sess == nil {
		h.suppressed.Add(1)
		h.log.Warn("Idle downlink report unmatched to SGW-C session",
			"sgwu", peerAddr,
			"cp_seid", report.CPSEID,
			"up_seid", report.UPSEID,
			"pdr_id", report.PDRID,
			"far_id", report.FARID,
			"local_teid", fmt.Sprintf("0x%08X", report.LocalTEID))
		return
	}
	candidate := h.candidate(sess, report)
	if matched, reason := matchesAny(h.cfg.Suppress, candidate); matched {
		h.suppressed.Add(1)
		h.log.Info("Idle downlink report suppressed by policy",
			"sgwu", peerAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"ebi", candidate.EBI,
			"qci", candidate.QCI,
			"reason", reason)
		return
	}
	if matched, reason := matchesAny(h.cfg.HighPriority, candidate); !matched {
		h.suppressed.Add(1)
		h.log.Info("Idle downlink report suppressed: no high-priority policy match",
			"sgwu", peerAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"ebi", candidate.EBI,
			"qci", candidate.QCI,
			"reason", reason)
		return
	}
	at := time.Now()
	if throttled, retryAfter := h.throttle(sess.SessionID, candidate.EBI, at); throttled {
		h.throttled.Add(1)
		h.log.Info("Idle downlink report throttled",
			"sgwu", peerAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"ebi", candidate.EBI,
			"qci", candidate.QCI,
			"retry_after", retryAfter)
		return
	}
	if !h.cfg.TriggerDDN {
		h.suppressed.Add(1)
		h.log.Info("Idle downlink report accepted but DDN trigger disabled",
			"sgwu", peerAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"ebi", candidate.EBI,
			"qci", candidate.QCI)
		return
	}

	decision := h.decide(candidate, at)
	if decision.Action != "" && decision.Action != ddncontrol.ActionSendNow {
		h.suppressed.Add(1)
		h.log.Info("Idle downlink DDN controlled",
			"sgwu", peerAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"ebi", candidate.EBI,
			"qci", candidate.QCI,
			"action", decision.Action,
			"priority", decision.Priority,
			"reason", decision.Reason,
			"retry_after", decision.RetryAfter)
		return
	}
	if h.ddn == nil {
		h.ddnFailed.Add(1)
		h.log.Warn("Idle downlink DDN skipped: sender unavailable",
			"sgwu", peerAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	seq, err := h.ddn.SendDownlinkDataNotification(ctx, sess)
	cancel()
	if err != nil {
		h.ddnFailed.Add(1)
		h.log.Warn("Idle downlink DDN trigger failed",
			"sgwu", peerAddr,
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"ebi", candidate.EBI,
			"qci", candidate.QCI,
			"error", err)
		return
	}
	h.ddnSent.Add(1)
	sess.MarkMMERestorationDDNTriggered(seq, at)
	h.log.Info("Idle downlink DDN triggered",
		"sgwu", peerAddr,
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"ebi", candidate.EBI,
		"qci", candidate.QCI,
		"priority", decision.Priority,
		"reason", decision.Reason,
		"seq", seq)
}

func (h *Handler) candidate(sess *session.SGWSession, report pfcpie.VectorCoreIdleDownlinkReport) ddncontrol.Candidate {
	ebi := report.EBI
	if ebi == 0 {
		ebi = sess.DefaultBearerID
	}
	c := ddncontrol.Candidate{
		MMEAddr: fmt.Sprintf("%s:2123", sess.MMEControlFTEID.IPv4.String()),
		IMSI:    sess.IMSI,
		APN:     sess.APN,
		EBI:     ebi,
		QCI:     report.QCI,
	}
	if b := sess.GetBearer(ebi); b != nil {
		if c.QCI == 0 {
			c.QCI = b.QCI
		}
		c.ARPPriority = b.ARP.PriorityLevel
	}
	return c
}

func (h *Handler) throttle(sessionID string, ebi uint8, at time.Time) (bool, time.Duration) {
	if h.cfg.ReportThrottle <= 0 {
		return false, 0
	}
	key := fmt.Sprintf("%s/%d", sessionID, ebi)
	h.mu.Lock()
	defer h.mu.Unlock()
	if last, ok := h.lastReport[key]; ok {
		until := last.Add(h.cfg.ReportThrottle)
		if at.Before(until) {
			return true, until.Sub(at)
		}
	}
	h.lastReport[key] = at
	return false, 0
}

func (h *Handler) decide(c ddncontrol.Candidate, at time.Time) ddncontrol.Decision {
	if h.ddnCtl == nil {
		return ddncontrol.Decision{
			Action:   ddncontrol.ActionSendNow,
			Priority: ddncontrol.PriorityHigh,
			Reason:   "idle-downlink-ddn-control-unavailable",
			MMEAddr:  c.MMEAddr,
			IMSI:     c.IMSI,
			APN:      c.APN,
			EBI:      c.EBI,
			QCI:      c.QCI,
		}
	}
	return h.ddnCtl.Decide(c, at)
}

func matchesAny(rules []ddncontrol.PriorityRule, c ddncontrol.Candidate) (bool, string) {
	for _, rule := range rules {
		if ruleMatches(rule, c) {
			if strings.TrimSpace(rule.Reason) != "" {
				return true, rule.Reason
			}
			return true, "idle-downlink-policy-match"
		}
	}
	return false, "idle-downlink-policy-no-match"
}

func ruleMatches(rule ddncontrol.PriorityRule, c ddncontrol.Candidate) bool {
	if rule.APN != "" && !strings.Contains(strings.ToLower(c.APN), strings.ToLower(rule.APN)) {
		return false
	}
	if rule.QCI != 0 && rule.QCI != c.QCI {
		return false
	}
	if rule.ARPPriorityMin != 0 && (c.ARPPriority == 0 || c.ARPPriority < rule.ARPPriorityMin) {
		return false
	}
	if rule.ARPPriorityMax != 0 && (c.ARPPriority == 0 || c.ARPPriority > rule.ARPPriorityMax) {
		return false
	}
	return true
}
