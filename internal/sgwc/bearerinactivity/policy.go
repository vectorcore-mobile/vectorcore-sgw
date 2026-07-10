package bearerinactivity

import (
	"fmt"
	"sort"
	"strings"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

type DecisionAction string

const (
	DecisionPreserve                DecisionAction = "preserve"
	DecisionCleanupDedicatedBearer  DecisionAction = "cleanup_dedicated_bearer"
	DecisionCleanupDefaultBearer    DecisionAction = "cleanup_default_bearer"
	DecisionDeferNoActivityEvidence DecisionAction = "defer_no_activity_evidence"
	DecisionDeferNotIdle            DecisionAction = "defer_not_idle"
	DecisionDeferRecentControl      DecisionAction = "defer_recent_control_activity"
	DecisionDeferNoPolicy           DecisionAction = "defer_no_matching_cleanup_policy"
	DecisionDenyDefaultBearer       DecisionAction = "deny_default_bearer_cleanup"
	DecisionDisabled                DecisionAction = "disabled"
)

type Decision struct {
	SessionID               string
	IMSI                    string
	APN                     string
	EBI                     uint8
	BearerType              string
	QCI                     uint8
	ARPPriority             uint8
	BearerState             string
	Action                  DecisionAction
	Reason                  string
	IdleThreshold           time.Duration
	IdleFor                 time.Duration
	LastControlActivityAt   time.Time
	LastUserPlaneActivityAt time.Time
	LastActivityAt          time.Time
	LastActivitySource      string
	RequireNoRecentControl  bool
	MatchedPreserveRule     string
	MatchedCleanupRule      string
}

type Evaluator struct {
	cfg sgwcconfig.BearerInactivityConfig
}

func NewEvaluator(cfg sgwcconfig.BearerInactivityConfig) Evaluator {
	return Evaluator{cfg: cfg}
}

func (e Evaluator) EvaluateManager(m *session.Manager, now time.Time) []Decision {
	if m == nil {
		return nil
	}
	sessions := m.List()
	out := make([]Decision, 0)
	for _, sess := range sessions {
		out = append(out, e.EvaluateSession(sess, now)...)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].IMSI != out[j].IMSI {
			return out[i].IMSI < out[j].IMSI
		}
		if out[i].APN != out[j].APN {
			return out[i].APN < out[j].APN
		}
		return out[i].EBI < out[j].EBI
	})
	return out
}

func (e Evaluator) EvaluateSession(sess *session.SGWSession, now time.Time) []Decision {
	if sess == nil {
		return nil
	}
	if now.IsZero() {
		now = time.Now()
	}
	bearers := sess.BearerList()
	sort.Slice(bearers, func(i, j int) bool { return bearers[i].EBI < bearers[j].EBI })
	out := make([]Decision, 0, len(bearers))
	for _, b := range bearers {
		out = append(out, e.EvaluateBearer(sess, b, now))
	}
	return out
}

func (e Evaluator) EvaluateBearer(sess *session.SGWSession, b *bearer.Bearer, now time.Time) Decision {
	if now.IsZero() {
		now = time.Now()
	}
	d := baseDecision(sess, b, now, e.cfg)
	if sess == nil || b == nil {
		d.Action = DecisionDeferNoActivityEvidence
		d.Reason = "missing-session-or-bearer"
		return d
	}
	if !e.cfg.Enabled {
		d.Action = DecisionDisabled
		d.Reason = "bearer-inactivity-disabled"
		return d
	}
	if rule, ok := firstMatchingRule(e.cfg.Preserve, sess.APN, d.BearerType, b); ok {
		d.Action = DecisionPreserve
		d.Reason = policyReason(rule, "preserve-rule")
		d.MatchedPreserveRule = d.Reason
		return d
	}
	rule, ok := firstMatchingRule(e.cfg.Cleanup, sess.APN, d.BearerType, b)
	if !ok {
		d.Action = DecisionDeferNoPolicy
		d.Reason = "no-matching-cleanup-policy"
		return d
	}
	d.MatchedCleanupRule = policyReason(rule, "cleanup-rule")
	if d.BearerType == "default" && !e.cfg.DeleteDefaultBearers {
		d.Action = DecisionDenyDefaultBearer
		d.Reason = "default-bearer-cleanup-disabled"
		return d
	}
	threshold := e.idleThreshold(d.BearerType, b.State, rule)
	d.IdleThreshold = threshold
	if threshold <= 0 {
		d.Action = DecisionDenyDefaultBearer
		d.Reason = "default-bearer-idle-timeout-disabled"
		return d
	}
	if d.LastActivityAt.IsZero() {
		d.Action = DecisionDeferNoActivityEvidence
		d.Reason = "no-control-or-user-plane-activity"
		return d
	}
	d.IdleFor = now.Sub(d.LastActivityAt)
	if d.IdleFor < 0 {
		d.IdleFor = 0
	}
	if e.cfg.RequireNoRecentControlActivity && !d.LastControlActivityAt.IsZero() && now.Sub(d.LastControlActivityAt) < threshold {
		d.Action = DecisionDeferRecentControl
		d.Reason = "recent-control-plane-activity"
		return d
	}
	if d.IdleFor < threshold {
		d.Action = DecisionDeferNotIdle
		d.Reason = "bearer-not-idle"
		return d
	}
	if d.BearerType == "default" {
		d.Action = DecisionCleanupDefaultBearer
	} else {
		d.Action = DecisionCleanupDedicatedBearer
	}
	d.Reason = d.MatchedCleanupRule
	return d
}

func (e Evaluator) idleThreshold(bearerType string, state bearer.BearerState, rule sgwcconfig.BearerInactivityRuleConfig) time.Duration {
	if state == bearer.BearerStatePending {
		return time.Duration(e.cfg.PendingBearerTimeoutSeconds) * time.Second
	}
	if rule.IdleSeconds > 0 {
		return time.Duration(rule.IdleSeconds) * time.Second
	}
	if bearerType == "default" {
		return time.Duration(e.cfg.DefaultBearerIdleSeconds) * time.Second
	}
	return time.Duration(e.cfg.DedicatedBearerIdleSeconds) * time.Second
}

func baseDecision(sess *session.SGWSession, b *bearer.Bearer, now time.Time, cfg sgwcconfig.BearerInactivityConfig) Decision {
	d := Decision{RequireNoRecentControl: cfg.RequireNoRecentControlActivity}
	if sess != nil {
		d.SessionID = sess.SessionID
		d.IMSI = sess.IMSI
		d.APN = sess.APN
	}
	if b == nil {
		return d
	}
	d.EBI = b.EBI
	d.QCI = b.QCI
	d.ARPPriority = b.ARP.PriorityLevel
	d.BearerState = string(b.State)
	if sess != nil && b.EBI == sess.DefaultBearerID {
		d.BearerType = "default"
	} else {
		d.BearerType = "dedicated"
	}
	d.LastControlActivityAt = b.LastControlActivityAt
	d.LastUserPlaneActivityAt = b.LastUserPlaneActivityAt
	d.LastActivitySource = b.LastActivitySource
	d.LastActivityAt = latestTime(b.LastControlActivityAt, b.LastUserPlaneActivityAt)
	if !d.LastActivityAt.IsZero() {
		d.IdleFor = now.Sub(d.LastActivityAt)
		if d.IdleFor < 0 {
			d.IdleFor = 0
		}
	}
	return d
}

func firstMatchingRule(rules []sgwcconfig.BearerInactivityRuleConfig, apn, bearerType string, b *bearer.Bearer) (sgwcconfig.BearerInactivityRuleConfig, bool) {
	for _, rule := range rules {
		if bearerRuleMatches(rule, apn, bearerType, b) {
			return rule, true
		}
	}
	return sgwcconfig.BearerInactivityRuleConfig{}, false
}

func bearerRuleMatches(rule sgwcconfig.BearerInactivityRuleConfig, apn, bearerType string, b *bearer.Bearer) bool {
	if b == nil {
		return false
	}
	if rule.APN != "" && !strings.EqualFold(rule.APN, apn) {
		return false
	}
	if rule.BearerType != "" && !strings.EqualFold(rule.BearerType, bearerType) {
		return false
	}
	if rule.QCI != 0 && rule.QCI != b.QCI {
		return false
	}
	if rule.ARPPriorityMin != 0 || rule.ARPPriorityMax != 0 {
		minPriority, maxPriority := rule.ARPPriorityMin, rule.ARPPriorityMax
		if minPriority == 0 {
			minPriority = 1
		}
		if maxPriority == 0 {
			maxPriority = 15
		}
		if b.ARP.PriorityLevel < minPriority || b.ARP.PriorityLevel > maxPriority {
			return false
		}
	}
	return true
}

func policyReason(rule sgwcconfig.BearerInactivityRuleConfig, fallback string) string {
	if rule.Reason != "" {
		return rule.Reason
	}
	return fallback
}

func latestTime(a, b time.Time) time.Time {
	if a.IsZero() {
		return b
	}
	if b.IsZero() || a.After(b) {
		return a
	}
	return b
}

func (d Decision) String() string {
	return fmt.Sprintf("%s imsi=%s apn=%s ebi=%d reason=%s", d.Action, d.IMSI, d.APN, d.EBI, d.Reason)
}
