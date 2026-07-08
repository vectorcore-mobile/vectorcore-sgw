package session

import (
	"context"
	"fmt"
	"time"

	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

type PFCPRepairAction string

const (
	PFCPRepairNone                 PFCPRepairAction = "none"
	PFCPRepairReestablishSession   PFCPRepairAction = "reestablish_session"
	PFCPRepairRecreateMissingRules PFCPRepairAction = "recreate_missing_rules"
	PFCPRepairCleanup              PFCPRepairAction = "cleanup"
)

type PFCPRepairPlan struct {
	SessionID  string
	IMSI       string
	APN        string
	Action     PFCPRepairAction
	Reason     string
	Binding    PFCPSessionBinding
	BearerEBIs []uint8
	PDRIDs     []uint32
	FARIDs     []uint32
	Repairable bool
}

type PFCPRepairExecutor interface {
	ReestablishPFCPSession(ctx context.Context, sess *SGWSession, plan PFCPRepairPlan) error
	RecreatePFCPRules(ctx context.Context, sess *SGWSession, plan PFCPRepairPlan) error
	CleanupUnrepairablePFCP(ctx context.Context, sess *SGWSession, plan PFCPRepairPlan) error
}

type PFCPRepairResult struct {
	Planned        int
	Noop           int
	Reestablished  int
	RulesRecreated int
	Cleanup        int
	Failed         int
}

func (s *SGWSession) PFCPRepairPlan() PFCPRepairPlan {
	snap := s.Snapshot()
	status := s.PFCPReconciliationSnapshot()
	binding := s.PFCPBinding()
	pdrIDs, farIDs := s.expectedPFCPRuleIDs()
	bearerEBIs := make([]uint8, 0, len(snap.Bearers))
	for _, b := range snap.Bearers {
		bearerEBIs = append(bearerEBIs, b.EBI)
	}
	plan := PFCPRepairPlan{
		SessionID:  s.SessionID,
		IMSI:       s.IMSI,
		APN:        s.APN,
		Binding:    binding,
		BearerEBIs: bearerEBIs,
		PDRIDs:     pdrIDs,
		FARIDs:     farIDs,
	}
	switch status.State {
	case PFCPReconciliationMatched:
		plan.Action = PFCPRepairNone
		plan.Reason = "pfcp-already-matched"
	case PFCPReconciliationMissing:
		plan.Action = PFCPRepairReestablishSession
		plan.Reason = "sgwu-session-missing"
		plan.Repairable = hasEnoughStateForSessionReestablish(snap)
	case PFCPReconciliationMismatched:
		plan.Action = PFCPRepairRecreateMissingRules
		plan.Reason = status.Reason
		plan.Repairable = hasEnoughStateForSessionReestablish(snap)
	case PFCPReconciliationNoBinding:
		plan.Action = PFCPRepairReestablishSession
		plan.Reason = "no-pfcp-binding"
		plan.Repairable = hasEnoughStateForSessionReestablish(snap)
	case PFCPReconciliationUnverifiable, PFCPReconciliationUnknown, "":
		plan.Action = PFCPRepairNone
		plan.Reason = fmt.Sprintf("repair-deferred: %s", status.Reason)
	default:
		plan.Action = PFCPRepairNone
		plan.Reason = fmt.Sprintf("repair-deferred: reconciliation=%s", status.State)
	}
	if !plan.Repairable && (plan.Action == PFCPRepairReestablishSession || plan.Action == PFCPRepairRecreateMissingRules) {
		plan.Action = PFCPRepairCleanup
		plan.Reason += "; insufficient-state-for-repair"
	}
	return plan
}

func (m *Manager) PFCPRepairPlans() []PFCPRepairPlan {
	sessions := m.List()
	out := make([]PFCPRepairPlan, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, sess.PFCPRepairPlan())
	}
	return out
}

func (m *Manager) ApplyPFCPRepairPlans(ctx context.Context, exec PFCPRepairExecutor) PFCPRepairResult {
	sessions := m.List()
	result := PFCPRepairResult{Planned: len(sessions)}
	for _, sess := range sessions {
		plan := sess.PFCPRepairPlan()
		switch plan.Action {
		case PFCPRepairNone:
			result.Noop++
		case PFCPRepairReestablishSession:
			if exec == nil || !plan.Repairable {
				result.Failed++
				sess.MarkPFCPReconciliation(PFCPReconciliationUnverifiable, "repair executor unavailable", timeNow())
				continue
			}
			if err := exec.ReestablishPFCPSession(ctx, sess, plan); err != nil {
				result.Failed++
				sess.MarkPFCPReconciliation(PFCPReconciliationMismatched, "repair failed: "+err.Error(), timeNow())
				continue
			}
			result.Reestablished++
			sess.MarkPFCPReconciliation(PFCPReconciliationMatched, "pfcp-session-reestablished", timeNow())
		case PFCPRepairRecreateMissingRules:
			if exec == nil || !plan.Repairable {
				result.Failed++
				sess.MarkPFCPReconciliation(PFCPReconciliationUnverifiable, "repair executor unavailable", timeNow())
				continue
			}
			if err := exec.RecreatePFCPRules(ctx, sess, plan); err != nil {
				result.Failed++
				sess.MarkPFCPReconciliation(PFCPReconciliationMismatched, "rule repair failed: "+err.Error(), timeNow())
				continue
			}
			result.RulesRecreated++
			sess.MarkPFCPReconciliation(PFCPReconciliationMatched, "pfcp-rules-recreated", timeNow())
		case PFCPRepairCleanup:
			if exec == nil {
				result.Failed++
				sess.MarkPFCPReconciliation(PFCPReconciliationUnverifiable, "cleanup executor unavailable", timeNow())
				continue
			}
			if err := exec.CleanupUnrepairablePFCP(ctx, sess, plan); err != nil {
				result.Failed++
				sess.MarkPFCPReconciliation(PFCPReconciliationMismatched, "cleanup failed: "+err.Error(), timeNow())
				continue
			}
			result.Cleanup++
		}
	}
	return result
}

func hasEnoughStateForSessionReestablish(snap sessioncheckpoint.SessionSnapshot) bool {
	if snap.SessionID == "" || snap.IMSI == "" || snap.DefaultBearerID == 0 || len(snap.Bearers) == 0 {
		return false
	}
	hasDefault := false
	for _, b := range snap.Bearers {
		if b.EBI == snap.DefaultBearerID {
			hasDefault = true
		}
	}
	return hasDefault
}

var timeNow = func() time.Time { return time.Now() }
