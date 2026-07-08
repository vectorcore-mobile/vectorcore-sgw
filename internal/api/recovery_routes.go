package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

type RecoveryStatusProvider interface {
	Status() sessioncheckpoint.RuntimeStatus
}

type RecoverySummaryView struct {
	TotalSessions      int            `json:"total_sessions"`
	SessionsByState    map[string]int `json:"sessions_by_state"`
	PFCPReconciliation map[string]int `json:"pfcp_reconciliation"`
	PFCPRepairPlans    map[string]int `json:"pfcp_repair_plans"`
	RepairablePlans    int            `json:"repairable_plans"`
	UnrepairablePlans  int            `json:"unrepairable_plans"`
}

type RecoveryStatusOutput struct {
	Body struct {
		Checkpoint sessioncheckpoint.RuntimeStatus `json:"checkpoint"`
		Summary    RecoverySummaryView             `json:"summary"`
	}
}

func RegisterRecoveryRoutes(api huma.API, status RecoveryStatusProvider, sessions *session.Manager) {
	huma.Register(api, huma.Operation{
		OperationID: "get-session-recovery-status",
		Method:      http.MethodGet,
		Path:        "/recovery/status",
		Summary:     "Show SGW-C session checkpoint and recovery status",
	}, func(ctx context.Context, _ *struct{}) (*RecoveryStatusOutput, error) {
		out := &RecoveryStatusOutput{}
		if status != nil {
			out.Body.Checkpoint = status.Status()
		}
		out.Body.Summary = recoverySummary(sessions)
		return out, nil
	})
}

func recoverySummary(sessions *session.Manager) RecoverySummaryView {
	summary := RecoverySummaryView{
		SessionsByState:    make(map[string]int),
		PFCPReconciliation: make(map[string]int),
		PFCPRepairPlans:    make(map[string]int),
	}
	if sessions == nil {
		return summary
	}
	for _, sess := range sessions.List() {
		summary.TotalSessions++
		summary.SessionsByState[string(sess.GetState())]++
		reconciliation := sess.PFCPReconciliationSnapshot()
		summary.PFCPReconciliation[string(reconciliation.State)]++
		plan := sess.PFCPRepairPlan()
		summary.PFCPRepairPlans[string(plan.Action)]++
		if plan.Repairable {
			summary.RepairablePlans++
		} else if plan.Action != session.PFCPRepairNone {
			summary.UnrepairablePlans++
		}
	}
	return summary
}
