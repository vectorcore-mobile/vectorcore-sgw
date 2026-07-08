package session_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/session"
)

func TestPFCPRepairPlanForMatchedSession(t *testing.T) {
	_, sess := managerWithPFCPBinding(t)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMatched, "ok", time.Unix(1, 0))

	plan := sess.PFCPRepairPlan()
	if plan.Action != session.PFCPRepairNone || plan.Repairable {
		t.Fatalf("repair plan = %+v; want none", plan)
	}
}

func TestPFCPRepairPlanForMissingSessionReestablish(t *testing.T) {
	_, sess := managerWithPFCPBinding(t)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMissing, "missing", time.Unix(1, 0))

	plan := sess.PFCPRepairPlan()
	if plan.Action != session.PFCPRepairReestablishSession || !plan.Repairable {
		t.Fatalf("repair plan = %+v; want repairable reestablish", plan)
	}
	if len(plan.BearerEBIs) != 2 || plan.BearerEBIs[0] != 5 || plan.BearerEBIs[1] != 7 {
		t.Fatalf("repair plan EBIs = %+v; want 5,7", plan.BearerEBIs)
	}
	if len(plan.PDRIDs) != 4 || len(plan.FARIDs) != 4 {
		t.Fatalf("repair plan rules = pdr:%+v far:%+v; want all expected rule IDs", plan.PDRIDs, plan.FARIDs)
	}
}

func TestPFCPRepairPlanForMismatchRecreateRules(t *testing.T) {
	_, sess := managerWithPFCPBinding(t)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMismatched, "rule-mismatch", time.Unix(1, 0))

	plan := sess.PFCPRepairPlan()
	if plan.Action != session.PFCPRepairRecreateMissingRules || !plan.Repairable {
		t.Fatalf("repair plan = %+v; want repairable recreate_missing_rules", plan)
	}
}

func TestPFCPRepairPlanForUnverifiableDefersRepair(t *testing.T) {
	_, sess := managerWithPFCPBinding(t)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationUnverifiable, "inventory unavailable", time.Unix(1, 0))

	plan := sess.PFCPRepairPlan()
	if plan.Action != session.PFCPRepairNone || plan.Repairable {
		t.Fatalf("repair plan = %+v; want deferred no-op", plan)
	}
}

func TestPFCPRepairPlanCleanupWhenStateInsufficient(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.DeleteBearer(5)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMissing, "missing", time.Unix(1, 0))

	plan := sess.PFCPRepairPlan()
	if plan.Action != session.PFCPRepairCleanup || plan.Repairable {
		t.Fatalf("repair plan = %+v; want cleanup for insufficient state", plan)
	}
}

func TestApplyPFCPRepairPlansReestablishesAndMarksMatched(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMissing, "missing", time.Unix(1, 0))
	exec := &fakeRepairExecutor{}

	result := m.ApplyPFCPRepairPlans(context.Background(), exec)
	if result.Reestablished != 1 || exec.reestablishCount != 1 {
		t.Fatalf("repair result = %+v executor=%+v; want one reestablish", result, exec)
	}
	if got := sess.GetState(); got != session.StateActive {
		t.Fatalf("session state = %q; want active after repair", got)
	}
	if status := sess.PFCPReconciliationSnapshot(); status.State != session.PFCPReconciliationMatched {
		t.Fatalf("reconciliation status = %+v; want matched", status)
	}
}

func TestApplyPFCPRepairPlansRecreatesRules(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMismatched, "rule-mismatch", time.Unix(1, 0))
	exec := &fakeRepairExecutor{}

	result := m.ApplyPFCPRepairPlans(context.Background(), exec)
	if result.RulesRecreated != 1 || exec.recreateCount != 1 {
		t.Fatalf("repair result = %+v executor=%+v; want one rule recreate", result, exec)
	}
	if status := sess.PFCPReconciliationSnapshot(); status.State != session.PFCPReconciliationMatched {
		t.Fatalf("reconciliation status = %+v; want matched", status)
	}
}

func TestApplyPFCPRepairPlansFailureKeepsRecovering(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMissing, "missing", time.Unix(1, 0))
	exec := &fakeRepairExecutor{err: errors.New("pfcp rejected")}

	result := m.ApplyPFCPRepairPlans(context.Background(), exec)
	if result.Failed != 1 {
		t.Fatalf("repair result = %+v; want one failure", result)
	}
	if got := sess.GetState(); got != session.StateRecovering {
		t.Fatalf("session state = %q; want recovering after failed repair", got)
	}
	status := sess.PFCPReconciliationSnapshot()
	if status.State != session.PFCPReconciliationMismatched || status.Reason == "" {
		t.Fatalf("reconciliation status = %+v; want mismatched failure reason", status)
	}
}

type fakeRepairExecutor struct {
	err              error
	reestablishCount int
	recreateCount    int
	cleanupCount     int
}

func (f *fakeRepairExecutor) ReestablishPFCPSession(context.Context, *session.SGWSession, session.PFCPRepairPlan) error {
	f.reestablishCount++
	return f.err
}

func (f *fakeRepairExecutor) RecreatePFCPRules(context.Context, *session.SGWSession, session.PFCPRepairPlan) error {
	f.recreateCount++
	return f.err
}

func (f *fakeRepairExecutor) CleanupUnrepairablePFCP(context.Context, *session.SGWSession, session.PFCPRepairPlan) error {
	f.cleanupCount++
	return f.err
}
