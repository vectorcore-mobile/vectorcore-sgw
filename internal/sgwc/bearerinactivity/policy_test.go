package bearerinactivity

import (
	"net/netip"
	"testing"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

func TestEvaluatorCleansIdleDedicatedBearer(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sess := testSession(t)
	addBearer(t, sess, 7, 9, bearer.BearerStateActive)
	sess.MarkBearerControlActivity(7, "test", now.Add(-10*time.Minute))

	decision := NewEvaluator(testConfig(true)).EvaluateBearer(sess, sess.GetBearer(7), now)
	if decision.Action != DecisionCleanupDedicatedBearer {
		t.Fatalf("decision = %+v; want cleanup dedicated", decision)
	}
	if decision.IdleThreshold != 5*time.Minute || decision.IdleFor != 10*time.Minute {
		t.Fatalf("idle = %s threshold=%s; want 10m/5m", decision.IdleFor, decision.IdleThreshold)
	}
}

func TestEvaluatorPreserveRuleWinsBeforeCleanup(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sess := testSession(t)
	addBearer(t, sess, 7, 1, bearer.BearerStateActive)
	sess.MarkBearerControlActivity(7, "test", now.Add(-30*time.Minute))

	decision := NewEvaluator(testConfig(true)).EvaluateBearer(sess, sess.GetBearer(7), now)
	if decision.Action != DecisionPreserve || decision.Reason != "bearer-inactivity-preserve-qci-1" {
		t.Fatalf("decision = %+v; want preserve qci 1", decision)
	}
}

func TestEvaluatorDeniesDefaultBearerCleanupUnlessExplicitlyEnabled(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sess := testSession(t)
	sess.MarkBearerControlActivity(5, "test", now.Add(-30*time.Minute))
	cfg := testConfig(true)
	cfg.Cleanup = append(cfg.Cleanup, sgwcconfig.BearerInactivityRuleConfig{
		BearerType:  "default",
		IdleSeconds: 300,
	})

	decision := NewEvaluator(cfg).EvaluateBearer(sess, sess.GetBearer(5), now)
	if decision.Action != DecisionDenyDefaultBearer {
		t.Fatalf("decision = %+v; want default bearer cleanup denial", decision)
	}
}

func TestEvaluatorDefersWithoutActivityEvidence(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sess := testSession(t)
	addBearer(t, sess, 7, 9, bearer.BearerStateActive)
	b := sess.GetBearer(7)
	b.LastControlActivityAt = time.Time{}
	b.LastUserPlaneActivityAt = time.Time{}
	b.LastActivitySource = ""

	decision := NewEvaluator(testConfig(true)).EvaluateBearer(sess, b, now)
	if decision.Action != DecisionDeferNoActivityEvidence {
		t.Fatalf("decision = %+v; want no activity evidence defer", decision)
	}
}

func TestEvaluatorDefersRecentControlActivity(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sess := testSession(t)
	addBearer(t, sess, 7, 9, bearer.BearerStateActive)
	sess.MarkBearerControlActivity(7, "modify_bearer", now.Add(-time.Minute))

	decision := NewEvaluator(testConfig(true)).EvaluateBearer(sess, sess.GetBearer(7), now)
	if decision.Action != DecisionDeferRecentControl {
		t.Fatalf("decision = %+v; want recent control defer", decision)
	}
}

func TestEvaluatorUsesPendingBearerTimeout(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sess := testSession(t)
	addBearer(t, sess, 7, 9, bearer.BearerStatePending)
	sess.MarkBearerControlActivity(7, "create_bearer", now.Add(-2*time.Minute))

	decision := NewEvaluator(testConfig(true)).EvaluateBearer(sess, sess.GetBearer(7), now)
	if decision.Action != DecisionCleanupDedicatedBearer {
		t.Fatalf("decision = %+v; want pending dedicated cleanup", decision)
	}
	if decision.IdleThreshold != time.Minute {
		t.Fatalf("pending threshold = %s; want 1m", decision.IdleThreshold)
	}
}

func TestEvaluatorDisabled(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	sess := testSession(t)
	addBearer(t, sess, 7, 9, bearer.BearerStateActive)

	decision := NewEvaluator(testConfig(false)).EvaluateBearer(sess, sess.GetBearer(7), now)
	if decision.Action != DecisionDisabled {
		t.Fatalf("decision = %+v; want disabled", decision)
	}
}

func TestEvaluateManagerSortsByIMSIAPNEBI(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	m := session.NewManager()
	first, _, err := m.Create(testCreateParams("311430000000002", "internet", 5))
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	second, _, err := m.Create(testCreateParams("311430000000001", "ims", 6))
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	addBearer(t, first, 7, 9, bearer.BearerStateActive)
	addBearer(t, second, 8, 9, bearer.BearerStateActive)

	decisions := NewEvaluator(testConfig(true)).EvaluateManager(m, now)
	if len(decisions) != 4 {
		t.Fatalf("decisions = %d; want 4", len(decisions))
	}
	if decisions[0].IMSI != "311430000000001" || decisions[0].APN != "ims" || decisions[0].EBI != 6 {
		t.Fatalf("first decision = %+v; want sorted IMS APN EBI", decisions[0])
	}
}

func TestEvaluatorUsesRestoredCheckpointActivityState(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	source := session.NewManager()
	sess, _, err := source.Create(testCreateParams("311430000000001", "internet", 5))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	addBearer(t, sess, 7, 9, bearer.BearerStateActive)
	sess.MarkBearerControlActivity(7, "create_bearer_response", now.Add(-10*time.Minute))
	sess.MarkBearerUserPlaneActivity(7, "pfcp_usage_report", now.Add(-8*time.Minute))

	restored := session.NewManager()
	result, err := restored.RestoreSnapshots(source.Snapshots())
	if err != nil {
		t.Fatalf("RestoreSnapshots: %v", err)
	}
	if result.Restored != 1 {
		t.Fatalf("restore result = %+v; want one restored", result)
	}
	restoredSess := restored.Find(sess.SessionID)
	if restoredSess == nil {
		t.Fatal("restored session missing")
	}

	decision := NewEvaluator(testConfig(true)).EvaluateBearer(restoredSess, restoredSess.GetBearer(7), now)
	if decision.Action != DecisionCleanupDedicatedBearer {
		t.Fatalf("decision = %+v; want cleanup dedicated from restored activity", decision)
	}
	if decision.LastActivitySource != "pfcp_usage_report" || decision.IdleFor != 8*time.Minute {
		t.Fatalf("restored activity decision = %+v; want user-plane source idle 8m", decision)
	}
}

func testConfig(enabled bool) sgwcconfig.BearerInactivityConfig {
	return sgwcconfig.BearerInactivityConfig{
		Enabled:                        enabled,
		CheckIntervalSeconds:           30,
		DedicatedBearerIdleSeconds:     300,
		PendingBearerTimeoutSeconds:    60,
		DefaultBearerIdleSeconds:       0,
		DeleteDefaultBearers:           false,
		RequireNoRecentControlActivity: true,
		Preserve: []sgwcconfig.BearerInactivityRuleConfig{
			{QCI: 1},
		},
		Cleanup: []sgwcconfig.BearerInactivityRuleConfig{
			{BearerType: "dedicated", IdleSeconds: 300},
		},
	}
}

func testSession(t *testing.T) *session.SGWSession {
	t.Helper()
	m := session.NewManager()
	sess, _, err := m.Create(testCreateParams("311430000000001", "internet", 5))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	return sess
}

func testCreateParams(imsi, apn string, defaultEBI uint8) session.CreateParams {
	return session.CreateParams{
		IMSI:           imsi,
		APN:            apn,
		RATType:        6,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0xAABBCCDD,
			IPv4: netip.MustParseAddr("10.1.1.1"),
		},
		DefaultEBI:  defaultEBI,
		QCI:         9,
		ARP:         bearer.ARP{PriorityLevel: 9},
		MBRUplink:   256000,
		MBRDownlink: 256000,
	}
}

func addBearer(t *testing.T, sess *session.SGWSession, ebi, qci uint8, state bearer.BearerState) {
	t.Helper()
	sess.SetBearer(&bearer.Bearer{
		EBI:   ebi,
		QCI:   qci,
		ARP:   bearer.ARP{PriorityLevel: 9},
		State: state,
	})
}
