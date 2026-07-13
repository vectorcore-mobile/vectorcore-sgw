package api

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/bearerinactivity"
	"vectorcore-sgw/internal/sgwc/session"
)

func TestBearerInactivityRouteExposesDecisionsAndRuntime(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	now := time.Unix(1000, 0).UTC()
	sess.SetBearer(&bearer.Bearer{
		EBI:    7,
		QCI:    9,
		ARP:    bearer.ARP{PriorityLevel: 9},
		State:  bearer.BearerStateActive,
		PDRIDs: [2]uint32{3, 4},
		FARIDs: [2]uint32{5, 6},
	})
	sess.MarkBearerControlActivity(7, "test", now.Add(-10*time.Minute))
	cfg := sgwcconfig.Default().GTPC.BearerInactivity
	cfg.Enabled = true
	cfg.Preserve = nil
	cfg.Cleanup = []sgwcconfig.BearerInactivityRuleConfig{{
		BearerType:  "dedicated",
		IdleSeconds: 300,
	}}
	status := bearerinactivity.NewStatus()
	status.RecordScan(now, bearerinactivity.CleanupResult{Planned: 1, Cleaned: 1}, nil)
	reporter := bearerinactivity.Reporter{
		Sessions:  mgr,
		Evaluator: bearerinactivity.NewEvaluator(cfg),
		Status:    status,
		Now:       func() time.Time { return now },
	}

	srv := NewServer("127.0.0.1:0", BuildInfo{Component: "SGW-C", Version: "test"}, slog.New(slog.DiscardHandler))
	RegisterBearerInactivityRoutes(srv.HumaAPI(), reporter)

	var out BearerInactivityOutput
	getJSON(t, srv, "/gtpc/bearer-inactivity", &out.Body)

	if out.Body.Total != 2 || out.Body.Candidates != 1 {
		t.Fatalf("summary = total:%d candidates:%d decisions:%+v", out.Body.Total, out.Body.Candidates, out.Body.Decisions)
	}
	if out.Body.Runtime.Scans != 1 || out.Body.Runtime.Cleaned != 1 {
		t.Fatalf("runtime = %+v; want one clean scan", out.Body.Runtime)
	}
	if out.Body.Actions[string(bearerinactivity.DecisionCleanupDedicatedBearer)] != 1 {
		t.Fatalf("actions = %+v; want one dedicated cleanup candidate", out.Body.Actions)
	}
	found := false
	for _, decision := range out.Body.Decisions {
		if decision.EBI == 7 {
			found = true
			if decision.Action != string(bearerinactivity.DecisionCleanupDedicatedBearer) ||
				decision.Reason != "bearer-inactivity-cleanup-dedicated-idle-300" ||
				decision.IdleThresholdSeconds != 300 ||
				decision.IdleForSeconds != 600 {
				t.Fatalf("decision for EBI 7 = %+v", decision)
			}
		}
	}
	if !found {
		t.Fatal("missing decision for EBI 7")
	}
}

func TestSGWCRoutesExposeBearerActivityFields(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	at := time.Unix(99, 0).UTC()
	b := sess.GetBearer(5)
	b.SGWS1UFTEID = bearer.FTEID{TEID: 0x11111111, IPv4: netip.MustParseAddr("10.0.0.1")}
	sess.SetBearer(b)
	b = sess.GetBearer(5)
	b.LastControlActivityAt = at
	b.LastUserPlaneActivityAt = at.Add(time.Second)
	b.LastActivitySource = "pfcp-usage-report"
	b.InactiveSince = at.Add(2 * time.Second)
	b.CleanupEligible = true

	srv := newTestSGWCAPI(m)
	var out SessionGetOutput
	getJSON(t, srv, "/sessions/"+sess.SessionID, &out.Body)

	if len(out.Body.Bearers) != 1 {
		t.Fatalf("bearers = %d; want 1", len(out.Body.Bearers))
	}
	got := out.Body.Bearers[0]
	if !got.LastControlActivityAt.Equal(at) ||
		!got.LastUserPlaneActivityAt.Equal(at.Add(time.Second)) ||
		got.LastActivitySource != "pfcp-usage-report" ||
		!got.InactiveSince.Equal(at.Add(2*time.Second)) ||
		!got.CleanupEligible {
		t.Fatalf("bearer activity view = %+v", got)
	}
}
