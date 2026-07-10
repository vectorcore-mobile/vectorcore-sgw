package metrics

import (
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/bearerinactivity"
	"vectorcore-sgw/internal/sgwc/session"
)

func TestBearerInactivityMetricsExportDecisionsAndRuntime(t *testing.T) {
	reg := prometheus.NewRegistry()
	now := time.Unix(1000, 0).UTC()
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:             "311430000000001",
		APN:              "internet",
		RATType:          6,
		ServingNetwork:   "311-435",
		MMEControlFTEID:  session.FTEID{TEID: 1, IPv4: netip.MustParseAddr("10.0.0.1")},
		DefaultEBI:       5,
		QCI:              9,
		ARP:              bearer.ARP{PriorityLevel: 9},
		ReuseSGWS11FTEID: session.FTEID{TEID: 2, IPv4: netip.MustParseAddr("10.0.0.2")},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
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
	NewBearerInactivityMetrics(reg, reporter)

	decisionMetric := findMetricWithLabels(t, reg, "sgwc_bearer_inactivity_decisions", map[string]string{
		"action": string(bearerinactivity.DecisionCleanupDedicatedBearer),
	})
	if got := decisionMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("cleanup decision metric = %v; want 1", got)
	}
	if got := findMetricWithLabels(t, reg, "sgwc_bearer_inactivity_scans_total", nil).GetCounter().GetValue(); got != 1 {
		t.Fatalf("scan counter = %v; want 1", got)
	}
	if got := findMetricWithLabels(t, reg, "sgwc_bearer_inactivity_cleaned_total", nil).GetCounter().GetValue(); got != 1 {
		t.Fatalf("cleaned counter = %v; want 1", got)
	}
}
