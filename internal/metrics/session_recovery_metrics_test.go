package metrics

import (
	"net/netip"
	"testing"

	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

func TestSessionRecoveryMetricsExportStatusAndSessionSummary(t *testing.T) {
	reg := prometheus.NewRegistry()
	status := sessioncheckpoint.NewStatusTracker(sessioncheckpoint.RuntimeConfig{
		Enabled:          true,
		Backend:          sessioncheckpoint.BackendSQLite,
		RestoreOnStartup: true,
	})
	status.RecordSessionRestore(2, 1, 0, 1, 1)
	status.RecordPeerSnapshotsLoaded(3)
	status.RecordGTPCPeersRestored(2)
	status.RecordPFCPPeersRestored(1)

	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:             "311430000000001",
		APN:              "ims",
		RATType:          6,
		ServingNetwork:   "311-435",
		MMEControlFTEID:  session.FTEID{TEID: 1, IPv4: netip.MustParseAddr("10.0.0.1")},
		DefaultEBI:       6,
		QCI:              5,
		ARP:              bearer.ARP{PriorityLevel: 1},
		ReuseSGWS11FTEID: session.FTEID{TEID: 2, IPv4: netip.MustParseAddr("10.0.0.2")},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMissing, "missing", sess.UpdatedAt)

	NewSessionRecoveryMetrics(reg, status, mgr)

	if got := findMetricWithLabels(t, reg, "sgwc_checkpoint_enabled", nil).GetGauge().GetValue(); got != 1 {
		t.Fatalf("checkpoint enabled = %v; want 1", got)
	}
	if got := findMetricWithLabels(t, reg, "sgwc_checkpoint_sessions_restored", nil).GetGauge().GetValue(); got != 1 {
		t.Fatalf("sessions restored = %v; want 1", got)
	}
	if got := findMetricWithLabels(t, reg, "sgwc_checkpoint_gtpc_peers_restored", nil).GetGauge().GetValue(); got != 2 {
		t.Fatalf("GTP-C peers restored = %v; want 2", got)
	}
	stateMetric := findMetricWithLabels(t, reg, "sgwc_recovery_sessions", map[string]string{"state": string(session.StateRecovering)})
	if got := stateMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("recovering sessions metric = %v; want 1", got)
	}
	reconcileMetric := findMetricWithLabels(t, reg, "sgwc_pfcp_reconciliation_sessions", map[string]string{"state": string(session.PFCPReconciliationMissing)})
	if got := reconcileMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("missing reconciliation metric = %v; want 1", got)
	}
}
