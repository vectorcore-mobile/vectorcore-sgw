package metrics

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/pgwfailure"
	"vectorcore-sgw/internal/sgwc/session"
)

func TestPGWFailureMetricsExportsSnapshot(t *testing.T) {
	reg := prometheus.NewRegistry()
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311430000000001",
		APN:            "internet",
		RATType:        6,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0xAABBCCDD,
			IPv4: netip.MustParseAddr("10.1.1.1"),
		},
		DefaultEBI:  5,
		QCI:         9,
		ARP:         bearer.ARP{PriorityLevel: 9},
		MBRUplink:   256000,
		MBRDownlink: 256000,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mgr.RegisterPGW(sess.SessionID, "10.90.250.92:30064")
	handler := pgwfailure.NewHandler(mgr, pgwfailure.Config{
		Enabled:                true,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RolePGW,
		Addr:     "10.90.250.92:2123",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		Reason:   "echo_timeout",
		At:       time.Unix(30, 0).UTC(),
	})

	NewPGWFailureMetrics(reg, handler)

	stateMetric := findMetricWithLabels(t, reg, "sgwc_pgw_path_state", map[string]string{
		"pgw":   "10.90.250.92:2123",
		"state": "down",
	})
	if got := stateMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("down state gauge = %v; want 1", got)
	}

	affectedMetric := findMetricWithLabels(t, reg, "sgwc_pgw_affected_sessions", map[string]string{
		"pgw": "10.90.250.92:2123",
	})
	if got := affectedMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("affected sessions = %v; want 1", got)
	}

	downMetric := findMetricWithLabels(t, reg, "sgwc_pgw_path_down_total", map[string]string{
		"pgw": "10.90.250.92:2123",
	})
	if got := downMetric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("path down events = %v; want 1", got)
	}
}
