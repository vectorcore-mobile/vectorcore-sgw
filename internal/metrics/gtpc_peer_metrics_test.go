package metrics

import (
	"log/slog"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"vectorcore-sgw/internal/sgwc/peerhealth"
)

func TestGTPCPeerMetricsExportsSnapshot(t *testing.T) {
	reg := prometheus.NewRegistry()
	peers := peerhealth.NewTable(slog.New(slog.DiscardHandler))
	peers.ObserveAddr(peerhealth.RolePGW, "192.0.2.10:2123", 33, 1, nil)
	peers.MarkEchoSent(peerhealth.RolePGW, "192.0.2.10:2123", 2)
	peers.MarkEchoTimeout(peerhealth.RolePGW, "192.0.2.10:2123", 2, peerhealth.ProbeConfig{
		SuspectAfterMissed: 2,
		DownAfterMissed:    3,
		DegradedRTT:        500 * time.Millisecond,
	})

	NewGTPCPeerMetrics(reg, peers)

	stateMetric := findMetricWithLabels(t, reg, "sgwc_gtpc_peer_state", map[string]string{
		"role":  "pgw",
		"peer":  "192.0.2.10:2123",
		"state": "degraded",
	})
	if got := stateMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("degraded state gauge = %v; want 1", got)
	}

	timeoutMetric := findMetricWithLabels(t, reg, "sgwc_gtpc_peer_echo_timeouts_total", map[string]string{
		"role": "pgw",
		"peer": "192.0.2.10:2123",
	})
	if got := timeoutMetric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("timeout counter = %v; want 1", got)
	}
}

func findMetricWithLabels(t *testing.T, reg *prometheus.Registry, name string, labels map[string]string) *dto.Metric {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() != name {
			continue
		}
		for _, metric := range family.Metric {
			if metricHasLabels(metric, labels) {
				return metric
			}
		}
	}
	t.Fatalf("metric %q with labels %+v not found", name, labels)
	return nil
}

func metricHasLabels(metric *dto.Metric, labels map[string]string) bool {
	for wantName, wantValue := range labels {
		found := false
		for _, label := range metric.Label {
			if label.GetName() == wantName {
				if label.GetValue() != wantValue {
					return false
				}
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
