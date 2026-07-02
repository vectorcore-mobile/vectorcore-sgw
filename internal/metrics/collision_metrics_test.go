package metrics

import (
	"testing"

	"vectorcore-sgw/internal/sgwc/collision"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

func TestCollisionMetricsExportsRejections(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewCollisionMetrics(reg)

	m.OnDecision(
		collision.ActiveProcedure{Procedure: collision.ProcedureDeleteSession},
		collision.Request{Procedure: collision.ProcedureUpdateBearer, Owner: collision.OwnerPGW},
		collision.Decision{Action: collision.ActionRejectNew, Policy: collision.PolicySessionOverlap},
	)

	metric := findMetric(t, reg, "sgwc_gtpv2c_collision_rejections_total")
	if got := metric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("collision rejection counter = %v, want 1", got)
	}
	assertLabel(t, metric, "action", string(collision.ActionRejectNew))
	assertLabel(t, metric, "policy", string(collision.PolicySessionOverlap))
	assertLabel(t, metric, "active_procedure", string(collision.ProcedureDeleteSession))
	assertLabel(t, metric, "new_procedure", string(collision.ProcedureUpdateBearer))
	assertLabel(t, metric, "owner", string(collision.OwnerPGW))
}

func TestCollisionMetricsExportsStaleExpirations(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewCollisionMetrics(reg)

	m.OnStaleExpired(collision.Request{Procedure: collision.ProcedureModifyBearer}, 3)

	metric := findMetric(t, reg, "sgwc_gtpv2c_collision_stale_expired_total")
	if got := metric.GetCounter().GetValue(); got != 3 {
		t.Fatalf("stale expiration counter = %v, want 3", got)
	}
	assertLabel(t, metric, "new_procedure", string(collision.ProcedureModifyBearer))
}

func findMetric(t *testing.T, reg *prometheus.Registry, name string) *dto.Metric {
	t.Helper()
	families, err := reg.Gather()
	if err != nil {
		t.Fatalf("Gather: %v", err)
	}
	for _, family := range families {
		if family.GetName() == name && len(family.Metric) > 0 {
			return family.Metric[0]
		}
	}
	t.Fatalf("metric %q not found in gathered families", name)
	return nil
}

func assertLabel(t *testing.T, metric *dto.Metric, name, want string) {
	t.Helper()
	for _, label := range metric.Label {
		if label.GetName() == name {
			if label.GetValue() != want {
				t.Fatalf("label %q = %q, want %q", name, label.GetValue(), want)
			}
			return
		}
	}
	t.Fatalf("label %q not found", name)
}
