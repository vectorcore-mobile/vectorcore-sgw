package metrics

import (
	"vectorcore-sgw/internal/sgwc/collision"

	"github.com/prometheus/client_golang/prometheus"
)

// CollisionMetrics exposes SGW-C GTPv2-C transaction collision KPIs.
type CollisionMetrics struct {
	rejections   *prometheus.CounterVec
	staleExpired *prometheus.CounterVec
}

// NewCollisionMetrics creates and registers GTPv2-C collision metrics.
func NewCollisionMetrics(reg *prometheus.Registry) *CollisionMetrics {
	rejections := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sgwc_gtpv2c_collision_rejections_total",
		Help: "Total SGW-C GTPv2-C transaction collision rejections.",
	}, []string{"action", "policy", "active_procedure", "new_procedure", "owner"})

	staleExpired := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sgwc_gtpv2c_collision_stale_expired_total",
		Help: "Total stale SGW-C GTPv2-C active procedure records expired before a new decision.",
	}, []string{"new_procedure"})

	reg.MustRegister(rejections, staleExpired)
	return &CollisionMetrics{
		rejections:   rejections,
		staleExpired: staleExpired,
	}
}

// OnDecision records a rejected transaction collision policy decision.
func (m *CollisionMetrics) OnDecision(active collision.ActiveProcedure, req collision.Request, decision collision.Decision) {
	if m == nil {
		return
	}
	m.rejections.WithLabelValues(
		string(decision.Action),
		string(decision.Policy),
		string(active.Procedure),
		string(req.Procedure),
		string(req.Owner),
	).Inc()
}

// OnStaleExpired records active procedure records expired before a new decision.
func (m *CollisionMetrics) OnStaleExpired(req collision.Request, expired int) {
	if m == nil || expired <= 0 {
		return
	}
	m.staleExpired.WithLabelValues(string(req.Procedure)).Add(float64(expired))
}
