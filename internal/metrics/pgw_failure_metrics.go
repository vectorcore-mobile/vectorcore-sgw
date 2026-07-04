package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/pgwfailure"
	"vectorcore-sgw/internal/sgwc/session"
)

type PGWFailureReader interface {
	Snapshot() []pgwfailure.Snapshot
}

type PGWFailureMetrics struct {
	failures PGWFailureReader

	state            *prometheus.Desc
	affectedSessions *prometheus.Desc
	restarts         *prometheus.Desc
	pathDownEvents   *prometheus.Desc
}

func NewPGWFailureMetrics(reg *prometheus.Registry, failures PGWFailureReader) *PGWFailureMetrics {
	m := &PGWFailureMetrics{
		failures: failures,
		state: prometheus.NewDesc(
			"sgwc_pgw_path_state",
			"SGW-C PGW path state as a one-hot gauge.",
			[]string{"pgw", "state"},
			nil,
		),
		affectedSessions: prometheus.NewDesc(
			"sgwc_pgw_affected_sessions",
			"Current number of SGW-C sessions affected by PGW path or restart state.",
			[]string{"pgw"},
			nil,
		),
		restarts: prometheus.NewDesc(
			"sgwc_pgw_restarts_total",
			"Total PGW Recovery IE restart counter changes handled by SGW-C.",
			[]string{"pgw"},
			nil,
		),
		pathDownEvents: prometheus.NewDesc(
			"sgwc_pgw_path_down_total",
			"Total PGW path-down state transitions handled by SGW-C.",
			[]string{"pgw"},
			nil,
		),
	}
	if reg != nil {
		reg.MustRegister(m)
	}
	return m
}

func (m *PGWFailureMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.state
	ch <- m.affectedSessions
	ch <- m.restarts
	ch <- m.pathDownEvents
}

func (m *PGWFailureMetrics) Collect(ch chan<- prometheus.Metric) {
	if m == nil || m.failures == nil {
		return
	}
	for _, snap := range m.failures.Snapshot() {
		for _, state := range []session.PGWPathState{
			session.PGWPathStateUnknown,
			session.PGWPathStateUp,
			session.PGWPathStateDegraded,
			session.PGWPathStateSuspect,
			session.PGWPathStateDown,
			session.PGWPathStateRestarted,
		} {
			value := 0.0
			if snap.State == state {
				value = 1
			}
			ch <- prometheus.MustNewConstMetric(m.state, prometheus.GaugeValue, value, snap.PGWAddr, string(state))
		}
		ch <- prometheus.MustNewConstMetric(m.affectedSessions, prometheus.GaugeValue, float64(snap.AffectedSessions), snap.PGWAddr)
		ch <- prometheus.MustNewConstMetric(m.restarts, prometheus.CounterValue, float64(snap.Restarts), snap.PGWAddr)
		ch <- prometheus.MustNewConstMetric(m.pathDownEvents, prometheus.CounterValue, float64(snap.PathDownEvents), snap.PGWAddr)
	}
}
