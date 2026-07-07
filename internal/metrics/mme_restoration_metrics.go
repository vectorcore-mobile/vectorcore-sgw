package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/mmerestoration"
	"vectorcore-sgw/internal/sgwc/session"
)

type MMERestorationReader interface {
	Snapshot() []mmerestoration.Snapshot
}

type MMERestorationMetrics struct {
	restorations MMERestorationReader

	state            *prometheus.Desc
	affectedSessions *prometheus.Desc
	restarts         *prometheus.Desc
	pathDownEvents   *prometheus.Desc
}

func NewMMERestorationMetrics(reg *prometheus.Registry, restorations MMERestorationReader) *MMERestorationMetrics {
	m := &MMERestorationMetrics{
		restorations: restorations,
		state: prometheus.NewDesc(
			"sgwc_mme_restoration_state",
			"SGW-C MME restoration state as a one-hot gauge.",
			[]string{"mme", "state"},
			nil,
		),
		affectedSessions: prometheus.NewDesc(
			"sgwc_mme_restoration_affected_sessions",
			"Current number of SGW-C sessions affected by MME restoration state.",
			[]string{"mme"},
			nil,
		),
		restarts: prometheus.NewDesc(
			"sgwc_mme_restarts_total",
			"Total MME Recovery IE restart counter changes handled by SGW-C restoration.",
			[]string{"mme"},
			nil,
		),
		pathDownEvents: prometheus.NewDesc(
			"sgwc_mme_path_down_total",
			"Total MME path-down state transitions handled by SGW-C restoration.",
			[]string{"mme"},
			nil,
		),
	}
	if reg != nil {
		reg.MustRegister(m)
	}
	return m
}

func (m *MMERestorationMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.state
	ch <- m.affectedSessions
	ch <- m.restarts
	ch <- m.pathDownEvents
}

func (m *MMERestorationMetrics) Collect(ch chan<- prometheus.Metric) {
	if m == nil || m.restorations == nil {
		return
	}
	for _, snap := range m.restorations.Snapshot() {
		for _, state := range []session.MMERestorationState{
			session.MMERestorationStateUnknown,
			session.MMERestorationStateUp,
			session.MMERestorationStateDegraded,
			session.MMERestorationStateSuspect,
			session.MMERestorationStateDown,
			session.MMERestorationStateRestarted,
			session.MMERestorationStateRestorationPending,
		} {
			value := 0.0
			if snap.State == state {
				value = 1
			}
			ch <- prometheus.MustNewConstMetric(m.state, prometheus.GaugeValue, value, snap.MMEAddr, string(state))
		}
		ch <- prometheus.MustNewConstMetric(m.affectedSessions, prometheus.GaugeValue, float64(snap.AffectedSessions), snap.MMEAddr)
		ch <- prometheus.MustNewConstMetric(m.restarts, prometheus.CounterValue, float64(snap.Restarts), snap.MMEAddr)
		ch <- prometheus.MustNewConstMetric(m.pathDownEvents, prometheus.CounterValue, float64(snap.PathDownEvents), snap.MMEAddr)
	}
}
