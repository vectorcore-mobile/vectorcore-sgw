package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/ddncontrol"
)

type DDNControlReader interface {
	Snapshot() ddncontrol.Snapshot
}

type DDNControlMetrics struct {
	control DDNControlReader

	tokens               *prometheus.Desc
	sent                 *prometheus.Desc
	delayed              *prometheus.Desc
	suppressed           *prometheus.Desc
	highPriorityBypassed *prometheus.Desc
	lowPriorityThrottle  *prometheus.Desc
	ueSent               *prometheus.Desc
	ueDelayed            *prometheus.Desc
	ueSuppressed         *prometheus.Desc
}

func NewDDNControlMetrics(reg *prometheus.Registry, control DDNControlReader) *DDNControlMetrics {
	m := &DDNControlMetrics{
		control: control,
		tokens: prometheus.NewDesc(
			"sgwc_ddn_control_tokens",
			"Current per-MME DDN control token count.",
			[]string{"mme"},
			nil,
		),
		sent: prometheus.NewDesc(
			"sgwc_ddn_control_sent_total",
			"Total DDN sends allowed by DDN control per MME.",
			[]string{"mme"},
			nil,
		),
		delayed: prometheus.NewDesc(
			"sgwc_ddn_control_delayed_total",
			"Total DDN delay decisions per MME.",
			[]string{"mme"},
			nil,
		),
		suppressed: prometheus.NewDesc(
			"sgwc_ddn_control_suppressed_total",
			"Total DDN suppress decisions per MME.",
			[]string{"mme"},
			nil,
		),
		highPriorityBypassed: prometheus.NewDesc(
			"sgwc_ddn_control_high_priority_bypassed_total",
			"Total high-priority DDN bypass sends per MME.",
			[]string{"mme"},
			nil,
		),
		lowPriorityThrottle: prometheus.NewDesc(
			"sgwc_ddn_control_low_priority_throttle_active",
			"Whether MME low-priority DDN throttling is currently active.",
			[]string{"mme", "reason"},
			nil,
		),
		ueSent: prometheus.NewDesc(
			"sgwc_ddn_control_ue_sent_total",
			"Total DDN sends allowed by DDN control per UE.",
			[]string{"imsi", "mme", "apn", "priority"},
			nil,
		),
		ueDelayed: prometheus.NewDesc(
			"sgwc_ddn_control_ue_delayed_total",
			"Total DDN delay decisions per UE.",
			[]string{"imsi", "mme", "apn", "priority"},
			nil,
		),
		ueSuppressed: prometheus.NewDesc(
			"sgwc_ddn_control_ue_suppressed_total",
			"Total DDN suppress decisions per UE.",
			[]string{"imsi", "mme", "apn", "priority"},
			nil,
		),
	}
	if reg != nil {
		reg.MustRegister(m)
	}
	return m
}

func (m *DDNControlMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.tokens
	ch <- m.sent
	ch <- m.delayed
	ch <- m.suppressed
	ch <- m.highPriorityBypassed
	ch <- m.lowPriorityThrottle
	ch <- m.ueSent
	ch <- m.ueDelayed
	ch <- m.ueSuppressed
}

func (m *DDNControlMetrics) Collect(ch chan<- prometheus.Metric) {
	if m == nil || m.control == nil {
		return
	}
	snap := m.control.Snapshot()
	for _, mme := range snap.MMEs {
		ch <- prometheus.MustNewConstMetric(m.tokens, prometheus.GaugeValue, float64(mme.Tokens), mme.MMEAddr)
		ch <- prometheus.MustNewConstMetric(m.sent, prometheus.CounterValue, float64(mme.Sent), mme.MMEAddr)
		ch <- prometheus.MustNewConstMetric(m.delayed, prometheus.CounterValue, float64(mme.Delayed), mme.MMEAddr)
		ch <- prometheus.MustNewConstMetric(m.suppressed, prometheus.CounterValue, float64(mme.Suppressed), mme.MMEAddr)
		ch <- prometheus.MustNewConstMetric(m.highPriorityBypassed, prometheus.CounterValue, float64(mme.HighPriorityBypassed), mme.MMEAddr)
		active := 0.0
		if !mme.LowPriorityThrottledUntil.IsZero() {
			active = 1
		}
		ch <- prometheus.MustNewConstMetric(m.lowPriorityThrottle, prometheus.GaugeValue, active, mme.MMEAddr, mme.LowPriorityThrottleReason)
	}
	for _, ue := range snap.UEs {
		priority := string(ue.LastPriority)
		ch <- prometheus.MustNewConstMetric(m.ueSent, prometheus.CounterValue, float64(ue.Sent), ue.IMSI, ue.LastMMEAddr, ue.LastAPN, priority)
		ch <- prometheus.MustNewConstMetric(m.ueDelayed, prometheus.CounterValue, float64(ue.Delayed), ue.IMSI, ue.LastMMEAddr, ue.LastAPN, priority)
		ch <- prometheus.MustNewConstMetric(m.ueSuppressed, prometheus.CounterValue, float64(ue.Suppressed), ue.IMSI, ue.LastMMEAddr, ue.LastAPN, priority)
	}
}
