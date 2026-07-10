package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/bearerinactivity"
)

type BearerInactivityReader interface {
	Snapshot() bearerinactivity.Snapshot
}

type BearerInactivityMetrics struct {
	reader BearerInactivityReader

	decisions    *prometheus.Desc
	scans        *prometheus.Desc
	planned      *prometheus.Desc
	skipped      *prometheus.Desc
	cleaned      *prometheus.Desc
	failed       *prometheus.Desc
	denied       *prometheus.Desc
	missingRules *prometheus.Desc
}

func NewBearerInactivityMetrics(reg *prometheus.Registry, reader BearerInactivityReader) *BearerInactivityMetrics {
	m := &BearerInactivityMetrics{
		reader: reader,
		decisions: prometheus.NewDesc(
			"sgwc_bearer_inactivity_decisions",
			"Current bearer inactivity policy decisions by action.",
			[]string{"action"},
			nil,
		),
		scans: prometheus.NewDesc(
			"sgwc_bearer_inactivity_scans_total",
			"Total bearer inactivity cleanup scans executed.",
			nil,
			nil,
		),
		planned: prometheus.NewDesc(
			"sgwc_bearer_inactivity_planned_total",
			"Total bearer inactivity decisions planned for execution.",
			nil,
			nil,
		),
		skipped: prometheus.NewDesc(
			"sgwc_bearer_inactivity_skipped_total",
			"Total bearer inactivity decisions skipped by execution.",
			nil,
			nil,
		),
		cleaned: prometheus.NewDesc(
			"sgwc_bearer_inactivity_cleaned_total",
			"Total bearer inactivity cleanups completed.",
			nil,
			nil,
		),
		failed: prometheus.NewDesc(
			"sgwc_bearer_inactivity_failed_total",
			"Total bearer inactivity cleanup failures.",
			nil,
			nil,
		),
		denied: prometheus.NewDesc(
			"sgwc_bearer_inactivity_denied_default_total",
			"Total bearer inactivity default bearer cleanup denials.",
			nil,
			nil,
		),
		missingRules: prometheus.NewDesc(
			"sgwc_bearer_inactivity_missing_rules_total",
			"Total bearer inactivity cleanup failures caused by missing PDR/FAR IDs.",
			nil,
			nil,
		),
	}
	if reg != nil {
		reg.MustRegister(m)
	}
	return m
}

func (m *BearerInactivityMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.decisions
	ch <- m.scans
	ch <- m.planned
	ch <- m.skipped
	ch <- m.cleaned
	ch <- m.failed
	ch <- m.denied
	ch <- m.missingRules
}

func (m *BearerInactivityMetrics) Collect(ch chan<- prometheus.Metric) {
	if m == nil || m.reader == nil {
		return
	}
	snap := m.reader.Snapshot()
	for _, action := range bearerInactivityActions() {
		ch <- prometheus.MustNewConstMetric(m.decisions, prometheus.GaugeValue, float64(snap.ActionCounts[action]), string(action))
	}
	runtime := snap.Runtime
	ch <- prometheus.MustNewConstMetric(m.scans, prometheus.CounterValue, float64(runtime.Scans))
	ch <- prometheus.MustNewConstMetric(m.planned, prometheus.CounterValue, float64(runtime.Planned))
	ch <- prometheus.MustNewConstMetric(m.skipped, prometheus.CounterValue, float64(runtime.Skipped))
	ch <- prometheus.MustNewConstMetric(m.cleaned, prometheus.CounterValue, float64(runtime.Cleaned))
	ch <- prometheus.MustNewConstMetric(m.failed, prometheus.CounterValue, float64(runtime.Failed))
	ch <- prometheus.MustNewConstMetric(m.denied, prometheus.CounterValue, float64(runtime.DeniedDefault))
	ch <- prometheus.MustNewConstMetric(m.missingRules, prometheus.CounterValue, float64(runtime.MissingRules))
}

func bearerInactivityActions() []bearerinactivity.DecisionAction {
	return []bearerinactivity.DecisionAction{
		bearerinactivity.DecisionPreserve,
		bearerinactivity.DecisionCleanupDedicatedBearer,
		bearerinactivity.DecisionCleanupDefaultBearer,
		bearerinactivity.DecisionDeferNoActivityEvidence,
		bearerinactivity.DecisionDeferNotIdle,
		bearerinactivity.DecisionDeferRecentControl,
		bearerinactivity.DecisionDeferNoPolicy,
		bearerinactivity.DecisionDenyDefaultBearer,
		bearerinactivity.DecisionDisabled,
	}
}
