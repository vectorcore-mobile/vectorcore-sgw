package metrics

import (
	"strconv"

	"github.com/prometheus/client_golang/prometheus"
)

// NSAMetrics exposes Rel-15 NSA/DCNR Secondary RAT usage report KPIs.
type NSAMetrics struct {
	captured  *prometheus.CounterVec
	forwarded *prometheus.CounterVec
}

// NewNSAMetrics creates and registers NSA/DCNR metrics.
func NewNSAMetrics(reg *prometheus.Registry) *NSAMetrics {
	captured := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sgwc_nsa_secondary_rat_usage_reports_captured_total",
		Help: "Total Rel-15 Secondary RAT Usage Data Report IEs captured on S11.",
	}, []string{"apn", "source_procedure"})

	forwarded := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "sgwc_nsa_secondary_rat_usage_reports_forwarded_total",
		Help: "Total Rel-15 Secondary RAT Usage Data Report IEs forwarded on S5/S8-C.",
	}, []string{"apn", "cause"})

	reg.MustRegister(captured, forwarded)
	return &NSAMetrics{captured: captured, forwarded: forwarded}
}

// OnSecondaryRATUsageReportsCaptured records S11 report capture.
func (m *NSAMetrics) OnSecondaryRATUsageReportsCaptured(apn, sourceProcedure string, count int) {
	if m == nil || count <= 0 {
		return
	}
	m.captured.WithLabelValues(apn, sourceProcedure).Add(float64(count))
}

// OnSecondaryRATUsageReportsForwarded records S5/S8-C report forwarding.
func (m *NSAMetrics) OnSecondaryRATUsageReportsForwarded(apn string, cause uint8, count int) {
	if m == nil || count <= 0 {
		return
	}
	m.forwarded.WithLabelValues(apn, causeLabel(cause)).Add(float64(count))
}

func causeLabel(cause uint8) string {
	if cause == 0 {
		return "none"
	}
	return strconv.Itoa(int(cause))
}
