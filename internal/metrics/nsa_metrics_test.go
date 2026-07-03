package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func TestNSAMetricsExportsCapturedReports(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewNSAMetrics(reg)

	m.OnSecondaryRATUsageReportsCaptured("ims.mnc435.mcc311.gprs", "s11_modify_bearer_request", 2)

	metric := findMetric(t, reg, "sgwc_nsa_secondary_rat_usage_reports_captured_total")
	if got := metric.GetCounter().GetValue(); got != 2 {
		t.Fatalf("captured counter = %v, want 2", got)
	}
	assertLabel(t, metric, "apn", "ims.mnc435.mcc311.gprs")
	assertLabel(t, metric, "source_procedure", "s11_modify_bearer_request")
}

func TestNSAMetricsExportsForwardedReports(t *testing.T) {
	reg := prometheus.NewRegistry()
	m := NewNSAMetrics(reg)

	m.OnSecondaryRATUsageReportsForwarded("internet", 16, 1)

	metric := findMetric(t, reg, "sgwc_nsa_secondary_rat_usage_reports_forwarded_total")
	if got := metric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("forwarded counter = %v, want 1", got)
	}
	assertLabel(t, metric, "apn", "internet")
	assertLabel(t, metric, "cause", "16")
}
