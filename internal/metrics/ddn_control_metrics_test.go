package metrics

import (
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/ddncontrol"
)

func TestDDNControlMetricsExportsSnapshot(t *testing.T) {
	reg := prometheus.NewRegistry()
	state := ddncontrol.NewState(ddncontrol.Config{
		Enabled:                  true,
		PerMMERateLimitPerSecond: 10,
		PerMMEBurst:              20,
		HighPriorityBypass:       true,
		HighPriority:             []ddncontrol.PriorityRule{{APN: "ims"}},
		LowPriority:              []ddncontrol.PriorityRule{{APN: "internet", QCI: 9}},
	})
	at := time.Unix(100, 0).UTC()
	state.RecordSent(ddncontrol.Candidate{
		MMEAddr:     "10.1.1.1:2123",
		IMSI:        "311430000000001",
		APN:         "ims",
		EBI:         6,
		QCI:         1,
		ARPPriority: 1,
	}, ddncontrol.PriorityHigh, at)
	state.RecordSuppressed(ddncontrol.Candidate{
		MMEAddr:     "10.1.1.1:2123",
		IMSI:        "311430000000002",
		APN:         "internet",
		EBI:         5,
		QCI:         9,
		ARPPriority: 9,
	}, ddncontrol.PriorityLow, at)
	state.MarkMMELowPriorityThrottled("10.1.1.1:2123", "ddn-ack-low-priority-throttling", at.Add(30*time.Second), at)

	NewDDNControlMetrics(reg, state)

	sentMetric := findMetricWithLabels(t, reg, "sgwc_ddn_control_sent_total", map[string]string{
		"mme": "10.1.1.1:2123",
	})
	if got := sentMetric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("sent total = %v; want 1", got)
	}

	suppressedMetric := findMetricWithLabels(t, reg, "sgwc_ddn_control_suppressed_total", map[string]string{
		"mme": "10.1.1.1:2123",
	})
	if got := suppressedMetric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("suppressed total = %v; want 1", got)
	}

	throttleMetric := findMetricWithLabels(t, reg, "sgwc_ddn_control_low_priority_throttle_active", map[string]string{
		"mme":    "10.1.1.1:2123",
		"reason": "ddn-ack-low-priority-throttling",
	})
	if got := throttleMetric.GetGauge().GetValue(); got != 1 {
		t.Fatalf("low-priority throttle active = %v; want 1", got)
	}

	ueSentMetric := findMetricWithLabels(t, reg, "sgwc_ddn_control_ue_sent_total", map[string]string{
		"imsi":     "311430000000001",
		"mme":      "10.1.1.1:2123",
		"apn":      "ims",
		"priority": "high",
	})
	if got := ueSentMetric.GetCounter().GetValue(); got != 1 {
		t.Fatalf("UE sent total = %v; want 1", got)
	}
}
