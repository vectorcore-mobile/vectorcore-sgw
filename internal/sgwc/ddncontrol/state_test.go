package ddncontrol

import (
	"testing"
	"time"
)

func TestClassifyPreservesPriorityOrder(t *testing.T) {
	state := NewState(Config{
		HighPriority: []PriorityRule{{APN: "ims", Reason: "ims-priority"}},
		LowPriority:  []PriorityRule{{QCI: 1, Reason: "low-qci-one"}},
	})

	priority, reason := state.Classify(Candidate{APN: "IMS", QCI: 1})
	if priority != PriorityHigh || reason != "ims-priority" {
		t.Fatalf("Classify = %s/%q; want high/ims-priority", priority, reason)
	}
}

func TestClassifyMatchesARPRange(t *testing.T) {
	state := NewState(Config{
		HighPriority: []PriorityRule{{ARPPriorityMin: 1, ARPPriorityMax: 3, Reason: "high-arp"}},
	})

	priority, reason := state.Classify(Candidate{ARPPriority: 2})
	if priority != PriorityHigh || reason != "high-arp" {
		t.Fatalf("Classify = %s/%q; want high/high-arp", priority, reason)
	}

	priority, reason = state.Classify(Candidate{ARPPriority: 9})
	if priority != PriorityNormal || reason != "default-normal" {
		t.Fatalf("Classify = %s/%q; want normal/default-normal", priority, reason)
	}
}

func TestRecordSentCreatesMMEAndUEState(t *testing.T) {
	at := time.Unix(100, 0).UTC()
	state := NewState(Config{
		PerMMERateLimitPerSecond: 50,
		PerMMEBurst:              100,
		HighPriorityBypass:       true,
	})

	state.RecordSent(Candidate{
		MMEAddr:     "10.90.250.77:2123",
		IMSI:        "311435300070599",
		APN:         "ims",
		EBI:         6,
		QCI:         1,
		ARPPriority: 1,
	}, PriorityHigh, at)

	snap := state.Snapshot()
	if len(snap.MMEs) != 1 || len(snap.UEs) != 1 {
		t.Fatalf("snapshot sizes = mme:%d ue:%d; want 1/1", len(snap.MMEs), len(snap.UEs))
	}
	if got := snap.MMEs[0]; got.Sent != 1 || got.HighPriorityBypassed != 1 || got.Tokens != 100 ||
		got.Burst != 100 || got.RateLimitPerSecond != 50 || !got.LastRefillAt.Equal(at) {
		t.Fatalf("MME state = %+v; want sent/high-priority/tokens initialized", got)
	}
	if got := snap.UEs[0]; got.Sent != 1 || got.LastPriority != PriorityHigh || got.LastEBI != 6 ||
		got.LastAPN != "ims" || !got.LastDDNAt.Equal(at) {
		t.Fatalf("UE state = %+v; want sent high-priority IMS EBI 6", got)
	}
}

func TestMarkMMELowPriorityThrottled(t *testing.T) {
	at := time.Unix(200, 0).UTC()
	until := time.Unix(260, 0).UTC()
	state := NewState(Config{PerMMEBurst: 10, PerMMERateLimitPerSecond: 5})

	state.MarkMMELowPriorityThrottled("10.90.250.77:2123", "mme-ddn-ack", until, at)

	snap := state.Snapshot()
	if len(snap.MMEs) != 1 {
		t.Fatalf("MME states = %d; want 1", len(snap.MMEs))
	}
	got := snap.MMEs[0]
	if got.LowPriorityThrottleReason != "mme-ddn-ack" ||
		!got.LowPriorityThrottledUntil.Equal(until) ||
		!got.LowPriorityThrottleReceived.Equal(at) {
		t.Fatalf("MME throttle state = %+v; want reason/until/received", got)
	}
}

func TestDecideSendConsumesTokenAndRefills(t *testing.T) {
	at := time.Unix(300, 0).UTC()
	state := NewState(Config{
		Enabled:                  true,
		PerMMERateLimitPerSecond: 2,
		PerMMEBurst:              2,
	})
	candidate := Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00101", APN: "internet", EBI: 5, QCI: 9}

	first := state.Decide(candidate, at)
	if first.Action != ActionSendNow || first.TokensBefore != 2 || first.TokensAfter != 1 {
		t.Fatalf("first decision = %+v; want send token 2->1", first)
	}
	second := state.Decide(candidate, at.Add(100*time.Millisecond))
	if second.Action != ActionSendNow || second.TokensBefore != 1 || second.TokensAfter != 0 {
		t.Fatalf("second decision = %+v; want send token 1->0", second)
	}
	third := state.Decide(candidate, at.Add(600*time.Millisecond))
	if third.Action != ActionSendNow || third.TokensBefore != 1 || third.TokensAfter != 0 {
		t.Fatalf("third decision = %+v; want refill one token and send", third)
	}
}

func TestDecideDelaysWhenPerMMEBucketEmpty(t *testing.T) {
	at := time.Unix(400, 0).UTC()
	state := NewState(Config{
		Enabled:                  true,
		PerMMERateLimitPerSecond: 4,
		PerMMEBurst:              1,
	})
	candidate := Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00101", APN: "internet", EBI: 5, QCI: 9}

	_ = state.Decide(candidate, at)
	decision := state.Decide(Candidate{MMEAddr: candidate.MMEAddr, IMSI: "00102", APN: "internet", EBI: 5, QCI: 9}, at.Add(10*time.Millisecond))
	if decision.Action != ActionDelay || decision.Reason != "per-mme-rate-limit" || decision.RetryAfter != 250*time.Millisecond {
		t.Fatalf("decision = %+v; want delay for rate limit with 250ms retry", decision)
	}
	snap := state.Snapshot()
	if snap.MMEs[0].Delayed != 1 {
		t.Fatalf("MME delayed count = %d; want 1", snap.MMEs[0].Delayed)
	}
}

func TestDecideHighPriorityBypassesEmptyBucket(t *testing.T) {
	at := time.Unix(500, 0).UTC()
	state := NewState(Config{
		Enabled:                  true,
		PerMMERateLimitPerSecond: 1,
		PerMMEBurst:              1,
		HighPriorityBypass:       true,
		HighPriority:             []PriorityRule{{APN: "ims", Reason: "ims"}},
	})

	_ = state.Decide(Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00101", APN: "internet", EBI: 5, QCI: 9}, at)
	decision := state.Decide(Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00102", APN: "ims", EBI: 6, QCI: 1}, at.Add(10*time.Millisecond))
	if decision.Action != ActionSendNow || !decision.Bypass || decision.Reason != "high-priority-bypass" {
		t.Fatalf("decision = %+v; want high-priority bypass send", decision)
	}
	snap := state.Snapshot()
	if snap.MMEs[0].HighPriorityBypassed != 1 || snap.MMEs[0].Sent != 2 {
		t.Fatalf("MME state = %+v; want one bypass and two sends", snap.MMEs[0])
	}
}

func TestDecideSuppressesDuplicateLowPriorityUE(t *testing.T) {
	at := time.Unix(600, 0).UTC()
	state := NewState(Config{
		Enabled:                  true,
		PerMMERateLimitPerSecond: 10,
		PerMMEBurst:              10,
		PerUESuppression:         10 * time.Second,
		LowPriority:              []PriorityRule{{APN: "internet", QCI: 9}},
	})
	candidate := Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00101", APN: "internet", EBI: 5, QCI: 9}

	_ = state.Decide(candidate, at)
	decision := state.Decide(candidate, at.Add(3*time.Second))
	if decision.Action != ActionSuppress || decision.Reason != "per-ue-suppression" || decision.RetryAfter != 7*time.Second {
		t.Fatalf("decision = %+v; want per-UE suppression with 7s retry", decision)
	}
	snap := state.Snapshot()
	if snap.UEs[0].Suppressed != 1 || snap.UEs[0].Sent != 1 {
		t.Fatalf("UE state = %+v; want one send and one suppression", snap.UEs[0])
	}
}

func TestDecideDoesNotSuppressDuplicateHighPriorityUE(t *testing.T) {
	at := time.Unix(700, 0).UTC()
	state := NewState(Config{
		Enabled:                  true,
		PerMMERateLimitPerSecond: 10,
		PerMMEBurst:              10,
		PerUESuppression:         10 * time.Second,
		HighPriority:             []PriorityRule{{APN: "ims"}},
	})
	candidate := Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00101", APN: "ims", EBI: 6, QCI: 1}

	_ = state.Decide(candidate, at)
	decision := state.Decide(candidate, at.Add(3*time.Second))
	if decision.Action != ActionSendNow || decision.Priority != PriorityHigh {
		t.Fatalf("decision = %+v; want duplicate high-priority send", decision)
	}
}

func TestDecideSuppressesLowPriorityDuringMMEThrottle(t *testing.T) {
	at := time.Unix(800, 0).UTC()
	state := NewState(Config{
		Enabled:                       true,
		PerMMERateLimitPerSecond:      10,
		PerMMEBurst:                   10,
		HonorMMELowPriorityThrottling: true,
		LowPriority:                   []PriorityRule{{APN: "internet", QCI: 9}},
	})
	state.MarkMMELowPriorityThrottled("10.90.250.77:2123", "mme-ddn-ack", at.Add(30*time.Second), at)

	decision := state.Decide(Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00101", APN: "internet", EBI: 5, QCI: 9}, at.Add(5*time.Second))
	if decision.Action != ActionSuppress || decision.Reason != "mme-low-priority-throttling" || decision.RetryAfter != 25*time.Second {
		t.Fatalf("decision = %+v; want MME low-priority throttle suppression", decision)
	}
}

func TestDecideDisabledAllowsAndRecordsSent(t *testing.T) {
	at := time.Unix(900, 0).UTC()
	state := NewState(Config{Enabled: false, PerMMEBurst: 1, PerMMERateLimitPerSecond: 1})

	decision := state.Decide(Candidate{MMEAddr: "10.90.250.77:2123", IMSI: "00101"}, at)
	if decision.Action != ActionSendNow || decision.Reason != "ddn-control-disabled" {
		t.Fatalf("decision = %+v; want disabled send", decision)
	}
	snap := state.Snapshot()
	if snap.MMEs[0].Sent != 1 || snap.UEs[0].Sent != 1 {
		t.Fatalf("snapshot = %+v; want disabled path recorded as sent", snap)
	}
}
