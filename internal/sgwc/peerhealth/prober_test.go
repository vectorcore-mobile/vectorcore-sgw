package peerhealth

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestProberMarksEchoResponse(t *testing.T) {
	tbl := testTable()
	tbl.ObserveAddr(RolePGW, "192.0.2.10:2123", 33, 1, nil)
	rec := uint8(4)
	prober := NewProber(tbl, ProberConfig{
		Enabled:            true,
		EchoInterval:       time.Hour,
		EchoTimeout:        time.Second,
		DownAfterMissed:    3,
		SuspectAfterMissed: 2,
		DegradedRTT:        500 * time.Millisecond,
		ProbePGWPeers:      true,
	}, func(context.Context, Target, uint32) (*EchoResult, error) {
		return &EchoResult{RTT: 10 * time.Millisecond, Recovery: &rec}, nil
	}, nil, func(Target) uint32 { return 7 })

	prober.probeOnce(context.Background())

	got := tbl.Snapshot()[0]
	if got.EchoSent != 1 || got.EchoResponses != 1 || got.EchoTimeouts != 0 {
		t.Fatalf("echo counters sent=%d responses=%d timeouts=%d; want 1/1/0", got.EchoSent, got.EchoResponses, got.EchoTimeouts)
	}
	if got.State != StateUp {
		t.Fatalf("state = %s; want up", got.State)
	}
	if !got.RecoverySeen || got.RecoveryCounter != 4 {
		t.Fatalf("recovery seen=%v counter=%d; want true/4", got.RecoverySeen, got.RecoveryCounter)
	}
}

func TestProberMarksTimeoutStates(t *testing.T) {
	tbl := testTable()
	tbl.ObserveAddr(RoleMME, "10.90.250.77:2123", 32, 1, nil)
	prober := NewProber(tbl, ProberConfig{
		Enabled:            true,
		EchoInterval:       time.Hour,
		EchoTimeout:        time.Second,
		DownAfterMissed:    3,
		SuspectAfterMissed: 2,
		DegradedRTT:        500 * time.Millisecond,
		ProbeMMEPeers:      true,
	}, func(context.Context, Target, uint32) (*EchoResult, error) {
		return nil, errors.New("timeout")
	}, nil, func(Target) uint32 { return 7 })

	prober.probeOnce(context.Background())
	if got := tbl.Snapshot()[0]; got.State != StateDegraded || got.ConsecutiveMisses != 1 {
		t.Fatalf("after first miss state=%s misses=%d; want degraded/1", got.State, got.ConsecutiveMisses)
	}
	prober.probeOnce(context.Background())
	if got := tbl.Snapshot()[0]; got.State != StateSuspect || got.ConsecutiveMisses != 2 {
		t.Fatalf("after second miss state=%s misses=%d; want suspect/2", got.State, got.ConsecutiveMisses)
	}
	prober.probeOnce(context.Background())
	if got := tbl.Snapshot()[0]; got.State != StateDown || got.ConsecutiveMisses != 3 {
		t.Fatalf("after third miss state=%s misses=%d; want down/3", got.State, got.ConsecutiveMisses)
	}
}
