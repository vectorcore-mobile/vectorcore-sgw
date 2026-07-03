package peerhealth

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"
)

func testTable() *Table {
	tbl := NewTable(slog.New(slog.NewTextHandler(io.Discard, nil)))
	now := time.Date(2026, 7, 3, 1, 0, 0, 0, time.UTC)
	tbl.now = func() time.Time { return now }
	return tbl
}

func TestObserveCreatesUpPeer(t *testing.T) {
	tbl := testTable()
	rec := uint8(7)
	tbl.Observe(RoleMME, &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}, 32, 0x010203, &rec)

	snaps := tbl.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d; want 1", len(snaps))
	}
	got := snaps[0]
	if got.Role != RoleMME || got.Addr != "10.90.250.77:2123" || got.State != StateUp {
		t.Fatalf("peer = %+v; want MME up at 10.90.250.77:2123", got)
	}
	if !got.RecoverySeen || got.RecoveryCounter != 7 {
		t.Fatalf("recovery = seen:%v counter:%d; want seen:true counter:7", got.RecoverySeen, got.RecoveryCounter)
	}
	if got.Restarts != 0 {
		t.Fatalf("restarts = %d; want 0 on first Recovery IE", got.Restarts)
	}
}

func TestObserveNormalizesGTPControlPeerPort(t *testing.T) {
	tbl := testTable()
	tbl.Observe(RoleMME, &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 30096}, 34, 1, nil)
	tbl.ObserveAddr(RoleMME, "10.90.250.77:30200", 35, 2, nil)

	snaps := tbl.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d; want one canonical peer", len(snaps))
	}
	if got := snaps[0].Addr; got != "10.90.250.77:2123" {
		t.Fatalf("peer addr = %q; want canonical GTP-C endpoint 10.90.250.77:2123", got)
	}
	state, ok := tbl.State(RoleMME, "10.90.250.77:30096")
	if !ok || state != StateUp {
		t.Fatalf("State via transient port = %s ok=%v; want up/true", state, ok)
	}
}

func TestObserveDetectsRecoveryCounterChange(t *testing.T) {
	tbl := testTable()
	first := uint8(3)
	next := uint8(4)
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}

	tbl.Observe(RolePGW, addr, 33, 1, &first)
	tbl.Observe(RolePGW, addr, 35, 2, &first)
	tbl.Observe(RolePGW, addr, 35, 3, &next)

	snaps := tbl.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("snapshots = %d; want 1", len(snaps))
	}
	got := snaps[0]
	if got.RecoveryCounter != 4 {
		t.Fatalf("RecoveryCounter = %d; want 4", got.RecoveryCounter)
	}
	if got.Restarts != 1 {
		t.Fatalf("Restarts = %d; want 1", got.Restarts)
	}
	if got.RestartDetectedAt.IsZero() {
		t.Fatal("RestartDetectedAt is zero; want restart timestamp")
	}
}

func TestStateReturnsCurrentPeerState(t *testing.T) {
	tbl := testTable()
	tbl.ObserveAddr(RolePGW, "192.0.2.10:2123", 33, 1, nil)
	tbl.MarkEchoTimeout(RolePGW, "192.0.2.10:2123", 2, ProbeConfig{
		SuspectAfterMissed: 2,
		DownAfterMissed:    3,
		DegradedRTT:        500 * time.Millisecond,
	})

	state, ok := tbl.State(RolePGW, "192.0.2.10:2123")
	if !ok {
		t.Fatal("State returned ok=false for known peer")
	}
	if state != StateDegraded {
		t.Fatalf("State = %s; want degraded", state)
	}
	if _, ok := tbl.State(RoleMME, "192.0.2.10:2123"); ok {
		t.Fatal("State returned ok=true for unknown role")
	}
}

func TestSnapshotSortedByRoleAndAddr(t *testing.T) {
	tbl := testTable()
	tbl.ObserveAddr(RolePGW, "192.0.2.20:2123", 33, 1, nil)
	tbl.ObserveAddr(RoleMME, "10.90.250.77:2123", 32, 2, nil)
	tbl.ObserveAddr(RolePGW, "192.0.2.10:2123", 33, 3, nil)

	snaps := tbl.Snapshot()
	if len(snaps) != 3 {
		t.Fatalf("snapshots = %d; want 3", len(snaps))
	}
	want := []struct {
		role Role
		addr string
	}{
		{RoleMME, "10.90.250.77:2123"},
		{RolePGW, "192.0.2.10:2123"},
		{RolePGW, "192.0.2.20:2123"},
	}
	for i := range want {
		if snaps[i].Role != want[i].role || snaps[i].Addr != want[i].addr {
			t.Fatalf("snapshot[%d] = %s %s; want %s %s", i, snaps[i].Role, snaps[i].Addr, want[i].role, want[i].addr)
		}
	}
}
