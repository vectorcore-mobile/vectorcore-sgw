package peerhealth

import (
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
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

type recordingHandler struct {
	stateChanges []StateChangeEvent
	restarts     []RestartEvent
}

func (h *recordingHandler) OnPeerStateChange(event StateChangeEvent) {
	h.stateChanges = append(h.stateChanges, event)
}

func (h *recordingHandler) OnPeerRestart(event RestartEvent) {
	h.restarts = append(h.restarts, event)
}

func TestEventHandlerReceivesStateChangeAfterEchoTimeout(t *testing.T) {
	tbl := testTable()
	rec := &recordingHandler{}
	tbl.SetEventHandler(rec)

	tbl.ObserveAddr(RolePGW, "192.0.2.10:2123", 33, 1, nil)
	tbl.MarkEchoTimeout(RolePGW, "192.0.2.10:30200", 2, ProbeConfig{
		SuspectAfterMissed: 2,
		DownAfterMissed:    3,
	})

	if len(rec.stateChanges) != 2 {
		t.Fatalf("state change events = %d; want observe and timeout events", len(rec.stateChanges))
	}
	got := rec.stateChanges[1]
	if got.Role != RolePGW || got.Addr != "192.0.2.10:2123" ||
		got.OldState != StateUp || got.NewState != StateDegraded || got.Reason != "echo_timeout" {
		t.Fatalf("timeout event = %+v; want PGW up->degraded echo_timeout", got)
	}
}

func TestEventHandlerReceivesRestartEvent(t *testing.T) {
	tbl := testTable()
	rec := &recordingHandler{}
	tbl.SetEventHandler(rec)
	first := uint8(3)
	next := uint8(4)

	tbl.ObserveAddr(RolePGW, "192.0.2.10:2123", 33, 1, &first)
	tbl.ObserveAddr(RolePGW, "192.0.2.10:2123", 33, 2, &next)

	if len(rec.restarts) != 1 {
		t.Fatalf("restart events = %d; want 1", len(rec.restarts))
	}
	got := rec.restarts[0]
	if got.Role != RolePGW || got.Addr != "192.0.2.10:2123" ||
		got.OldRecovery != 3 || got.NewRecovery != 4 {
		t.Fatalf("restart event = %+v; want Recovery 3->4", got)
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

func TestCheckpointSinkReceivesRecoverySnapshot(t *testing.T) {
	tbl := testTable()
	sink := &peerCheckpointRecorder{}
	tbl.SetCheckpointSink(sink)
	rec := uint8(9)

	tbl.ObserveAddr(RoleMME, "10.90.250.77:30200", 32, 1, &rec)

	if len(sink.snapshots) != 1 {
		t.Fatalf("checkpoint snapshots = %d; want 1", len(sink.snapshots))
	}
	got := sink.snapshots[0]
	if got.Role != "mme" || got.Addr != "10.90.250.77:2123" || got.RecoveryCounter != 9 {
		t.Fatalf("checkpoint snapshot = %+v; want MME normalized recovery 9", got)
	}
}

func TestRestoreCheckpointSnapshotSeedsRecoveryWithoutRestartEvent(t *testing.T) {
	tbl := testTable()
	recorder := &recordingHandler{}
	tbl.SetEventHandler(recorder)
	restored := tbl.RestoreCheckpointSnapshots([]sessioncheckpoint.PeerSnapshot{{
		Role:            "pgw",
		Addr:            "192.0.2.10:2123",
		State:           "up",
		RecoverySeen:    true,
		RecoveryCounter: 3,
		UpdatedAt:       time.Unix(100, 0).UTC(),
	}})
	if restored != 1 {
		t.Fatalf("restored = %d; want 1", restored)
	}
	if len(recorder.restarts) != 0 {
		t.Fatalf("restart events during restore = %d; want 0", len(recorder.restarts))
	}

	next := uint8(4)
	tbl.ObserveAddr(RolePGW, "192.0.2.10:2123", 33, 2, &next)
	if len(recorder.restarts) != 1 {
		t.Fatalf("restart events after Recovery change = %d; want 1", len(recorder.restarts))
	}
	if recorder.restarts[0].OldRecovery != 3 || recorder.restarts[0].NewRecovery != 4 {
		t.Fatalf("restart = %+v; want 3->4", recorder.restarts[0])
	}
}

type peerCheckpointRecorder struct {
	snapshots []sessioncheckpoint.PeerSnapshot
}

func (r *peerCheckpointRecorder) SavePeerSnapshot(snapshot sessioncheckpoint.PeerSnapshot) {
	r.snapshots = append(r.snapshots, snapshot)
}
