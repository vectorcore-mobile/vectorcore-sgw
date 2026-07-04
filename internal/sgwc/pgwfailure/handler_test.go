package pgwfailure

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/session"
)

func testSessionParams(imsi string) session.CreateParams {
	return session.CreateParams{
		IMSI:           imsi,
		APN:            "internet",
		RATType:        6,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0xAABBCCDD,
			IPv4: netip.MustParseAddr("10.1.1.1"),
		},
		DefaultEBI:  5,
		QCI:         9,
		ARP:         bearer.ARP{PriorityLevel: 9},
		MBRUplink:   256000,
		MBRDownlink: 256000,
	}
}

func TestHandlerMarksOnlyAffectedPGWSessions(t *testing.T) {
	mgr := session.NewManager()
	first, _, err := mgr.Create(testSessionParams("311430000000001"))
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	second, _, err := mgr.Create(testSessionParams("311430000000002"))
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	mgr.RegisterPGW(first.SessionID, "10.90.250.92:30064")
	mgr.RegisterPGW(second.SessionID, "10.90.250.93:2123")

	handler := NewHandler(mgr, Config{
		Enabled:                true,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))
	at := time.Unix(1000, 0).UTC()
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RolePGW,
		Addr:     "10.90.250.92:2123",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		Reason:   "echo_timeout",
		At:       at,
	})

	firstStatus := first.PGWFailureSnapshot()
	if firstStatus.PathState != session.PGWPathStateDown || !firstStatus.PathDownAt.Equal(at) {
		t.Fatalf("affected session status = %+v; want down at event time", firstStatus)
	}
	secondStatus := second.PGWFailureSnapshot()
	if secondStatus.PathState != session.PGWPathStateUp {
		t.Fatalf("unaffected session status = %+v; want unchanged up", secondStatus)
	}
}

func TestHandlerMarksPGWRecovery(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParams("311430000000001"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mgr.RegisterPGW(sess.SessionID, "10.90.250.92:2123")
	handler := NewHandler(mgr, Config{Enabled: true, MarkSessionsOnPathDown: true}, slog.New(slog.DiscardHandler))

	downAt := time.Unix(1000, 0).UTC()
	upAt := time.Unix(1100, 0).UTC()
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RolePGW,
		Addr:     "10.90.250.92:2123",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		Reason:   "echo_timeout",
		At:       downAt,
	})
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RolePGW,
		Addr:     "10.90.250.92:2123",
		OldState: peerhealth.StateDown,
		NewState: peerhealth.StateUp,
		Reason:   "echo_response",
		At:       upAt,
	})

	status := sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateUp || !status.PathDownAt.IsZero() {
		t.Fatalf("recovered status = %+v; want up with cleared PathDownAt", status)
	}
}

func TestHandlerMarksPGWRestart(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParams("311430000000001"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mgr.RegisterPGW(sess.SessionID, "10.90.250.92:2123")
	handler := NewHandler(mgr, Config{Enabled: true, MarkSessionsOnRestart: true}, slog.New(slog.DiscardHandler))

	at := time.Unix(1200, 0).UTC()
	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RolePGW,
		Addr:        "10.90.250.92:2123",
		OldRecovery: 11,
		NewRecovery: 12,
		At:          at,
	})

	status := sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateRestarted || !status.RecoverySeen ||
		status.RecoveryCounter != 12 || !status.RestartDetectedAt.Equal(at) {
		t.Fatalf("restart status = %+v; want restarted recovery 12", status)
	}
}

func TestHandlerIgnoresMMEEvents(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParams("311430000000001"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mgr.RegisterPGW(sess.SessionID, "10.90.250.92:2123")
	handler := NewHandler(mgr, Config{
		Enabled:                true,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))

	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RoleMME,
		Addr:     "10.90.250.77:2123",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		At:       time.Unix(1300, 0).UTC(),
	})
	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(1300, 0).UTC(),
	})

	status := sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateUp || status.RecoverySeen {
		t.Fatalf("status after MME events = %+v; want unchanged PGW state", status)
	}
}

func TestHandlerHonorsDisabledConfig(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParams("311430000000001"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	mgr.RegisterPGW(sess.SessionID, "10.90.250.92:2123")
	handler := NewHandler(mgr, Config{
		Enabled:                false,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))

	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RolePGW,
		Addr:     "10.90.250.92:2123",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		At:       time.Unix(1400, 0).UTC(),
	})
	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RolePGW,
		Addr:        "10.90.250.92:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(1400, 0).UTC(),
	})

	status := sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateUp || status.RecoverySeen {
		t.Fatalf("status with disabled handler = %+v; want unchanged PGW state", status)
	}
}
