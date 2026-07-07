package mmerestoration

import (
	"context"
	"errors"
	"log/slog"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/session"
)

type fakeS5CDeleter struct {
	calls int
	cause uint8
	err   error
}

func (f *fakeS5CDeleter) DeleteSession(context.Context, *session.SGWSession) (uint8, error) {
	f.calls++
	if f.cause == 0 {
		f.cause = ie.CauseRequestAccepted
	}
	return f.cause, f.err
}

type fakePFCPDeleter struct {
	calls    int
	peerAddr string
	cpSEID   uint64
	upSEID   uint64
	err      error
}

func (f *fakePFCPDeleter) DeleteSessionOnPeer(_ context.Context, peerAddr string, cpSEID, upSEID uint64) error {
	f.calls++
	f.peerAddr = peerAddr
	f.cpSEID = cpSEID
	f.upSEID = upSEID
	return f.err
}

type fakeDDNSender struct {
	calls    int
	sessions []*session.SGWSession
	seq      uint32
	err      error
}

func (f *fakeDDNSender) SendDownlinkDataNotification(_ context.Context, sess *session.SGWSession) (uint32, error) {
	f.calls++
	f.sessions = append(f.sessions, sess)
	if f.seq == 0 {
		f.seq = 0x100
	}
	seq := f.seq
	f.seq++
	return seq, f.err
}

func testSessionParams(imsi, mmeIP string) session.CreateParams {
	return session.CreateParams{
		IMSI:           imsi,
		APN:            "internet",
		RATType:        6,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0xAABBCCDD,
			IPv4: netip.MustParseAddr(mmeIP),
		},
		DefaultEBI:  5,
		QCI:         9,
		ARP:         bearer.ARP{PriorityLevel: 9},
		MBRUplink:   256000,
		MBRDownlink: 256000,
	}
}

func testSessionParamsWithPolicyFields(imsi, mmeIP, apn string, qci, arpPriority uint8) session.CreateParams {
	params := testSessionParams(imsi, mmeIP)
	params.APN = apn
	params.QCI = qci
	params.ARP = bearer.ARP{PriorityLevel: arpPriority}
	return params
}

func TestHandlerMarksOnlyAffectedMMESessionsOnRestart(t *testing.T) {
	mgr := session.NewManager()
	first, _, err := mgr.Create(testSessionParams("311430000000001", "10.90.250.77"))
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	second, _, err := mgr.Create(testSessionParams("311430000000002", "10.90.250.78"))
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	handler := NewHandler(mgr, Config{Enabled: true, MarkSessionsOnRestart: true}, slog.New(slog.DiscardHandler))

	at := time.Unix(1700, 0).UTC()
	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 24,
		NewRecovery: 25,
		At:          at,
	})

	firstStatus := first.MMERestorationSnapshot()
	if firstStatus.State != session.MMERestorationStateRestorationPending ||
		!firstStatus.RestorationPending ||
		!firstStatus.RecoverySeen ||
		firstStatus.RecoveryCounter != 25 ||
		firstStatus.MMEAddr != "10.90.250.77:2123" ||
		!firstStatus.RestartDetectedAt.Equal(at) {
		t.Fatalf("affected MME restoration status = %+v; want restoration pending recovery 25", firstStatus)
	}
	secondStatus := second.MMERestorationSnapshot()
	if secondStatus.State != "" && secondStatus.State != session.MMERestorationStateUnknown {
		t.Fatalf("unaffected MME restoration status = %+v; want unchanged", secondStatus)
	}
}

func TestHandlerMarksMMEPathDownAndUp(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParams("311430000000001", "10.90.250.77"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	handler := NewHandler(mgr, Config{Enabled: true, MarkSessionsOnPathDown: true}, slog.New(slog.DiscardHandler))

	downAt := time.Unix(1800, 0).UTC()
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RoleMME,
		Addr:     "10.90.250.77:30032",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		Reason:   "echo_timeout",
		At:       downAt,
	})
	status := sess.MMERestorationSnapshot()
	if status.State != session.MMERestorationStateDown ||
		status.MMEAddr != "10.90.250.77:2123" ||
		!status.PathDownAt.Equal(downAt) {
		t.Fatalf("down status = %+v; want down on canonical MME", status)
	}

	upAt := time.Unix(1900, 0).UTC()
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RoleMME,
		Addr:     "10.90.250.77:2123",
		OldState: peerhealth.StateDown,
		NewState: peerhealth.StateUp,
		Reason:   "echo_response",
		At:       upAt,
	})
	status = sess.MMERestorationSnapshot()
	if status.State != session.MMERestorationStateUp || !status.PathDownAt.IsZero() {
		t.Fatalf("up status = %+v; want up with cleared PathDownAt", status)
	}
}

func TestHandlerPathUpDoesNotClearRestartPending(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParams("311430000000001", "10.90.250.77"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	handler := NewHandler(mgr, Config{
		Enabled:                true,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 10,
		NewRecovery: 11,
		At:          time.Unix(1950, 0).UTC(),
	})
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RoleMME,
		Addr:     "10.90.250.77:2123",
		OldState: peerhealth.StateSuspect,
		NewState: peerhealth.StateUp,
		Reason:   "echo_response",
		At:       time.Unix(1960, 0).UTC(),
	})

	status := sess.MMERestorationSnapshot()
	if !status.RestorationPending || !status.RecoverySeen || status.RecoveryCounter != 11 {
		t.Fatalf("status after path up = %+v; want restart restoration still pending", status)
	}
}

func TestHandlerIgnoresPGWEventsAndDisabledConfig(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParams("311430000000001", "10.90.250.77"))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	handler := NewHandler(mgr, Config{
		Enabled:                true,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RolePGW,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2000, 0).UTC(),
	})
	if status := sess.MMERestorationSnapshot(); status.RecoverySeen {
		t.Fatalf("status after PGW event = %+v; want unchanged", status)
	}

	disabled := NewHandler(mgr, Config{Enabled: false, MarkSessionsOnRestart: true}, slog.New(slog.DiscardHandler))
	disabled.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2100, 0).UTC(),
	})
	if status := sess.MMERestorationSnapshot(); status.RecoverySeen {
		t.Fatalf("status with disabled handler = %+v; want unchanged", status)
	}
}

func TestHandlerAppliesRestorationPolicyOnRestart(t *testing.T) {
	mgr := session.NewManager()
	ims, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000001", "10.90.250.77", "ims", 5, 1))
	if err != nil {
		t.Fatalf("Create IMS: %v", err)
	}
	internet, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000002", "10.90.250.77", "internet", 9, 9))
	if err != nil {
		t.Fatalf("Create internet: %v", err)
	}
	handler := NewHandler(mgr, Config{
		Enabled:               true,
		MarkSessionsOnRestart: true,
		DefaultAction:         session.MMERestorationPolicyPreserve,
		Preserve:              []PolicyRule{{APN: "ims", Reason: "preserve-ims"}},
		Delete:                []PolicyRule{{APN: "internet", QCI: 9, Reason: "delete-low-priority-internet"}},
	}, slog.New(slog.DiscardHandler))

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2200, 0).UTC(),
	})

	imsStatus := ims.MMERestorationSnapshot()
	if imsStatus.PolicyAction != session.MMERestorationPolicyPreserve ||
		imsStatus.PolicyReason != "preserve-ims" ||
		!imsStatus.RestorationPending {
		t.Fatalf("IMS status = %+v; want preserve policy with restoration pending", imsStatus)
	}
	internetStatus := internet.MMERestorationSnapshot()
	if internetStatus.PolicyAction != session.MMERestorationPolicyDelete ||
		internetStatus.PolicyReason != "delete-low-priority-internet" ||
		!internetStatus.RestorationPending {
		t.Fatalf("internet status = %+v; want delete policy with restoration pending", internetStatus)
	}
	if internet.GetState() == session.StateDeleted || internet.BearerCount() == 0 {
		t.Fatalf("Phase 3 must not enforce delete policy yet; state=%s bearers=%d", internet.GetState(), internet.BearerCount())
	}
}

func TestHandlerPreserveRuleWinsBeforeDeleteRule(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000001", "10.90.250.77", "ims", 9, 9))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	handler := NewHandler(mgr, Config{
		Enabled:               true,
		MarkSessionsOnRestart: true,
		Preserve:              []PolicyRule{{APN: "ims", Reason: "preserve-ims"}},
		Delete:                []PolicyRule{{QCI: 9, Reason: "delete-qci-9"}},
	}, slog.New(slog.DiscardHandler))

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2300, 0).UTC(),
	})

	status := sess.MMERestorationSnapshot()
	if status.PolicyAction != session.MMERestorationPolicyPreserve || status.PolicyReason != "preserve-ims" {
		t.Fatalf("status = %+v; want preserve rule to win before delete rule", status)
	}
}

func TestHandlerEnforcesDeletePolicyThroughPGWPFCPAndLocalCleanup(t *testing.T) {
	mgr := session.NewManager()
	ims, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000001", "10.90.250.77", "ims", 5, 1))
	if err != nil {
		t.Fatalf("Create IMS: %v", err)
	}
	internet, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000002", "10.90.250.77", "internet", 9, 9))
	if err != nil {
		t.Fatalf("Create internet: %v", err)
	}
	internet.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 101, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 202, IPv4: netip.MustParseAddr("10.90.250.11")},
		SGWUAddr:    "10.90.250.11:8805",
		Established: true,
	}
	s5c := &fakeS5CDeleter{cause: ie.CauseRequestAccepted}
	pfcp := &fakePFCPDeleter{}
	handler := NewHandlerWithCleanup(mgr, Config{
		Enabled:               true,
		MarkSessionsOnRestart: true,
		EnforceDeletePolicy:   true,
		CleanupTimeout:        time.Second,
		Preserve:              []PolicyRule{{APN: "ims", Reason: "preserve-ims"}},
		Delete:                []PolicyRule{{APN: "internet", QCI: 9, Reason: "delete-low-priority-internet"}},
	}, s5c, pfcp, slog.New(slog.DiscardHandler))

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2400, 0).UTC(),
	})

	if mgr.Find(ims.SessionID) != ims {
		t.Fatal("preserved IMS session was removed")
	}
	if mgr.Find(internet.SessionID) != nil {
		t.Fatal("delete-policy internet session still present after enforcement")
	}
	if s5c.calls != 1 {
		t.Fatalf("S5-C DeleteSession calls = %d; want 1", s5c.calls)
	}
	if pfcp.calls != 1 || pfcp.peerAddr != "10.90.250.11:8805" || pfcp.cpSEID != 101 || pfcp.upSEID != 202 {
		t.Fatalf("PFCP delete = calls:%d peer:%s cp:%d up:%d; want one delete for internet session",
			pfcp.calls, pfcp.peerAddr, pfcp.cpSEID, pfcp.upSEID)
	}
}

func TestHandlerRetainsDeletePolicySessionWhenPGWDeleteFails(t *testing.T) {
	mgr := session.NewManager()
	internet, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000001", "10.90.250.77", "internet", 9, 9))
	if err != nil {
		t.Fatalf("Create internet: %v", err)
	}
	s5c := &fakeS5CDeleter{err: errors.New("timeout")}
	pfcp := &fakePFCPDeleter{}
	handler := NewHandlerWithCleanup(mgr, Config{
		Enabled:               true,
		MarkSessionsOnRestart: true,
		EnforceDeletePolicy:   true,
		CleanupTimeout:        time.Second,
		Delete:                []PolicyRule{{APN: "internet", QCI: 9, Reason: "delete-low-priority-internet"}},
	}, s5c, pfcp, slog.New(slog.DiscardHandler))

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2500, 0).UTC(),
	})

	if mgr.Find(internet.SessionID) != internet {
		t.Fatal("session was removed despite PGW delete failure")
	}
	if pfcp.calls != 0 {
		t.Fatalf("PFCP delete calls = %d; want 0 when PGW delete fails", pfcp.calls)
	}
	status := internet.MMERestorationSnapshot()
	if status.PolicyAction != session.MMERestorationPolicyDelete || !strings.Contains(status.PolicyReason, "enforcement failed") {
		t.Fatalf("status after failed enforcement = %+v; want delete with failure reason", status)
	}
}

func TestHandlerTriggersDDNForPreservedSessionsOnly(t *testing.T) {
	mgr := session.NewManager()
	ims, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000001", "10.90.250.77", "ims", 5, 1))
	if err != nil {
		t.Fatalf("Create IMS: %v", err)
	}
	internet, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000002", "10.90.250.77", "internet", 9, 9))
	if err != nil {
		t.Fatalf("Create internet: %v", err)
	}
	ddn := &fakeDDNSender{seq: 0x1200}
	handler := NewHandlerWithCleanup(mgr, Config{
		Enabled:               true,
		MarkSessionsOnRestart: true,
		TriggerDDN:            true,
		Preserve:              []PolicyRule{{APN: "ims", Reason: "preserve-ims"}},
		Delete:                []PolicyRule{{APN: "internet", QCI: 9, Reason: "delete-low-priority-internet"}},
	}, nil, nil, slog.New(slog.DiscardHandler))
	handler.SetDDNSender(ddn)

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2600, 0).UTC(),
	})

	if ddn.calls != 1 || len(ddn.sessions) != 1 || ddn.sessions[0] != ims {
		t.Fatalf("DDN calls = %d sessions=%v; want one DDN for IMS only", ddn.calls, ddn.sessions)
	}
	imsStatus := ims.MMERestorationSnapshot()
	if !imsStatus.DDNTriggered || imsStatus.DDNSequence != 0x1200 || !imsStatus.DDNTriggeredAt.Equal(time.Unix(2600, 0).UTC()) {
		t.Fatalf("IMS DDN status = %+v; want triggered seq 0x1200", imsStatus)
	}
	internetStatus := internet.MMERestorationSnapshot()
	if internetStatus.DDNTriggered {
		t.Fatalf("internet DDN status = %+v; delete-policy session must not receive DDN", internetStatus)
	}
}

func TestHandlerRecordsDDNFailureForPreservedSession(t *testing.T) {
	mgr := session.NewManager()
	ims, _, err := mgr.Create(testSessionParamsWithPolicyFields("311430000000001", "10.90.250.77", "ims", 5, 1))
	if err != nil {
		t.Fatalf("Create IMS: %v", err)
	}
	ddn := &fakeDDNSender{err: errors.New("send failed")}
	handler := NewHandlerWithCleanup(mgr, Config{
		Enabled:               true,
		MarkSessionsOnRestart: true,
		TriggerDDN:            true,
		Preserve:              []PolicyRule{{APN: "ims", Reason: "preserve-ims"}},
	}, nil, nil, slog.New(slog.DiscardHandler))
	handler.SetDDNSender(ddn)

	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.90.250.77:2123",
		OldRecovery: 1,
		NewRecovery: 2,
		At:          time.Unix(2700, 0).UTC(),
	})

	status := ims.MMERestorationSnapshot()
	if status.DDNTriggered || !strings.Contains(status.DDNFailureReason, "send failed") {
		t.Fatalf("IMS DDN status = %+v; want failure reason without triggered flag", status)
	}
}
