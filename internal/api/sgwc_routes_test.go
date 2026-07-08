package api

import (
	"log/slog"
	"net/netip"
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/ddncontrol"
	"vectorcore-sgw/internal/sgwc/mmerestoration"
	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/pgwfailure"
	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

func newTestSGWCAPI(sessions *session.Manager) *Server {
	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))
	RegisterSGWCRoutes(srv.HumaAPI(), sessions)
	return srv
}

func defaultSGWCSessionParams() session.CreateParams {
	return session.CreateParams{
		IMSI:           "311430000000001",
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

func TestSGWCRoutesExposeRecoveringPFCPState(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 0x1111, IPv4: netip.MustParseAddr("192.0.2.11")},
		SGWUFSEID:   session.FSEID{SEID: 0x2222, IPv4: netip.MustParseAddr("192.0.2.12")},
		SGWUName:    "sgwu-a",
		SGWUAddr:    "192.0.2.12:8805",
		Established: true,
	}
	if got := m.InvalidatePFCPBindings(); got != 1 {
		t.Fatalf("InvalidatePFCPBindings = %d; want 1", got)
	}

	srv := newTestSGWCAPI(m)
	var out SessionGetOutput
	getJSON(t, srv, "/sessions/"+sess.SessionID, &out.Body)

	if out.Body.State != string(session.StateRecovering) {
		t.Fatalf("state = %q; want %q", out.Body.State, session.StateRecovering)
	}
	if out.Body.PFCPState != "stale" {
		t.Fatalf("pfcp_state = %q; want stale", out.Body.PFCPState)
	}
	if out.Body.PFCPLocalSEID != "0x0000000000000000" || out.Body.PFCPUPSEID != "0x0000000000000000" {
		t.Fatalf("PFCP SEIDs = %s/%s; want cleared SEIDs", out.Body.PFCPLocalSEID, out.Body.PFCPUPSEID)
	}
}

func TestSGWCRoutesExposePFCPPeerPlacement(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 0x1111, IPv4: netip.MustParseAddr("192.0.2.11")},
		SGWUFSEID:   session.FSEID{SEID: 0x2222, IPv4: netip.MustParseAddr("192.0.2.12")},
		SGWUName:    "sgwu-a",
		SGWUAddr:    "192.0.2.12:8805",
		Established: true,
	}

	srv := newTestSGWCAPI(m)
	var out SessionGetOutput
	getJSON(t, srv, "/sessions/"+sess.SessionID, &out.Body)

	if out.Body.PFCPState != "established" {
		t.Fatalf("pfcp_state = %q; want established", out.Body.PFCPState)
	}
	if out.Body.PFCPSGWUName != "sgwu-a" || out.Body.PFCPSGWUAddr != "192.0.2.12:8805" {
		t.Fatalf("PFCP peer = %q/%q; want sgwu-a/192.0.2.12:8805",
			out.Body.PFCPSGWUName, out.Body.PFCPSGWUAddr)
	}
}

func TestSGWCRoutesExposeSecondaryRATUsageReports(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.RecordSecondaryRATUsageDataReports([]session.SecondaryRATUsageDataReport{{
		ReceivedAt:      time.Unix(10, 0).UTC(),
		SourceProcedure: "s11_modify_bearer_request",
		MMEPeer:         "10.90.250.77:2123",
		SGWS11TEID:      0x11223344,
		SequenceNumber:  0x010203,
		Payload:         []byte{0x01, 0x02, 0x03, 0x04},
	}})

	srv := newTestSGWCAPI(m)
	var out SessionGetOutput
	getJSON(t, srv, "/sessions/"+sess.SessionID, &out.Body)

	if out.Body.SecondaryRATUsageReportCount != 1 {
		t.Fatalf("secondary report count = %d; want 1", out.Body.SecondaryRATUsageReportCount)
	}
	if len(out.Body.SecondaryRATUsageDataReports) != 1 {
		t.Fatalf("secondary reports len = %d; want 1", len(out.Body.SecondaryRATUsageDataReports))
	}
	got := out.Body.SecondaryRATUsageDataReports[0]
	if got.SourceProcedure != "s11_modify_bearer_request" ||
		got.MMEPeer != "10.90.250.77:2123" ||
		got.SGWS11TEID != "0x11223344" ||
		got.SequenceNumber != "0x010203" ||
		got.PayloadLength != 4 {
		t.Fatalf("secondary report view = %+v", got)
	}
}

func TestSGWCRoutesExposePGWFailureState(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.RegisterPGW(sess.SessionID, "10.90.250.92:30064")
	downAt := time.Unix(20, 0).UTC()
	if got := m.MarkPGWPathState("10.90.250.92:2123", session.PGWPathStateDown, downAt); got != 1 {
		t.Fatalf("MarkPGWPathState = %d; want 1", got)
	}

	srv := newTestSGWCAPI(m)
	var out SessionGetOutput
	getJSON(t, srv, "/sessions/"+sess.SessionID, &out.Body)

	if out.Body.PGWFailure.PathState != "down" ||
		out.Body.PGWFailure.PGWAddr != "10.90.250.92:2123" ||
		!out.Body.PGWFailure.PathDownAt.Equal(downAt) {
		t.Fatalf("PGW failure view = %+v; want down at canonical PGW", out.Body.PGWFailure)
	}
}

func TestSGWCRoutesExposeMMERestorationState(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	at := time.Unix(50, 0).UTC()
	sess.MarkMMERestart("10.1.1.1:2123", 7, at)
	sess.SetMMERestorationPolicy(session.MMERestorationPolicyPreserve, "preserve-ims", at.Add(time.Second))
	sess.MarkMMERestorationDDNTriggered(0x123456, at.Add(2*time.Second))
	sess.MarkMMERestorationDDNControlDecision("send_now", "high", "high-priority-bypass", 0, at.Add(2*time.Second))
	sess.MarkMMERestorationDDNAck(16, at.Add(3*time.Second))
	sess.MarkMMERestorationUserPlaneRestored(5, at.Add(4*time.Second))

	srv := newTestSGWCAPI(m)
	var out SessionGetOutput
	getJSON(t, srv, "/sessions/"+sess.SessionID, &out.Body)

	got := out.Body.MMERestoration
	if got.State != "up" ||
		got.MMEAddr != "10.1.1.1:2123" ||
		got.RestorationPending ||
		got.PolicyAction != "preserve" ||
		got.PolicyReason != "preserve-ims" ||
		!got.DDNTriggered ||
		got.DDNSequence != "0x123456" ||
		!got.DDNAcked ||
		got.DDNAckCause != 16 ||
		got.DDNControlAction != "send_now" ||
		got.DDNControlPriority != "high" ||
		got.DDNControlReason != "high-priority-bypass" ||
		!got.UserPlaneRestored ||
		got.RestoredEBI != 5 {
		t.Fatalf("MME restoration view = %+v; want completed preserved restoration", got)
	}
}

func TestSGWCRoutesExposeDefaultAndDedicatedBearerDetails(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defaultBearer := sess.GetBearer(5)
	defaultBearer.State = bearer.BearerStateActive
	defaultBearer.SGWS1UFTEID = bearer.FTEID{TEID: 0x11111111, IPv4: netip.MustParseAddr("10.0.0.1")}
	defaultBearer.SGWS5UFTEID = bearer.FTEID{TEID: 0x22222222, IPv4: netip.MustParseAddr("10.0.0.2")}
	defaultBearer.PDRIDs = [2]uint32{1, 2}
	defaultBearer.FARIDs = [2]uint32{1, 2}
	sess.SetBearer(defaultBearer)
	sess.SetBearer(&bearer.Bearer{
		EBI:         6,
		QCI:         5,
		ARP:         bearer.ARP{PriorityLevel: 2, PreemptionCapability: true, PreemptionVulnerability: false},
		State:       bearer.BearerStateActive,
		ENBS1UFTEID: bearer.FTEID{TEID: 0x33333333, IPv4: netip.MustParseAddr("10.0.0.3")},
		SGWS1UFTEID: bearer.FTEID{TEID: 0x44444444, IPv4: netip.MustParseAddr("10.0.0.4")},
		PGWS5UFTEID: bearer.FTEID{TEID: 0x55555555, IPv4: netip.MustParseAddr("10.0.0.5")},
		SGWS5UFTEID: bearer.FTEID{TEID: 0x66666666, IPv4: netip.MustParseAddr("10.0.0.6")},
		TFT:         &bearer.TFT{Raw: []byte{0x21, 0x01, 0x02}},
		PDRIDs:      [2]uint32{3, 4},
		FARIDs:      [2]uint32{3, 4},
	})

	srv := newTestSGWCAPI(m)
	var out SessionGetOutput
	getJSON(t, srv, "/sessions/"+sess.SessionID, &out.Body)

	if out.Body.BearerCount != 2 || len(out.Body.Bearers) != 2 {
		t.Fatalf("bearers = count %d len %d; want 2", out.Body.BearerCount, len(out.Body.Bearers))
	}
	if out.Body.Bearers[0].EBI != 5 || out.Body.Bearers[0].Type != "default" {
		t.Fatalf("first bearer = %+v; want default EBI 5", out.Body.Bearers[0])
	}
	dedicated := out.Body.Bearers[1]
	if dedicated.EBI != 6 || dedicated.Type != "dedicated" || dedicated.QCI != 5 ||
		dedicated.ARPPriorityLevel != 2 || !dedicated.ARPPreemptionCapability ||
		dedicated.UplinkPDRID != 3 || dedicated.DownlinkPDRID != 4 ||
		dedicated.UplinkFARID != 3 || dedicated.DownlinkFARID != 4 {
		t.Fatalf("dedicated bearer view = %+v; want QoS and PDR/FAR details", dedicated)
	}
}

func TestRecoveryRoutesExposeCheckpointAndSessionSummary(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.MarkPFCPReconciliation(session.PFCPReconciliationMissing, "sgwu-session-not-found", time.Unix(80, 0).UTC())
	status := sessioncheckpoint.NewStatusTracker(sessioncheckpoint.RuntimeConfig{
		Enabled:                   true,
		Backend:                   sessioncheckpoint.BackendSQLite,
		SQLitePath:                "/tmp/sgwc-state.db",
		RestoreOnStartup:          true,
		ReconcileOnStartup:        true,
		CheckpointIntervalSeconds: 5,
	})
	status.RecordSessionRestore(2, 1, 0, 1, 1)
	status.RecordPeerSnapshotsLoaded(3)
	status.RecordGTPCPeersRestored(2)
	status.RecordPFCPPeersRestored(1)

	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))
	RegisterRecoveryRoutes(srv.HumaAPI(), status, m)

	var out RecoveryStatusOutput
	getJSON(t, srv, "/recovery/status", &out.Body)

	if !out.Body.Checkpoint.Enabled ||
		out.Body.Checkpoint.Backend != sessioncheckpoint.BackendSQLite ||
		out.Body.Checkpoint.SessionsLoaded != 2 ||
		out.Body.Checkpoint.SessionsRestored != 1 ||
		out.Body.Checkpoint.SessionsSkipped != 1 ||
		out.Body.Checkpoint.GTPCPeersRestored != 2 ||
		out.Body.Checkpoint.PFCPPeersRestored != 1 {
		t.Fatalf("checkpoint status = %+v", out.Body.Checkpoint)
	}
	if out.Body.Summary.TotalSessions != 1 ||
		out.Body.Summary.SessionsByState[string(session.StateRecovering)] != 1 ||
		out.Body.Summary.PFCPReconciliation[string(session.PFCPReconciliationMissing)] != 1 ||
		out.Body.Summary.PFCPRepairPlans[string(session.PFCPRepairReestablishSession)] != 1 {
		t.Fatalf("recovery summary = %+v", out.Body.Summary)
	}
}

func TestMMERestorationRoutesExposeSummary(t *testing.T) {
	m := session.NewManager()
	_, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	handler := mmerestoration.NewHandler(m, mmerestoration.Config{
		Enabled:                true,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RoleMME,
		Addr:     "10.1.1.1:2123",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		Reason:   "echo_timeout",
		At:       time.Unix(60, 0).UTC(),
	})
	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RoleMME,
		Addr:        "10.1.1.1:2123",
		OldRecovery: 6,
		NewRecovery: 7,
		At:          time.Unix(70, 0).UTC(),
	})

	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))
	RegisterMMERestorationRoutes(srv.HumaAPI(), handler)
	var out MMERestorationListOutput
	getJSON(t, srv, "/gtpc/mme-restorations", &out.Body)

	if out.Body.Total != 1 || len(out.Body.MMERestorations) != 1 {
		t.Fatalf("MME restorations = total %d len %d; want 1", out.Body.Total, len(out.Body.MMERestorations))
	}
	got := out.Body.MMERestorations[0]
	if got.MMEAddr != "10.1.1.1:2123" || got.State != "restoration_pending" ||
		got.AffectedSessions != 1 || got.RecoveryCounter != 7 ||
		got.Restarts != 1 || got.PathDownEvents != 1 {
		t.Fatalf("MME restoration summary = %+v; want restarted affected MME", got)
	}
}

func TestDDNControlRoutesExposeSnapshot(t *testing.T) {
	state := ddncontrol.NewState(ddncontrol.Config{
		Enabled:                  true,
		PerMMERateLimitPerSecond: 10,
		PerMMEBurst:              20,
		HighPriorityBypass:       true,
		HighPriority:             []ddncontrol.PriorityRule{{APN: "ims"}},
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
	state.MarkMMELowPriorityThrottled("10.1.1.1:2123", "ddn-ack-low-priority-throttling", at.Add(30*time.Second), at)

	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))
	RegisterDDNControlRoutes(srv.HumaAPI(), state)
	var out DDNControlOutput
	getJSON(t, srv, "/gtpc/ddn-control", &out.Body)

	if out.Body.MMETotal != 1 || out.Body.UETotal != 1 {
		t.Fatalf("DDN control totals = mme:%d ue:%d; want 1/1", out.Body.MMETotal, out.Body.UETotal)
	}
	if got := out.Body.MMEs[0]; got.MMEAddr != "10.1.1.1:2123" || got.Sent != 1 ||
		got.HighPriorityBypassed != 1 || got.LowPriorityThrottleReason != "ddn-ack-low-priority-throttling" {
		t.Fatalf("DDN MME view = %+v; want sent/high-priority/throttle state", got)
	}
	if got := out.Body.UEs[0]; got.IMSI != "311430000000001" || got.LastPriority != "high" || got.LastEBI != 6 || got.Sent != 1 {
		t.Fatalf("DDN UE view = %+v; want high-priority sent UE state", got)
	}
}

func TestPGWFailureRoutesExposeFailureSummary(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultSGWCSessionParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.RegisterPGW(sess.SessionID, "10.90.250.92:30064")
	handler := pgwfailure.NewHandler(m, pgwfailure.Config{
		Enabled:                true,
		MarkSessionsOnPathDown: true,
		MarkSessionsOnRestart:  true,
	}, slog.New(slog.DiscardHandler))
	handler.OnPeerStateChange(peerhealth.StateChangeEvent{
		Role:     peerhealth.RolePGW,
		Addr:     "10.90.250.92:2123",
		OldState: peerhealth.StateUp,
		NewState: peerhealth.StateDown,
		Reason:   "echo_timeout",
		At:       time.Unix(30, 0).UTC(),
	})
	handler.OnPeerRestart(peerhealth.RestartEvent{
		Role:        peerhealth.RolePGW,
		Addr:        "10.90.250.92:2123",
		OldRecovery: 3,
		NewRecovery: 4,
		At:          time.Unix(40, 0).UTC(),
	})

	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))
	RegisterPGWFailureRoutes(srv.HumaAPI(), handler)
	var out PGWFailureListOutput
	getJSON(t, srv, "/gtpc/pgw-failures", &out.Body)

	if out.Body.Total != 1 || len(out.Body.PGWFailures) != 1 {
		t.Fatalf("PGW failures = total %d len %d; want 1", out.Body.Total, len(out.Body.PGWFailures))
	}
	got := out.Body.PGWFailures[0]
	if got.PGWAddr != "10.90.250.92:2123" || got.State != "restarted" ||
		got.AffectedSessions != 1 || got.RecoveryCounter != 4 ||
		got.Restarts != 1 || got.PathDownEvents != 1 {
		t.Fatalf("PGW failure summary = %+v; want restarted affected PGW", got)
	}
}

func TestGTPCPeerRoutesExposePeerHealth(t *testing.T) {
	peers := peerhealth.NewTable(slog.New(slog.DiscardHandler))
	recovery := uint8(3)
	peers.ObserveAddr(peerhealth.RoleMME, "10.90.250.77:2123", 32, 0x010203, &recovery)
	peers.MarkEchoSent(peerhealth.RoleMME, "10.90.250.77:2123", 0x010204)
	peers.MarkEchoResponse(peerhealth.RoleMME, "10.90.250.77:2123", 0x010204, 25*time.Millisecond, &recovery, peerhealth.ProbeConfig{
		SuspectAfterMissed: 2,
		DownAfterMissed:    3,
		DegradedRTT:        500 * time.Millisecond,
	})

	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))
	RegisterGTPCPeerRoutes(srv.HumaAPI(), peers)
	var out GTPCPeerListOutput
	getJSON(t, srv, "/gtpc/peers", &out.Body)

	if out.Body.Total != 1 || len(out.Body.Peers) != 1 {
		t.Fatalf("peer list = total %d len %d; want 1", out.Body.Total, len(out.Body.Peers))
	}
	got := out.Body.Peers[0]
	if got.Role != "mme" || got.Addr != "10.90.250.77:2123" || got.State != "up" {
		t.Fatalf("peer view = %+v; want mme peer up", got)
	}
	if got.LastRTTMS != 25 || got.EchoSent != 1 || got.EchoResponses != 1 || got.EchoTimeouts != 0 {
		t.Fatalf("peer echo stats = %+v; want RTT 25ms sent/response 1/1", got)
	}
	if !got.RecoverySeen || got.RecoveryCounter != 3 {
		t.Fatalf("peer recovery = seen:%v counter:%d; want true/3", got.RecoverySeen, got.RecoveryCounter)
	}
}
