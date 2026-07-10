package s11

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/gtpv2/transport"
	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/collision"
	"vectorcore-sgw/internal/sgwc/ddncontrol"
	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/recovery"
	"vectorcore-sgw/internal/sgwc/s5c"
	"vectorcore-sgw/internal/sgwc/session"
)

type createBearerShapeFixture struct {
	Name          string                `json:"name"`
	Source        string                `json:"source"`
	MessageType   uint8                 `json:"message_type"`
	TEID          uint32                `json:"teid"`
	Sequence      uint32                `json:"sequence"`
	TopLevelOrder []createBearerShapeIE `json:"top_level_order"`
}

type createBearerShapeIE struct {
	Type          uint8                 `json:"type"`
	Name          string                `json:"name"`
	Instance      uint8                 `json:"instance"`
	Length        int                   `json:"length"`
	Value         *uint8                `json:"value,omitempty"`
	Hex           string                `json:"hex,omitempty"`
	InterfaceType *uint8                `json:"interface_type,omitempty"`
	TEID          *uint32               `json:"teid,omitempty"`
	IPv4          string                `json:"ipv4,omitempty"`
	Children      []createBearerShapeIE `json:"children,omitempty"`
}

type fakeGTPCConn struct {
	nextSeq uint32
	sends   [][]byte
	replies [][]byte
	resp    []byte
}

func (f *fakeGTPCConn) AllocSeq() uint32 {
	f.nextSeq++
	return f.nextSeq
}

func (f *fakeGTPCConn) Send(_ context.Context, _ *net.UDPAddr, raw []byte) ([]byte, error) {
	f.sends = append(f.sends, append([]byte(nil), raw...))
	return append([]byte(nil), f.resp...), nil
}

func (f *fakeGTPCConn) Reply(_ *net.UDPAddr, raw []byte) error {
	f.replies = append(f.replies, append([]byte(nil), raw...))
	return nil
}

func (f *fakeGTPCConn) Serve(context.Context) error { return nil }
func (f *fakeGTPCConn) Close() error                { return nil }
func (f *fakeGTPCConn) LocalAddr() net.Addr         { return &net.UDPAddr{} }

func TestSendDownlinkDataNotificationBuildsS11DDN(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP: bearer.ARP{
			PriorityLevel:           1,
			PreemptionCapability:    true,
			PreemptionVulnerability: false,
		},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	h := &Handler{
		conn:    &fakeGTPCConn{},
		localIP: netip.MustParseAddr("10.90.250.10"),
		log:     slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	seq, err := h.SendDownlinkDataNotification(context.Background(), sess)
	if err != nil {
		t.Fatalf("SendDownlinkDataNotification: %v", err)
	}
	if seq != 1 {
		t.Fatalf("DDN seq = %d; want 1", seq)
	}
	raw := h.conn.(*fakeGTPCConn).replies[0]
	ddn, err := message.ParseDownlinkDataNotification(raw)
	if err != nil {
		t.Fatalf("ParseDownlinkDataNotification: %v", err)
	}
	if ddn.TEID != sess.MMEControlFTEID.TEID || ddn.SequenceNumber != seq {
		t.Fatalf("DDN header TEID=0x%08X seq=%d; want TEID=0x%08X seq=%d",
			ddn.TEID, ddn.SequenceNumber, sess.MMEControlFTEID.TEID, seq)
	}
	if ddn.IMSI == nil {
		t.Fatal("DDN IMSI missing")
	}
	if got, err := ddn.IMSI.IMSI(); err != nil || got != sess.IMSI {
		t.Fatalf("DDN IMSI = %q err=%v; want %s", got, err, sess.IMSI)
	}
	if len(ddn.EBIs) != 1 {
		t.Fatalf("DDN EBI count = %d; want 1", len(ddn.EBIs))
	}
	if got, err := ddn.EBIs[0].EBIValue(); err != nil || got != sess.DefaultBearerID {
		t.Fatalf("DDN EBI = %d err=%v; want %d", got, err, sess.DefaultBearerID)
	}
	if ddn.ARP == nil || len(ddn.ARP.Value) != 1 || ddn.ARP.Value[0] != 0x44 {
		t.Fatalf("DDN ARP = %#v; want value 0x44", ddn.ARP)
	}
	if ddn.SenderFTEID == nil {
		t.Fatal("DDN Sender F-TEID missing")
	}
	fteid, err := ddn.SenderFTEID.FTEIDValue()
	if err != nil {
		t.Fatalf("DDN Sender F-TEID decode: %v", err)
	}
	if fteid.IntfType != ie.IFTypeS11S4SGW || fteid.TEID != sess.SGWS11FTEID.TEID || fteid.IPv4.String() != "10.90.250.10" {
		t.Fatalf("DDN Sender F-TEID = %+v; want S11/S4 SGW TEID 0x%08X IP 10.90.250.10",
			fteid, sess.SGWS11FTEID.TEID)
	}
}

func TestHandleDownlinkDataNotificationAckMarksRestorationSession(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	const ddnSeq uint32 = 0x1234
	sess.MarkMMERestorationDDNTriggered(ddnSeq, time.Unix(10, 0).UTC())
	h := &Handler{sessions: mgr, log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	ddn := &message.DownlinkDataNotification{Header: message.Header{SequenceNumber: ddnSeq}}
	raw, err := message.MarshalDownlinkDataNotificationAck(ddn, sess.SGWS11FTEID.TEID, ie.CauseRequestAccepted)
	if err != nil {
		t.Fatalf("Marshal DDN Ack: %v", err)
	}

	h.handleDownlinkDataNotificationAck(&net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}, raw)

	status := sess.MMERestorationSnapshot()
	if !status.DDNAcked || status.DDNAckCause != ie.CauseRequestAccepted {
		t.Fatalf("DDN status = %+v; want acked cause accepted", status)
	}
}

func TestHandleDownlinkDataNotificationAckDoesNotStopPagingByDefault(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	const ddnSeq uint32 = 0x1234
	sess.MarkMMERestart("10.90.250.77:2123", 2, time.Unix(9, 0).UTC())
	sess.SetMMERestorationPolicy(session.MMERestorationPolicyPreserve, "preserve-ims", time.Unix(9, 0).UTC())
	sess.MarkMMERestorationDDNTriggered(ddnSeq, time.Unix(10, 0).UTC())
	conn := &fakeGTPCConn{}
	h := &Handler{cfg: sgwcconfig.Default(), conn: conn, sessions: mgr, log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	ddn := &message.DownlinkDataNotification{Header: message.Header{SequenceNumber: ddnSeq}}
	raw, err := message.MarshalDownlinkDataNotificationAck(ddn, sess.SGWS11FTEID.TEID, ie.CauseRequestAccepted)
	if err != nil {
		t.Fatalf("Marshal DDN Ack: %v", err)
	}

	h.handleDownlinkDataNotificationAck(&net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}, raw)

	if len(conn.replies) != 0 {
		t.Fatalf("Stop Paging replies = %d; want 0 by default", len(conn.replies))
	}
	status := sess.MMERestorationSnapshot()
	if status.StopPagingSent {
		t.Fatalf("Stop Paging status = %+v; want not sent by default", status)
	}
}

func TestHandleDownlinkDataNotificationAckStopPagingWhenEnabled(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	const ddnSeq uint32 = 0x1234
	sess.MarkMMERestart("10.90.250.77:2123", 2, time.Unix(9, 0).UTC())
	sess.SetMMERestorationPolicy(session.MMERestorationPolicyPreserve, "preserve-ims", time.Unix(9, 0).UTC())
	sess.MarkMMERestorationDDNTriggered(ddnSeq, time.Unix(10, 0).UTC())
	cfg := sgwcconfig.Default()
	cfg.GTPC.DDNControl.StopPagingEnabled = true
	cfg.GTPC.DDNControl.StopPagingOnDDNAck = true
	conn := &fakeGTPCConn{}
	h := &Handler{cfg: cfg, conn: conn, sessions: mgr, log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	ddn := &message.DownlinkDataNotification{Header: message.Header{SequenceNumber: ddnSeq}}
	raw, err := message.MarshalDownlinkDataNotificationAck(ddn, sess.SGWS11FTEID.TEID, ie.CauseRequestAccepted)
	if err != nil {
		t.Fatalf("Marshal DDN Ack: %v", err)
	}

	h.handleDownlinkDataNotificationAck(&net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}, raw)

	if len(conn.replies) != 1 {
		t.Fatalf("Stop Paging replies = %d; want 1", len(conn.replies))
	}
	ind, err := message.ParseStopPagingIndication(conn.replies[0])
	if err != nil {
		t.Fatalf("Parse Stop Paging: %v", err)
	}
	if ind.TEID != sess.MMEControlFTEID.TEID {
		t.Fatalf("Stop Paging TEID = 0x%08X; want 0x%08X", ind.TEID, sess.MMEControlFTEID.TEID)
	}
	status := sess.MMERestorationSnapshot()
	if !status.StopPagingSent || status.StopPagingSequence == 0 {
		t.Fatalf("Stop Paging status = %+v; want sent", status)
	}
}

func TestHandleDownlinkDataNotificationAckRecordsLowPriorityThrottling(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	const ddnSeq uint32 = 0x1234
	sess.MarkMMERestorationDDNTriggered(ddnSeq, time.Unix(10, 0).UTC())
	ddnCtl := ddncontrol.NewState(ddncontrol.Config{
		Enabled:                       true,
		PerMMERateLimitPerSecond:      10,
		PerMMEBurst:                   10,
		HonorMMELowPriorityThrottling: true,
		LowPriority:                   []ddncontrol.PriorityRule{{APN: "internet", QCI: 9}},
	})
	h := &Handler{
		sessions: mgr,
		log:      slog.New(slog.NewTextHandler(os.Stdout, nil)),
		ddnCtl:   ddnCtl,
	}
	ddn := &message.DownlinkDataNotification{Header: message.Header{SequenceNumber: ddnSeq}}
	raw, err := message.MarshalDownlinkDataNotificationAck(
		ddn,
		sess.SGWS11FTEID.TEID,
		ie.CauseRequestAccepted,
		&ie.IE{Type: ie.TypeThrottling, Value: []byte{40, 180}},
	)
	if err != nil {
		t.Fatalf("Marshal DDN Ack: %v", err)
	}

	h.handleDownlinkDataNotificationAck(&net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 30032}, raw)

	snap := ddnCtl.Snapshot()
	if len(snap.MMEs) != 1 {
		t.Fatalf("DDN MME states = %d; want 1", len(snap.MMEs))
	}
	if snap.MMEs[0].MMEAddr != "10.90.250.77:2123" ||
		snap.MMEs[0].LowPriorityThrottleReason != "ddn-ack-low-priority-throttling" ||
		snap.MMEs[0].LowPriorityThrottledUntil.IsZero() {
		t.Fatalf("DDN MME state = %+v; want canonical MME throttle state", snap.MMEs[0])
	}
	decision := ddnCtl.Decide(ddncontrol.Candidate{
		MMEAddr: "10.90.250.77:2123",
		IMSI:    "311435300070600",
		APN:     "internet",
		EBI:     5,
		QCI:     9,
	}, time.Now())
	if decision.Action != ddncontrol.ActionSuppress || decision.Reason != "mme-low-priority-throttling" {
		t.Fatalf("DDN decision = %+v; want low-priority suppression from MME throttle", decision)
	}
}

func TestDDNLowPriorityThrottleDurationUsesConfigFallback(t *testing.T) {
	h := &Handler{cfg: &sgwcconfig.Config{}}
	h.cfg.GTPC.DDNControl.LowPriorityThrottleSeconds = 55

	got := h.ddnLowPriorityThrottleDuration(&ie.IE{Type: ie.TypeThrottling, Value: []byte{0, 180}})
	if got != 55*time.Second {
		t.Fatalf("throttle duration = %s; want 55s config fallback", got)
	}
}

func TestHandleDownlinkDataNotificationAckMatchesTEIDZeroByIMSI(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	const ddnSeq uint32 = 0x1234
	sess.MarkMMERestorationDDNTriggered(ddnSeq, time.Unix(10, 0).UTC())
	h := &Handler{sessions: mgr, log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	ddn := &message.DownlinkDataNotification{Header: message.Header{SequenceNumber: ddnSeq}}
	raw, err := message.MarshalDownlinkDataNotificationAck(ddn, 0, ie.CauseRequestAccepted, ie.NewIMSI(sess.IMSI))
	if err != nil {
		t.Fatalf("Marshal DDN Ack: %v", err)
	}

	h.handleDownlinkDataNotificationAck(&net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 30032}, raw)

	status := sess.MMERestorationSnapshot()
	if !status.DDNAcked || status.DDNAckCause != ie.CauseRequestAccepted {
		t.Fatalf("DDN status = %+v; want acked via TEID-zero/IMSI fallback", status)
	}
}

func TestHandleDownlinkDataNotificationFailureMarksRestorationSession(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	const ddnSeq uint32 = 0x2233
	sess.MarkMMERestorationDDNTriggered(ddnSeq, time.Unix(10, 0).UTC())
	h := &Handler{sessions: mgr, log: slog.New(slog.NewTextHandler(os.Stdout, nil))}
	raw, err := message.MarshalDownlinkDataNotificationFailureIndication(
		sess.SGWS11FTEID.TEID,
		ddnSeq,
		ie.CauseRequestRejected,
		ie.NewIMSI(sess.IMSI),
	)
	if err != nil {
		t.Fatalf("Marshal DDN Failure Indication: %v", err)
	}

	h.handleDownlinkDataNotificationFailureIndication(&net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}, raw)

	status := sess.MMERestorationSnapshot()
	if status.DDNFailureCause != ie.CauseRequestRejected || status.DDNFailureReason != "ddn-failure-indication" {
		t.Fatalf("DDN status = %+v; want failure indication cause request rejected", status)
	}
}

func TestSendStopPagingIndicationBuildsS11StopPaging(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	h := &Handler{
		conn: &fakeGTPCConn{},
		log:  slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}

	seq, err := h.SendStopPagingIndication(context.Background(), sess)
	if err != nil {
		t.Fatalf("SendStopPagingIndication: %v", err)
	}
	raw := h.conn.(*fakeGTPCConn).replies[0]
	ind, err := message.ParseStopPagingIndication(raw)
	if err != nil {
		t.Fatalf("ParseStopPagingIndication: %v", err)
	}
	if ind.TEID != sess.MMEControlFTEID.TEID || ind.SequenceNumber != seq {
		t.Fatalf("Stop Paging header TEID=0x%08X seq=%d; want TEID=0x%08X seq=%d",
			ind.TEID, ind.SequenceNumber, sess.MMEControlFTEID.TEID, seq)
	}
	if ind.IMSI == nil {
		t.Fatal("Stop Paging IMSI missing")
	}
	if got, err := ind.IMSI.IMSI(); err != nil || got != sess.IMSI {
		t.Fatalf("Stop Paging IMSI = %q err=%v; want %s", got, err, sess.IMSI)
	}
	status := sess.MMERestorationSnapshot()
	if !status.StopPagingSent || status.StopPagingSequence != seq {
		t.Fatalf("Stop Paging status = %+v; want sent seq %d", status, seq)
	}
}

func TestModifyBearerCompletesMMERestorationAfterPFCPForwardingRestored(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 101, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 202, IPv4: netip.MustParseAddr("10.90.250.11")},
		SGWUAddr:    "10.90.250.11:8805",
		Established: true,
	})
	b := sess.GetBearer(6)
	b.SGWS1UFTEID = bearer.FTEID{TEID: 0x90000002, IPv4: netip.MustParseAddr("10.90.250.11")}
	sess.SetBearer(b)
	sess.MarkMMERestart("10.90.250.77:2123", 3, time.Unix(10, 0).UTC())
	sess.SetMMERestorationPolicy(session.MMERestorationPolicyPreserve, "preserve-ims", time.Unix(11, 0).UTC())
	sess.MarkMMERestorationDDNTriggered(0x1234, time.Unix(12, 0).UTC())
	sess.MarkMMERestorationDDNAck(ie.CauseRequestAccepted, time.Unix(13, 0).UTC())
	if got := sess.GetState(); got != session.StateRecovering {
		t.Fatalf("state after DDN Ack = %s; want recovering", got)
	}

	conn, err := transport.Listen("127.0.0.1:0", 1, 1, slog.Default())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	pfcp := &fakePFCPClient{}
	h := &Handler{
		log:      slog.Default(),
		sessions: mgr,
		pfcp:     pfcp,
		recovery: recovery.New(0),
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeModifyBearerRequest,
		TEID:           sess.SGWS11FTEID.TEID,
		SequenceNumber: 0x20202,
	}
	bc := ie.NewBearerContext(0,
		ie.NewEBI(6),
		ie.NewFTEID(0, ie.IFTypeS1UENB, 0xA0B0C0D0, netip.MustParseAddr("10.90.250.88")),
	)
	raw, err := message.Marshal(hdr, []*ie.IE{bc})
	if err != nil {
		t.Fatalf("Marshal MBReq: %v", err)
	}
	parsedHdr, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse MBReq: %v", err)
	}

	h.handleModifyBearerRequest(conn, addr, parsedHdr, ies)

	if pfcp.modifies != 1 {
		t.Fatalf("PFCP modifies = %d; want 1", pfcp.modifies)
	}
	if len(pfcp.lastUpdates) != 1 ||
		pfcp.lastUpdates[0].FARID != 2 ||
		pfcp.lastUpdates[0].ApplyAction != pfcpie.ApplyActionFORW ||
		pfcp.lastUpdates[0].OuterTEID != 0xA0B0C0D0 ||
		pfcp.lastUpdates[0].OuterIP.String() != "10.90.250.88" {
		t.Fatalf("PFCP update = %+v; want FAR 2 FORW to eNB", pfcp.lastUpdates)
	}
	status := sess.MMERestorationSnapshot()
	if status.RestorationPending || !status.UserPlaneRestored || status.RestoredEBI != 6 {
		t.Fatalf("restoration status = %+v; want pending cleared and user plane restored for EBI 6", status)
	}
	if got := sess.GetState(); got != session.StateActive {
		t.Fatalf("state after Modify Bearer = %s; want active", got)
	}
}

func TestModifyBearerDefaultResumeRestoresActiveSiblingBearer(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            "ims",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 101, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 202, IPv4: netip.MustParseAddr("10.90.250.11")},
		SGWUAddr:    "10.90.250.11:8805",
		Established: true,
	})
	defaultBearer := sess.GetBearer(6)
	defaultBearer.SGWS1UFTEID = bearer.FTEID{TEID: 0x90000002, IPv4: netip.MustParseAddr("10.90.250.11")}
	sess.SetBearer(defaultBearer)
	sess.SetBearer(&bearer.Bearer{
		EBI:         7,
		QCI:         1,
		ARP:         bearer.ARP{PriorityLevel: 1},
		State:       bearer.BearerStateActive,
		SGWS1UFTEID: bearer.FTEID{TEID: 0x90000012, IPv4: netip.MustParseAddr("10.90.250.11")},
		PDRIDs:      [2]uint32{11, 12},
		FARIDs:      [2]uint32{21, 22},
	})

	conn, err := transport.Listen("127.0.0.1:0", 1, 1, slog.Default())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	defer conn.Close() //nolint:errcheck
	pfcp := &fakePFCPClient{}
	h := &Handler{
		log:      slog.Default(),
		sessions: mgr,
		pfcp:     pfcp,
		recovery: recovery.New(0),
	}
	addr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeModifyBearerRequest,
		TEID:           sess.SGWS11FTEID.TEID,
		SequenceNumber: 0x20203,
	}
	bc := ie.NewBearerContext(0,
		ie.NewEBI(6),
		ie.NewFTEID(0, ie.IFTypeS1UENB, 0xA0B0C0D0, netip.MustParseAddr("10.90.250.88")),
	)
	raw, err := message.Marshal(hdr, []*ie.IE{bc})
	if err != nil {
		t.Fatalf("Marshal MBReq: %v", err)
	}
	parsedHdr, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse MBReq: %v", err)
	}

	h.handleModifyBearerRequest(conn, addr, parsedHdr, ies)

	if pfcp.modifies != 2 {
		t.Fatalf("PFCP modifies = %d; want default plus sibling restore", pfcp.modifies)
	}
	if len(pfcp.lastUpdates) != 1 ||
		pfcp.lastUpdates[0].FARID != 22 ||
		pfcp.lastUpdates[0].ApplyAction != pfcpie.ApplyActionFORW ||
		pfcp.lastUpdates[0].OuterTEID != 0xA0B0C0D0 {
		t.Fatalf("last PFCP update = %+v; want sibling FAR 22 FORW to eNB", pfcp.lastUpdates)
	}
	dedicated := sess.GetBearer(7)
	if dedicated.ENBS1UFTEID.TEID != 0xA0B0C0D0 || dedicated.ENBS1UFTEID.IPv4.String() != "10.90.250.88" {
		t.Fatalf("dedicated ENB FTEID = %+v; want restored to Modify Bearer eNB", dedicated.ENBS1UFTEID)
	}
}

type fakeS5CClient struct {
	replies                   [][]byte
	deleteSessionFromS11Calls int
	modifyBearerCalls         int
	lastModifyBearer          *message.ModifyBearerRequest
}

func (f *fakeS5CClient) PGWAddr(*message.CreateSessionRequest) (*net.UDPAddr, error) {
	return &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}, nil
}

func (f *fakeS5CClient) CreateSession(context.Context, *net.UDPAddr, *message.CreateSessionRequest, uint32, bearer.FTEID) (*s5c.CreateSessionResult, error) {
	return nil, nil
}

func (f *fakeS5CClient) DispatchPiggybacks(*net.UDPAddr, []message.Frame) {}
func (f *fakeS5CClient) DeleteSession(context.Context, *session.SGWSession) (uint8, error) {
	return ie.CauseRequestAccepted, nil
}
func (f *fakeS5CClient) DeleteSessionFromS11(context.Context, *session.SGWSession, *message.DeleteSessionRequest) (uint8, error) {
	f.deleteSessionFromS11Calls++
	return ie.CauseRequestAccepted, nil
}
func (f *fakeS5CClient) ModifyBearerFromS11(_ context.Context, _ *session.SGWSession, req *message.ModifyBearerRequest) (uint8, error) {
	f.modifyBearerCalls++
	f.lastModifyBearer = req
	return ie.CauseRequestAccepted, nil
}
func (f *fakeS5CClient) ReplyToPGW(_ *net.UDPAddr, raw []byte) error {
	f.replies = append(f.replies, append([]byte(nil), raw...))
	return nil
}
func (f *fakeS5CClient) AllocTEID() (uint32, error) { return 0x11112222, nil }
func (f *fakeS5CClient) FreeTEID(uint32)            {}

type fakePFCPClient struct {
	adds        int
	removes     int
	modifies    int
	lastUpdates []pfcpclient.FARUpdate
}

func (f *fakePFCPClient) AllocCPSEID() uint64 { return 1 }
func (f *fakePFCPClient) EstablishSession(context.Context, pfcpclient.SessionParams) (*pfcpclient.SessionResult, error) {
	return nil, nil
}
func (f *fakePFCPClient) ModifySessionOnPeer(_ context.Context, _ string, _, _ uint64, updates []pfcpclient.FARUpdate) error {
	f.modifies++
	f.lastUpdates = append([]pfcpclient.FARUpdate(nil), updates...)
	return nil
}
func (f *fakePFCPClient) AddBearerRulesOnPeer(_ context.Context, _ string, _, _ uint64, createPDRs, _ []*pfcpie.IE) ([]*pfcpie.IE, error) {
	f.adds++
	var out []*pfcpie.IE
	for _, createPDR := range createPDRs {
		children, err := createPDR.Children()
		if err != nil {
			continue
		}
		pdrIDIE := pfcpie.Find(children, pfcpie.TypePDRID)
		if pdrIDIE == nil {
			continue
		}
		pdrID, _ := pdrIDIE.PDRIDValue()
		teid := uint32(0x90000000) + uint32(pdrID)
		out = append(out, pfcpie.NewCreatedPDR(
			pfcpie.NewPDRID(pdrID),
			pfcpie.NewFTEIDv4(teid, netip.MustParseAddr("10.90.250.59")),
		))
	}
	return out, nil
}
func (f *fakePFCPClient) RemoveBearerRulesOnPeer(context.Context, string, uint64, uint64, []uint32, []uint32) error {
	f.removes++
	return nil
}
func (f *fakePFCPClient) DeleteSessionOnPeer(context.Context, string, uint64, uint64) error {
	return nil
}

type captureSlogHandler struct {
	messages []string
}

func (h *captureSlogHandler) Enabled(context.Context, slog.Level) bool {
	return true
}

func (h *captureSlogHandler) Handle(_ context.Context, r slog.Record) error {
	h.messages = append(h.messages, r.Message)
	return nil
}

func (h *captureSlogHandler) WithAttrs([]slog.Attr) slog.Handler {
	return h
}

func (h *captureSlogHandler) WithGroup(string) slog.Handler {
	return h
}

func (h *captureSlogHandler) HasMessage(message string) bool {
	for _, got := range h.messages {
		if got == message {
			return true
		}
	}
	return false
}

func (h *captureSlogHandler) Messages() []string {
	return append([]string(nil), h.messages...)
}

func TestHandleS5CUpdateBearerRejectsTransactionCollision(t *testing.T) {
	mgr, sess := testCollisionSession(t)
	s5cFake := &fakeS5CClient{}
	gtpc := &fakeGTPCConn{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      s5cFake,
		pfcp:     &fakePFCPClient{},
	}
	if _, dec := sess.ProcedureTracker().Begin(collision.Request{
		Procedure: collision.ProcedureDeleteSession,
		Owner:     collision.OwnerMME,
		EBIs:      []uint8{5},
	}); dec.Action != collision.ActionAllow {
		t.Fatalf("seed collision procedure decision = %s, want allow", dec.Action)
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeUpdateBearerRequest,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x10203,
	}
	raw, err := message.MarshalUpdateBearerRequest(
		hdr.TEID,
		hdr.SequenceNumber,
		ie.NewBearerContext(0, ie.NewEBI(5), ie.NewBearerQoS(9, 9, 0, 9, 0, 0, 0, 0)),
		ie.NewAMBR(256000, 256000),
	)
	if err != nil {
		t.Fatalf("Marshal Update Bearer Request: %v", err)
	}

	h.HandleS5CInbound(nil, pgwAddr, hdr, raw)

	assertBearerCauseResponse(t, s5cFake.replies, message.MsgTypeUpdateBearerResponse, sess.PGWControlFTEID.TEID, hdr.SequenceNumber, ie.CauseRequestRejected)
	if len(gtpc.sends) != 0 {
		t.Fatalf("S11 sends after collided Update Bearer = %d; want 0", len(gtpc.sends))
	}
}

func TestHandleS5CDeleteBearerRejectsTransactionCollision(t *testing.T) {
	mgr, sess := testCollisionSession(t)
	s5cFake := &fakeS5CClient{}
	gtpc := &fakeGTPCConn{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      s5cFake,
		pfcp:     &fakePFCPClient{},
	}
	if _, dec := sess.ProcedureTracker().Begin(collision.Request{
		Procedure: collision.ProcedureModifyBearer,
		Owner:     collision.OwnerMME,
		EBIs:      []uint8{5},
	}); dec.Action != collision.ActionAllow {
		t.Fatalf("seed collision procedure decision = %s, want allow", dec.Action)
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDeleteBearerRequest,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x10204,
	}
	raw, err := message.MarshalDeleteBearerRequest(hdr.TEID, hdr.SequenceNumber, ie.NewEBI(5))
	if err != nil {
		t.Fatalf("Marshal Delete Bearer Request: %v", err)
	}

	h.HandleS5CInbound(nil, pgwAddr, hdr, raw)

	assertBearerCauseResponse(t, s5cFake.replies, message.MsgTypeDeleteBearerResponse, sess.PGWControlFTEID.TEID, hdr.SequenceNumber, ie.CauseRequestRejected)
	if len(gtpc.sends) != 0 {
		t.Fatalf("S11 sends after collided Delete Bearer = %d; want 0", len(gtpc.sends))
	}
}

func TestHandleS11DeleteBearerCommandRelaysToPGWAndPreservesBearerUntilOutcome(t *testing.T) {
	mgr, sess := testCollisionSession(t)
	sess.SetBearer(&bearer.Bearer{
		EBI:    7,
		QCI:    1,
		State:  bearer.BearerStateActive,
		PDRIDs: [2]uint32{3, 4},
		FARIDs: [2]uint32{3, 4},
	})
	s5cFake := &fakeS5CClient{}
	pfcpFake := &fakePFCPClient{}
	gtpc := &fakeGTPCConn{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      s5cFake,
		pfcp:     pfcpFake,
		localIP:  netip.MustParseAddr("10.90.250.59"),
	}
	mmeAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 30096}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDeleteBearerCommand,
		TEID:           sess.SGWS11FTEID.TEID,
		SequenceNumber: 0x222222,
	}
	raw, err := message.MarshalDeleteBearerCommand(hdr.TEID, hdr.SequenceNumber,
		ie.NewBearerContext(0, ie.NewEBI(7)))
	if err != nil {
		t.Fatalf("Marshal Delete Bearer Command: %v", err)
	}

	h.handle(nil, mmeAddr, hdr, raw)

	if sess.GetBearer(7) == nil {
		t.Fatal("dedicated bearer EBI 7 was removed before PGW outcome")
	}
	if pfcpFake.removes != 0 {
		t.Fatalf("PFCP RemoveBearerRules calls = %d; want 0 before PGW outcome", pfcpFake.removes)
	}
	if len(h.dbCmds) != 1 {
		t.Fatalf("pending Delete Bearer Command entries = %d; want 1", len(h.dbCmds))
	}
	if len(s5cFake.replies) != 1 {
		t.Fatalf("S5C sends = %d; want 1 Delete Bearer Command to PGW", len(s5cFake.replies))
	}
	outHdr, outIEs, err := message.Parse(s5cFake.replies[0])
	if err != nil {
		t.Fatalf("Parse S5C Delete Bearer Command: %v", err)
	}
	if outHdr.MessageType != message.MsgTypeDeleteBearerCommand {
		t.Fatalf("S5C message type = %d; want Delete Bearer Command", outHdr.MessageType)
	}
	if outHdr.TEID != sess.PGWControlFTEID.TEID {
		t.Fatalf("S5C Delete Bearer Command TEID = 0x%08X; want PGW TEID 0x%08X", outHdr.TEID, sess.PGWControlFTEID.TEID)
	}
	if sender := ie.FindInstance(outIEs, ie.TypeFTEID, 0); sender == nil {
		t.Fatal("S5C Delete Bearer Command missing Sender F-TEID for Control Plane")
	}
	if len(gtpc.replies) != 0 {
		t.Fatalf("S11 failure indications = %d; want 0 on successful command", len(gtpc.replies))
	}
}

func TestHandleS5CDeleteBearerFailureClearsPendingCommandWithoutDeletingBearer(t *testing.T) {
	mgr, sess := testCollisionSession(t)
	sess.SetBearer(&bearer.Bearer{
		EBI:    7,
		QCI:    1,
		State:  bearer.BearerStateActive,
		PDRIDs: [2]uint32{3, 4},
		FARIDs: [2]uint32{3, 4},
	})
	gtpc := &fakeGTPCConn{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      &fakeS5CClient{},
		pfcp:     &fakePFCPClient{},
		localIP:  netip.MustParseAddr("10.90.250.59"),
		dbCmds:   make(map[deleteBearerCommandPendingKey]deleteBearerCommandPending),
	}
	h.markDeleteBearerCommandPending(sess, message.Header{
		TEID:           sess.SGWS11FTEID.TEID,
		SequenceNumber: 0x222222,
	}, []uint8{7})
	if len(h.dbCmds) != 1 {
		t.Fatalf("pending Delete Bearer Command entries before failure = %d; want 1", len(h.dbCmds))
	}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDeleteBearerFailureIndication,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x444444,
	}
	raw, err := message.MarshalDeleteBearerFailureIndication(hdr.TEID, hdr.SequenceNumber,
		ie.NewCause(ie.CauseRequestRejected, 0, 0, 0, nil),
		ie.NewBearerContext(0, ie.NewEBI(7), ie.NewCause(ie.CauseRequestRejected, 0, 0, 0, nil)),
	)
	if err != nil {
		t.Fatalf("Marshal Delete Bearer Failure Indication: %v", err)
	}

	h.HandleS5CInbound(nil, pgwAddr, hdr, raw)

	if len(h.dbCmds) != 0 {
		t.Fatalf("pending Delete Bearer Command entries after failure = %d; want 0", len(h.dbCmds))
	}
	if sess.GetBearer(7) == nil {
		t.Fatal("dedicated bearer EBI 7 was deleted after PGW failure indication")
	}
	if len(gtpc.replies) != 1 {
		t.Fatalf("relayed S11 failure indications = %d; want 1", len(gtpc.replies))
	}
}

func TestHandleS11DeleteBearerCommandParseErrorSendsFailureWithMMETEID(t *testing.T) {
	mgr, sess := testCollisionSession(t)
	gtpc := &fakeGTPCConn{}
	conn, err := transport.Listen("127.0.0.1:0", 1, 1, slog.Default())
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      &fakeS5CClient{},
		pfcp:     &fakePFCPClient{},
		localIP:  netip.MustParseAddr("10.90.250.59"),
	}
	mmeAddr := client.LocalAddr().(*net.UDPAddr)
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDeleteBearerCommand,
		TEID:           sess.SGWS11FTEID.TEID,
		SequenceNumber: 0x333333,
	}
	raw, err := message.MarshalDeleteBearerCommand(hdr.TEID, hdr.SequenceNumber)
	if err != nil {
		t.Fatalf("Marshal malformed Delete Bearer Command: %v", err)
	}

	h.handleDeleteBearerCommand(conn, mmeAddr, hdr, raw)

	buf := make([]byte, 1500)
	n, _, err := client.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("Read failure indication: %v", err)
	}
	respHdr, respIEs, err := message.Parse(buf[:n])
	if err != nil {
		t.Fatalf("Parse Delete Bearer Failure Indication: %v", err)
	}
	if respHdr.MessageType != message.MsgTypeDeleteBearerFailureIndication {
		t.Fatalf("response type = %d; want Delete Bearer Failure Indication", respHdr.MessageType)
	}
	if respHdr.TEID != sess.MMEControlFTEID.TEID {
		t.Fatalf("response TEID = 0x%08X; want MME TEID 0x%08X", respHdr.TEID, sess.MMEControlFTEID.TEID)
	}
	causeIE := ie.FindFirst(respIEs, ie.TypeCause)
	if causeIE == nil {
		t.Fatal("Delete Bearer Failure Indication missing Cause")
	}
	cause, err := causeIE.CauseValue()
	if err != nil {
		t.Fatalf("CauseValue: %v", err)
	}
	if cause != ie.CauseInvalidMessageFormat {
		t.Fatalf("cause = %d; want Invalid Message Format", cause)
	}
}

func TestBeginProcedureAllowsS11DeleteSessionDuringBearerProcedure(t *testing.T) {
	_, sess := testCollisionSession(t)
	metrics := &fakeCollisionMetrics{}
	h := &Handler{log: slog.Default()}
	h.SetCollisionMetrics(metrics)
	_, dec := sess.ProcedureTracker().Begin(collision.Request{
		Procedure: collision.ProcedureCreateBearer,
		Owner:     collision.OwnerPGW,
		EBIs:      []uint8{5},
	})
	if dec.Action != collision.ActionAllow {
		t.Fatalf("seed collision procedure decision = %s, want allow", dec.Action)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 30096}
	proc, ok := h.beginProcedure(sess, mmeProcedureRequest(collision.ProcedureDeleteSession, addr, sess.SGWS11FTEID.TEID, 0x10205, []uint8{5}))
	if !ok {
		t.Fatalf("beginProcedure returned !ok; want Delete Session accepted during active bearer procedure")
	}
	if proc.ID == 0 || proc.Procedure != collision.ProcedureDeleteSession {
		t.Fatalf("beginProcedure proc = %+v; want Delete Session active procedure", proc)
	}
	activeNow := sess.ProcedureTracker().Active()
	if len(activeNow) != 2 {
		t.Fatalf("active procedures after Delete Session = %+v; want original bearer proc plus Delete Session", activeNow)
	}
	if metrics.decisions != 0 {
		t.Fatalf("collision metric decisions = %d; want 0", metrics.decisions)
	}
}

func TestBeginProcedurePermissiveModeAllowsUnknownBearerScope(t *testing.T) {
	_, sess := testCollisionSession(t)
	h := &Handler{
		log:              slog.Default(),
		collisionMode:    collision.ModePermissive,
		collisionTimeout: collision.DefaultActiveProcedureTimeout,
	}
	_, dec := sess.ProcedureTracker().Begin(collision.Request{
		Procedure: collision.ProcedureUpdateBearer,
		Owner:     collision.OwnerPGW,
	})
	if dec.Action != collision.ActionAllow {
		t.Fatalf("seed collision procedure decision = %s, want allow", dec.Action)
	}
	addr := &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}
	proc, ok := h.beginProcedure(sess, mmeProcedureRequest(collision.ProcedureModifyBearer, addr, sess.SGWS11FTEID.TEID, 0x10206, []uint8{7}))
	if !ok {
		t.Fatal("beginProcedure rejected unknown-scope bearer overlap in permissive mode")
	}
	defer finishProcedure(sess, proc)
	if got := sess.ProcedureTracker().Active(); len(got) != 2 {
		t.Fatalf("active procedures after permissive overlap = %d; want 2", len(got))
	}
}

func TestBeginProcedureWarnsOnDownPeer(t *testing.T) {
	_, sess := testCollisionSession(t)
	logs := &captureSlogHandler{}
	cfg := sgwcconfig.Default()
	peers := peerhealth.NewTable(slog.New(slog.DiscardHandler))
	addr := &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}
	peers.Observe(peerhealth.RoleMME, addr, message.MsgTypeModifyBearerRequest, 1, nil)
	for seq := uint32(2); seq <= 4; seq++ {
		peers.MarkEchoTimeout(peerhealth.RoleMME, addr.String(), seq, peerhealth.ProbeConfig{
			SuspectAfterMissed: 2,
			DownAfterMissed:    3,
			DegradedRTT:        500 * time.Millisecond,
		})
	}

	h := &Handler{
		cfg:              cfg,
		log:              slog.New(logs),
		peerHealth:       peers,
		collisionMode:    collision.ModeStrict,
		collisionTimeout: collision.DefaultActiveProcedureTimeout,
	}
	proc, ok := h.beginProcedure(sess, mmeProcedureRequest(collision.ProcedureModifyBearer, addr, sess.SGWS11FTEID.TEID, 0x10206, []uint8{5}))
	if !ok {
		t.Fatal("beginProcedure rejected procedure; want warning only")
	}
	defer finishProcedure(sess, proc)
	if !logs.HasMessage("GTPv2-C procedure toward down peer") {
		t.Fatalf("warning log messages = %+v; want down-peer procedure warning", logs.Messages())
	}
}

func TestBeginProcedureDownPeerWarningCanBeDisabled(t *testing.T) {
	_, sess := testCollisionSession(t)
	logs := &captureSlogHandler{}
	cfg := sgwcconfig.Default()
	cfg.GTPC.PeerHealth.WarnOnDownPeerProcedure = false
	peers := peerhealth.NewTable(slog.New(slog.DiscardHandler))
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}
	peers.Observe(peerhealth.RolePGW, addr, message.MsgTypeCreateBearerRequest, 1, nil)
	for seq := uint32(2); seq <= 4; seq++ {
		peers.MarkEchoTimeout(peerhealth.RolePGW, addr.String(), seq, peerhealth.ProbeConfig{
			SuspectAfterMissed: 2,
			DownAfterMissed:    3,
			DegradedRTT:        500 * time.Millisecond,
		})
	}

	h := &Handler{
		cfg:              cfg,
		log:              slog.New(logs),
		peerHealth:       peers,
		collisionMode:    collision.ModeStrict,
		collisionTimeout: collision.DefaultActiveProcedureTimeout,
	}
	proc, ok := h.beginProcedure(sess, pgwProcedureRequest(collision.ProcedureCreateBearer, addr, sess.PGWControlFTEID.TEID, 0x10207, []uint8{5}))
	if !ok {
		t.Fatal("beginProcedure rejected procedure; want warning-only feature disabled")
	}
	defer finishProcedure(sess, proc)
	if logs.HasMessage("GTPv2-C procedure toward down peer") {
		t.Fatalf("warning log messages = %+v; want no down-peer procedure warning", logs.Messages())
	}
}

func TestBeginProcedureBlocksDownPGWWhenConfigured(t *testing.T) {
	_, sess := testCollisionSession(t)
	cfg := sgwcconfig.Default()
	cfg.GTPC.PGWFailure.BlockNewProceduresToDownPGW = true
	peers := peerhealth.NewTable(slog.New(slog.DiscardHandler))
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}
	peers.Observe(peerhealth.RolePGW, addr, message.MsgTypeCreateBearerRequest, 1, nil)
	for seq := uint32(2); seq <= 4; seq++ {
		peers.MarkEchoTimeout(peerhealth.RolePGW, addr.String(), seq, peerhealth.ProbeConfig{
			SuspectAfterMissed: 2,
			DownAfterMissed:    3,
			DegradedRTT:        500 * time.Millisecond,
		})
	}

	h := &Handler{
		cfg:              cfg,
		log:              slog.Default(),
		peerHealth:       peers,
		collisionMode:    collision.ModeStrict,
		collisionTimeout: collision.DefaultActiveProcedureTimeout,
	}
	proc, ok := h.beginProcedure(sess, pgwProcedureRequest(collision.ProcedureCreateBearer, addr, sess.PGWControlFTEID.TEID, 0x10207, []uint8{5}))
	if ok {
		t.Fatalf("beginProcedure returned ok with proc %+v; want down PGW block", proc)
	}
	if active := sess.ProcedureTracker().Active(); len(active) != 0 {
		t.Fatalf("active procedures after PGW block = %+v; want none", active)
	}
}

func TestCaptureSecondaryRATUsageReportsUsesBearerOwner(t *testing.T) {
	mgr := session.NewManager()
	defaultSess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435000070570",
		APN:            "internet.mnc435.mcc311.gprs",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 5,
		QCI:        9,
		ARP:        bearer.ARP{PriorityLevel: 9},
	})
	if err != nil {
		t.Fatalf("Create default session: %v", err)
	}
	imsSess, _, err := mgr.Create(session.CreateParams{
		IMSI:             "311435000070570",
		APN:              "ims.mnc435.mcc311.gprs",
		RATType:          ie.RATTypeEUTRAN,
		ServingNetwork:   "311-435",
		MMEControlFTEID:  defaultSess.MMEControlFTEID,
		ReuseSGWS11FTEID: defaultSess.SGWS11FTEID,
		DefaultEBI:       6,
		QCI:              5,
		ARP:              bearer.ARP{PriorityLevel: 5},
	})
	if err != nil {
		t.Fatalf("Create IMS session: %v", err)
	}
	h := &Handler{
		log:      slog.Default(),
		sessions: mgr,
	}
	reportPayload := []byte{0x01, 0x06, 0x00, 0xaa, 0xbb}
	req := &message.ModifyBearerRequest{
		BearerContexts: []*ie.IE{
			ie.NewBearerContext(0, ie.NewEBI(6)),
		},
		SecondaryRATUsageDataReports: []*ie.IE{
			ie.NewSecondaryRATUsageDataReport(reportPayload),
		},
	}
	reportPayload[0] = 0xff
	addr := &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeModifyBearerRequest,
		TEID:           defaultSess.SGWS11FTEID.TEID,
		SequenceNumber: 0x102030,
	}

	h.captureSecondaryRATUsageReports(addr, hdr, req, defaultSess)

	if got := defaultSess.SecondaryRATUsageReports(); len(got) != 0 {
		t.Fatalf("default PDN reports = %d; want 0 because EBI 6 belongs to IMS", len(got))
	}
	got := imsSess.SecondaryRATUsageReports()
	if len(got) != 1 {
		t.Fatalf("IMS reports = %d; want 1", len(got))
	}
	wantPayload := []byte{0x01, 0x06, 0x00, 0xaa, 0xbb}
	if !reflect.DeepEqual(got[0].Payload, wantPayload) {
		t.Fatalf("IMS report payload = %x, want %x", got[0].Payload, wantPayload)
	}
	if got[0].MMEPeer != "10.90.250.77:2123" {
		t.Fatalf("MMEPeer = %q, want 10.90.250.77:2123", got[0].MMEPeer)
	}
	if got[0].SequenceNumber != hdr.SequenceNumber {
		t.Fatalf("SequenceNumber = 0x%06X, want 0x%06X", got[0].SequenceNumber, hdr.SequenceNumber)
	}
	if got[0].SourceProcedure != "s11_modify_bearer_request" {
		t.Fatalf("SourceProcedure = %q", got[0].SourceProcedure)
	}
}

func TestNSADCNRConfigDisabledSkipsSecondaryRATCaptureAndForwardTargeting(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435000070570",
		APN:            "ims.mnc435.mcc311.gprs",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        5,
		ARP:        bearer.ARP{PriorityLevel: 5},
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	cfg := sgwcconfig.Default()
	cfg.GTPC.NSADCNR.Enabled = false
	h := &Handler{
		cfg:      cfg,
		log:      slog.Default(),
		sessions: mgr,
	}
	req := &message.ModifyBearerRequest{
		BearerContexts: []*ie.IE{
			ie.NewBearerContext(0, ie.NewEBI(6)),
		},
		SecondaryRATUsageDataReports: []*ie.IE{
			ie.NewSecondaryRATUsageDataReport([]byte{0x01, 0x06}),
		},
	}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeModifyBearerRequest,
		TEID:           sess.SGWS11FTEID.TEID,
		SequenceNumber: 0x102030,
	}

	h.captureSecondaryRATUsageReports(nil, hdr, req, sess)

	if got := sess.SecondaryRATUsageReports(); len(got) != 0 {
		t.Fatalf("secondary RAT reports captured with NSA/DCNR disabled = %d; want 0", len(got))
	}
	if targets := h.secondaryRATReportTargetSessions(hdr.TEID, []uint8{6}, sess, h.nsaDCNRForwardSecondaryRATUsageReports(req)); len(targets) != 0 {
		t.Fatalf("forward targets with NSA/DCNR disabled = %d; want 0", len(targets))
	}
}

func TestNSADCNRForwardingTargetsBearerOwnerWhenEnabled(t *testing.T) {
	mgr := session.NewManager()
	defaultSess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435000070570",
		APN:            "internet.mnc435.mcc311.gprs",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 5,
		QCI:        9,
		ARP:        bearer.ARP{PriorityLevel: 9},
	})
	if err != nil {
		t.Fatalf("Create default session: %v", err)
	}
	imsSess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435000070570",
		APN:            "ims.mnc435.mcc311.gprs",
		RATType:        ie.RATTypeEUTRAN,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		ReuseSGWS11FTEID: defaultSess.SGWS11FTEID,
		DefaultEBI:       6,
		QCI:              5,
		ARP:              bearer.ARP{PriorityLevel: 5},
	})
	if err != nil {
		t.Fatalf("Create IMS session: %v", err)
	}
	h := &Handler{
		cfg:      sgwcconfig.Default(),
		log:      slog.Default(),
		sessions: mgr,
	}
	req := &message.ModifyBearerRequest{
		BearerContexts: []*ie.IE{
			ie.NewBearerContext(0, ie.NewEBI(6)),
		},
		SecondaryRATUsageDataReports: []*ie.IE{
			ie.NewSecondaryRATUsageDataReport([]byte{0x01, 0x06}),
		},
	}

	targets := h.secondaryRATReportTargetSessions(defaultSess.SGWS11FTEID.TEID, []uint8{6}, defaultSess, h.nsaDCNRForwardSecondaryRATUsageReports(req))
	if len(targets) != 1 {
		t.Fatalf("forward targets = %d; want 1", len(targets))
	}
	if targets[0] != imsSess {
		t.Fatalf("forward target APN = %q; want %q", targets[0].APN, imsSess.APN)
	}
}

func TestObserveGTPPeerRecordsMMERecovery(t *testing.T) {
	table := peerhealth.NewTable(slog.Default())
	h := &Handler{peerHealth: table}
	addr := &net.UDPAddr{IP: net.ParseIP("10.90.250.77"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        false,
		MessageType:    message.MsgTypeEchoRequest,
		SequenceNumber: 0x010203,
	}
	h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, []*ie.IE{ie.NewRecovery(9)})

	snaps := table.Snapshot()
	if len(snaps) != 1 {
		t.Fatalf("peer snapshots = %d; want 1", len(snaps))
	}
	got := snaps[0]
	if got.Role != peerhealth.RoleMME || got.Addr != "10.90.250.77:2123" || got.State != peerhealth.StateUp {
		t.Fatalf("peer snapshot = %+v; want MME up at 10.90.250.77:2123", got)
	}
	if !got.RecoverySeen || got.RecoveryCounter != 9 {
		t.Fatalf("recovery = seen:%v counter:%d; want seen:true counter:9", got.RecoverySeen, got.RecoveryCounter)
	}
}

type fakeCollisionMetrics struct {
	decisions    int
	staleExpired int
	lastActive   collision.ActiveProcedure
	lastReq      collision.Request
	lastDecision collision.Decision
}

func (f *fakeCollisionMetrics) OnDecision(active collision.ActiveProcedure, req collision.Request, decision collision.Decision) {
	f.decisions++
	f.lastActive = active
	f.lastReq = req
	f.lastDecision = decision
}

func (f *fakeCollisionMetrics) OnStaleExpired(_ collision.Request, expired int) {
	f.staleExpired += expired
}

func testCollisionSession(t *testing.T) (*session.Manager, *session.SGWSession) {
	t.Helper()
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "311435000070570",
		APN:             "internet.mnc435.mcc311.gprs",
		RATType:         6,
		ServingNetwork:  "311-435",
		MMEControlFTEID: session.FTEID{TEID: 0x800FE004, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      5,
		QCI:             9,
		ARP:             bearer.ARP{PriorityLevel: 9},
		MBRUplink:       256000,
		MBRDownlink:     256000,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0x16BCBA4E, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x80190008, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 3, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)
	return mgr, sess
}

func assertBearerCauseResponse(t *testing.T, replies [][]byte, wantType uint8, wantTEID, wantSeq uint32, wantCause uint8) {
	t.Helper()
	if len(replies) != 1 {
		t.Fatalf("S5C replies = %d; want 1", len(replies))
	}
	hdr, ies, err := message.Parse(replies[0])
	if err != nil {
		t.Fatalf("Parse S5C response: %v", err)
	}
	if hdr.MessageType != wantType {
		t.Fatalf("S5C response type = %d; want %d", hdr.MessageType, wantType)
	}
	if hdr.TEID != wantTEID {
		t.Fatalf("S5C response TEID = 0x%08X; want 0x%08X", hdr.TEID, wantTEID)
	}
	if hdr.SequenceNumber != wantSeq {
		t.Fatalf("S5C response seq = %d; want %d", hdr.SequenceNumber, wantSeq)
	}
	causeIE := ie.FindFirst(ies, ie.TypeCause)
	if causeIE == nil {
		t.Fatal("S5C response missing Cause IE")
	}
	cause, err := causeIE.CauseValue()
	if err != nil {
		t.Fatalf("CauseValue: %v", err)
	}
	if cause != wantCause {
		t.Fatalf("S5C response cause = %d; want %d", cause, wantCause)
	}
}

func TestBuildS11CreateSessionResponseIEsMatchesCiscoPrimaryShape(t *testing.T) {
	h := &Handler{log: slog.Default()}
	s5cResult := &s5c.CreateSessionResult{
		PGWS5UFTEID:      bearer.FTEID{TEID: 0x51525354, IPv4: netip.MustParseAddr("10.90.252.92")},
		AMBR:             ie.NewAMBR(256000, 256000),
		APNRestriction:   &ie.IE{Type: ie.TypeAPNRestriction, Value: []byte{0x00}},
		PCO:              &ie.IE{Type: ie.TypePCO, Value: []byte{0x80, 0x80, 0x21}},
		ChargingID:       &ie.IE{Type: ie.TypeChargingID, Value: []byte{0xAA, 0xBB, 0xCC, 0xDD}},
		BearerChargingID: &ie.IE{Type: ie.TypeChargingID, Value: []byte{0x01, 0x02, 0x03, 0x04}},
	}
	pfcpResult := &pfcpSessionResult{
		sgwUS1UFTEID: bearer.FTEID{TEID: 0x41424344, IPv4: netip.MustParseAddr("10.90.250.59")},
	}

	ies := h.buildS11CreateSessionResponseIEs(
		nil,
		6,
		ie.NewFTEID(0, ie.IFTypeS11S4SGW, 0x10203040, netip.MustParseAddr("10.90.250.59")),
		ie.NewFTEID(1, ie.IFTypeS5S8CPGW, 0x20304050, netip.MustParseAddr("10.90.250.92")),
		ie.NewPAA(ie.PDNTypeIPv4, netip.MustParseAddr("10.150.3.113")),
		s5cResult.AMBR,
		s5cResult,
		pfcpResult,
	)

	wantOrder := []struct {
		typ  uint8
		inst uint8
	}{
		{ie.TypeFTEID, 0},
		{ie.TypeFTEID, 1},
		{ie.TypePAA, 0},
		{ie.TypeAPNRestriction, 0},
		{ie.TypeAMBR, 0},
		{ie.TypePCO, 0},
		{ie.TypeBearerContext, 0},
		{ie.TypeChargingID, 0},
	}
	if len(ies) != len(wantOrder) {
		t.Fatalf("S11 CSResp extra IE count = %d; want %d", len(ies), len(wantOrder))
	}
	for i, want := range wantOrder {
		if ies[i].Type != want.typ || ies[i].Instance != want.inst {
			t.Fatalf("S11 CSResp extra IE[%d] = type %d inst %d; want type %d inst %d",
				i, ies[i].Type, ies[i].Instance, want.typ, want.inst)
		}
	}
	bcChildren, err := ies[6].ChildIEs()
	if err != nil {
		t.Fatalf("S11 CSResp Bearer Context children: %v", err)
	}
	if chargingID := ie.FindFirst(bcChildren, ie.TypeChargingID); chargingID != nil {
		t.Fatalf("S11 CSResp Bearer Context contains Charging ID %#v; Cisco-compatible S11 shape must omit it", chargingID)
	}
	assertBearerContextChildOrder(t, bcChildren, []struct {
		typ  uint8
		inst uint8
	}{
		{ie.TypeEBI, 0},
		{ie.TypeCause, 0},
		{ie.TypeFTEID, 0},
		{ie.TypeFTEID, 2},
	})
}

func TestExpirePendingS11CreateBearerRollsBackAndFailsPGWOnce(t *testing.T) {
	sess := &session.SGWSession{
		SessionID:       "test-session",
		IMSI:            "311435300070599",
		APN:             "ims.mnc435.mcc311.gprs",
		MMEControlFTEID: session.FTEID{TEID: 0x800FE004, IPv4: netip.MustParseAddr("10.90.250.77")},
		PGWControlFTEID: session.FTEID{TEID: 0x80190008, IPv4: netip.MustParseAddr("10.90.250.92")},
		PFCP: session.PFCPSessionBinding{
			LocalFSEID:  session.FSEID{SEID: 2},
			SGWUFSEID:   session.FSEID{SEID: 3},
			SGWUAddr:    "127.0.0.2:8805",
			Established: true,
		},
	}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x45A81ED3,
		SequenceNumber: 0x087E02,
	}
	cbReq := &message.CreateBearerRequest{
		BearerContexts: []*ie.IE{
			ie.NewBearerContext(0,
				ie.NewEBI(0),
				ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
				ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
			),
		},
	}
	provs := []bearerProvisioning{{pdrUL: 3, pdrDL: 4, farUL: 3, farDL: 4}}
	txn := &createBearerTxnState{key: newCreateBearerTxnKey(pgwAddr, hdr)}
	s5cFake := &fakeS5CClient{}
	pfcpFake := &fakePFCPClient{}
	h := &Handler{
		log:            slog.Default(),
		s5c:            s5cFake,
		pfcp:           pfcpFake,
		cbS11:          make(map[s11CreateBearerResponseKey]*pendingS11CreateBearer),
		cbTxns:         map[createBearerTxnKey]*createBearerTxnState{txn.key: txn},
		cbProcFailures: make(map[createBearerProcedureKey]*createBearerProcedureFailure),
	}
	h.markCreateBearerTxnProvisioned(txn.key, provs)
	key := s11CreateBearerResponseKey{peer: "10.90.250.77:2123", seq: 7}
	h.cbS11[key] = &pendingS11CreateBearer{
		pgwAddr:     pgwAddr,
		mmeAddr:     key.peer,
		hdr:         hdr,
		cbReq:       cbReq,
		sess:        sess,
		txn:         txn,
		bearerProvs: provs,
		csrspSeq:    577540,
		s11Seq:      7,
		linkedEBI:   6,
		createdAt:   time.Now(),
	}

	h.expirePendingS11CreateBearer(key, time.Second)
	h.expirePendingS11CreateBearer(key, time.Second)

	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removals = %d; want one rollback", pfcpFake.removes)
	}
	if len(s5cFake.replies) != 1 {
		t.Fatalf("S5C replies = %d; want one timeout failure", len(s5cFake.replies))
	}
	resp, err := message.ParseCreateBearerResponse(s5cFake.replies[0])
	if err != nil {
		t.Fatalf("Parse timeout S5C CBResp: %v", err)
	}
	cause, err := resp.Cause.CauseValue()
	if err != nil || cause != ie.CauseRequestRejected {
		t.Fatalf("timeout S5C CBResp cause = %d err=%v; want Request rejected", cause, err)
	}
	if len(h.cbProcFailures) != 1 {
		t.Fatalf("latched procedure failures after piggyback timeout = %d; want 1", len(h.cbProcFailures))
	}
	for _, failure := range h.cbProcFailures {
		if failure.state != "failed_latched" {
			t.Fatalf("latched failure state = %q; want failed_latched", failure.state)
		}
		if failure.lastFailureCause != ie.CauseRequestRejected {
			t.Fatalf("latched failure cause = %d; want Request rejected", failure.lastFailureCause)
		}
	}
}

func TestCompletePiggybackCreateBearerResponseBuildsCiscoS5CResponseShape(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "311435300070599",
		APN:             "ims.mnc435.mcc311.gprs",
		MMEControlFTEID: session.FTEID{TEID: 0x800FE004, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x80190008, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30048}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           sess.PGWControlFTEID.TEID,
		SequenceNumber: 0x277A07,
	}
	cbReq := &message.CreateBearerRequest{BearerContexts: []*ie.IE{
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x55667788, netip.MustParseAddr("10.90.252.92")),
			&ie.IE{Type: ie.TypeChargingID, Value: []byte{0x01, 0x02, 0x03, 0x04}},
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
	}}
	provs := []bearerProvisioning{{
		qosIE:        ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		tftIE:        ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
		pgwUS5UFTEID: bearer.FTEID{TEID: 0x55667788, IPv4: netip.MustParseAddr("10.90.252.92")},
		pdrUL:        3,
		pdrDL:        4,
		farUL:        3,
		farDL:        4,
		sgwUS1UFTEID: bearer.FTEID{TEID: 0x90000003, IPv4: netip.MustParseAddr("10.90.250.59")},
		sgwUS5UFTEID: bearer.FTEID{TEID: 0x90000004, IPv4: netip.MustParseAddr("10.90.250.59")},
	}}
	txn := &createBearerTxnState{key: newCreateBearerTxnKey(pgwAddr, hdr)}
	s5cFake := &fakeS5CClient{}
	h := &Handler{
		log:    slog.Default(),
		s5c:    s5cFake,
		pfcp:   &fakePFCPClient{},
		cbTxns: map[createBearerTxnKey]*createBearerTxnState{txn.key: txn},
	}
	pending := &pendingS11CreateBearer{
		pgwAddr:     pgwAddr,
		hdr:         hdr,
		cbReq:       cbReq,
		sess:        sess,
		txn:         txn,
		bearerProvs: provs,
		s11Seq:      0x000A03,
		linkedEBI:   6,
		createdAt:   time.Now(),
	}
	s11RespRaw, err := message.MarshalCreateBearerResponse(
		sess.MMEControlFTEID.TEID,
		pending.s11Seq,
		ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
		ie.NewBearerContext(0,
			ie.NewEBI(7),
			ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
			ie.NewFTEID(0, ie.IFTypeS1UENB, 0x0A0B0C0D, netip.MustParseAddr("10.90.250.77")),
			ie.NewFTEID(1, ie.IFTypeS1USGW, 0x90000003, netip.MustParseAddr("10.90.250.59")),
		),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}

	h.completeCreateBearerFromS11Response(pending, s11RespRaw)

	if len(s5cFake.replies) != 1 {
		t.Fatalf("S5C replies = %d; want 1", len(s5cFake.replies))
	}
	resp, err := message.ParseCreateBearerResponse(s5cFake.replies[0])
	if err != nil {
		t.Fatalf("Parse S5/S8-C Create Bearer Response: %v", err)
	}
	if resp.TEID != sess.PGWControlFTEID.TEID {
		t.Fatalf("S5/S8-C CBResp TEID = 0x%08X; want PGW control TEID 0x%08X", resp.TEID, sess.PGWControlFTEID.TEID)
	}
	if len(resp.BearerContexts) != 1 {
		t.Fatalf("S5/S8-C CBResp Bearer Context count = %d; want 1", len(resp.BearerContexts))
	}
	assertS5CCreateBearerResponseContext(t, resp.BearerContexts[0], 7, ie.CauseRequestAccepted, 0x90000004, 0x55667788)
}

func TestDescribeGTPCauseDecodesMandatoryIEIncorrectOffendingEBI(t *testing.T) {
	causeIE := &ie.IE{Type: ie.TypeCause, Value: []byte{0x45, 0x00, 0x49, 0x00, 0x00, 0x00}}

	got := describeGTPCause(causeIE)
	if got.CauseText != "Mandatory IE incorrect" {
		t.Fatalf("CauseText = %q; want Mandatory IE incorrect", got.CauseText)
	}
	if got.OffendingIEType != ie.TypeEBI {
		t.Fatalf("OffendingIEType = %d; want %d", got.OffendingIEType, ie.TypeEBI)
	}
	if got.OffendingIEName != "EPS Bearer ID" {
		t.Fatalf("OffendingIEName = %q; want EPS Bearer ID", got.OffendingIEName)
	}
	if got.OffendingIEInstance != 0 {
		t.Fatalf("OffendingIEInstance = %d; want 0", got.OffendingIEInstance)
	}
}

func TestCreateBearerTxnStatePendingAndCachedDuplicate(t *testing.T) {
	h := &Handler{}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x0BE02E49,
		SequenceNumber: 0x010203,
	}
	sess := &session.SGWSession{SessionID: "test-session"}
	raw := []byte{0x48, message.MsgTypeCreateBearerRequest, 0x00, 0x08}

	txn, action := h.beginCreateBearerTxn(pgwAddr, hdr, raw, sess)
	if action != createBearerTxnActionNew {
		t.Fatalf("first action = %v; want new", action)
	}
	if txn.status != createBearerTxnPending {
		t.Fatalf("first status = %q; want pending", txn.status)
	}
	if txn.sessionID != sess.SessionID {
		t.Fatalf("txn sessionID = %q; want %q", txn.sessionID, sess.SessionID)
	}

	dup, action := h.beginCreateBearerTxn(pgwAddr, hdr, raw, sess)
	if action != createBearerTxnActionPending {
		t.Fatalf("duplicate action = %v; want pending", action)
	}
	if dup != txn {
		t.Fatalf("duplicate txn pointer differs")
	}

	resp := []byte{0x48, message.MsgTypeCreateBearerResponse, 0x00, 0x08}
	h.completeCreateBearerTxn(txn.key, resp, ie.CauseMandatoryIEIncorrect)

	cached, action := h.beginCreateBearerTxn(pgwAddr, hdr, raw, sess)
	if action != createBearerTxnActionCached {
		t.Fatalf("post-completion action = %v; want cached", action)
	}
	if cached.status != createBearerTxnFailed {
		t.Fatalf("cached status = %q; want failed", cached.status)
	}
	if cached.s5cCause != ie.CauseMandatoryIEIncorrect {
		t.Fatalf("cached cause = %d; want %d", cached.s5cCause, ie.CauseMandatoryIEIncorrect)
	}
	if string(cached.s5cResponse) != string(resp) {
		t.Fatalf("cached response = % X; want % X", cached.s5cResponse, resp)
	}
}

func TestCreateBearerTxnKeyUsesPeerIPPortLocalTEIDTypeAndSequence(t *testing.T) {
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 30123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x0BE02E49,
		SequenceNumber: 0x010203,
	}

	key := newCreateBearerTxnKey(pgwAddr, hdr)

	if key.peerIP != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("peerIP = %s; want 192.0.2.10", key.peerIP)
	}
	if key.peerPort != 30123 {
		t.Fatalf("peerPort = %d; want 30123", key.peerPort)
	}
	if key.localS5CTEID != 0x0BE02E49 {
		t.Fatalf("localS5CTEID = 0x%08X; want 0x0BE02E49", key.localS5CTEID)
	}
	if key.msgType != message.MsgTypeCreateBearerRequest {
		t.Fatalf("msgType = %d; want Create Bearer Request", key.msgType)
	}
	if key.sequence != 0x010203 {
		t.Fatalf("sequence = %d; want 0x010203", key.sequence)
	}
}

func TestCreateBearerTxnKeyTreatsNewSequenceAsNewTransaction(t *testing.T) {
	h := &Handler{}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x0BE02E49,
		SequenceNumber: 0x010203,
	}
	sess := &session.SGWSession{SessionID: "test-session"}
	raw := []byte{0x48, message.MsgTypeCreateBearerRequest, 0x00, 0x08}

	first, action := h.beginCreateBearerTxn(pgwAddr, hdr, raw, sess)
	if action != createBearerTxnActionNew {
		t.Fatalf("first action = %v; want new", action)
	}

	hdr.SequenceNumber = 0x010204
	second, action := h.beginCreateBearerTxn(pgwAddr, hdr, raw, sess)
	if action != createBearerTxnActionNew {
		t.Fatalf("new sequence action = %v; want new", action)
	}
	if second == first {
		t.Fatalf("new sequence reused transaction")
	}
}

func TestHandleCreateBearerExactDuplicateUsesCachedResponseWithoutPFCPOrS11Churn(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "001010123456789",
		APN:             "ims",
		MMEControlFTEID: session.FTEID{TEID: 0xA137D225, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0xBD654359, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x8019A006, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	s11Resp, err := message.MarshalCreateBearerResponse(
		sess.SGWS11FTEID.TEID,
		1,
		ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil),
		),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}
	gtpc := &fakeGTPCConn{resp: s11Resp}
	s5cFake := &fakeS5CClient{}
	pfcpFake := &fakePFCPClient{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      s5cFake,
		pfcp:     pfcpFake,
		cbTxns:   make(map[createBearerTxnKey]*createBearerTxnState),
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30096}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x08A806,
	}
	reqRaw, err := message.MarshalCreateBearerRequest(
		hdr.TEID,
		hdr.SequenceNumber,
		ie.NewEBI(6),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x11223344, netip.MustParseAddr("10.90.252.92")),
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
	)
	if err != nil {
		t.Fatalf("Marshal Create Bearer Request: %v", err)
	}

	h.handleCreateBearer(pgwAddr, hdr, reqRaw)
	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds after first request = %d; want 1", pfcpFake.adds)
	}
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends after first request = %d; want 1", len(gtpc.sends))
	}
	assertS11CreateBearerRequestWire(t, gtpc.sends[0], sess.MMEControlFTEID.TEID, 1, 6, 0x90000003, 0x11223344)
	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removes after first rejection = %d; want 1", pfcpFake.removes)
	}
	if len(s5cFake.replies) != 1 {
		t.Fatalf("S5C replies after first request = %d; want 1", len(s5cFake.replies))
	}

	firstReply := append([]byte(nil), s5cFake.replies[0]...)
	h.handleCreateBearer(pgwAddr, hdr, reqRaw)

	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds after duplicate = %d; want 1", pfcpFake.adds)
	}
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends after duplicate = %d; want 1", len(gtpc.sends))
	}
	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removes after duplicate = %d; want 1", pfcpFake.removes)
	}
	if len(s5cFake.replies) != 2 {
		t.Fatalf("S5C replies after duplicate = %d; want 2 cached replies", len(s5cFake.replies))
	}
	if string(s5cFake.replies[1]) != string(firstReply) {
		t.Fatalf("duplicate S5C response was not replayed from cached bytes")
	}
}

func TestHandleCreateBearerNewSequenceSameFingerprintUsesCachedResultWithNewSequence(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "001010123456789",
		APN:             "ims",
		MMEControlFTEID: session.FTEID{TEID: 0xA137D225, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0xBD654359, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x8019A006, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	s11Resp, err := message.MarshalCreateBearerResponse(
		sess.SGWS11FTEID.TEID,
		1,
		ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil),
		),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}
	gtpc := &fakeGTPCConn{resp: s11Resp}
	s5cFake := &fakeS5CClient{}
	pfcpFake := &fakePFCPClient{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      s5cFake,
		pfcp:     pfcpFake,
		cbTxns:   make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:    make(map[createBearerFingerprintKey]*createBearerTxnState),
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30096}
	makeReqWithShape := func(seq uint32, pgwUTEID uint32, tft []byte, qci uint8) (message.Header, []byte) {
		hdr := message.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    message.MsgTypeCreateBearerRequest,
			TEID:           sess.SGWS5CFTEID.TEID,
			SequenceNumber: seq,
		}
		raw, err := message.MarshalCreateBearerRequest(
			hdr.TEID,
			hdr.SequenceNumber,
			ie.NewEBI(6),
			ie.NewBearerContext(0,
				ie.NewEBI(0),
				ie.NewBearerTFT(tft),
				ie.NewFTEID(1, ie.IFTypeS5S8UPGW, pgwUTEID, netip.MustParseAddr("10.90.252.92")),
				ie.NewBearerQoS(1, qci, 0, 5, 128000, 128000, 64000, 64000),
			),
		)
		if err != nil {
			t.Fatalf("Marshal Create Bearer Request: %v", err)
		}
		return hdr, raw
	}
	makeReq := func(seq uint32, pgwUTEID uint32) (message.Header, []byte) {
		return makeReqWithShape(seq, pgwUTEID, []byte{0x21, 0x01, 0x02}, 5)
	}

	hdr1, raw1 := makeReq(0x051806, 0x11223344)
	h.handleCreateBearer(pgwAddr, hdr1, raw1)

	hdr2, raw2 := makeReq(0x051A06, 0x11223344)
	h.handleCreateBearer(pgwAddr, hdr2, raw2)

	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds after same fingerprint/new sequence = %d; want 1", pfcpFake.adds)
	}
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends after same fingerprint/new sequence = %d; want 1", len(gtpc.sends))
	}
	assertS11CreateBearerRequestWire(t, gtpc.sends[0], sess.MMEControlFTEID.TEID, 1, 6, 0x90000003, 0x11223344)
	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removes after same fingerprint/new sequence = %d; want 1", pfcpFake.removes)
	}
	if len(s5cFake.replies) != 2 {
		t.Fatalf("S5C replies after same fingerprint/new sequence = %d; want 2", len(s5cFake.replies))
	}
	resp2, err := message.ParseCreateBearerResponse(s5cFake.replies[1])
	if err != nil {
		t.Fatalf("Parse second S5C response: %v", err)
	}
	if resp2.SequenceNumber != hdr2.SequenceNumber {
		t.Fatalf("second S5C response sequence = 0x%06X; want 0x%06X", resp2.SequenceNumber, hdr2.SequenceNumber)
	}

	hdr3, raw3 := makeReqWithShape(0x051C06, 0x55667788, []byte{0x21, 0x05, 0x06}, 9)
	h.handleCreateBearer(pgwAddr, hdr3, raw3)
	if pfcpFake.adds != 2 {
		t.Fatalf("PFCP adds after distinct bearer operation = %d; want 2", pfcpFake.adds)
	}
	if len(gtpc.sends) != 2 {
		t.Fatalf("S11 sends after distinct bearer operation = %d; want 2", len(gtpc.sends))
	}
}

func TestS11CreateBearerRequestMatchesKnownGoodShapeFixture(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "001010123456789",
		APN:             "ims",
		MMEControlFTEID: session.FTEID{TEID: 0xA137D225, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0xBD654359, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x8019A006, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	s11Resp, err := message.MarshalCreateBearerResponse(
		sess.SGWS11FTEID.TEID,
		1,
		ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil),
		),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}
	gtpc := &fakeGTPCConn{resp: s11Resp}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      &fakeS5CClient{},
		pfcp:     &fakePFCPClient{},
		cbTxns:   make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:    make(map[createBearerFingerprintKey]*createBearerTxnState),
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30096}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x052206,
	}
	reqRaw, err := message.MarshalCreateBearerRequest(
		hdr.TEID,
		hdr.SequenceNumber,
		ie.NewEBI(6),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x11223344, netip.MustParseAddr("10.90.252.92")),
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
	)
	if err != nil {
		t.Fatalf("Marshal Create Bearer Request: %v", err)
	}

	h.handleCreateBearer(pgwAddr, hdr, reqRaw)
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends = %d; want 1", len(gtpc.sends))
	}

	fixture := loadCreateBearerShapeFixture(t)
	actual := decodeCreateBearerShape(t, gtpc.sends[0])
	if !reflect.DeepEqual(actual, fixture) {
		t.Fatalf("VectorCore S11 Create Bearer shape differs from known-good fixture\nactual:  %+v\nfixture: %+v", actual, fixture)
	}
}

func TestHandleCreateBearerIncludesAllMMEBearerContextResultsInS5CResponse(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "001010123456789",
		APN:             "ims",
		MMEControlFTEID: session.FTEID{TEID: 0xA137D225, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0xBD654359, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x8019A006, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	s11Resp, err := message.MarshalCreateBearerResponse(
		sess.SGWS11FTEID.TEID,
		1,
		ie.NewCause(ie.CauseRequestAcceptedPartially, 0, 0, 0, nil),
		ie.NewBearerContext(0,
			ie.NewEBI(7),
			ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
			ie.NewFTEID(0, ie.IFTypeS1UENB, 0x01020304, netip.MustParseAddr("10.90.250.88")),
			ie.NewFTEID(1, ie.IFTypeS1USGW, 0x90000003, netip.MustParseAddr("10.90.250.59")),
		),
		ie.NewBearerContext(0,
			ie.NewEBI(8),
			ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, &ie.IE{Type: ie.TypeEBI}),
			ie.NewFTEID(1, ie.IFTypeS1USGW, 0x90000005, netip.MustParseAddr("10.90.250.59")),
		),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}
	gtpc := &fakeGTPCConn{resp: s11Resp}
	s5cFake := &fakeS5CClient{}
	pfcpFake := &fakePFCPClient{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      s5cFake,
		pfcp:     pfcpFake,
		cbTxns:   make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:    make(map[createBearerFingerprintKey]*createBearerTxnState),
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30096}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x052006,
	}
	reqRaw, err := message.MarshalCreateBearerRequest(
		hdr.TEID,
		hdr.SequenceNumber,
		ie.NewEBI(6),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x11223344, netip.MustParseAddr("10.90.252.92")),
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x03, 0x04}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x55667788, netip.MustParseAddr("10.90.252.92")),
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
	)
	if err != nil {
		t.Fatalf("Marshal Create Bearer Request: %v", err)
	}

	h.handleCreateBearer(pgwAddr, hdr, reqRaw)

	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds = %d; want 1", pfcpFake.adds)
	}
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends = %d; want 1", len(gtpc.sends))
	}
	if len(s5cFake.replies) != 1 {
		t.Fatalf("S5C replies = %d; want 1", len(s5cFake.replies))
	}

	resp, err := message.ParseCreateBearerResponse(s5cFake.replies[0])
	if err != nil {
		t.Fatalf("Parse S5/S8-C Create Bearer Response: %v", err)
	}
	if resp.TEID != sess.PGWControlFTEID.TEID {
		t.Fatalf("S5/S8-C CBResp TEID = 0x%08X; want PGW control TEID 0x%08X", resp.TEID, sess.PGWControlFTEID.TEID)
	}
	if resp.SequenceNumber != hdr.SequenceNumber {
		t.Fatalf("S5/S8-C CBResp seq = 0x%06X; want PGW request seq 0x%06X", resp.SequenceNumber, hdr.SequenceNumber)
	}
	msgCause, err := resp.Cause.CauseValue()
	if err != nil || msgCause != ie.CauseRequestAcceptedPartially {
		t.Fatalf("S5/S8-C CBResp cause = %d err=%v; want Request accepted partially", msgCause, err)
	}
	if len(resp.BearerContexts) != 2 {
		t.Fatalf("S5/S8-C CBResp Bearer Context count = %d; want all 2 MME results per TS 29.274 Table 7.2.4-1", len(resp.BearerContexts))
	}

	assertS5CCreateBearerResponseContext(t, resp.BearerContexts[0], 7, ie.CauseRequestAccepted, 0x90000004, 0x11223344)
	assertS5CCreateBearerResponseContext(t, resp.BearerContexts[1], 8, ie.CauseMandatoryIEIncorrect, 0x90000006, 0x55667788)
}

func TestHandleCreateBearerRejectsMalformedMMEBearerContextResult(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "001010123456789",
		APN:             "ims",
		MMEControlFTEID: session.FTEID{TEID: 0xA137D225, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0xBD654359, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x8019A006, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	s11Resp, err := message.MarshalCreateBearerResponse(
		sess.SGWS11FTEID.TEID,
		1,
		ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
		ie.NewBearerContext(0,
			ie.NewEBI(7),
			// Missing mandatory bearer-level Cause.
			ie.NewFTEID(0, ie.IFTypeS1UENB, 0x01020304, netip.MustParseAddr("10.90.250.88")),
		),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}
	gtpc := &fakeGTPCConn{resp: s11Resp}
	s5cFake := &fakeS5CClient{}
	pfcpFake := &fakePFCPClient{}
	h := &Handler{
		conn:           gtpc,
		log:            slog.Default(),
		sessions:       mgr,
		s5c:            s5cFake,
		pfcp:           pfcpFake,
		cbTxns:         make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:          make(map[createBearerFingerprintKey]*createBearerTxnState),
		cbProcFailures: make(map[createBearerProcedureKey]*createBearerProcedureFailure),
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30096}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x052106,
	}
	reqRaw, err := message.MarshalCreateBearerRequest(
		hdr.TEID,
		hdr.SequenceNumber,
		ie.NewEBI(6),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x11223344, netip.MustParseAddr("10.90.252.92")),
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
	)
	if err != nil {
		t.Fatalf("Marshal Create Bearer Request: %v", err)
	}

	h.handleCreateBearer(pgwAddr, hdr, reqRaw)

	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds = %d; want 1", pfcpFake.adds)
	}
	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removes = %d; want rollback after malformed MME result", pfcpFake.removes)
	}
	if len(s5cFake.replies) != 1 {
		t.Fatalf("S5C replies = %d; want 1", len(s5cFake.replies))
	}
	resp, err := message.ParseCreateBearerResponse(s5cFake.replies[0])
	if err != nil {
		t.Fatalf("Parse S5/S8-C Create Bearer Response: %v", err)
	}
	cause, err := resp.Cause.CauseValue()
	if err != nil || cause != ie.CauseInvalidMessageFormat {
		t.Fatalf("S5/S8-C CBResp cause = %d err=%v; want Invalid Message Format", cause, err)
	}
	if len(resp.BearerContexts) != 1 {
		t.Fatalf("S5/S8-C CBResp bearer contexts = %d; want one error result for PGW bearer", len(resp.BearerContexts))
	}
}

func TestHandleCreateBearerRetryStormGuardSuppressesNewSequenceAfterCause69(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "311435300070599",
		APN:             "ims.mnc435.mcc311.gprs",
		MMEControlFTEID: session.FTEID{TEID: 0x800FE004, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0x16BCBA4E, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x80190008, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	s11Resp, err := message.MarshalCreateBearerResponse(
		sess.SGWS11FTEID.TEID,
		1,
		ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, &ie.IE{Type: ie.TypeEBI}),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, &ie.IE{Type: ie.TypeEBI}),
			ie.NewFTEID(1, ie.IFTypeS1USGW, 0x90000003, netip.MustParseAddr("10.90.250.59")),
		),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, &ie.IE{Type: ie.TypeEBI}),
			ie.NewFTEID(1, ie.IFTypeS1USGW, 0x90000005, netip.MustParseAddr("10.90.250.59")),
		),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}
	gtpc := &fakeGTPCConn{resp: s11Resp}
	s5cFake := &fakeS5CClient{}
	pfcpFake := &fakePFCPClient{}
	h := &Handler{
		conn:           gtpc,
		log:            slog.Default(),
		sessions:       mgr,
		s5c:            s5cFake,
		pfcp:           pfcpFake,
		cbTxns:         make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:          make(map[createBearerFingerprintKey]*createBearerTxnState),
		cbProcFailures: make(map[createBearerProcedureKey]*createBearerProcedureFailure),
	}

	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30048}
	makeReq := func(seq, pgwTEID1, pgwTEID2 uint32) (message.Header, []byte) {
		hdr := message.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    message.MsgTypeCreateBearerRequest,
			TEID:           sess.SGWS5CFTEID.TEID,
			SequenceNumber: seq,
		}
		raw, err := message.MarshalCreateBearerRequest(
			hdr.TEID,
			hdr.SequenceNumber,
			ie.NewEBI(6),
			ie.NewBearerContext(0,
				ie.NewEBI(0),
				ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
				ie.NewFTEID(1, ie.IFTypeS5S8UPGW, pgwTEID1, netip.MustParseAddr("10.90.250.92")),
				ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
			),
			ie.NewBearerContext(0,
				ie.NewEBI(0),
				ie.NewBearerTFT([]byte{0x21, 0x03, 0x04}),
				ie.NewFTEID(1, ie.IFTypeS5S8UPGW, pgwTEID2, netip.MustParseAddr("10.90.250.92")),
				ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
			),
		)
		if err != nil {
			t.Fatalf("Marshal Create Bearer Request: %v", err)
		}
		return hdr, raw
	}

	hdr1, raw1 := makeReq(1639427, 0x11111111, 0x22222222)
	h.handleCreateBearer(pgwAddr, hdr1, raw1)
	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds after first request = %d; want 1", pfcpFake.adds)
	}
	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removes after first cause 69 = %d; want one batched rollback", pfcpFake.removes)
	}
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends after first request = %d; want 1", len(gtpc.sends))
	}
	if len(s5cFake.replies) != 1 {
		t.Fatalf("S5C replies after first request = %d; want 1", len(s5cFake.replies))
	}
	if len(h.cbTxns) != 1 {
		t.Fatalf("Create Bearer transactions after first request = %d; want 1", len(h.cbTxns))
	}
	if len(h.cbProcFailures) != 1 {
		t.Fatalf("latched procedure failures = %d; want 1", len(h.cbProcFailures))
	}
	for _, failure := range h.cbProcFailures {
		if failure.state != "failed_latched" {
			t.Fatalf("guard state = %q; want failed_latched", failure.state)
		}
		failure.firstSeen = time.Now().Add(-time.Minute)
		failure.lastSeen = time.Now().Add(-time.Minute)
	}

	hdr2, raw2 := makeReq(1639939, 0x33333333, 0x44444444)
	h.handleCreateBearer(pgwAddr, hdr2, raw2)
	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds after guarded retry = %d; want no new allocation", pfcpFake.adds)
	}
	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removes after guarded retry = %d; want no new rollback", pfcpFake.removes)
	}
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends after guarded retry = %d; want no new S11 CBR", len(gtpc.sends))
	}
	if len(s5cFake.replies) != 2 {
		t.Fatalf("S5C replies after guarded retry = %d; want 2", len(s5cFake.replies))
	}
	if len(h.cbTxns) != 1 {
		t.Fatalf("Create Bearer transactions after guarded retry = %d; want no new transaction", len(h.cbTxns))
	}
	resp2, err := message.ParseCreateBearerResponse(s5cFake.replies[1])
	if err != nil {
		t.Fatalf("Parse guarded retry S5C response: %v", err)
	}
	if resp2.SequenceNumber != hdr2.SequenceNumber {
		t.Fatalf("guarded retry response seq = %d; want current PGW seq %d", resp2.SequenceNumber, hdr2.SequenceNumber)
	}
	cause, err := resp2.Cause.CauseValue()
	if err != nil || cause != ie.CauseMandatoryIEIncorrect {
		t.Fatalf("guarded retry response cause = %d err=%v; want cause 69", cause, err)
	}

	hdr3, raw3 := makeReq(1640451, 0x55555555, 0x66666666)
	h.handleCreateBearer(pgwAddr, hdr3, raw3)
	hdr4, raw4 := makeReq(1640963, 0x77777777, 0x88888888)
	h.handleCreateBearer(pgwAddr, hdr4, raw4)
	hdr5, raw5 := makeReq(1641475, 0x99999999, 0xAAAAAAAA)
	h.handleCreateBearer(pgwAddr, hdr5, raw5)
	if pfcpFake.adds != 1 {
		t.Fatalf("PFCP adds after guarded retry burst = %d; want no new allocation", pfcpFake.adds)
	}
	if pfcpFake.removes != 1 {
		t.Fatalf("PFCP removes after guarded retry burst = %d; want no new rollback", pfcpFake.removes)
	}
	if len(gtpc.sends) != 1 {
		t.Fatalf("S11 sends after guarded retry burst = %d; want no new S11 CBR", len(gtpc.sends))
	}
	if len(s5cFake.replies) != 5 {
		t.Fatalf("S5C replies after guarded retry burst = %d; want every guarded retry to receive a protocol response", len(s5cFake.replies))
	}
	for i, wantSeq := range []uint32{hdr2.SequenceNumber, hdr3.SequenceNumber, hdr4.SequenceNumber, hdr5.SequenceNumber} {
		resp, err := message.ParseCreateBearerResponse(s5cFake.replies[i+1])
		if err != nil {
			t.Fatalf("Parse guarded retry S5C response[%d]: %v", i+1, err)
		}
		if resp.SequenceNumber != wantSeq {
			t.Fatalf("guarded retry response[%d] seq = %d; want current PGW seq %d", i+1, resp.SequenceNumber, wantSeq)
		}
	}
	for _, failure := range h.cbProcFailures {
		if failure.suppressedCount != 4 {
			t.Fatalf("guard suppressed count = %d; want 4", failure.suppressedCount)
		}
	}
}

func TestHandleCreateBearerRetryStormGuardAllowsDifferentQoS(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "311435300070599",
		APN:             "ims.mnc435.mcc311.gprs",
		MMEControlFTEID: session.FTEID{TEID: 0x800FE004, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0x16BCBA4E, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x80190008, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	s11Resp, err := message.MarshalCreateBearerResponse(
		sess.SGWS11FTEID.TEID,
		1,
		ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil),
		ie.NewBearerContext(0, ie.NewEBI(0), ie.NewCause(ie.CauseMandatoryIEIncorrect, 0, 0, 0, nil)),
	)
	if err != nil {
		t.Fatalf("Marshal S11 Create Bearer Response: %v", err)
	}
	gtpc := &fakeGTPCConn{resp: s11Resp}
	h := &Handler{
		conn:           gtpc,
		log:            slog.Default(),
		sessions:       mgr,
		s5c:            &fakeS5CClient{},
		pfcp:           &fakePFCPClient{},
		cbTxns:         make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:          make(map[createBearerFingerprintKey]*createBearerTxnState),
		cbProcFailures: make(map[createBearerProcedureKey]*createBearerProcedureFailure),
	}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30048}
	makeReq := func(seq uint32, qci uint8) (message.Header, []byte) {
		hdr := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateBearerRequest, TEID: sess.SGWS5CFTEID.TEID, SequenceNumber: seq}
		raw, err := message.MarshalCreateBearerRequest(
			hdr.TEID, hdr.SequenceNumber,
			ie.NewEBI(6),
			ie.NewBearerContext(0,
				ie.NewEBI(0),
				ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
				ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x11111111+seq, netip.MustParseAddr("10.90.250.92")),
				ie.NewBearerQoS(1, qci, 0, 5, 128000, 128000, 64000, 64000),
			),
		)
		if err != nil {
			t.Fatalf("Marshal Create Bearer Request: %v", err)
		}
		return hdr, raw
	}

	hdr1, raw1 := makeReq(100, 5)
	h.handleCreateBearer(pgwAddr, hdr1, raw1)
	hdr2, raw2 := makeReq(101, 9)
	h.handleCreateBearer(pgwAddr, hdr2, raw2)

	pfcpFake := h.pfcp.(*fakePFCPClient)
	if pfcpFake.adds != 2 {
		t.Fatalf("PFCP adds = %d; want different QoS to bypass retry guard", pfcpFake.adds)
	}
	if len(gtpc.sends) != 2 {
		t.Fatalf("S11 sends = %d; want different QoS to send a new S11 CBR", len(gtpc.sends))
	}
}

func TestPrepareCreateBearerRelayPreservesAllBearerContextsForPiggyback(t *testing.T) {
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "001010123456789",
		APN:             "ims",
		MMEControlFTEID: session.FTEID{TEID: 0xA137D225, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	sess.State = session.StateActive
	sess.SGWS5CFTEID = session.FTEID{TEID: 0xBD654359, IPv4: netip.MustParseAddr("10.90.250.59")}
	sess.PGWControlFTEID = session.FTEID{TEID: 0x8019A006, IPv4: netip.MustParseAddr("10.90.250.92")}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUFSEID:   session.FSEID{SEID: 2, IPv4: netip.MustParseAddr("127.0.0.2")},
		SGWUAddr:    "127.0.0.2:8805",
		Established: true,
	}
	mgr.RegisterS5CTEID(sess.SessionID, sess.SGWS5CFTEID.TEID)

	gtpc := &fakeGTPCConn{}
	h := &Handler{
		conn:     gtpc,
		log:      slog.Default(),
		sessions: mgr,
		s5c:      &fakeS5CClient{},
		pfcp:     &fakePFCPClient{},
		cbTxns:   make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:    make(map[createBearerFingerprintKey]*createBearerTxnState),
	}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("10.90.250.92"), Port: 30096}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           sess.SGWS5CFTEID.TEID,
		SequenceNumber: 0x052406,
	}
	reqRaw, err := message.MarshalCreateBearerRequest(
		hdr.TEID,
		hdr.SequenceNumber,
		ie.NewEBI(6),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x11223344, netip.MustParseAddr("10.90.252.92")),
			&ie.IE{Type: ie.TypeChargingID, Value: []byte{0x01, 0x02, 0x03, 0x04}},
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x03, 0x04}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x55667788, netip.MustParseAddr("10.90.252.92")),
			&ie.IE{Type: ie.TypeChargingID, Value: []byte{0x05, 0x06, 0x07, 0x08}},
			ie.NewBearerQoS(1, 9, 0, 5, 128000, 128000, 64000, 64000),
		),
	)
	if err != nil {
		t.Fatalf("Marshal Create Bearer Request: %v", err)
	}

	prep, ok := h.prepareCreateBearerRelay(pgwAddr, hdr, reqRaw)
	if !ok {
		t.Fatal("prepareCreateBearerRelay returned !ok")
	}
	req, err := message.ParseCreateBearerRequest(prep.s11Raw)
	if err != nil {
		t.Fatalf("Parse prepared S11 Create Bearer Request: %v", err)
	}
	if req.TEID != sess.MMEControlFTEID.TEID {
		t.Fatalf("S11 CBReq TEID = 0x%08X; want MME TEID 0x%08X", req.TEID, sess.MMEControlFTEID.TEID)
	}
	if req.SequenceNumber != 1 {
		t.Fatalf("S11 CBReq sequence = %d; want allocated sequence 1", req.SequenceNumber)
	}
	if len(req.BearerContexts) != 2 {
		t.Fatalf("S11 CBReq Bearer Context count = %d; want both PGW contexts", len(req.BearerContexts))
	}
	assertS11CreateBearerContext(t, req.BearerContexts[0], 0x90000003, 0x11223344, []byte{0x21, 0x01, 0x02})
	assertS11CreateBearerContext(t, req.BearerContexts[1], 0x90000005, 0x55667788, []byte{0x21, 0x03, 0x04})
}

func TestCreateBearerTxnCachesMarshaledErrorResponse(t *testing.T) {
	h := &Handler{}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x0BE02E49,
		SequenceNumber: 0x010203,
	}
	sess := &session.SGWSession{SessionID: "test-session"}

	txn, action := h.beginCreateBearerTxn(pgwAddr, hdr, []byte{0x48, message.MsgTypeCreateBearerRequest}, sess)
	if action != createBearerTxnActionNew {
		t.Fatalf("first action = %v; want new", action)
	}

	raw, err := marshalBearerError(hdr, message.MsgTypeCreateBearerResponse, 0x10203040, ie.CauseSystemFailure)
	if err != nil {
		t.Fatalf("marshalBearerError: %v", err)
	}
	h.completeCreateBearerTxn(txn.key, raw, ie.CauseSystemFailure)

	cached, action := h.beginCreateBearerTxn(pgwAddr, hdr, []byte{0x48, message.MsgTypeCreateBearerRequest}, sess)
	if action != createBearerTxnActionCached {
		t.Fatalf("post-error action = %v; want cached", action)
	}
	parsedHdr, ies, err := message.Parse(cached.s5cResponse)
	if err != nil {
		t.Fatalf("Parse cached response: %v", err)
	}
	if parsedHdr.MessageType != message.MsgTypeCreateBearerResponse {
		t.Fatalf("cached message type = %d; want %d", parsedHdr.MessageType, message.MsgTypeCreateBearerResponse)
	}
	if parsedHdr.TEID != 0x10203040 {
		t.Fatalf("cached TEID = 0x%08X; want 0x10203040", parsedHdr.TEID)
	}
	if parsedHdr.SequenceNumber != hdr.SequenceNumber {
		t.Fatalf("cached sequence = %d; want %d", parsedHdr.SequenceNumber, hdr.SequenceNumber)
	}
	if len(ies) != 1 || ies[0].Type != ie.TypeCause {
		t.Fatalf("cached IEs = %#v; want one Cause IE", ies)
	}
	cause, err := ies[0].CauseValue()
	if err != nil {
		t.Fatalf("CauseValue: %v", err)
	}
	if cause != ie.CauseSystemFailure {
		t.Fatalf("cached cause = %d; want %d", cause, ie.CauseSystemFailure)
	}
}

func assertS11CreateBearerRequestWire(t *testing.T, raw []byte, wantTEID, wantSeq uint32, wantLBI, wantSGWS1UTEID, wantPGWS5UTEID uint32) {
	t.Helper()
	req, err := message.ParseCreateBearerRequest(raw)
	if err != nil {
		t.Fatalf("Parse S11 Create Bearer Request: %v", err)
	}
	if req.TEID != wantTEID {
		t.Fatalf("S11 CBReq TEID = 0x%08X; want 0x%08X", req.TEID, wantTEID)
	}
	if req.SequenceNumber != wantSeq {
		t.Fatalf("S11 CBReq seq = 0x%06X; want 0x%06X", req.SequenceNumber, wantSeq)
	}
	if req.LBI == nil || req.LBI.Instance != 0 {
		t.Fatalf("S11 CBReq LBI missing or wrong instance; got %#v", req.LBI)
	}
	lbi, err := req.LBI.EBIValue()
	if err != nil || lbi != uint8(wantLBI) {
		t.Fatalf("S11 CBReq LBI = %d err=%v; want %d per TS 29.274 Table 7.2.3-1", lbi, err, wantLBI)
	}
	if len(req.BearerContexts) != 1 {
		t.Fatalf("S11 CBReq Bearer Context count = %d; want 1", len(req.BearerContexts))
	}
	bc := req.BearerContexts[0]
	if bc.Instance != 0 {
		t.Fatalf("S11 CBReq Bearer Context instance = %d; want 0", bc.Instance)
	}
	children, err := bc.ChildIEs()
	if err != nil {
		t.Fatalf("S11 CBReq Bearer Context children: %v", err)
	}

	ebiIE := ie.FindFirst(children, ie.TypeEBI)
	if ebiIE == nil || ebiIE.Instance != 0 {
		t.Fatalf("S11 CBReq Bearer Context EBI missing or wrong instance; got %#v", ebiIE)
	}
	ebi, err := ebiIE.EBIValue()
	if err != nil || ebi != 0 {
		t.Fatalf("S11 CBReq Bearer Context EBI = %d err=%v; want 0 per TS 29.274 Table 7.2.3-2", ebi, err)
	}

	tftIE := ie.FindFirst(children, ie.TypeBearerTFT)
	if tftIE == nil || tftIE.Instance != 0 {
		t.Fatalf("S11 CBReq Bearer TFT missing or wrong instance; got %#v", tftIE)
	}
	tft, err := tftIE.BearerTFTValue()
	if err != nil || string(tft) != string([]byte{0x21, 0x01, 0x02}) {
		t.Fatalf("S11 CBReq Bearer TFT = % X err=%v; want 21 01 02", tft, err)
	}

	sgwS1U := ie.FindInstance(children, ie.TypeFTEID, 0)
	if sgwS1U == nil {
		t.Fatal("S11 CBReq missing S1-U SGW F-TEID instance 0 per TS 29.274 Table 7.2.3-2")
	}
	sgwF, err := sgwS1U.FTEIDValue()
	if err != nil {
		t.Fatalf("S11 CBReq S1-U SGW F-TEID decode: %v", err)
	}
	if sgwF.IntfType != ie.IFTypeS1USGW || sgwF.TEID != wantSGWS1UTEID || sgwF.IPv4 != netip.MustParseAddr("10.90.250.59") {
		t.Fatalf("S11 CBReq S1-U SGW F-TEID = iftype=%d teid=0x%08X ip=%s; want iftype=%d teid=0x%08X ip=10.90.250.59",
			sgwF.IntfType, sgwF.TEID, sgwF.IPv4, ie.IFTypeS1USGW, wantSGWS1UTEID)
	}

	pgwS5U := ie.FindInstance(children, ie.TypeFTEID, 1)
	if pgwS5U == nil {
		t.Fatal("S11 CBReq missing S5/S8-U PGW F-TEID instance 1 per TS 29.274 Table 7.2.3-2")
	}
	pgwF, err := pgwS5U.FTEIDValue()
	if err != nil {
		t.Fatalf("S11 CBReq S5/S8-U PGW F-TEID decode: %v", err)
	}
	if pgwF.IntfType != ie.IFTypeS5S8UPGW || pgwF.TEID != wantPGWS5UTEID || pgwF.IPv4 != netip.MustParseAddr("10.90.252.92") {
		t.Fatalf("S11 CBReq S5/S8-U PGW F-TEID = iftype=%d teid=0x%08X ip=%s; want iftype=%d teid=0x%08X ip=10.90.252.92",
			pgwF.IntfType, pgwF.TEID, pgwF.IPv4, ie.IFTypeS5S8UPGW, wantPGWS5UTEID)
	}

	qosIE := ie.FindFirst(children, ie.TypeBearerQoS)
	if qosIE == nil || qosIE.Instance != 0 {
		t.Fatalf("S11 CBReq Bearer QoS missing or wrong instance; got %#v", qosIE)
	}
	if len(qosIE.Value) != 22 {
		t.Fatalf("S11 CBReq Bearer QoS length = %d; want 22", len(qosIE.Value))
	}
}

func assertBearerContextChildOrder(t *testing.T, got []*ie.IE, want []struct {
	typ  uint8
	inst uint8
}) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("Bearer Context child count = %d; want %d", len(got), len(want))
	}
	for i, wantIE := range want {
		if got[i].Type != wantIE.typ || got[i].Instance != wantIE.inst {
			t.Fatalf("Bearer Context child[%d] = type %d inst %d; want type %d inst %d",
				i, got[i].Type, got[i].Instance, wantIE.typ, wantIE.inst)
		}
	}
}

func assertS11CreateBearerContext(t *testing.T, bc *ie.IE, wantSGWS1UTEID, wantPGWS5UTEID uint32, wantTFT []byte) {
	t.Helper()
	if bc == nil || bc.Type != ie.TypeBearerContext || bc.Instance != 0 {
		t.Fatalf("S11 CBReq Bearer Context = %#v; want instance 0 Bearer Context", bc)
	}
	children, err := bc.ChildIEs()
	if err != nil {
		t.Fatalf("S11 CBReq Bearer Context children: %v", err)
	}

	ebiIE := ie.FindFirst(children, ie.TypeEBI)
	if ebiIE == nil || ebiIE.Instance != 0 {
		t.Fatalf("S11 CBReq Bearer Context EBI missing or wrong instance; got %#v", ebiIE)
	}
	ebi, err := ebiIE.EBIValue()
	if err != nil || ebi != 0 {
		t.Fatalf("S11 CBReq Bearer Context EBI = %d err=%v; want 0 per TS 29.274 Table 7.2.3-2", ebi, err)
	}

	tftIE := ie.FindFirst(children, ie.TypeBearerTFT)
	if tftIE == nil || tftIE.Instance != 0 {
		t.Fatalf("S11 CBReq Bearer TFT missing or wrong instance; got %#v", tftIE)
	}
	tft, err := tftIE.BearerTFTValue()
	if err != nil || string(tft) != string(wantTFT) {
		t.Fatalf("S11 CBReq Bearer TFT = % X err=%v; want % X", tft, err, wantTFT)
	}

	sgwS1U := ie.FindInstance(children, ie.TypeFTEID, 0)
	if sgwS1U == nil {
		t.Fatal("S11 CBReq missing S1-U SGW F-TEID instance 0")
	}
	sgwF, err := sgwS1U.FTEIDValue()
	if err != nil {
		t.Fatalf("S11 CBReq S1-U SGW F-TEID decode: %v", err)
	}
	if sgwF.IntfType != ie.IFTypeS1USGW || sgwF.TEID != wantSGWS1UTEID || sgwF.IPv4 != netip.MustParseAddr("10.90.250.59") {
		t.Fatalf("S11 CBReq S1-U SGW F-TEID = iftype=%d teid=0x%08X ip=%s; want iftype=%d teid=0x%08X ip=10.90.250.59",
			sgwF.IntfType, sgwF.TEID, sgwF.IPv4, ie.IFTypeS1USGW, wantSGWS1UTEID)
	}

	pgwS5U := ie.FindInstance(children, ie.TypeFTEID, 1)
	if pgwS5U == nil {
		t.Fatal("S11 CBReq missing S5/S8-U PGW F-TEID instance 1")
	}
	pgwF, err := pgwS5U.FTEIDValue()
	if err != nil {
		t.Fatalf("S11 CBReq S5/S8-U PGW F-TEID decode: %v", err)
	}
	if pgwF.IntfType != ie.IFTypeS5S8UPGW || pgwF.TEID != wantPGWS5UTEID || pgwF.IPv4 != netip.MustParseAddr("10.90.252.92") {
		t.Fatalf("S11 CBReq S5/S8-U PGW F-TEID = iftype=%d teid=0x%08X ip=%s; want iftype=%d teid=0x%08X ip=10.90.252.92",
			pgwF.IntfType, pgwF.TEID, pgwF.IPv4, ie.IFTypeS5S8UPGW, wantPGWS5UTEID)
	}

	qosIE := ie.FindFirst(children, ie.TypeBearerQoS)
	if qosIE == nil || qosIE.Instance != 0 || len(qosIE.Value) != 22 {
		t.Fatalf("S11 CBReq Bearer QoS missing/wrong; got %#v", qosIE)
	}
	if chargingID := ie.FindFirst(children, ie.TypeChargingID); chargingID != nil {
		t.Fatalf("S11 CBReq Bearer Context contains Charging ID %#v; Cisco-compatible S11 Create Bearer shape must omit it", chargingID)
	}
}

func loadCreateBearerShapeFixture(t *testing.T) createBearerShapeFixture {
	t.Helper()
	path := filepath.Join("..", "..", "..", "docs", "fixtures", "s11-create-bearer-known-good-shape.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read known-good fixture %s: %v", path, err)
	}
	var fixture createBearerShapeFixture
	if err := json.Unmarshal(raw, &fixture); err != nil {
		t.Fatalf("parse known-good fixture %s: %v", path, err)
	}
	return fixture
}

func decodeCreateBearerShape(t *testing.T, raw []byte) createBearerShapeFixture {
	t.Helper()
	hdr, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse S11 Create Bearer Request: %v", err)
	}
	out := createBearerShapeFixture{
		Name:        "known-good-s11-create-bearer-request-shape",
		Source:      "Decoded fixture for TS 29.274 Rel-15 S11 Create Bearer Request shape; replace or extend with an external known-good SGW capture when available.",
		MessageType: hdr.MessageType,
		TEID:        hdr.TEID,
		Sequence:    hdr.SequenceNumber,
	}
	for _, topIE := range ies {
		out.TopLevelOrder = append(out.TopLevelOrder, decodeCreateBearerShapeIE(t, topIE, true))
	}
	return out
}

func decodeCreateBearerShapeIE(t *testing.T, got *ie.IE, topLevel bool) createBearerShapeIE {
	t.Helper()
	out := createBearerShapeIE{
		Type:     got.Type,
		Name:     gtpcIEName(got.Type),
		Instance: got.Instance,
		Length:   len(got.Value),
	}
	switch got.Type {
	case ie.TypeEBI:
		if topLevel {
			out.Name = "Linked EPS Bearer ID"
		}
		ebi, err := got.EBIValue()
		if err != nil {
			t.Fatalf("decode EBI IE: %v", err)
		}
		out.Value = uint8Ptr(ebi)
	case ie.TypeBearerTFT:
		tft, err := got.BearerTFTValue()
		if err != nil {
			t.Fatalf("decode Bearer TFT IE: %v", err)
		}
		out.Hex = hex.EncodeToString(tft)
	case ie.TypeFTEID:
		fteid, err := got.FTEIDValue()
		if err != nil {
			t.Fatalf("decode F-TEID IE: %v", err)
		}
		switch {
		case got.Instance == 0 && fteid.IntfType == ie.IFTypeS1USGW:
			out.Name = "S1-U SGW F-TEID"
		case got.Instance == 1 && fteid.IntfType == ie.IFTypeS5S8UPGW:
			out.Name = "S5/S8-U PGW F-TEID"
		}
		out.InterfaceType = uint8Ptr(fteid.IntfType)
		out.TEID = uint32Ptr(fteid.TEID)
		out.IPv4 = fteid.IPv4.String()
	case ie.TypeBearerQoS:
		out.Hex = hex.EncodeToString(got.Value)
	case ie.TypeBearerContext:
		children, err := got.ChildIEs()
		if err != nil {
			t.Fatalf("decode Bearer Context children: %v", err)
		}
		for _, child := range children {
			out.Children = append(out.Children, decodeCreateBearerShapeIE(t, child, false))
		}
	}
	return out
}

func uint8Ptr(v uint8) *uint8 {
	return &v
}

func uint32Ptr(v uint32) *uint32 {
	return &v
}

func assertS5CCreateBearerResponseContext(t *testing.T, bc *ie.IE, wantEBI, wantCause uint8, wantSGWS5UTEID, wantPGWS5UTEID uint32) {
	t.Helper()
	if bc == nil || bc.Type != ie.TypeBearerContext || bc.Instance != 0 {
		t.Fatalf("S5/S8-C CBResp Bearer Context = %#v; want instance 0 Bearer Context", bc)
	}
	children, err := bc.ChildIEs()
	if err != nil {
		t.Fatalf("S5/S8-C CBResp Bearer Context children: %v", err)
	}
	ebiIE := ie.FindFirst(children, ie.TypeEBI)
	if ebiIE == nil || ebiIE.Instance != 0 {
		t.Fatalf("S5/S8-C CBResp Bearer Context EBI missing or wrong instance; got %#v", ebiIE)
	}
	ebi, err := ebiIE.EBIValue()
	if err != nil || ebi != wantEBI {
		t.Fatalf("S5/S8-C CBResp Bearer Context EBI = %d err=%v; want %d", ebi, err, wantEBI)
	}
	causeIE := ie.FindFirst(children, ie.TypeCause)
	if causeIE == nil || causeIE.Instance != 0 {
		t.Fatalf("S5/S8-C CBResp Bearer Context Cause missing or wrong instance; got %#v", causeIE)
	}
	cause, err := causeIE.CauseValue()
	if err != nil || cause != wantCause {
		t.Fatalf("S5/S8-C CBResp Bearer Context Cause = %d err=%v; want %d", cause, err, wantCause)
	}
	sgwS5U := ie.FindInstance(children, ie.TypeFTEID, 2)
	if sgwS5U == nil {
		t.Fatal("S5/S8-C CBResp missing S5/S8-U SGW F-TEID instance 2 per TS 29.274 Table 7.2.4-2")
	}
	sgwF, err := sgwS5U.FTEIDValue()
	if err != nil {
		t.Fatalf("S5/S8-C CBResp S5/S8-U SGW F-TEID decode: %v", err)
	}
	if sgwF.IntfType != ie.IFTypeS5S8USGW || sgwF.TEID != wantSGWS5UTEID || sgwF.IPv4 != netip.MustParseAddr("10.90.250.59") {
		t.Fatalf("S5/S8-C CBResp S5/S8-U SGW F-TEID = iftype=%d teid=0x%08X ip=%s; want iftype=%d teid=0x%08X ip=10.90.250.59",
			sgwF.IntfType, sgwF.TEID, sgwF.IPv4, ie.IFTypeS5S8USGW, wantSGWS5UTEID)
	}
	pgwS5U := ie.FindInstance(children, ie.TypeFTEID, 3)
	if pgwS5U == nil {
		t.Fatal("S5/S8-C CBResp missing S5/S8-U PGW F-TEID instance 3 per Cisco S5/S8-C reference")
	}
	pgwF, err := pgwS5U.FTEIDValue()
	if err != nil {
		t.Fatalf("S5/S8-C CBResp S5/S8-U PGW F-TEID decode: %v", err)
	}
	if pgwF.IntfType != ie.IFTypeS5S8UPGW || pgwF.TEID != wantPGWS5UTEID || pgwF.IPv4 != netip.MustParseAddr("10.90.252.92") {
		t.Fatalf("S5/S8-C CBResp S5/S8-U PGW F-TEID = iftype=%d teid=0x%08X ip=%s; want iftype=%d teid=0x%08X ip=10.90.252.92",
			pgwF.IntfType, pgwF.TEID, pgwF.IPv4, ie.IFTypeS5S8UPGW, wantPGWS5UTEID)
	}
	if chargingID := ie.FindFirst(children, ie.TypeChargingID); chargingID != nil {
		t.Fatalf("S5/S8-C CBResp Bearer Context echoed Charging ID %#v; response must not echo PGW Charging ID", chargingID)
	}
}

func TestCreateBearerErrorResponseIncludesBearerContextResults(t *testing.T) {
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x0BE02E49,
		SequenceNumber: 0x010203,
	}
	cbReq := &message.CreateBearerRequest{
		BearerContexts: []*ie.IE{
			ie.NewBearerContext(0,
				ie.NewEBI(0),
				ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
				ie.NewBearerQoS(1, 2, 0, 5, 128000, 128000, 64000, 64000),
			),
		},
	}

	raw, err := marshalCreateBearerErrorResponse(hdr, 0x10203040, ie.CauseMandatoryIEMissing, cbReq)
	if err != nil {
		t.Fatalf("marshalCreateBearerErrorResponse: %v", err)
	}
	resp, err := message.ParseCreateBearerResponse(raw)
	if err != nil {
		t.Fatalf("ParseCreateBearerResponse: %v", err)
	}
	if resp.TEID != 0x10203040 {
		t.Fatalf("response TEID = 0x%08X; want 0x10203040", resp.TEID)
	}
	if resp.SequenceNumber != hdr.SequenceNumber {
		t.Fatalf("response sequence = %d; want %d", resp.SequenceNumber, hdr.SequenceNumber)
	}
	cause, err := resp.Cause.CauseValue()
	if err != nil || cause != ie.CauseMandatoryIEMissing {
		t.Fatalf("message cause = %d err=%v; want %d", cause, err, ie.CauseMandatoryIEMissing)
	}
	if len(resp.BearerContexts) != 1 {
		t.Fatalf("bearer contexts = %d; want 1", len(resp.BearerContexts))
	}
	children, err := resp.BearerContexts[0].ChildIEs()
	if err != nil {
		t.Fatalf("response bearer context children: %v", err)
	}
	ebi, err := ie.FindFirst(children, ie.TypeEBI).EBIValue()
	if err != nil || ebi != 0 {
		t.Fatalf("response BC EBI = %d err=%v; want 0", ebi, err)
	}
	bcCause, err := ie.FindFirst(children, ie.TypeCause).CauseValue()
	if err != nil || bcCause != ie.CauseMandatoryIEMissing {
		t.Fatalf("response BC cause = %d err=%v; want %d", bcCause, err, ie.CauseMandatoryIEMissing)
	}
}

func TestCreateBearerTxnProvisioningStateAndRollbackGuard(t *testing.T) {
	h := &Handler{}
	pgwAddr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 2123}
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x0BE02E49,
		SequenceNumber: 0x010203,
	}
	sess := &session.SGWSession{SessionID: "test-session"}

	txn, action := h.beginCreateBearerTxn(pgwAddr, hdr, []byte{0x48, message.MsgTypeCreateBearerRequest}, sess)
	if action != createBearerTxnActionNew {
		t.Fatalf("first action = %v; want new", action)
	}
	provs := []bearerProvisioning{
		{pdrUL: 3, pdrDL: 4, farUL: 3, farDL: 4},
		{pdrUL: 5, pdrDL: 6, farUL: 5, farDL: 6},
	}

	h.markCreateBearerTxnProvisioned(txn.key, provs)
	if !txn.pfcpProvisionalDone {
		t.Fatalf("pfcpProvisionalDone = false; want true")
	}
	if len(txn.provisionedBearers) != len(provs) {
		t.Fatalf("provisionedBearers len = %d; want %d", len(txn.provisionedBearers), len(provs))
	}
	provs[0].pdrUL = 99
	if txn.provisionedBearers[0].pdrUL != 3 {
		t.Fatalf("provisionedBearers was not copied")
	}

	if !h.markCreateBearerTxnRolledBack(txn.key, txn.provisionedBearers[0]) {
		t.Fatalf("first rollback mark = false; want true")
	}
	if h.markCreateBearerTxnRolledBack(txn.key, txn.provisionedBearers[0]) {
		t.Fatalf("second rollback mark = true; want false")
	}
	if !h.markCreateBearerTxnRolledBack(txn.key, txn.provisionedBearers[1]) {
		t.Fatalf("different rule rollback mark = false; want true")
	}
}

func TestDescribeS11CreateBearerRequestBuildShape(t *testing.T) {
	s1uIP := netip.MustParseAddr("192.0.2.20")
	s5uIP := netip.MustParseAddr("192.0.2.30")
	bcs := []*ie.IE{
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(0, ie.IFTypeS1USGW, 0x11223344, s1uIP),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x55667788, s5uIP),
			ie.NewBearerQoS(1, 2, 0, 5, 128000, 128000, 64000, 64000),
		),
	}

	got := describeS11CreateBearerRequestBuild(5, bcs)
	if got.LinkedEBI != 5 {
		t.Fatalf("LinkedEBI = %d; want 5", got.LinkedEBI)
	}
	if got.BearerContexts != 1 || len(got.Bearers) != 1 {
		t.Fatalf("BearerContexts/Bearers = %d/%d; want 1/1", got.BearerContexts, len(got.Bearers))
	}
	b := got.Bearers[0]
	if b.Index != 0 || b.GroupedLength == 0 {
		t.Fatalf("bearer index/length = %d/%d; want index 0 with nonzero length", b.Index, b.GroupedLength)
	}
	if b.EBI != 0 || b.EBIInstance != 0 {
		t.Fatalf("EBI/instance = %d/%d; want 0/0 per TS 29.274 Table 7.2.3-2", b.EBI, b.EBIInstance)
	}
	if !b.HasTFT || b.TFTLength != 3 || b.TFTInstance != 0 {
		t.Fatalf("TFT present/len/inst = %v/%d/%d; want true/3/0", b.HasTFT, b.TFTLength, b.TFTInstance)
	}
	if !b.HasBearerQoS || b.BearerQoSLength != 22 || b.BearerQoSInst != 0 {
		t.Fatalf("QoS present/len/inst = %v/%d/%d; want true/22/0", b.HasBearerQoS, b.BearerQoSLength, b.BearerQoSInst)
	}
	if !b.HasSGWS1UFTEID || b.SGWS1UIFType != ie.IFTypeS1USGW || b.SGWS1UTEID != 0x11223344 || b.SGWS1UIP != s1uIP.String() {
		t.Fatalf("SGW S1-U F-TEID = %+v; want iftype=%d teid=0x11223344 ip=%s", b, ie.IFTypeS1USGW, s1uIP)
	}
	if !b.HasPGWS5UFTEID || b.PGWS5UIFType != ie.IFTypeS5S8UPGW || b.PGWS5UTEID != 0x55667788 || b.PGWS5UIP != s5uIP.String() {
		t.Fatalf("PGW S5/S8-U F-TEID = %+v; want iftype=%d teid=0x55667788 ip=%s", b, ie.IFTypeS5S8UPGW, s5uIP)
	}
}
