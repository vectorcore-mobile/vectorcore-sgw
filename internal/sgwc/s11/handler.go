// Package s11 implements the SGW-C S11 GTPv2-C interface toward the MME
// per 3GPP TS 29.274.
package s11

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
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

// Handler processes inbound S11 messages from the MME.
type Handler struct {
	cfg              *sgwcconfig.Config
	conn             gtpcConn
	log              *slog.Logger
	sessions         *session.Manager
	recovery         *recovery.Counter
	s5c              s5cClient
	pfcp             pfcpClient
	collisionMetrics collisionMetrics
	nsaMetrics       nsaMetrics
	ddnCtl           *ddncontrol.State
	peerHealth       *peerhealth.Table
	collisionMode    collision.Mode
	collisionTimeout time.Duration
	baseCtx          context.Context
	localIP          netip.Addr // SGW-C S11 control-plane IP for Sender F-TEID IEs
	peerSeen         sync.Map   // addr string → uint8; last restart counter advertised to each MME peer

	cbTxnMu        sync.Mutex
	cbTxns         map[createBearerTxnKey]*createBearerTxnState
	cbFPs          map[createBearerFingerprintKey]*createBearerTxnState
	cbS11          map[s11CreateBearerResponseKey]*pendingS11CreateBearer
	cbProcFailures map[createBearerProcedureKey]*createBearerProcedureFailure

	dbCmdMu sync.Mutex
	dbCmds  map[deleteBearerCommandPendingKey]deleteBearerCommandPending
}

type gtpcConn interface {
	AllocSeq() uint32
	Send(ctx context.Context, addr *net.UDPAddr, raw []byte) ([]byte, error)
	Reply(addr *net.UDPAddr, raw []byte) error
	Serve(ctx context.Context) error
	Close() error
	LocalAddr() net.Addr
}

type s5cClient interface {
	PGWAddr(s11req *message.CreateSessionRequest) (*net.UDPAddr, error)
	CreateSession(ctx context.Context, pgwAddr *net.UDPAddr, s11req *message.CreateSessionRequest, sgwS5CTEID uint32, sgwUS5UFTEID bearer.FTEID) (*s5c.CreateSessionResult, error)
	DispatchPiggybacks(pgwAddr *net.UDPAddr, frames []message.Frame)
	DeleteSession(ctx context.Context, sess *session.SGWSession) (uint8, error)
	DeleteSessionFromS11(ctx context.Context, sess *session.SGWSession, req *message.DeleteSessionRequest) (uint8, error)
	ModifyBearerFromS11(ctx context.Context, sess *session.SGWSession, req *message.ModifyBearerRequest) (uint8, error)
	ReplyToPGW(pgwAddr *net.UDPAddr, raw []byte) error
	AllocTEID() (uint32, error)
	FreeTEID(teid uint32)
}

type pfcpClient interface {
	AllocCPSEID() uint64
	EstablishSession(ctx context.Context, params pfcpclient.SessionParams) (*pfcpclient.SessionResult, error)
	ModifySessionOnPeer(ctx context.Context, peerAddr string, cpSEID, upSEID uint64, updates []pfcpclient.FARUpdate) error
	AddBearerRulesOnPeer(ctx context.Context, peerAddr string, cpSEID, upSEID uint64, createPDRs, createFARs []*pfcpie.IE) ([]*pfcpie.IE, error)
	RemoveBearerRulesOnPeer(ctx context.Context, peerAddr string, cpSEID, upSEID uint64, pdrIDs, farIDs []uint32) error
	DeleteSessionOnPeer(ctx context.Context, peerAddr string, cpSEID, upSEID uint64) error
}

type s11CreateBearerResponseKey struct {
	peer string
	seq  uint32
}

type pendingS11CreateBearer struct {
	pgwAddr     *net.UDPAddr
	mmeAddr     string
	hdr         message.Header
	cbReq       *message.CreateBearerRequest
	sess        *session.SGWSession
	txn         *createBearerTxnState
	activeProc  collision.ActiveProcedure
	bearerProvs []bearerProvisioning
	csrspSeq    uint32
	s11Seq      uint32
	linkedEBI   uint8
	createdAt   time.Time
}

// New creates a new S11 handler, binds the S11 UDP listener, and wires the session manager.
// s5cClient is the S5/S8-C client for relaying procedures to the PGW.
// pfcpClient is the PFCP/Sxa client for provisioning the SGW-U data plane.
// localIP is the SGW-C control-plane IP included in Sender F-TEID IEs on S11.
func New(cfg *sgwcconfig.Config, sessions *session.Manager, rc *recovery.Counter, s5cClient *s5c.Client, pfcpClient *pfcpclient.Client, localIP netip.Addr, log *slog.Logger) (*Handler, error) {
	conn, err := transport.Listen(
		cfg.S11Listen(),
		cfg.S11.T3ResponseSeconds,
		cfg.S11.N3Requests,
		log,
	)
	if err != nil {
		return nil, fmt.Errorf("s11 listen: %w", err)
	}
	if cfg.QoS.OuterMarking.Enabled && cfg.QoS.OuterMarking.GTPC.Enabled {
		if err := conn.SetDSCP(uint8(cfg.QoS.OuterMarking.GTPC.DSCP)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("s11 QoS outer marking: %w", err)
		}
	}
	h := &Handler{
		cfg:              cfg,
		conn:             conn,
		log:              log,
		sessions:         sessions,
		recovery:         rc,
		s5c:              s5cClient,
		pfcp:             pfcpClient,
		collisionMode:    collisionModeFromConfig(cfg),
		collisionTimeout: collisionTimeoutFromConfig(cfg),
		baseCtx:          context.Background(),
		localIP:          localIP,
		cbTxns:           make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:            make(map[createBearerFingerprintKey]*createBearerTxnState),
		cbS11:            make(map[s11CreateBearerResponseKey]*pendingS11CreateBearer),
		cbProcFailures:   make(map[createBearerProcedureKey]*createBearerProcedureFailure),
		dbCmds:           make(map[deleteBearerCommandPendingKey]deleteBearerCommandPending),
	}
	conn.SetHandler(h.handle)
	return h, nil
}

// NewWithConn creates an S11 handler using an already-bound GTPv2-C transport.
// This is used when S11 and S5/S8-C share one configured control binding.
func NewWithConn(cfg *sgwcconfig.Config, conn *transport.Conn, sessions *session.Manager, rc *recovery.Counter, s5cClient *s5c.Client, pfcpClient *pfcpclient.Client, localIP netip.Addr, log *slog.Logger) *Handler {
	h := &Handler{
		cfg:              cfg,
		conn:             conn,
		log:              log,
		sessions:         sessions,
		recovery:         rc,
		s5c:              s5cClient,
		pfcp:             pfcpClient,
		collisionMode:    collisionModeFromConfig(cfg),
		collisionTimeout: collisionTimeoutFromConfig(cfg),
		baseCtx:          context.Background(),
		localIP:          localIP,
		cbTxns:           make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:            make(map[createBearerFingerprintKey]*createBearerTxnState),
		cbS11:            make(map[s11CreateBearerResponseKey]*pendingS11CreateBearer),
		cbProcFailures:   make(map[createBearerProcedureKey]*createBearerProcedureFailure),
		dbCmds:           make(map[deleteBearerCommandPendingKey]deleteBearerCommandPending),
	}
	return h
}

// Serve starts the S11 read loop. Blocks until ctx is cancelled.
func (h *Handler) Serve(ctx context.Context) error {
	h.SetBaseContext(ctx)
	h.log.Info("S11 listening", "addr", h.conn.LocalAddr())
	return h.conn.Serve(ctx)
}

func (h *Handler) SetBaseContext(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	h.baseCtx = ctx
}

func (h *Handler) operationContext() (context.Context, context.CancelFunc) {
	base := context.Background()
	if h != nil && h.baseCtx != nil {
		base = h.baseCtx
	}
	return context.WithTimeout(base, h.operationTimeout())
}

func (h *Handler) operationTimeout() time.Duration {
	if h != nil && h.cfg != nil && h.cfg.S11.T3ResponseSeconds > 0 && h.cfg.S11.N3Requests > 0 {
		return time.Duration(h.cfg.S11.T3ResponseSeconds*h.cfg.S11.N3Requests) * time.Second
	}
	return time.Duration(3*5) * time.Second
}

// Close shuts down the S11 listener.
func (h *Handler) Close() error {
	return h.conn.Close()
}

func (h *Handler) SetPeerHealth(table *peerhealth.Table) {
	h.peerHealth = table
}

func (h *Handler) SetDDNControl(state *ddncontrol.State) {
	h.ddnCtl = state
}

func (h *Handler) AllocSeq() uint32 {
	return h.conn.AllocSeq()
}

func (h *Handler) SendEcho(ctx context.Context, addr string, seq uint32) (*peerhealth.EchoResult, error) {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve MME Echo peer %q: %w", addr, err)
	}
	var rec *uint8
	if h.recovery != nil {
		v := h.recovery.Value()
		rec = &v
	}
	raw, err := message.MarshalEchoRequest(seq, rec)
	if err != nil {
		return nil, fmt.Errorf("marshal MME Echo Request: %w", err)
	}
	start := time.Now()
	respRaw, err := h.conn.Send(ctx, udpAddr, raw)
	if err != nil {
		return nil, err
	}
	rtt := time.Since(start)
	hdr, ies, err := message.Parse(respRaw)
	if err != nil {
		return nil, fmt.Errorf("parse MME Echo Response: %w", err)
	}
	if hdr.MessageType != message.MsgTypeEchoResponse {
		return nil, fmt.Errorf("unexpected MME Echo response message type %d", hdr.MessageType)
	}
	resp := message.ParseEchoResponse(hdr, ies)
	return &peerhealth.EchoResult{RTT: rtt, Recovery: recoveryIEValuePtr(resp.Recovery)}, nil
}

func (h *Handler) SendDownlinkDataNotification(ctx context.Context, sess *session.SGWSession) (uint32, error) {
	if h == nil || h.conn == nil {
		return 0, fmt.Errorf("S11 DDN sender unavailable")
	}
	if sess == nil {
		return 0, fmt.Errorf("S11 DDN session is nil")
	}
	if sess.MMEControlFTEID.TEID == 0 || !sess.MMEControlFTEID.IPv4.IsValid() {
		return 0, fmt.Errorf("S11 DDN missing MME S11 F-TEID")
	}
	b := sess.GetBearer(sess.DefaultBearerID)
	if b == nil {
		return 0, fmt.Errorf("S11 DDN missing default bearer EBI %d", sess.DefaultBearerID)
	}

	seq := h.conn.AllocSeq()
	raw, err := message.MarshalDownlinkDataNotification(
		sess.MMEControlFTEID.TEID,
		seq,
		ie.NewIMSI(sess.IMSI),
		ie.NewEBI(sess.DefaultBearerID),
		newARPFromBearer(b.ARP),
		ie.NewFTEID(0, ie.IFTypeS11S4SGW, sess.SGWS11FTEID.TEID, h.localIP),
	)
	if err != nil {
		return 0, fmt.Errorf("marshal S11 DDN: %w", err)
	}

	mmeIP4 := sess.MMEControlFTEID.IPv4.As4()
	mmeAddr := &net.UDPAddr{IP: mmeIP4[:], Port: peerhealth.GTPControlPort}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	if err := h.conn.Reply(mmeAddr, raw); err != nil {
		return 0, fmt.Errorf("send S11 DDN: %w", err)
	}
	h.log.Info("S11: Downlink Data Notification triggered for MME restoration",
		"mme", mmeAddr,
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"default_ebi", sess.DefaultBearerID,
		"mme_s11_teid", fmt.Sprintf("0x%08X", sess.MMEControlFTEID.TEID),
		"sgw_s11_teid", fmt.Sprintf("0x%08X", sess.SGWS11FTEID.TEID),
		"seq", seq)
	return seq, nil
}

func newARPFromBearer(arp bearer.ARP) *ie.IE {
	var pci, pvi uint8
	if arp.PreemptionCapability {
		pci = 1
	}
	if arp.PreemptionVulnerability {
		pvi = 1
	}
	return &ie.IE{Type: ie.TypeARP, Value: []byte{((pci & 1) << 6) | ((arp.PriorityLevel & 0x0F) << 2) | (pvi & 1)}}
}

func (h *Handler) SendStopPagingIndication(ctx context.Context, sess *session.SGWSession) (uint32, error) {
	if h == nil || h.conn == nil {
		return 0, fmt.Errorf("S11 Stop Paging sender unavailable")
	}
	if sess == nil {
		return 0, fmt.Errorf("S11 Stop Paging session is nil")
	}
	if sess.MMEControlFTEID.TEID == 0 || !sess.MMEControlFTEID.IPv4.IsValid() {
		return 0, fmt.Errorf("S11 Stop Paging missing MME S11 F-TEID")
	}

	seq := h.conn.AllocSeq()
	raw, err := message.MarshalStopPagingIndication(
		sess.MMEControlFTEID.TEID,
		seq,
		ie.NewIMSI(sess.IMSI),
	)
	if err != nil {
		return 0, fmt.Errorf("marshal S11 Stop Paging Indication: %w", err)
	}
	mmeIP4 := sess.MMEControlFTEID.IPv4.As4()
	mmeAddr := &net.UDPAddr{IP: mmeIP4[:], Port: peerhealth.GTPControlPort}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}
	if err := h.conn.Reply(mmeAddr, raw); err != nil {
		return 0, fmt.Errorf("send S11 Stop Paging Indication: %w", err)
	}
	sess.MarkMMERestorationStopPagingSent(seq, time.Now())
	h.log.Info("S11: Stop Paging Indication sent for MME restoration",
		"mme", mmeAddr,
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"default_ebi", sess.DefaultBearerID,
		"seq", seq)
	return seq, nil
}

func (h *Handler) handleDownlinkDataNotificationAck(addr *net.UDPAddr, raw []byte) {
	ack, err := message.ParseDownlinkDataNotificationAck(raw)
	if err != nil {
		h.log.Warn("S11: Downlink Data Notification Ack invalid", "from", addr, "error", err)
		return
	}
	cause, _ := ack.Cause.CauseValue()
	sess := h.findDDNRestorationSession(addr, ack.Header, ack.IMSI)
	if sess == nil {
		h.log.Warn("S11: Downlink Data Notification Ack unmatched",
			"from", addr,
			"teid", fmt.Sprintf("0x%08X", ack.TEID),
			"seq", ack.SequenceNumber,
			"cause", cause)
		return
	}
	now := time.Now()
	sess.MarkMMERestorationDDNAck(cause, now)
	throttleUntil := h.markDDNLowPriorityThrottle(addr, ack, now)
	stopPagingSeq, stopPagingErr := h.maybeSendStopPagingAfterDDNAck(sess, cause, now)
	h.log.Info("S11: Downlink Data Notification Ack received",
		"from", addr,
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"default_ebi", sess.DefaultBearerID,
		"teid", fmt.Sprintf("0x%08X", ack.TEID),
		"seq", ack.SequenceNumber,
		"cause", cause,
		"delay_present", ack.DataNotificationDelay != nil,
		"throttling_present", ack.LowPriorityTrafficThrottling != nil,
		"low_priority_throttle_until", throttleUntil,
		"stop_paging_seq", stopPagingSeq,
		"stop_paging_error", stopPagingErr)
}

func (h *Handler) maybeSendStopPagingAfterDDNAck(sess *session.SGWSession, cause uint8, at time.Time) (uint32, string) {
	if h == nil || h.cfg == nil || sess == nil {
		return 0, ""
	}
	if !h.cfg.GTPC.DDNControl.StopPagingEnabled || !h.cfg.GTPC.DDNControl.StopPagingOnDDNAck {
		return 0, ""
	}
	if cause != ie.CauseRequestAccepted {
		return 0, ""
	}
	status := sess.MMERestorationSnapshot()
	if !status.RestorationPending || !status.DDNTriggered || status.StopPagingSent || status.UserPlaneRestored {
		return 0, ""
	}
	timeout := time.Duration(h.cfg.GTPC.MMERestoration.CleanupTimeoutSeconds) * time.Second
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	seq, err := h.SendStopPagingIndication(ctx, sess)
	if err != nil {
		h.log.Warn("S11: Stop Paging Indication skipped after DDN Ack",
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"error", err)
		return 0, err.Error()
	}
	h.log.Info("S11: Stop Paging Indication triggered after DDN Ack",
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"default_ebi", sess.DefaultBearerID,
		"seq", seq,
		"at", at)
	return seq, ""
}

func (h *Handler) markDDNLowPriorityThrottle(addr *net.UDPAddr, ack *message.DownlinkDataNotificationAck, at time.Time) time.Time {
	if h == nil || h.ddnCtl == nil || ack == nil || ack.LowPriorityTrafficThrottling == nil {
		return time.Time{}
	}
	duration := h.ddnLowPriorityThrottleDuration(ack.LowPriorityTrafficThrottling)
	if duration <= 0 {
		return time.Time{}
	}
	mmeAddr := ""
	if addr != nil {
		mmeAddr = session.CanonicalGTPCEndpoint(addr.String())
	}
	if mmeAddr == "" {
		return time.Time{}
	}
	until := at.Add(duration)
	h.ddnCtl.MarkMMELowPriorityThrottled(mmeAddr, "ddn-ack-low-priority-throttling", until, at)
	return until
}

func (h *Handler) ddnLowPriorityThrottleDuration(throttling *ie.IE) time.Duration {
	if throttling != nil && len(throttling.Value) > 0 && throttling.Value[0] != 0 {
		return time.Duration(throttling.Value[0]) * time.Second
	}
	if h != nil && h.cfg != nil && h.cfg.GTPC.DDNControl.LowPriorityThrottleSeconds > 0 {
		return time.Duration(h.cfg.GTPC.DDNControl.LowPriorityThrottleSeconds) * time.Second
	}
	return 0
}

func (h *Handler) handleDownlinkDataNotificationFailureIndication(addr *net.UDPAddr, raw []byte) {
	ind, err := message.ParseDownlinkDataNotificationFailureIndication(raw)
	if err != nil {
		h.log.Warn("S11: Downlink Data Notification Failure Indication invalid", "from", addr, "error", err)
		return
	}
	cause, _ := ind.Cause.CauseValue()
	sess := h.findDDNRestorationSession(addr, ind.Header, ind.IMSI)
	if sess == nil {
		h.log.Warn("S11: Downlink Data Notification Failure Indication unmatched",
			"from", addr,
			"teid", fmt.Sprintf("0x%08X", ind.TEID),
			"seq", ind.SequenceNumber,
			"cause", cause)
		return
	}
	sess.MarkMMERestorationDDNFailureIndication(cause, time.Now())
	h.log.Warn("S11: Downlink Data Notification Failure Indication received",
		"from", addr,
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"default_ebi", sess.DefaultBearerID,
		"teid", fmt.Sprintf("0x%08X", ind.TEID),
		"seq", ind.SequenceNumber,
		"cause", cause)
}

func (h *Handler) findDDNRestorationSession(addr *net.UDPAddr, hdr message.Header, imsiIE *ie.IE) *session.SGWSession {
	if h == nil || h.sessions == nil || addr == nil {
		return nil
	}
	if sess := h.sessions.FindMMERestorationByDDN(addr.String(), hdr.TEID, hdr.SequenceNumber); sess != nil {
		return sess
	}
	if hdr.TEID != 0 {
		if sess := h.sessions.FindMMERestorationByDDN(addr.String(), 0, hdr.SequenceNumber); sess != nil {
			return sess
		}
	}
	if imsiIE != nil {
		if imsi, err := imsiIE.IMSI(); err == nil {
			return h.sessions.FindMMERestorationByIMSI(addr.String(), imsi)
		}
	}
	return nil
}

// Handle dispatches one inbound S11 GTPv2-C request. It is exported so the
// SGW-C shared control socket can route S11 messages without owning a second
// UDP listener.
func (h *Handler) Handle(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
	h.handle(conn, addr, hdr, raw)
}

func (h *Handler) handle(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
	_, ies, err := message.Parse(raw)
	if err != nil {
		h.log.Warn("S11: malformed message", "from", addr, "error", err)
		// Peer TEID cannot be determined from a malformed message; use 0.
		h.sendCause(conn, addr, hdr, 0, ie.CauseInvalidMessageFormat)
		return
	}
	switch hdr.MessageType {
	case message.MsgTypeEchoRequest:
		h.handleEchoRequest(conn, addr, hdr, ies)
	case message.MsgTypeCreateSessionRequest:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleCreateSessionRequest(conn, addr, hdr, ies)
	case message.MsgTypeModifyBearerRequest:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleModifyBearerRequest(conn, addr, hdr, ies)
	case message.MsgTypeCreateBearerResponse:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handlePiggybackCreateBearerResponse(conn, addr, hdr, raw)
	case message.MsgTypeDeleteSessionRequest:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleDeleteSessionRequest(conn, addr, hdr, ies)
	case message.MsgTypeReleaseAccessBearersRequest:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleReleaseAccessBearersRequest(conn, addr, hdr, ies)
	case message.MsgTypeDeleteBearerCommand:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleDeleteBearerCommand(conn, addr, hdr, raw)
	case message.MsgTypeDownlinkDataNotificationAck:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleDownlinkDataNotificationAck(addr, raw)
	case message.MsgTypeDownlinkDataNotificationFailureIndication:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleDownlinkDataNotificationFailureIndication(addr, raw)
	case message.MsgTypeUpdateBearerResponse, message.MsgTypeDeleteBearerResponse:
		h.observeGTPPeer(peerhealth.RoleMME, addr, hdr, ies)
		h.handleLateBearerResponse(addr, hdr, ies)
	default:
		h.log.Warn("S11: unhandled message type", "from", addr, "msg_type", hdr.MessageType)
	}
}

func (h *Handler) handleLateBearerResponse(addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	cause := uint8(0)
	if causeIE := ie.FindFirst(ies, ie.TypeCause); causeIE != nil {
		if v, err := causeIE.CauseValue(); err == nil {
			cause = v
		}
	}
	h.log.Warn("S11: late or unsolicited bearer response",
		"from", addr,
		"msg_type", hdr.MessageType,
		"teid", fmt.Sprintf("0x%08X", hdr.TEID),
		"seq", hdr.SequenceNumber,
		"cause", cause,
	)
}

func (h *Handler) observeGTPPeer(role peerhealth.Role, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	if h == nil || h.peerHealth == nil {
		return
	}
	h.peerHealth.Observe(role, addr, hdr.MessageType, hdr.SequenceNumber, recoveryValuePtr(ies))
}

func recoveryValuePtr(ies []*ie.IE) *uint8 {
	recIE := ie.FindFirst(ies, ie.TypeRecovery)
	return recoveryIEValuePtr(recIE)
}

func recoveryIEValuePtr(recIE *ie.IE) *uint8 {
	if recIE == nil {
		return nil
	}
	rec, err := recIE.RecoveryValue()
	if err != nil {
		return nil
	}
	return &rec
}

func (h *Handler) handleEchoRequest(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	req := message.ParseEchoRequest(hdr, ies)
	resp, err := message.MarshalEchoResponse(req, h.recovery.Value())
	if err != nil {
		h.log.Error("S11: echo response marshal failed", "error", err)
		return
	}
	if err := conn.Reply(addr, resp); err != nil {
		h.log.Warn("S11: echo response send failed", "to", addr, "error", err)
		return
	}
	h.log.Debug("S11: Echo", "from", addr, "seq", hdr.SequenceNumber)
}

func (h *Handler) handleCreateSessionRequest(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	opCtx, cancelOp := h.operationContext()
	defer cancelOp()

	// Extract peer (MME) TEID before parse so error responses carry the correct
	// response TEID per TS 29.274 Rel-15 §5.5.2 ("the node should look up the
	// remote peer's TEID and accordingly set the GTPv2-C header TEID"). On
	// initial attach hdr.TEID=0.
	peerTEID := peerTEIDFromIEs(ies)

	req, err := message.ParseCreateSessionRequest(hdr, ies)
	if err != nil {
		h.log.Warn("S11: Create Session Request invalid", "from", addr, "error", err)
		h.sendMissingIECause(conn, addr, hdr, peerTEID, err)
		return
	}

	// IMSI is Conditional per Table 7.2.1-1; use MEI as fallback for emergency UEs.
	var imsi string
	if req.IMSI != nil {
		imsi, _ = req.IMSI.IMSI()
	} else if req.MEI != nil {
		mei, _ := req.MEI.MEIValue()
		imsi = "mei:" + mei
	}

	apn, _ := req.APN.APNValue()
	ratType, _ := req.RATType.RATTypeValue()

	var servingNetwork string
	if req.ServingNetwork != nil {
		mcc, mnc, _ := req.ServingNetwork.ServingNetworkValue()
		servingNetwork = mcc + "-" + mnc
	}

	mmeF, _ := req.FTEID.FTEIDValue()
	mmeTEID := mmeF.TEID

	// Decode the default bearer context EBI and QoS.
	ebi, qci, arp := extractDefaultBearer(req.BearerContexts)

	var reuseSGWS11FTEID session.FTEID
	if hdr.TEID != 0 {
		if existing := h.sessions.FindByS11TEID(hdr.TEID); existing != nil {
			reuseSGWS11FTEID = existing.SGWS11FTEID
		}
	}

	sess, evicted, err := h.sessions.Create(session.CreateParams{
		IMSI:             imsi,
		APN:              apn,
		RATType:          ratType,
		ServingNetwork:   servingNetwork,
		ReuseSGWS11FTEID: reuseSGWS11FTEID,
		MMEControlFTEID: session.FTEID{
			TEID: mmeF.TEID,
			IPv4: mmeF.IPv4,
		},
		DefaultEBI:  ebi,
		QCI:         qci,
		ARP:         arp,
		MBRUplink:   0,
		MBRDownlink: 0,
	})
	if err != nil {
		h.log.Error("S11: session create failed", "from", addr, "error", err)
		h.sendCause(conn, addr, hdr, mmeTEID, ie.CauseSystemFailure)
		return
	}

	// C13: if an existing PDN connection was evicted (UE re-attach), send Delete
	// Session to PGW to release its bearer state before establishing the new session.
	if evicted != nil && evicted.PGWControlFTEID.TEID != 0 {
		h.clearCreateBearerProcedureFailuresForSession(evicted.SessionID, "reattach_evicted_session")
		h.log.Info("S11: re-attach detected — releasing evicted PGW session",
			"evicted_session_id", evicted.SessionID,
			"pgw_s5c_teid", fmt.Sprintf("0x%08X", evicted.PGWControlFTEID.TEID),
		)
		if _, err := h.s5c.DeleteSession(opCtx, evicted); err != nil {
			h.log.Warn("S11: PGW Delete Session for evicted session failed — PGW state may leak",
				"evicted_session_id", evicted.SessionID, "error", err)
		}
	}
	// A-001 FIX: also release the PFCP session for the evicted binding.
	// Per C13 (C8 extension): remote teardown must include both PGW (S5/S8-C) and
	// SGW-U (PFCP) cleanup. Local sessions.Delete() alone leaves stale forwarding state
	// on the SGW-U with orphaned TEIDs that may collide with the new session.
	if evicted != nil && evicted.PFCP.Established && evicted.PFCP.SGWUFSEID.SEID != 0 {
		if pfcpErr := h.pfcp.DeleteSessionOnPeer(opCtx,
			evicted.PFCP.SGWUAddr,
			evicted.PFCP.LocalFSEID.SEID,
			evicted.PFCP.SGWUFSEID.SEID,
		); pfcpErr != nil {
			h.log.Warn("S11: PFCP DeleteSession for evicted session failed — SGW-U state may leak",
				"evicted_session_id", evicted.SessionID, "error", pfcpErr)
		}
	}

	h.log.Info("S11: Create Session Request — establishing PFCP provisional session first",
		"from", addr,
		"seq", hdr.SequenceNumber,
		"imsi", imsi,
		"apn", apn,
		"session_id", sess.SessionID,
		"sgw_s11_teid", fmt.Sprintf("0x%08X", sess.SGWS11FTEID.TEID),
	)

	// Resolve PGW S5/S8-C address per TS 23.401 Rel-15 §5.3.2.1.
	// Address MUST come from F-TEID IE (instance 1) in MME CSReq.
	pgwAddr, err := h.s5c.PGWAddr(req)
	if err != nil {
		h.log.Error("S11: PGW S5/S8-C address unavailable", "error", err)
		h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "create_session_abort")
		h.sessions.Delete(sess.SessionID)
		h.sendCause(conn, addr, hdr, mmeTEID, ie.CauseConditionalIEMissing)
		return
	}
	createPGWReq := collision.Request{
		Procedure: collision.ProcedureCreateSession,
		Owner:     collision.OwnerPGW,
		Peer:      pgwAddr.String(),
		TEID:      0,
		Seq:       hdr.SequenceNumber,
		EBIs:      []uint8{ebi},
	}
	if !h.allowPeerProcedure(sess, createPGWReq) {
		h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "create_session_abort")
		h.sessions.Delete(sess.SessionID)
		h.sendCause(conn, addr, hdr, mmeTEID, ie.CauseSystemFailure)
		return
	}

	// R15-REAUDIT-001: PFCP Session Establishment BEFORE S5/S8-C CSReq.
	// The provisional PFCP session allocates the SGW-U S5/S8-U TEID (Created PDR 2),
	// which must be included in the S5/S8-C CSReq bearer context so the PGW-U can send
	// downlink traffic to the correct SGW-U tunnel endpoint.
	// FAR 1 starts as DROP; it is upgraded to FORW (with PGW-U OHC) after PGW CSResp.
	pfcpResult, pfcpErr := h.establishProvisionalPFCPSession(opCtx, sess)
	if pfcpErr != nil {
		h.log.Error("S11: PFCP provisional session failed — aborting CSReq",
			"session_id", sess.SessionID, "error", pfcpErr)
		h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "create_session_abort")
		h.sessions.Delete(sess.SessionID)
		h.sendCause(conn, addr, hdr, mmeTEID, ie.CauseSystemFailure)
		return
	}

	// Allocate and register the SGW local S5/S8-C TEID before sending the S5/S8-C
	// Create Session Request. Once advertised in Sender F-TEID, the PGW may
	// immediately address responses or PGW-initiated procedures to this local TEID.
	sgwS5CTEID, err := h.s5c.AllocTEID()
	if err != nil {
		h.log.Error("S11: SGW S5/S8-C TEID allocation failed", "session_id", sess.SessionID, "error", err)
		if delErr := h.pfcp.DeleteSessionOnPeer(opCtx, pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
			h.log.Warn("S11: PFCP DeleteSession rollback after S5-C TEID allocation failure failed", "error", delErr)
		}
		h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "create_session_abort")
		h.sessions.Delete(sess.SessionID)
		h.sendCause(conn, addr, hdr, mmeTEID, ie.CauseNoResourcesAvailable)
		return
	}
	releaseS5CTEID := func() {
		if sgwS5CTEID != 0 {
			h.s5c.FreeTEID(sgwS5CTEID)
			sgwS5CTEID = 0
		}
	}
	sess.SetSGWS5CFTEID(session.FTEID{TEID: sgwS5CTEID, IPv4: h.localIP})
	h.sessions.RegisterS5CTEID(sess.SessionID, sgwS5CTEID)

	// Send Create Session Request to PGW on S5/S8-C, including SGW-U S5/S8-U TEID.
	// Per TS 29.274 Rel-15 §7.2.1 / Table 7.2.1-1 (S5/S8-C direction).
	s5cResult, err := h.s5c.CreateSession(opCtx, pgwAddr, req, sgwS5CTEID, pfcpResult.sgwUS5UFTEID)
	if err != nil {
		h.log.Error("S11: S5/S8-C Create Session failed", "pgw", pgwAddr, "error", err)
		// Roll back PFCP provisional session — PGW never acknowledged it.
		if delErr := h.pfcp.DeleteSessionOnPeer(opCtx, pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
			h.log.Warn("S11: PFCP DeleteSession rollback failed", "error", delErr)
		}
		h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "create_session_abort")
		h.sessions.Delete(sess.SessionID)
		releaseS5CTEID()
		h.sendCause(conn, addr, hdr, mmeTEID, ie.CauseSystemFailure)
		return
	}

	if s5cResult.Cause != ie.CauseRequestAccepted {
		h.log.Warn("S11: PGW rejected Create Session Request",
			"pgw", pgwAddr, "cause", s5cResult.Cause)
		// Roll back PFCP provisional session.
		if delErr := h.pfcp.DeleteSessionOnPeer(opCtx, pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
			h.log.Warn("S11: PFCP DeleteSession rollback on PGW rejection failed", "error", delErr)
		}
		h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "create_session_abort")
		h.sessions.Delete(sess.SessionID)
		releaseS5CTEID()
		// Propagate PGW's rejection cause to MME.
		// CS=1 per TS 29.274 §8.4: this cause originated at the PGW (remote node),
		// not at the SGW-C. Build response manually to set CS correctly (C12).
		var relayedMMETEID uint32
		if f, err := req.FTEID.FTEIDValue(); err == nil {
			relayedMMETEID = f.TEID
		}
		relayHdr := message.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    message.MsgTypeCreateSessionResponse,
			TEID:           relayedMMETEID,
			SequenceNumber: req.Header.SequenceNumber,
		}
		failResp, _ := message.Marshal(relayHdr, []*ie.IE{ie.NewCause(s5cResult.Cause, 0, 0, 1, nil)})
		conn.Reply(addr, failResp) //nolint:errcheck
		return
	}

	// Update session with PGW response per TS 29.274 §7.2.2 / Table 7.2.2-1.
	sess.SetPGWControlFTEID(s5cResult.PGWControlFTEID)
	h.sessions.RegisterPGW(sess.SessionID, pgwAddr.String())
	sess.SetUEIPv4(s5cResult.UEIP)

	// Update default bearer with PGW-U S5/S8-U F-TEID per Table 7.2.2-2.
	if b := sess.GetBearer(ebi); b != nil {
		b.PGWS5UFTEID = s5cResult.PGWS5UFTEID
		sess.SetBearer(b)
	}

	// Upgrade FAR 1 from DROP to FORW now that we have the PGW-U S5/S8-U TEID.
	// R15-REAUDIT-001: this completes the PFCP-first sequence.
	if s5cResult.PGWS5UFTEID.TEID != 0 {
		if modErr := h.modifyPFCPUplinkFAR(opCtx,
			pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID, s5cResult.PGWS5UFTEID); modErr != nil {
			h.log.Error("S11: PFCP modify uplink FAR failed — tearing down",
				"session_id", sess.SessionID, "error", modErr)
			if _, dsErr := h.s5c.DeleteSession(opCtx, sess); dsErr != nil {
				h.log.Warn("S11: PGW Delete Session after PFCP modify failure also failed",
					"session_id", sess.SessionID, "error", dsErr)
			}
			if delErr := h.pfcp.DeleteSessionOnPeer(opCtx, pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
				h.log.Warn("S11: PFCP DeleteSession after modify failure also failed", "error", delErr)
			}
			h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "create_session_abort")
			h.sessions.Delete(sess.SessionID)
			releaseS5CTEID()
			h.sendCause(conn, addr, hdr, mmeTEID, ie.CauseSystemFailure)
			return
		}
	}

	// Store PFCP binding in session state.
	cpSEID := pfcpResult.cpSEID
	upSEID := pfcpResult.upSEID
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: cpSEID, IPv4: h.localIP},
		SGWUFSEID:   session.FSEID{SEID: upSEID},
		SGWUName:    pfcpResult.peerName,
		SGWUAddr:    pfcpResult.peerAddr,
		Established: true,
	})

	// Store SGW-U TEIDs in bearer state from Created PDRs.
	// R15-003: SGW-U S1-U TEID included in S11 CSResp Bearer Context (instance 0 within BC).
	if b := sess.GetBearer(ebi); b != nil {
		b.SGWS1UFTEID = pfcpResult.sgwUS1UFTEID
		b.SGWS5UFTEID = pfcpResult.sgwUS5UFTEID
		sess.SetBearer(b)
	}

	// R15-001: session is StateActive only after PFCP session is established.
	sess.Transition(session.StateActive)

	h.log.Info("S11: session established (PFCP provisioned)",
		"session_id", sess.SessionID,
		"imsi", imsi,
		"ue_ip", sess.UEIPv4,
		"pgw_s5c_teid", fmt.Sprintf("0x%08X", sess.PGWControlFTEID.TEID),
		"cp_seid", cpSEID,
		"up_seid", upSEID,
	)

	// Build S11 Create Session Response per TS 29.274 Rel-15 §7.2.2 / Table 7.2.2-1.
	//
	// Sender F-TEID (instance 0): SGW-C's S11 control TEID — C on success.
	// PGW S5/S8-C F-TEID (instance 1): forwarded from PGW CSResp — C.
	// PAA: UE IP from PGW PAA — C on success.
	// AMBR: forwarded from PGW if provided, else from MME — C on success.
	// APN Restriction: forwarded from PGW if provided — C on success.
	// PCO: forwarded byte-for-byte from PGW if provided — C on success.
	// Bearer Context created (instance 0): per Table 7.2.2-2.
	//   - EBI: M
	//   - Cause: M (bearer level)
	//   - S1-U SGW F-TEID (instance 0 within BC): C per Table 7.2.2-2 — SGW-U's allocated TEID (R15-003).
	//   - S5/S8-U PGW F-TEID (instance 2 within BC): C — forwarded from PGW CSResp per Table 7.2.2-2 S11 column.
	sgwS11FTEID := ie.NewFTEID(0, ie.IFTypeS11S4SGW, sess.SGWS11FTEID.TEID, h.localIP)
	pgwS5CFTEID := ie.NewFTEID(1, ie.IFTypeS5S8CPGW,
		s5cResult.PGWControlFTEID.TEID, s5cResult.PGWControlFTEID.IPv4)

	var paaSGW *ie.IE
	if s5cResult.UEIP.IsValid() {
		paaSGW = ie.NewPAA(ie.PDNTypeIPv4, s5cResult.UEIP)
	} else {
		paaSGW = req.PAA // fall back to MME's suggested PAA
	}

	ambrIE := s5cResult.AMBR
	if ambrIE == nil {
		ambrIE = req.AMBR // PGW echoed AMBR; fall back to MME value
	}

	extraIEs := h.buildS11CreateSessionResponseIEs(
		addr,
		ebi,
		sgwS11FTEID,
		pgwS5CFTEID,
		paaSGW,
		ambrIE,
		s5cResult,
		pfcpResult,
	)

	h.log.Info("S11: Create Session Response built",
		"imsi", imsi,
		"seq", req.Header.SequenceNumber,
		"cause", ie.CauseRequestAccepted,
		"ue_ip", sess.UEIPv4,
		"sgw_s11_teid", fmt.Sprintf("0x%08X", sess.SGWS11FTEID.TEID),
		"mme_s11_teid", fmt.Sprintf("0x%08X", mmeTEID),
		"pgw_s5c_teid", fmt.Sprintf("0x%08X", sess.PGWControlFTEID.TEID),
		"has_paa", paaSGW != nil,
		"has_apn_restriction", s5cResult.APNRestriction != nil,
		"has_pco", s5cResult.PCO != nil,
		"has_ambr", ambrIE != nil,
		"has_recovery", ie.FindFirst(extraIEs, ie.TypeRecovery) != nil,
		"bearer_contexts", 1,
		"has_sgw_s1u_fteid", pfcpResult.sgwUS1UFTEID.TEID != 0 && pfcpResult.sgwUS1UFTEID.IPv4.IsValid(),
		"has_pgw_s5u_fteid", s5cResult.PGWS5UFTEID.TEID != 0 && s5cResult.PGWS5UFTEID.IPv4.IsValid(),
	)

	resp, err := message.MarshalCreateSessionResponse(req, ie.CauseRequestAccepted, extraIEs...)
	if err != nil {
		h.log.Error("S11: Create Session Response marshal failed", "error", err)
		return
	}
	var remainingPiggybacks []message.Frame
	piggybackedCreateBearer := false
	for _, frame := range s5cResult.Piggybacks {
		if frame.Header.MessageType != message.MsgTypeCreateBearerRequest {
			remainingPiggybacks = append(remainingPiggybacks, frame)
			continue
		}
		if piggybackedCreateBearer {
			remainingPiggybacks = append(remainingPiggybacks, frame)
			h.log.Warn("S11: multiple Create Bearer piggybacks in one Create Session Response; relaying additional request separately",
				"session_id", sess.SessionID,
				"piggyback_seq", frame.Header.SequenceNumber,
			)
			continue
		}
		prep, ok := h.prepareCreateBearerRelay(pgwAddr, frame.Header, frame.Raw)
		if !ok {
			continue
		}
		piggybackedResp, pErr := message.MarshalPiggybacked(resp, prep.s11Raw)
		if pErr != nil {
			h.log.Error("S11: Create Session Response piggyback marshal failed", "error", pErr)
			h.removeAllCreateBearerTxnProvisioning(prep.txn.key, prep.sess, prep.bearerProvs)
			h.replyCreateBearerTxnError(prep.txn.key, prep.pgwAddr, prep.hdr, prep.cbReq,
				prep.sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
			continue
		}
		resp = piggybackedResp
		piggybackedCreateBearer = true
		h.registerPendingS11CreateBearer(addr, req.Header.SequenceNumber, prep)
		h.log.Info("S11: forwarding Create Session Response with piggybacked Create Bearer Request",
			"session_id", sess.SessionID,
			"mme_teid", fmt.Sprintf("0x%08X", mmeTEID),
			"csrsp_seq", req.Header.SequenceNumber,
			"piggyback_msg_type", message.MsgTypeCreateBearerRequest,
			"piggyback_seq", prep.s11Seq,
			"bearer_contexts", len(prep.cbReq.BearerContexts),
			"linked_ebi", prep.linkedEBI,
		)
	}
	if err := conn.Reply(addr, resp); err != nil {
		h.log.Warn("S11: Create Session Response send failed", "to", addr, "error", err)
	}
	if len(remainingPiggybacks) > 0 {
		h.log.Info("S5/S8-C: dispatching piggybacked frames after Create Session commit",
			"session_id", sess.SessionID,
			"frames", len(remainingPiggybacks),
			"sgw_s5c_teid", fmt.Sprintf("0x%08X", sess.SGWS5CFTEID.TEID),
			"pgw_s5c_teid", fmt.Sprintf("0x%08X", sess.PGWControlFTEID.TEID),
		)
		h.s5c.DispatchPiggybacks(pgwAddr, remainingPiggybacks)
	}
}

func (h *Handler) buildS11CreateSessionResponseIEs(
	addr *net.UDPAddr,
	ebi uint8,
	sgwS11FTEID *ie.IE,
	pgwS5CFTEID *ie.IE,
	paaSGW *ie.IE,
	ambrIE *ie.IE,
	s5cResult *s5c.CreateSessionResult,
	pfcpResult *pfcpSessionResult,
) []*ie.IE {
	var bcChildren []*ie.IE
	bcChildren = append(bcChildren, ie.NewEBI(ebi))
	bcChildren = append(bcChildren, ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil))
	// SGW-U S1-U F-TEID at instance 0 per TS 29.274 Rel-15 Table 7.2.2-2, S11 column (R15-003).
	// IFTypeS1USGW = 1 per TS 29.274 Table 8.22-1.
	if pfcpResult.sgwUS1UFTEID.TEID != 0 && pfcpResult.sgwUS1UFTEID.IPv4.IsValid() {
		bcChildren = append(bcChildren,
			ie.NewFTEID(0, ie.IFTypeS1USGW,
				pfcpResult.sgwUS1UFTEID.TEID, pfcpResult.sgwUS1UFTEID.IPv4))
	}
	// PGW S5/S8-U F-TEID forwarded at instance 2 per TS 29.274 Rel-15 Table 7.2.2-2,
	// S11 column (SGW-C→MME direction). Per C10.
	if s5cResult.PGWS5UFTEID.TEID != 0 {
		bcChildren = append(bcChildren,
			ie.NewFTEID(2, ie.IFTypeS5S8UPGW,
				s5cResult.PGWS5UFTEID.TEID, s5cResult.PGWS5UFTEID.IPv4))
	}
	bcCreated := ie.NewBearerContext(0, bcChildren...)

	// Cisco StarOS accepts the IMS piggybacked Create Bearer path when the primary
	// CSRsp closely matches its known-good ordering. IE order is not generally
	// semantically significant, but keeping a stable order is harmless and gives
	// interop-sensitive peers the same shape on every APN:
	// Cause is added by MarshalCreateSessionResponse, then these IEs follow.
	var extraIEs []*ie.IE
	extraIEs = append(extraIEs, sgwS11FTEID, pgwS5CFTEID, paaSGW)
	if s5cResult.APNRestriction != nil {
		extraIEs = append(extraIEs, s5cResult.APNRestriction)
	}
	if ambrIE != nil {
		extraIEs = append(extraIEs, ambrIE)
	}
	if s5cResult.PCO != nil {
		extraIEs = append(extraIEs, s5cResult.PCO)
	}
	extraIEs = append(extraIEs, bcCreated)
	if s5cResult.ChargingID != nil {
		extraIEs = append(extraIEs, s5cResult.ChargingID)
	}
	if h.recovery != nil && addr != nil {
		if recIE := h.maybeRecoveryIE(addr); recIE != nil {
			extraIEs = append(extraIEs, recIE)
		}
	}
	return extraIEs
}

func (h *Handler) handleModifyBearerRequest(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	opCtx, cancelOp := h.operationContext()
	defer cancelOp()

	req, err := message.ParseModifyBearerRequest(hdr, ies)
	if err != nil {
		h.log.Warn("S11: Modify Bearer Request invalid", "from", addr, "error", err)
		h.sendMissingIECause(conn, addr, hdr, peerTEIDFromIEs(ies), err)
		return
	}

	defaultSess := h.sessions.FindByS11TEID(hdr.TEID)
	if defaultSess == nil {
		h.log.Warn("S11: Modify Bearer Request — session not found", "teid", fmt.Sprintf("0x%08X", hdr.TEID))
		// Use Sender F-TEID if present; otherwise 0 (session unknown, MME TEID unavailable).
		var peerTEID uint32
		if req.FTEID != nil {
			if f, err := req.FTEID.FTEIDValue(); err == nil {
				peerTEID = f.TEID
			}
		}
		resp, _ := message.MarshalModifyBearerResponse(req, peerTEID, ie.CauseContextNotFound)
		conn.Reply(addr, resp) //nolint:errcheck
		return
	}
	mmeTEID := defaultSess.MMEControlFTEID.TEID
	mbEBIs := bearerContextEBIs(req.BearerContexts)
	mbProc, ok := h.beginProcedure(defaultSess, mmeProcedureRequest(collision.ProcedureModifyBearer, addr, hdr.TEID, hdr.SequenceNumber, mbEBIs))
	if !ok {
		resp, _ := message.MarshalModifyBearerResponse(req, mmeTEID, ie.CauseRequestRejected)
		conn.Reply(addr, resp) //nolint:errcheck
		return
	}
	defer finishProcedure(defaultSess, mbProc)
	h.captureSecondaryRATUsageReports(addr, hdr, req, defaultSess)

	// Process each bearer context and record the per-bearer outcome.
	// Per TS 29.274 Rel-15 Tables 7.2.8-1/7.2.8-2: MBResp must include a Bearer
	// Context modified IE for each bearer processed, carrying EBI (M), Cause (M),
	// and S1-U SGW F-TEID (C, instance 0 per Table 7.2.8-2).
	type mbResult struct {
		ebi         uint8
		cause       uint8
		sgwS1UFTEID bearer.FTEID // populated from bearer state after PFCP session exists
	}
	var results []mbResult

	reportForwardTargets := h.secondaryRATReportTargetSessions(hdr.TEID, mbEBIs, defaultSess, h.nsaDCNRForwardSecondaryRATUsageReports(req))
	requestedEBIs := make(map[uint8]bool, len(mbEBIs))
	for _, ebi := range mbEBIs {
		requestedEBIs[ebi] = true
	}

	for _, bcIE := range req.BearerContexts {
		children, err := bcIE.ChildIEs()
		if err != nil {
			continue
		}
		ebiIE := ie.FindFirst(children, ie.TypeEBI)
		if ebiIE == nil {
			continue // cannot build response entry without EBI; skip
		}
		ebi, _ := ebiIE.EBIValue()

		fteidIE := ie.FindFirst(children, ie.TypeFTEID) // eNodeB S1-U F-TEID
		if fteidIE == nil {
			results = append(results, mbResult{ebi: ebi, cause: ie.CauseMandatoryIEMissing})
			continue
		}

		sess := h.sessions.FindByS11TEIDAndBearer(hdr.TEID, ebi)
		if sess == nil {
			knownEBIs, knownPDNs := h.knownS11BearerState(hdr.TEID)
			h.log.Warn("S11: Modify Bearer — bearer owner not found",
				"mme_peer", addr.String(),
				"sgw_s11_teid", fmt.Sprintf("0x%08X", hdr.TEID),
				"requested_ebi", ebi,
				"known_ebis", knownEBIs,
				"known_pdns", knownPDNs,
			)
			results = append(results, mbResult{ebi: ebi, cause: ie.CauseContextNotFound})
			continue
		}

		b := sess.GetBearer(ebi)
		if b == nil {
			h.log.Warn("S11: Modify Bearer — unknown EBI", "session_id", sess.SessionID, "ebi", ebi)
			results = append(results, mbResult{ebi: ebi, cause: ie.CauseContextNotFound})
			continue
		}

		fteid, _ := fteidIE.FTEIDValue()

		if !sess.PFCP.Established || sess.PFCP.SGWUFSEID.SEID == 0 {
			h.log.Warn("S11: Modify Bearer — PFCP binding unavailable; rejecting bearer update",
				"session_id", sess.SessionID, "ebi", ebi)
			results = append(results, mbResult{ebi: ebi, cause: ie.CauseSystemFailure})
			continue
		}

		// Save prior eNB FTEID for rollback on PFCP failure (R15-006).
		oldENBFTEID := b.ENBS1UFTEID

		b.ENBS1UFTEID = bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4}
		sess.SetBearer(b)
		h.log.Info("S11: Modify Bearer owner resolution",
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"sgw_s11_teid", fmt.Sprintf("0x%08X", hdr.TEID),
			"mme_s11_teid", fmt.Sprintf("0x%08X", sess.MMEControlFTEID.TEID),
			"ebi", ebi,
			"pgw_s5c_teid", fmt.Sprintf("0x%08X", sess.PGWControlFTEID.TEID),
			"enb_teid", fmt.Sprintf("0x%08X", fteid.TEID),
			"enb_ip", fteid.IPv4,
			"lookup_source", "s11_teid_bearer_owner",
		)

		// PFCP Session Modification: upgrade Core→Access FAR from DROP to FORW
		// with the eNB TEID as Outer Header Creation per TS 29.244 Rel-15 §7.5.4.
		// Default bearer FAR 2 is established at session creation; dedicated bearers
		// must carry their own PFCP rule IDs from Create Bearer acceptance.
		pdrID, farID, ok := downlinkPFCPRuleIDs(sess, b)
		if !ok {
			h.log.Warn("S11: Modify Bearer — missing downlink PFCP rule IDs; rejecting bearer update",
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"default_ebi", sess.DefaultBearerID,
				"ebi", ebi,
				"pdr_ids", b.PDRIDs,
				"far_ids", b.FARIDs,
			)
			b.ENBS1UFTEID = oldENBFTEID
			sess.SetBearer(b)
			results = append(results, mbResult{ebi: ebi, cause: ie.CauseSystemFailure})
			continue
		}
		pfcpErr := h.pfcp.ModifySessionOnPeer(opCtx,
			sess.PFCP.SGWUAddr,
			sess.PFCP.LocalFSEID.SEID,
			sess.PFCP.SGWUFSEID.SEID,
			[]pfcpclient.FARUpdate{{
				FARID:              farID,
				PDRID:              pdrID,
				ApplyAction:        pfcpie.ApplyActionFORW,
				DestInterface:      pfcpie.DestInterfaceAccess,
				OuterTEID:          fteid.TEID,
				OuterIP:            fteid.IPv4,
				OuterHeaderRemoval: true,
			}},
		)
		if pfcpErr != nil {
			// R15-006 FIX: PFCP failure is fatal — restore prior state and return failure.
			// Per TS 23.401: do not report bearer success if the UP function did not
			// install the new forwarding state. Preserve previous state for MME retry.
			h.log.Warn("S11: PFCP Session Modification failed — rolling back eNB FTEID and returning failure",
				"session_id", sess.SessionID, "ebi", ebi, "error", pfcpErr)
			b.ENBS1UFTEID = oldENBFTEID
			sess.SetBearer(b)
			results = append(results, mbResult{ebi: ebi, cause: ie.CauseSystemFailure})
			continue
		}

		// PFCP succeeded: include SGW-U S1-U TEID in MBResp
		// per TS 29.274 Rel-15 Table 7.2.8-2 (S1-U SGW F-TEID, instance 0).
		var sgwS1U bearer.FTEID
		if refreshedB := sess.GetBearer(ebi); refreshedB != nil {
			sgwS1U = refreshedB.SGWS1UFTEID
		}
		if h.shouldCompleteMMERestorationOnModifyBearer(sess) {
			sess.MarkMMERestorationUserPlaneRestored(ebi, time.Now())
			h.log.Info("S11: MME restoration user plane restored by Modify Bearer",
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"default_ebi", sess.DefaultBearerID,
				"ebi", ebi,
				"far_id", farID,
				"enb_teid", fmt.Sprintf("0x%08X", fteid.TEID),
				"enb_ip", fteid.IPv4)
		}
		if ebi == sess.DefaultBearerID {
			h.restoreSiblingBearersAfterModifyBearer(opCtx, sess, requestedEBIs, bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4})
		}
		results = append(results, mbResult{ebi: ebi, cause: ie.CauseRequestAccepted, sgwS1UFTEID: sgwS1U})
	}

	reportForwardCause := ie.CauseRequestAccepted
	reportForwarded := false
	for _, reportForwardSess := range reportForwardTargets {
		if reportForwardSess.PGWControlFTEID.TEID == 0 {
			continue
		}
		reportForwarded = true
		pgwAddr := pgwAddrFromSession(reportForwardSess)
		reportReq := collision.Request{
			Procedure: collision.ProcedureModifyBearer,
			Owner:     collision.OwnerPGW,
			Peer:      pgwAddr,
			TEID:      reportForwardSess.PGWControlFTEID.TEID,
			Seq:       hdr.SequenceNumber,
			EBIs:      mbEBIs,
		}
		if !h.allowPeerProcedure(reportForwardSess, reportReq) {
			if reportForwardCause == ie.CauseRequestAccepted {
				reportForwardCause = ie.CauseSystemFailure
			}
			if h.nsaMetrics != nil {
				h.nsaMetrics.OnSecondaryRATUsageReportsForwarded(reportForwardSess.APN, ie.CauseSystemFailure, len(req.SecondaryRATUsageDataReports))
			}
			continue
		}
		cause, err := h.s5c.ModifyBearerFromS11(opCtx, reportForwardSess, req)
		if err != nil {
			h.log.Warn("S11: S5/S8-C Modify Bearer report forwarding failed",
				"session_id", reportForwardSess.SessionID,
				"apn", reportForwardSess.APN,
				"pgw_s5c_teid", fmt.Sprintf("0x%08X", reportForwardSess.PGWControlFTEID.TEID),
				"reports", len(req.SecondaryRATUsageDataReports),
				"error", err)
			if reportForwardCause == ie.CauseRequestAccepted {
				reportForwardCause = ie.CauseSystemFailure
			}
		} else {
			h.log.Info("S11: S5/S8-C Modify Bearer report forwarding completed",
				"session_id", reportForwardSess.SessionID,
				"apn", reportForwardSess.APN,
				"pgw_s5c_teid", fmt.Sprintf("0x%08X", reportForwardSess.PGWControlFTEID.TEID),
				"reports", len(req.SecondaryRATUsageDataReports),
				"cause", cause)
			if cause != ie.CauseRequestAccepted && reportForwardCause == ie.CauseRequestAccepted {
				reportForwardCause = cause
			}
		}
		if h.nsaMetrics != nil {
			h.nsaMetrics.OnSecondaryRATUsageReportsForwarded(reportForwardSess.APN, cause, len(req.SecondaryRATUsageDataReports))
		}
	}

	// Build Bearer Context Modified IEs per TS 29.274 Rel-15 Table 7.2.8-1/7.2.8-2.
	// "Bearer Contexts modified" = instance 0 (all modified bearers share the same
	// instance 0; multiple IEs of the same type+instance are permitted).
	// "Bearer Contexts marked for removal" = instance 1. None in this phase.
	var bcIEs []*ie.IE
	for _, r := range results {
		bcChildren := []*ie.IE{
			ie.NewEBI(r.ebi),
			ie.NewCause(r.cause, 0, 0, 0, nil),
		}
		// S1-U SGW F-TEID at instance 0 per TS 29.274 Rel-15 Table 7.2.8-2 (R15-003).
		// IFTypeS1USGW = 1 per TS 29.274 Table 8.22-1.
		if r.cause == ie.CauseRequestAccepted && r.sgwS1UFTEID.TEID != 0 && r.sgwS1UFTEID.IPv4.IsValid() {
			bcChildren = append(bcChildren,
				ie.NewFTEID(0, ie.IFTypeS1USGW, r.sgwS1UFTEID.TEID, r.sgwS1UFTEID.IPv4))
		}
		bcIEs = append(bcIEs, ie.NewBearerContext(0, bcChildren...))
	}

	// Message-level cause: accepted if any bearer was accepted; otherwise report
	// the first failure cause (all-fail case). Empty results = no bearer contexts
	// in request (RAT-type-only update) → accepted at message level.
	msgCause := ie.CauseRequestAccepted
	if len(results) > 0 {
		anyAccepted := false
		for _, r := range results {
			if r.cause == ie.CauseRequestAccepted {
				anyAccepted = true
				break
			}
		}
		if !anyAccepted {
			msgCause = results[0].cause
		}
	}
	if len(results) == 0 && reportForwarded && reportForwardCause != ie.CauseRequestAccepted {
		msgCause = reportForwardCause
	}

	// Include Recovery IE per TS 29.274 §7.2.0 on first contact with this MME.
	if recIE := h.maybeRecoveryIE(addr); recIE != nil {
		bcIEs = append(bcIEs, recIE)
	}

	resp, err := message.MarshalModifyBearerResponse(req, mmeTEID, msgCause, bcIEs...)
	if err != nil {
		h.log.Error("S11: Modify Bearer Response marshal failed", "error", err)
		return
	}
	if err := conn.Reply(addr, resp); err != nil {
		h.log.Warn("S11: Modify Bearer Response send failed", "to", addr, "error", err)
	}
}

func (h *Handler) restoreSiblingBearersAfterModifyBearer(ctx context.Context, sess *session.SGWSession, requestedEBIs map[uint8]bool, enbFTEID bearer.FTEID) {
	if h == nil || h.pfcp == nil || sess == nil || !enbFTEID.IPv4.IsValid() || enbFTEID.TEID == 0 {
		return
	}
	for _, b := range sess.BearerList() {
		if b == nil || b.EBI == sess.DefaultBearerID || requestedEBIs[b.EBI] {
			continue
		}
		if b.State == bearer.BearerStateDeleting || b.State == bearer.BearerStateDeleted {
			continue
		}
		pdrID, farID, ok := downlinkPFCPRuleIDs(sess, b)
		if !ok {
			h.log.Warn("S11: Modify Bearer resume audit — active sibling bearer missing downlink PFCP rule IDs",
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"default_ebi", sess.DefaultBearerID,
				"ebi", b.EBI,
				"qci", b.QCI,
				"pdr_ids", b.PDRIDs,
				"far_ids", b.FARIDs)
			continue
		}
		oldENB := b.ENBS1UFTEID
		b.ENBS1UFTEID = enbFTEID
		sess.SetBearer(b)
		err := h.pfcp.ModifySessionOnPeer(ctx,
			sess.PFCP.SGWUAddr,
			sess.PFCP.LocalFSEID.SEID,
			sess.PFCP.SGWUFSEID.SEID,
			[]pfcpclient.FARUpdate{{
				FARID:              farID,
				PDRID:              pdrID,
				ApplyAction:        pfcpie.ApplyActionFORW,
				DestInterface:      pfcpie.DestInterfaceAccess,
				OuterTEID:          enbFTEID.TEID,
				OuterIP:            enbFTEID.IPv4,
				OuterHeaderRemoval: true,
			}},
		)
		if err != nil {
			b.ENBS1UFTEID = oldENB
			sess.SetBearer(b)
			h.log.Warn("S11: Modify Bearer resume audit — sibling bearer restore failed",
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"default_ebi", sess.DefaultBearerID,
				"ebi", b.EBI,
				"qci", b.QCI,
				"far_id", farID,
				"enb_teid", fmt.Sprintf("0x%08X", enbFTEID.TEID),
				"enb_ip", enbFTEID.IPv4,
				"error", err)
			continue
		}
		h.log.Info("S11: Modify Bearer resume audit — sibling bearer restored to FORWARD",
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"ebi", b.EBI,
			"qci", b.QCI,
			"pdr_id", pdrID,
			"far_id", farID,
			"enb_teid", fmt.Sprintf("0x%08X", enbFTEID.TEID),
			"enb_ip", enbFTEID.IPv4)
	}
}

func (h *Handler) captureSecondaryRATUsageReports(addr *net.UDPAddr, hdr message.Header, req *message.ModifyBearerRequest, defaultSess *session.SGWSession) {
	if req == nil || !h.nsaDCNREnabled() || len(req.SecondaryRATUsageDataReports) == 0 || h.sessions == nil {
		return
	}
	targets := h.secondaryRATReportTargetSessions(hdr.TEID, bearerContextEBIs(req.BearerContexts), defaultSess, true)
	if len(targets) == 0 {
		return
	}

	peer := ""
	if addr != nil {
		peer = addr.String()
	}
	reports := make([]session.SecondaryRATUsageDataReport, 0, len(req.SecondaryRATUsageDataReports))
	for _, reportIE := range req.SecondaryRATUsageDataReports {
		payload, err := reportIE.SecondaryRATUsageDataReportValue()
		if err != nil {
			h.log.Warn("S11: Secondary RAT Usage Data Report invalid",
				"sgw_s11_teid", fmt.Sprintf("0x%08X", hdr.TEID),
				"seq", hdr.SequenceNumber,
				"error", err)
			continue
		}
		reports = append(reports, session.SecondaryRATUsageDataReport{
			ReceivedAt:      time.Now(),
			SourceProcedure: "s11_modify_bearer_request",
			MMEPeer:         peer,
			SGWS11TEID:      hdr.TEID,
			SequenceNumber:  hdr.SequenceNumber,
			Payload:         payload,
		})
	}
	if len(reports) == 0 {
		return
	}
	for _, sess := range targets {
		sess.RecordSecondaryRATUsageDataReports(reports)
		if h.nsaMetrics != nil {
			h.nsaMetrics.OnSecondaryRATUsageReportsCaptured(sess.APN, "s11_modify_bearer_request", len(reports))
		}
		h.log.Info("S11: Secondary RAT usage reports captured",
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"default_ebi", sess.DefaultBearerID,
			"sgw_s11_teid", fmt.Sprintf("0x%08X", hdr.TEID),
			"seq", hdr.SequenceNumber,
			"reports", len(reports),
			"lookup_source", "s11_teid_bearer_owner",
		)
	}
}

func (h *Handler) shouldCompleteMMERestorationOnModifyBearer(sess *session.SGWSession) bool {
	if sess == nil {
		return false
	}
	status := sess.MMERestorationSnapshot()
	return status.RestorationPending &&
		status.PolicyAction == session.MMERestorationPolicyPreserve &&
		status.DDNAcked &&
		status.DDNAckCause == ie.CauseRequestAccepted &&
		!status.UserPlaneRestored
}

func (h *Handler) secondaryRATReportTargetSessions(sgwS11TEID uint32, ebis []uint8, defaultSess *session.SGWSession, hasReports bool) []*session.SGWSession {
	if !hasReports || h.sessions == nil {
		return nil
	}
	targetMap := make(map[*session.SGWSession]struct{})
	for _, ebi := range ebis {
		if sess := h.sessions.FindByS11TEIDAndBearer(sgwS11TEID, ebi); sess != nil {
			targetMap[sess] = struct{}{}
		}
	}
	if len(targetMap) == 0 && defaultSess != nil {
		targetMap[defaultSess] = struct{}{}
	}
	targets := make([]*session.SGWSession, 0, len(targetMap))
	for sess := range targetMap {
		targets = append(targets, sess)
	}
	return targets
}

func (h *Handler) nsaDCNREnabled() bool {
	return h == nil || h.cfg == nil || h.cfg.GTPC.NSADCNR.Enabled
}

func (h *Handler) nsaDCNRForwardSecondaryRATUsageReports(req *message.ModifyBearerRequest) bool {
	return req != nil &&
		len(req.SecondaryRATUsageDataReports) > 0 &&
		h.nsaDCNREnabled() &&
		(h.cfg == nil || h.cfg.GTPC.NSADCNR.ForwardSecondaryRATUsageReports)
}

func (h *Handler) handleDeleteSessionRequest(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	opCtx, cancelOp := h.operationContext()
	defer cancelOp()

	req, err := message.ParseDeleteSessionRequest(hdr, ies)
	if err != nil {
		h.log.Warn("S11: Delete Session Request invalid", "from", addr, "error", err)
		h.sendMissingIECause(conn, addr, hdr, peerTEIDFromIEs(ies), err)
		return
	}

	sess := h.sessions.FindByS11TEID(hdr.TEID)
	if sess == nil {
		h.log.Warn("S11: Delete Session Request — session not found", "teid", fmt.Sprintf("0x%08X", hdr.TEID))
		// DSReq carries no Sender F-TEID; MME TEID unavailable without session.
		resp, _ := message.MarshalDeleteSessionResponse(req, 0, ie.CauseContextNotFound)
		conn.Reply(addr, resp) //nolint:errcheck
		return
	}
	if req.EBI != nil {
		if deleteEBI, eErr := req.EBI.EBIValue(); eErr == nil {
			if owner := h.sessions.FindByS11TEIDAndDefaultBearer(hdr.TEID, deleteEBI); owner != nil {
				sess = owner
			} else if owner := h.sessions.FindByS11TEIDAndBearer(hdr.TEID, deleteEBI); owner != nil {
				sess = owner
			} else {
				knownEBIs, knownPDNs := h.knownS11BearerState(hdr.TEID)
				h.log.Warn("S11: Delete Session — bearer owner not found",
					"mme_peer", addr.String(),
					"sgw_s11_teid", fmt.Sprintf("0x%08X", hdr.TEID),
					"delete_ebi", deleteEBI,
					"known_ebis", knownEBIs,
					"known_pdns", knownPDNs,
				)
				resp, _ := message.MarshalDeleteSessionResponse(req, sess.MMEControlFTEID.TEID, ie.CauseContextNotFound)
				conn.Reply(addr, resp) //nolint:errcheck
				return
			}
			h.log.Info("S11: Delete Session owner resolved",
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"delete_ebi", deleteEBI,
				"owner_apn", sess.APN,
				"owner_default_ebi", sess.DefaultBearerID,
				"sgw_s11_teid", fmt.Sprintf("0x%08X", hdr.TEID),
				"mme_s11_teid", fmt.Sprintf("0x%08X", sess.MMEControlFTEID.TEID),
				"pgw_s5c_teid", fmt.Sprintf("0x%08X", sess.PGWControlFTEID.TEID),
				"lookup_source", "s11_teid_delete_ebi_owner",
			)
		}
	}

	mmeTEID := sess.MMEControlFTEID.TEID
	var dsEBIs []uint8
	if req.EBI != nil {
		if deleteEBI, eErr := req.EBI.EBIValue(); eErr == nil {
			dsEBIs = []uint8{deleteEBI}
		}
	}
	dsProc, ok := h.beginProcedure(sess, mmeProcedureRequest(collision.ProcedureDeleteSession, addr, hdr.TEID, hdr.SequenceNumber, dsEBIs))
	if !ok {
		resp, _ := message.MarshalDeleteSessionResponse(req, mmeTEID, ie.CauseRequestRejected)
		conn.Reply(addr, resp) //nolint:errcheck
		return
	}
	defer finishProcedure(sess, dsProc)
	sess.Transition(session.StateDeleting)

	// Propagate Delete Session Request to PGW on S5/S8-C if a PGW session exists.
	// Per TS 29.274 Rel-15 §7.2.9 / Table 7.2.9.1-1 (S5/S8-C direction).
	// R15-005: propagate PGW cause to MME; retain local state on failure for retry.
	if sess.PGWControlFTEID.TEID != 0 {
		pgwReq := collision.Request{
			Procedure: collision.ProcedureDeleteSession,
			Owner:     collision.OwnerPGW,
			Peer:      pgwAddrFromSession(sess),
			TEID:      sess.PGWControlFTEID.TEID,
			Seq:       hdr.SequenceNumber,
			EBIs:      dsEBIs,
		}
		if !h.allowPeerProcedure(sess, pgwReq) {
			resp, _ := message.MarshalDeleteSessionResponse(req, mmeTEID, ie.CauseSystemFailure)
			conn.Reply(addr, resp) //nolint:errcheck
			return
		}
		pgwCause, pgwErr := h.s5c.DeleteSessionFromS11(opCtx, sess, req)
		if pgwErr != nil {
			// Transport or decode error: return system failure; retain local state for retry.
			h.log.Warn("S11: S5/S8-C Delete Session transport error — retaining local state",
				"session_id", sess.SessionID, "error", pgwErr)
			resp, _ := message.MarshalDeleteSessionResponse(req, mmeTEID, ie.CauseSystemFailure)
			conn.Reply(addr, resp) //nolint:errcheck
			return
		}
		if pgwCause != ie.CauseRequestAccepted {
			// PGW rejected: relay cause with CS=1 per TS 29.274 §8.4 (C12); retain local state.
			h.log.Warn("S11: PGW rejected Delete Session — retaining local state",
				"session_id", sess.SessionID, "pgw_cause", pgwCause)
			relayHdr := message.Header{
				Version:        2,
				HasTEID:        true,
				MessageType:    message.MsgTypeDeleteSessionResponse,
				TEID:           mmeTEID,
				SequenceNumber: req.Header.SequenceNumber,
			}
			raw, _ := message.Marshal(relayHdr, []*ie.IE{ie.NewCause(pgwCause, 0, 0, 1 /* cs=1 */, nil)})
			conn.Reply(addr, raw) //nolint:errcheck
			return
		}
	}

	// PGW accepted (or no PGW session): delete PFCP session on SGW-U before local cleanup.
	// Per TS 23.214 Rel-15 §6.3 and C13 (remote teardown on delete).
	if sess.PFCP.Established && sess.PFCP.SGWUFSEID.SEID != 0 {
		if pfcpErr := h.pfcp.DeleteSessionOnPeer(opCtx,
			sess.PFCP.SGWUAddr,
			sess.PFCP.LocalFSEID.SEID,
			sess.PFCP.SGWUFSEID.SEID,
		); pfcpErr != nil {
			h.log.Warn("S11: PFCP Session Deletion failed — SGW-U state may leak",
				"session_id", sess.SessionID, "error", pfcpErr)
			// Non-fatal: continue with local cleanup. The PFCP binding on the SGW-U
			// may need manual cleanup, but control-plane state must be released.
		}
	}

	h.clearCreateBearerProcedureFailuresForSession(sess.SessionID, "s11_delete_session")
	h.sessions.Delete(sess.SessionID)
	h.log.Info("S11: Delete Session Request — session removed",
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
	)

	// Build Delete Session Response with Recovery IE per §7.2.0 if needed.
	h.buildAndReplyDeleteSessionResponse(conn, addr, req, mmeTEID)
}

func (h *Handler) buildAndReplyDeleteSessionResponse(conn *transport.Conn, addr *net.UDPAddr, req *message.DeleteSessionRequest, mmeTEID uint32) {
	var ies []*ie.IE
	ies = append(ies, ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil))
	if recIE := h.maybeRecoveryIE(addr); recIE != nil {
		ies = append(ies, recIE)
	}
	h2 := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDeleteSessionResponse,
		TEID:           mmeTEID,
		SequenceNumber: req.Header.SequenceNumber,
	}
	resp, err := message.Marshal(h2, ies)
	if err != nil {
		h.log.Error("S11: Delete Session Response marshal failed", "error", err)
		return
	}
	if err := conn.Reply(addr, resp); err != nil {
		h.log.Warn("S11: Delete Session Response send failed", "to", addr, "error", err)
	}
}

func (h *Handler) knownS11BearerState(sgwS11TEID uint32) ([]uint8, []map[string]any) {
	sessions := h.sessions.FindAllByS11TEID(sgwS11TEID)
	ebiSeen := make(map[uint8]bool)
	var ebis []uint8
	var pdns []map[string]any
	for _, sess := range sessions {
		pdns = append(pdns, map[string]any{
			"apn":         sess.APN,
			"default_ebi": sess.DefaultBearerID,
		})
		for _, b := range sess.BearerList() {
			if !ebiSeen[b.EBI] {
				ebiSeen[b.EBI] = true
				ebis = append(ebis, b.EBI)
			}
		}
	}
	return ebis, pdns
}

func downlinkPFCPRuleIDs(sess *session.SGWSession, b *bearer.Bearer) (uint16, uint32, bool) {
	if sess == nil || b == nil {
		return 0, 0, false
	}
	pdrID, farID := uint16(b.PDRIDs[1]), b.FARIDs[1]
	if pdrID != 0 && farID != 0 {
		return pdrID, farID, true
	}
	if b.EBI == sess.DefaultBearerID {
		// Default bearer PFCP rules are established with legacy IDs 1/2 and are
		// not stored on the bearer object in older sessions. Only the default
		// bearer may use this compatibility fallback.
		return 2, 2, true
	}
	return 0, 0, false
}

func releaseAccessBearerFARUpdates(sess *session.SGWSession) ([]pfcpclient.FARUpdate, error) {
	var updates []pfcpclient.FARUpdate
	for _, b := range sess.BearerList() {
		pdrID, farID, ok := downlinkPFCPRuleIDs(sess, b)
		if !ok {
			return nil, fmt.Errorf("missing downlink PFCP rule IDs for EBI %d", b.EBI)
		}
		updates = append(updates, pfcpclient.FARUpdate{
			FARID:       farID,
			PDRID:       pdrID,
			ApplyAction: pfcpie.ApplyActionDROP,
		})
	}
	return updates, nil
}

func (h *Handler) handleReleaseAccessBearersRequest(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	opCtx, cancelOp := h.operationContext()
	defer cancelOp()

	req := message.ParseReleaseAccessBearersRequest(hdr, ies)

	sessions := h.sessions.FindAllByS11TEID(hdr.TEID)
	if len(sessions) == 0 {
		h.log.Warn("S11: Release Access Bearers — session not found", "teid", fmt.Sprintf("0x%08X", hdr.TEID))
		// RABReq carries no Sender F-TEID; MME TEID unavailable without session.
		resp, _ := message.MarshalReleaseAccessBearersResponse(req, 0, ie.CauseContextNotFound)
		conn.Reply(addr, resp) //nolint:errcheck
		return
	}
	controlSess := sessions[len(sessions)-1]
	rabProc, ok := h.beginProcedure(controlSess, mmeProcedureRequest(collision.ProcedureReleaseAccessBearers, addr, hdr.TEID, hdr.SequenceNumber, nil))
	if !ok {
		resp, _ := message.MarshalReleaseAccessBearersResponse(req, controlSess.MMEControlFTEID.TEID, ie.CauseRequestRejected)
		conn.Reply(addr, resp) //nolint:errcheck
		return
	}
	defer finishProcedure(controlSess, rabProc)

	// R15-005 FIX: update SGW-U forwarding state before responding to the MME.
	// Per TS 23.401 Rel-15 §5.3.5: "The SGW shall [...] store the packet(s) that
	// require a DDN (downlink data notification) and [...] release the S1-U
	// bearers." In a CUPS SGW the UP function must apply the idle-state FAR
	// (DROP here; full BUFF+DDN requires BAR support, deferred) before the
	// control-plane procedure completes.
	for _, sess := range sessions {
		if !sess.PFCP.Established || sess.PFCP.SGWUFSEID.SEID == 0 {
			h.log.Warn("S11: Release Access Bearers — PFCP binding unavailable; clearing local access state only",
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
			)
			continue
		}
		updates, updateErr := releaseAccessBearerFARUpdates(sess)
		if updateErr != nil {
			h.log.Warn("S11: Release Access Bearers — missing downlink PFCP rule IDs",
				"session_id", sess.SessionID,
				"imsi", sess.IMSI,
				"apn", sess.APN,
				"error", updateErr,
			)
			resp, _ := message.MarshalReleaseAccessBearersResponse(req, controlSess.MMEControlFTEID.TEID, ie.CauseSystemFailure)
			conn.Reply(addr, resp) //nolint:errcheck
			return
		}
		if len(updates) == 0 {
			continue
		}
		pfcpErr := h.pfcp.ModifySessionOnPeer(opCtx,
			sess.PFCP.SGWUAddr,
			sess.PFCP.LocalFSEID.SEID,
			sess.PFCP.SGWUFSEID.SEID,
			updates,
		)
		if pfcpErr != nil {
			h.log.Warn("S11: PFCP Session Modification for Release Access Bearers failed — SGW-U may continue forwarding to released eNB",
				"session_id", sess.SessionID, "error", pfcpErr)
			resp, _ := message.MarshalReleaseAccessBearersResponse(req, controlSess.MMEControlFTEID.TEID, ie.CauseSystemFailure)
			conn.Reply(addr, resp) //nolint:errcheck
			return
		}
	}

	// PFCP updated — now clear local eNB FTEIDs per TS 23.401 §5.3.5.
	for _, sess := range sessions {
		sess.ClearENBFTEIDs()
	}
	knownEBIs, knownPDNs := h.knownS11BearerState(hdr.TEID)
	h.log.Info("S11: Release Access Bearers Request — eNodeB FTEIDs cleared, SGW-U FARs set to DROP",
		"imsi", controlSess.IMSI,
		"sgw_s11_teid", fmt.Sprintf("0x%08X", hdr.TEID),
		"pdn_count_after", len(sessions),
		"known_ebis", knownEBIs,
		"known_pdns", knownPDNs,
		"session_preserved", true,
		"pfcp_preserved", true,
	)

	// Include Recovery IE per TS 29.274 §7.2.0 on first contact with this MME.
	var rabIEs []*ie.IE
	rabIEs = append(rabIEs, ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil))
	if recIE := h.maybeRecoveryIE(addr); recIE != nil {
		rabIEs = append(rabIEs, recIE)
	}
	rabHdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeReleaseAccessBearersResponse,
		TEID:           controlSess.MMEControlFTEID.TEID,
		SequenceNumber: req.Header.SequenceNumber,
	}
	resp, err := message.Marshal(rabHdr, rabIEs)
	if err != nil {
		h.log.Error("S11: Release Access Bearers Response marshal failed", "error", err)
		return
	}
	if err := conn.Reply(addr, resp); err != nil {
		h.log.Warn("S11: Release Access Bearers Response send failed", "to", addr, "error", err)
	}
}

// ── PFCP integration helpers ──────────────────────────────────────────────────

// pfcpSessionResult holds the outcome of a PFCP Session Establishment for one bearer.
type pfcpSessionResult struct {
	peerName     string
	peerAddr     string
	cpSEID       uint64
	upSEID       uint64
	sgwUS1UFTEID bearer.FTEID // SGW-U S1-U TEID (from PDR with Access source interface)
	sgwUS5UFTEID bearer.FTEID // SGW-U S5/S8-U TEID (from PDR with Core source interface)
}

// establishProvisionalPFCPSession sends a PFCP Session Establishment Request for the
// default bearer per TS 29.244 Rel-15 §7.5.2 / Table 7.5.2.2-1.
//
// R15-REAUDIT-001: PFCP is established BEFORE S5/S8-C CSReq so the SGW-U S5/S8-U
// TEID (from Created PDR 2) can be included in the bearer context of the S5/S8-C CSReq.
// FAR 1 (uplink) is initially DROP — the PGW-U TEID is not yet known.
// Once the PGW CSResp arrives, call modifyPFCPUplinkFAR to switch FAR 1 to FORW.
//
// PDR layout (2 PDRs per default bearer):
//
//	PDR 1: Access→Core (source=Access, CHOOSE F-TEID for S1-U, FAR 1=DROP initially)
//	PDR 2: Core→Access (source=Core, CHOOSE F-TEID for S5/S8-U, FAR 2=DROP until MBReq)
//
// FAR layout:
//
//	FAR 1: Access→Core DROP (provisional) — upgraded to FORW after PGW CSResp
//	FAR 2: Core→Access DROP — upgraded to FORW on Modify Bearer Request
func (h *Handler) establishProvisionalPFCPSession(ctx context.Context, sess *session.SGWSession) (*pfcpSessionResult, error) {
	cpSEID := h.pfcp.AllocCPSEID()
	defaultBearer := sess.GetBearer(sess.DefaultBearerID)
	qosIE := pfcpie.NewVectorCoreQoSMarking(sess.DefaultBearerID, 0, false)
	if defaultBearer != nil && defaultBearer.QCI != 0 {
		qosIE = pfcpie.NewVectorCoreQoSMarking(defaultBearer.EBI, defaultBearer.QCI, true)
		h.log.Info("SGW-C: bearer QoS state updated",
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"ebi", defaultBearer.EBI,
			"qci", defaultBearer.QCI,
			"arp_pl", defaultBearer.ARP.PriorityLevel,
			"gbr_ul", defaultBearer.GBRUplink,
			"gbr_dl", defaultBearer.GBRDownlink,
			"mbr_ul", defaultBearer.MBRUplink,
			"mbr_dl", defaultBearer.MBRDownlink,
		)
	}

	// PDR 1: Access (S1-U) → Core (S5/S8), uplink direction.
	// F-TEID with CHOOSE=1 so SGW-U allocates the S1-U TEID.
	pdi1 := pfcpie.NewPDI(
		pfcpie.NewSourceInterface(pfcpie.SourceInterfaceAccess),
		pfcpie.NewFTEIDChoose(), // SGW-U allocates S1-U GTP-U TEID
	)
	createPDR1 := pfcpie.NewCreatePDR(
		pfcpie.NewPDRID(1),
		pfcpie.NewPrecedence(100),
		pdi1,
		pfcpie.NewFARID(1),
		qosIE,
	)

	// PDR 2: Core (S5/S8) → Access (S1-U), downlink direction.
	// F-TEID with CHOOSE=1 so SGW-U allocates the S5/S8-U TEID.
	pdi2 := pfcpie.NewPDI(
		pfcpie.NewSourceInterface(pfcpie.SourceInterfaceCore),
		pfcpie.NewFTEIDChoose(), // SGW-U allocates S5/S8-U GTP-U TEID
	)
	createPDR2 := pfcpie.NewCreatePDR(
		pfcpie.NewPDRID(2),
		pfcpie.NewPrecedence(200),
		pdi2,
		pfcpie.NewFARID(2),
		qosIE,
	)

	// FAR 1: DROP (uplink, provisional). Upgraded to FORW after PGW CSResp provides PGW-U TEID.
	// Per R15-REAUDIT-001: cannot include PGW-U OHC here because PGW-U TEID is unknown
	// until after S5/S8-C CSResp. Use DROP so no traffic leaks uplink before PGW is ready.
	createFAR1 := pfcpie.NewCreateFAR(
		pfcpie.NewFARID(1),
		pfcpie.NewApplyAction(pfcpie.ApplyActionDROP),
	)

	// FAR 2: DROP (downlink toward eNB). Upgraded to FORW on Modify Bearer Request.
	// The eNB TEID is not yet known at this point.
	createFAR2 := pfcpie.NewCreateFAR(
		pfcpie.NewFARID(2),
		pfcpie.NewApplyAction(pfcpie.ApplyActionDROP),
	)

	result, err := h.pfcp.EstablishSession(ctx, pfcpclient.SessionParams{
		LocalIP:    h.localIP,
		CPFSEID:    cpSEID,
		CreatePDRs: []*pfcpie.IE{createPDR1, createPDR2},
		CreateFARs: []*pfcpie.IE{createFAR1, createFAR2},
	})
	if err != nil {
		return nil, err
	}

	out := &pfcpSessionResult{
		peerName: result.PeerName,
		peerAddr: result.PeerAddr,
		cpSEID:   cpSEID,
		upSEID:   result.UPSEID,
	}

	// Extract SGW-U TEIDs from Created PDR IEs.
	// PDR 1 (Access→Core) carries the S1-U TEID.
	// PDR 2 (Core→Access) carries the S5/S8-U TEID.
	for _, cpdrIE := range result.CreatedPDRs {
		children, cErr := cpdrIE.Children()
		if cErr != nil {
			continue
		}
		pdrIDIE := pfcpie.Find(children, pfcpie.TypePDRID)
		fteidIE := pfcpie.Find(children, pfcpie.TypeFTEID)
		if pdrIDIE == nil || fteidIE == nil {
			continue
		}
		pdrID, _ := pdrIDIE.PDRIDValue()
		fteid, _, fteidErr := fteidIE.FTEIDPFCPValue()
		if fteidErr != nil {
			continue
		}
		switch pdrID {
		case 1: // Access→Core: SGW-U's S1-U endpoint
			out.sgwUS1UFTEID = bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4}
		case 2: // Core→Access: SGW-U's S5/S8-U endpoint
			out.sgwUS5UFTEID = bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4}
		}
	}

	return out, nil
}

// modifyPFCPUplinkFAR switches FAR 1 (uplink, Access→Core) from DROP to FORW with
// Outer Header Creation pointing to the PGW-U S5/S8-U TEID and IP.
// Called after S5/S8-C CSResp provides the PGW-U GTP-U endpoint (R15-REAUDIT-001).
func (h *Handler) modifyPFCPUplinkFAR(ctx context.Context, peerAddr string, cpSEID, upSEID uint64, pgwS5UFTEID bearer.FTEID) error {
	return h.pfcp.ModifySessionOnPeer(ctx, peerAddr, cpSEID, upSEID, []pfcpclient.FARUpdate{
		{
			FARID:              1,
			PDRID:              1,
			ApplyAction:        pfcpie.ApplyActionFORW,
			DestInterface:      pfcpie.DestInterfaceCore,
			OuterTEID:          pgwS5UFTEID.TEID,
			OuterIP:            pgwS5UFTEID.IPv4,
			OuterHeaderRemoval: true,
		},
	})
}

// maybeRecoveryIE returns a Recovery IE (instance 0) if this peer has not yet
// received our current restart counter, per TS 29.274 §7.2.0. Returns nil
// once the counter has been advertised. Always non-nil on first contact.
func (h *Handler) maybeRecoveryIE(addr *net.UDPAddr) *ie.IE {
	cur := h.recovery.Value()
	key := addr.String()
	if v, ok := h.peerSeen.Load(key); ok && v.(uint8) == cur {
		return nil
	}
	h.peerSeen.Store(key, cur)
	return ie.NewRecovery(cur)
}

// ── Helpers ──────────────────────────────────────────────────────────────────

func (h *Handler) sendCause(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, peerTEID uint32, cause uint8) {
	h.sendCauseWithOffending(conn, addr, hdr, peerTEID, cause, nil)
}

func (h *Handler) sendMissingIECause(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, peerTEID uint32, err error) {
	cause := ie.CauseInvalidMessageFormat
	var offending *ie.IE
	if me, ok := err.(*message.MissingIEError); ok {
		cause = ie.CauseMandatoryIEMissing
		offending = &ie.IE{Type: me.IEType}
	}
	h.sendCauseWithOffending(conn, addr, hdr, peerTEID, cause, offending)
}

// sendCauseWithOffending sends a generic error response with an optional offending IE.
// peerTEID is the MME's S11 control TEID, looked up per §5.5.2's response-TEID rule.
// Pass 0 when the peer TEID cannot be determined (e.g., malformed inbound message).
func (h *Handler) sendCauseWithOffending(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, peerTEID uint32, cause uint8, offending *ie.IE) {
	// Per TS 29.274 Rel-15 Table 6.1-1: response types are explicit constants,
	// never computed arithmetically from the request type.
	respType, ok := message.ResponseTypeFor(hdr.MessageType)
	if !ok {
		h.log.Warn("S11: no response type for message", "msg_type", hdr.MessageType)
		return
	}
	respHdr := message.Header{
		Version:        2,
		HasTEID:        hdr.HasTEID,
		MessageType:    respType,
		TEID:           peerTEID,
		SequenceNumber: hdr.SequenceNumber,
	}
	raw, err := message.Marshal(respHdr, []*ie.IE{ie.NewCause(cause, 0, 0, 0, offending)})
	if err != nil {
		h.log.Error("S11: cause response marshal failed", "error", err)
		return
	}
	if err := conn.Reply(addr, raw); err != nil {
		h.log.Warn("S11: cause response send failed", "to", addr, "error", err)
	}
}

// peerTEIDFromIEs extracts the Sender F-TEID (instance 0) TEID value from a raw IE list.
// Used to populate the response header TEID on initial CSReq (where hdr.TEID=0) per
// TS 29.274 Rel-15 §5.5.2. Returns 0 if the F-TEID IE is absent or malformed.
func peerTEIDFromIEs(ies []*ie.IE) uint32 {
	fteid := ie.FindInstance(ies, ie.TypeFTEID, 0)
	if fteid == nil {
		return 0
	}
	f, err := fteid.FTEIDValue()
	if err != nil {
		return 0
	}
	return f.TEID
}

// extractDefaultBearer pulls EBI, QCI, and ARP from the first bearer context IE.
func extractDefaultBearer(bcIEs []*ie.IE) (ebi, qci uint8, arp bearer.ARP) {
	if len(bcIEs) == 0 {
		return 5, 9, bearer.ARP{PriorityLevel: 9}
	}
	children, err := bcIEs[0].ChildIEs()
	if err != nil {
		return 5, 9, bearer.ARP{PriorityLevel: 9}
	}
	if ebiIE := ie.FindFirst(children, ie.TypeEBI); ebiIE != nil {
		ebi, _ = ebiIE.EBIValue()
	}
	if qosIE := ie.FindFirst(children, ie.TypeBearerQoS); qosIE != nil && len(qosIE.Value) >= 2 {
		// Per TS 29.274 Section 8.15 Figure 8.15-1, Bearer QoS octet 1:
		// Bit 7 (0x40) = PCI: 1 → bearer IS pre-emption capable, 0 → NOT capable.
		// Bits 6-3 (0x3C>>2) = PL: priority level 1-15.
		// Bit 1 (0x01) = PVI: 1 → bearer IS pre-emption vulnerable, 0 → NOT vulnerable.
		arp.PriorityLevel = (qosIE.Value[0] >> 2) & 0x0F
		arp.PreemptionCapability = qosIE.Value[0]&0x40 != 0
		arp.PreemptionVulnerability = qosIE.Value[0]&0x01 != 0
		qci = qosIE.Value[1]
	}
	if ebi == 0 {
		ebi = 5
	}
	if qci == 0 {
		qci = 9
	}
	return ebi, qci, arp
}

// addrFromUDP extracts a netip.Addr from a UDPAddr (IPv4 only for v0).
func addrFromUDP(a *net.UDPAddr) netip.Addr {
	if a == nil {
		return netip.Addr{}
	}
	if v4 := a.IP.To4(); v4 != nil {
		return netip.AddrFrom4([4]byte(v4))
	}
	return netip.Addr{}
}
