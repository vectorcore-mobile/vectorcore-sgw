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
	"vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/recovery"
	"vectorcore-sgw/internal/sgwc/s5c"
	"vectorcore-sgw/internal/sgwc/session"
)

// Handler processes inbound S11 messages from the MME.
type Handler struct {
	cfg      *sgwcconfig.Config
	conn     gtpcConn
	log      *slog.Logger
	sessions *session.Manager
	recovery *recovery.Counter
	s5c      s5cClient
	pfcp     pfcpClient
	localIP  netip.Addr // SGW-C S11 control-plane IP for Sender F-TEID IEs
	peerSeen sync.Map   // addr string → uint8; last restart counter advertised to each MME peer

	cbTxnMu        sync.Mutex
	cbTxns         map[createBearerTxnKey]*createBearerTxnState
	cbFPs          map[createBearerFingerprintKey]*createBearerTxnState
	cbS11          map[s11CreateBearerResponseKey]*pendingS11CreateBearer
	cbProcFailures map[createBearerProcedureKey]*createBearerProcedureFailure
}

type gtpcConn interface {
	AllocSeq() uint32
	Send(ctx context.Context, addr *net.UDPAddr, raw []byte) ([]byte, error)
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
		cfg:            cfg,
		conn:           conn,
		log:            log,
		sessions:       sessions,
		recovery:       rc,
		s5c:            s5cClient,
		pfcp:           pfcpClient,
		localIP:        localIP,
		cbTxns:         make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:          make(map[createBearerFingerprintKey]*createBearerTxnState),
		cbS11:          make(map[s11CreateBearerResponseKey]*pendingS11CreateBearer),
		cbProcFailures: make(map[createBearerProcedureKey]*createBearerProcedureFailure),
	}
	conn.SetHandler(h.handle)
	return h, nil
}

// NewWithConn creates an S11 handler using an already-bound GTPv2-C transport.
// This is used when S11 and S5/S8-C share one configured control binding.
func NewWithConn(cfg *sgwcconfig.Config, conn *transport.Conn, sessions *session.Manager, rc *recovery.Counter, s5cClient *s5c.Client, pfcpClient *pfcpclient.Client, localIP netip.Addr, log *slog.Logger) *Handler {
	h := &Handler{
		cfg:            cfg,
		conn:           conn,
		log:            log,
		sessions:       sessions,
		recovery:       rc,
		s5c:            s5cClient,
		pfcp:           pfcpClient,
		localIP:        localIP,
		cbTxns:         make(map[createBearerTxnKey]*createBearerTxnState),
		cbFPs:          make(map[createBearerFingerprintKey]*createBearerTxnState),
		cbS11:          make(map[s11CreateBearerResponseKey]*pendingS11CreateBearer),
		cbProcFailures: make(map[createBearerProcedureKey]*createBearerProcedureFailure),
	}
	return h
}

// Serve starts the S11 read loop. Blocks until ctx is cancelled.
func (h *Handler) Serve(ctx context.Context) error {
	h.log.Info("S11 listening", "addr", h.conn.LocalAddr())
	return h.conn.Serve(ctx)
}

// Close shuts down the S11 listener.
func (h *Handler) Close() error {
	return h.conn.Close()
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
		h.handleCreateSessionRequest(conn, addr, hdr, ies)
	case message.MsgTypeModifyBearerRequest:
		h.handleModifyBearerRequest(conn, addr, hdr, ies)
	case message.MsgTypeCreateBearerResponse:
		h.handlePiggybackCreateBearerResponse(conn, addr, hdr, raw)
	case message.MsgTypeDeleteSessionRequest:
		h.handleDeleteSessionRequest(conn, addr, hdr, ies)
	case message.MsgTypeReleaseAccessBearersRequest:
		h.handleReleaseAccessBearersRequest(conn, addr, hdr, ies)
	default:
		h.log.Warn("S11: unhandled message type", "from", addr, "msg_type", hdr.MessageType)
	}
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
		if _, err := h.s5c.DeleteSession(context.TODO(), evicted); err != nil {
			h.log.Warn("S11: PGW Delete Session for evicted session failed — PGW state may leak",
				"evicted_session_id", evicted.SessionID, "error", err)
		}
	}
	// A-001 FIX: also release the PFCP session for the evicted binding.
	// Per C13 (C8 extension): remote teardown must include both PGW (S5/S8-C) and
	// SGW-U (PFCP) cleanup. Local sessions.Delete() alone leaves stale forwarding state
	// on the SGW-U with orphaned TEIDs that may collide with the new session.
	if evicted != nil && evicted.PFCP.Established && evicted.PFCP.SGWUFSEID.SEID != 0 {
		if pfcpErr := h.pfcp.DeleteSessionOnPeer(context.TODO(),
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

	// R15-REAUDIT-001: PFCP Session Establishment BEFORE S5/S8-C CSReq.
	// The provisional PFCP session allocates the SGW-U S5/S8-U TEID (Created PDR 2),
	// which must be included in the S5/S8-C CSReq bearer context so the PGW-U can send
	// downlink traffic to the correct SGW-U tunnel endpoint.
	// FAR 1 starts as DROP; it is upgraded to FORW (with PGW-U OHC) after PGW CSResp.
	pfcpResult, pfcpErr := h.establishProvisionalPFCPSession(context.TODO())
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
		if delErr := h.pfcp.DeleteSessionOnPeer(context.TODO(), pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
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
	sess.SGWS5CFTEID = session.FTEID{TEID: sgwS5CTEID, IPv4: h.localIP}
	h.sessions.RegisterS5CTEID(sess.SessionID, sgwS5CTEID)

	// Send Create Session Request to PGW on S5/S8-C, including SGW-U S5/S8-U TEID.
	// Per TS 29.274 Rel-15 §7.2.1 / Table 7.2.1-1 (S5/S8-C direction).
	s5cResult, err := h.s5c.CreateSession(context.TODO(), pgwAddr, req, sgwS5CTEID, pfcpResult.sgwUS5UFTEID)
	if err != nil {
		h.log.Error("S11: S5/S8-C Create Session failed", "pgw", pgwAddr, "error", err)
		// Roll back PFCP provisional session — PGW never acknowledged it.
		if delErr := h.pfcp.DeleteSessionOnPeer(context.TODO(), pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
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
		if delErr := h.pfcp.DeleteSessionOnPeer(context.TODO(), pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
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
	sess.PGWControlFTEID = s5cResult.PGWControlFTEID
	sess.UEIPv4 = s5cResult.UEIP

	// Update default bearer with PGW-U S5/S8-U F-TEID per Table 7.2.2-2.
	if b := sess.GetBearer(ebi); b != nil {
		b.PGWS5UFTEID = s5cResult.PGWS5UFTEID
		sess.SetBearer(b)
	}

	// Upgrade FAR 1 from DROP to FORW now that we have the PGW-U S5/S8-U TEID.
	// R15-REAUDIT-001: this completes the PFCP-first sequence.
	if s5cResult.PGWS5UFTEID.TEID != 0 {
		if modErr := h.modifyPFCPUplinkFAR(context.TODO(),
			pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID, s5cResult.PGWS5UFTEID); modErr != nil {
			h.log.Error("S11: PFCP modify uplink FAR failed — tearing down",
				"session_id", sess.SessionID, "error", modErr)
			if _, dsErr := h.s5c.DeleteSession(context.TODO(), sess); dsErr != nil {
				h.log.Warn("S11: PGW Delete Session after PFCP modify failure also failed",
					"session_id", sess.SessionID, "error", dsErr)
			}
			if delErr := h.pfcp.DeleteSessionOnPeer(context.TODO(), pfcpResult.peerAddr, pfcpResult.cpSEID, pfcpResult.upSEID); delErr != nil {
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
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: cpSEID, IPv4: h.localIP},
		SGWUFSEID:   session.FSEID{SEID: upSEID},
		SGWUName:    pfcpResult.peerName,
		SGWUAddr:    pfcpResult.peerAddr,
		Established: true,
	}

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
		// carry their own PFCP rule IDs from Create Bearer acceptance.
		pdrID, farID := uint16(b.PDRIDs[1]), b.FARIDs[1]
		if pdrID == 0 || farID == 0 {
			pdrID, farID = 2, 2
		}
		pfcpErr := h.pfcp.ModifySessionOnPeer(context.TODO(),
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
		results = append(results, mbResult{ebi: ebi, cause: ie.CauseRequestAccepted, sgwS1UFTEID: sgwS1U})
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

func (h *Handler) handleDeleteSessionRequest(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
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
	sess.Transition(session.StateDeleting)

	// Propagate Delete Session Request to PGW on S5/S8-C if a PGW session exists.
	// Per TS 29.274 Rel-15 §7.2.9 / Table 7.2.9.1-1 (S5/S8-C direction).
	// R15-005: propagate PGW cause to MME; retain local state on failure for retry.
	if sess.PGWControlFTEID.TEID != 0 {
		pgwCause, pgwErr := h.s5c.DeleteSessionFromS11(context.TODO(), sess, req)
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
		if pfcpErr := h.pfcp.DeleteSessionOnPeer(context.TODO(),
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

func (h *Handler) handleReleaseAccessBearersRequest(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, ies []*ie.IE) {
	req := message.ParseReleaseAccessBearersRequest(hdr, ies)

	sess := h.sessions.FindByS11TEID(hdr.TEID)
	if sess == nil {
		h.log.Warn("S11: Release Access Bearers — session not found", "teid", fmt.Sprintf("0x%08X", hdr.TEID))
		// RABReq carries no Sender F-TEID; MME TEID unavailable without session.
		resp, _ := message.MarshalReleaseAccessBearersResponse(req, 0, ie.CauseContextNotFound)
		conn.Reply(addr, resp) //nolint:errcheck
		return
	}

	// R15-005 FIX: update SGW-U forwarding state before responding to the MME.
	// Per TS 23.401 Rel-15 §5.3.5: "The SGW shall [...] store the packet(s) that
	// require a DDN (downlink data notification) and [...] release the S1-U
	// bearers." In a CUPS SGW the UP function must apply the idle-state FAR
	// (DROP here; full BUFF+DDN requires BAR support, deferred) before the
	// control-plane procedure completes.
	if sess.PFCP.Established && sess.PFCP.SGWUFSEID.SEID != 0 {
		pfcpErr := h.pfcp.ModifySessionOnPeer(context.TODO(),
			sess.PFCP.SGWUAddr,
			sess.PFCP.LocalFSEID.SEID,
			sess.PFCP.SGWUFSEID.SEID,
			[]pfcpclient.FARUpdate{{
				FARID:       2, // Core→Access (downlink) FAR — was FORW to eNB, now DROP
				PDRID:       2,
				ApplyAction: pfcpie.ApplyActionDROP,
			}},
		)
		if pfcpErr != nil {
			h.log.Warn("S11: PFCP Session Modification for Release Access Bearers failed — SGW-U may continue forwarding to released eNB",
				"session_id", sess.SessionID, "error", pfcpErr)
			resp, _ := message.MarshalReleaseAccessBearersResponse(req, sess.MMEControlFTEID.TEID, ie.CauseSystemFailure)
			conn.Reply(addr, resp) //nolint:errcheck
			return
		}
	}

	// PFCP updated — now clear local eNB FTEIDs per TS 23.401 §5.3.5.
	sess.ClearENBFTEIDs()
	h.log.Info("S11: Release Access Bearers Request — eNodeB FTEIDs cleared, SGW-U FAR set to DROP",
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
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
		TEID:           sess.MMEControlFTEID.TEID,
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
func (h *Handler) establishProvisionalPFCPSession(ctx context.Context) (*pfcpSessionResult, error) {
	cpSEID := h.pfcp.AllocCPSEID()

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
