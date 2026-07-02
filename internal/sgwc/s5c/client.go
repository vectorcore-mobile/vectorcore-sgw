// Package s5c implements the SGW-C S5/S8-C GTPv2-C client toward PGW-C
// per 3GPP TS 29.274 Rel-15.
package s5c

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/gtpv2/transport"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/recovery"
	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/teid"
)

// Client is the SGW-C S5/S8-C control-plane client toward PGW-C.
type Client struct {
	conn      *transport.Conn
	log       *slog.Logger
	teidAlloc *teid.Allocator
	localIP   netip.Addr // SGW-C S5/S8-C IP for Sender F-TEID IEs
	rc        *recovery.Counter
	peerSeen  sync.Map // addr string → uint8; last restart counter advertised to each peer
}

// CreateSessionResult holds the outcome of a successful PGW Create Session exchange.
type CreateSessionResult struct {
	Cause            uint8
	SGWS5CTEID       uint32        // SGW's local S5/S8-C TEID advertised in the request
	PGWControlFTEID  session.FTEID // PGW S5/S8-C control F-TEID (from CSResp Sender FTEID inst 0)
	PGWS5UFTEID      bearer.FTEID  // PGW-U S5/S8-U F-TEID (from CSResp bearer context inst 2 per Table 7.2.2-2)
	DefaultEBI       uint8
	UEIP             netip.Addr // from PGW PAA IE
	AMBR             *ie.IE     // forwarded to MME in S11 CSResp
	PCO              *ie.IE     // forwarded to MME in S11 CSResp
	APNRestriction   *ie.IE     // forwarded to MME in S11 CSResp
	ChargingID       *ie.IE     // forwarded to MME in S11 CSResp when message-level
	BearerChargingID *ie.IE     // retained from PGW Bearer Context for accounting/debug; not forwarded in S11 CSRsp Bearer Context
	Piggybacks       []message.Frame
}

// New creates an S5/S8-C client listening on the configured S5/S8-C control binding.
// localIP is the control-plane IP to advertise in Sender F-TEID IEs.
// rc is the GTPv2-C restart counter used for Recovery IE advertisement per TS 29.274 §7.2.0.
func New(cfg *sgwcconfig.Config, localIP netip.Addr, rc *recovery.Counter, log *slog.Logger) (*Client, error) {
	conn, err := transport.Listen(
		cfg.S5CListen(),
		cfg.S11.T3ResponseSeconds,
		cfg.S11.N3Requests,
		log,
	)
	if err != nil {
		return nil, fmt.Errorf("s5c listen: %w", err)
	}
	if cfg.QoS.OuterMarking.Enabled && cfg.QoS.OuterMarking.GTPC.Enabled {
		if err := conn.SetDSCP(uint8(cfg.QoS.OuterMarking.GTPC.DSCP)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("s5c QoS outer marking: %w", err)
		}
	}

	c := &Client{
		conn:      conn,
		log:       log,
		teidAlloc: teid.NewAllocator(),
		localIP:   localIP,
		rc:        rc,
	}

	return c, nil
}

// NewWithConn creates an S5/S8-C client using an already-bound GTPv2-C
// transport. This is used when S11 and S5/S8-C share one configured control
// binding.
func NewWithConn(conn *transport.Conn, localIP netip.Addr, rc *recovery.Counter, log *slog.Logger) *Client {
	return &Client{
		conn:      conn,
		log:       log,
		teidAlloc: teid.NewAllocator(),
		localIP:   localIP,
		rc:        rc,
	}
}

// PGWAddr resolves the PGW S5/S8-C address for a new session.
// Per TS 23.401 Rel-15 §5.3.2.1: the PGW address MUST come from F-TEID IE
// (instance 1) in the MME's CSReq. If absent, the CSReq is non-conformant
// and the procedure must be rejected.
func (c *Client) PGWAddr(s11req *message.CreateSessionRequest) (*net.UDPAddr, error) {
	if s11req.PGWFTEID != nil {
		pgwF, err := s11req.PGWFTEID.FTEIDValue()
		if err == nil && pgwF.IPv4.IsValid() {
			ip4 := pgwF.IPv4.As4()
			return &net.UDPAddr{IP: ip4[:], Port: 2123}, nil
		}
	}
	return nil, fmt.Errorf("PGW S5/S8-C address unavailable: MME CSReq missing PGW F-TEID IE (instance 1) per TS 23.401 §5.3.2.1")
}

// CreateSession sends a Create Session Request to pgwAddr and returns the result.
// On success the result carries the SGWS5CTEID and PGW response IEs.
// On PGW rejection, Cause is the PGW's cause code.
// Per TS 29.274 Rel-15 §7.2.1 / Table 7.2.1-1 (S5/S8-C direction).
// R15-REAUDIT-001: sgwUS5UFTEID is the SGW-U S5/S8-U F-TEID to include in the bearer context
// (C per Table 7.2.1-2 — absent when zero, included when non-zero after PFCP allocation).
func (c *Client) CreateSession(ctx context.Context, pgwAddr *net.UDPAddr, s11req *message.CreateSessionRequest, sgwS5CTEID uint32, sgwUS5UFTEID bearer.FTEID) (*CreateSessionResult, error) {
	seq := c.conn.AllocSeq()
	recIE := c.maybeRecoveryIE(pgwAddr)
	raw, err := buildCSReq(s11req, sgwS5CTEID, c.localIP, seq, recIE, sgwUS5UFTEID)
	if err != nil {
		return nil, fmt.Errorf("build S5/S8-C CSReq: %w", err)
	}

	c.log.Info("S5/S8-C: Create Session Request",
		"pgw", pgwAddr,
		"sgw_s5c_teid", fmt.Sprintf("0x%08X", sgwS5CTEID),
		"seq", seq,
	)

	respRaw, piggybacks, err := c.conn.SendWithPiggybacks(ctx, pgwAddr, raw)
	if err != nil {
		return nil, fmt.Errorf("s5c send CSReq: %w", err)
	}

	h, ies, err := message.Parse(respRaw)
	if err != nil {
		return nil, fmt.Errorf("s5c parse CSResp: %w", err)
	}
	if h.MessageType != message.MsgTypeCreateSessionResponse {
		return nil, fmt.Errorf("s5c unexpected message type %d (want %d)",
			h.MessageType, message.MsgTypeCreateSessionResponse)
	}

	resp, err := message.ParseCreateSessionResponse(h, ies)
	if err != nil {
		return nil, fmt.Errorf("s5c decode CSResp: %w", err)
	}

	cause, _ := resp.Cause.CauseValue()
	if cause != ie.CauseRequestAccepted {
		reject := describeCause(resp.Cause)
		c.log.Warn("S5/S8-C: PGW rejected Create Session Request",
			"pgw", pgwAddr,
			"cause", cause,
			"cause_text", reject.CauseText,
			"offending_ie_type", reject.OffendingIEType,
			"offending_ie", reject.OffendingIEName,
			"offending_ie_instance", reject.OffendingIEInstance,
		)
		return &CreateSessionResult{Cause: cause, Piggybacks: piggybacks}, nil
	}

	// C11: on cause=16, PGW Sender F-TEID (instance 1 on S5/S8) and Bearer Context
	// Created are C with condition "present when Request Accepted"
	// per Table 7.2.2-1 / Table 7.2.2-2.
	// Instance 1 is PGW S5/S8-C F-TEID on S5/S8 interface per Table 7.2.2-1.
	if resp.PGWFTEID == nil {
		return nil, fmt.Errorf("s5c PGW CSResp cause=16 but PGW Sender F-TEID (instance 1, S5/S8) absent (Table 7.2.2-1)")
	}
	if len(resp.BearerContexts) == 0 {
		return nil, fmt.Errorf("s5c PGW CSResp cause=16 but Bearer Context Created absent (Table 7.2.2-2)")
	}

	result := &CreateSessionResult{
		Cause:          cause,
		SGWS5CTEID:     sgwS5CTEID,
		AMBR:           resp.AMBR,
		PCO:            resp.PCO,
		APNRestriction: resp.APNRestriction,
		ChargingID:     resp.ChargingID,
		Piggybacks:     piggybacks,
	}

	// PGW S5/S8-C F-TEID: Sender F-TEID instance 1 on S5/S8 interface per
	// TS 29.274 Rel-15 Table 7.2.2-1 (S5/S8 column). Instance 0 is for S11/S4
	// and is not sent by a compliant PGW on the S5/S8 interface.
	pgwF, err := resp.PGWFTEID.FTEIDValue()
	if err == nil {
		result.PGWControlFTEID = session.FTEID{TEID: pgwF.TEID, IPv4: pgwF.IPv4}
	}

	// UE IP from PAA: C on success per Table 7.2.2-1.
	if resp.PAA != nil {
		paa, err := resp.PAA.PAAValue()
		if err == nil {
			result.UEIP = paa.IPv4
		}
	} else {
		c.log.Warn("S5/S8-C: PGW CSResp cause=16 but PAA absent (Table 7.2.2-1, C on success)")
	}

	// PGW S5/S8-U F-TEID: instance 2 within Bearer Context per TS 29.274 Rel-15
	// Table 7.2.2-2, S5/S8-C column (PGW→SGW-C direction). Per C10.
	children, err := resp.BearerContexts[0].ChildIEs()
	if err == nil {
		if ebiIE := ie.FindFirst(children, ie.TypeEBI); ebiIE != nil {
			result.DefaultEBI, _ = ebiIE.EBIValue()
		}
		if fteidIE := ie.FindInstance(children, ie.TypeFTEID, 2); fteidIE != nil {
			pgwUF, err := fteidIE.FTEIDValue()
			if err == nil {
				result.PGWS5UFTEID = bearer.FTEID{TEID: pgwUF.TEID, IPv4: pgwUF.IPv4}
			}
		}
		if chargingIDIE := ie.FindFirst(children, ie.TypeChargingID); chargingIDIE != nil {
			result.BearerChargingID = chargingIDIE
		}
	}

	c.log.Info("S5/S8-C: Create Session Response — accepted",
		"pgw", pgwAddr,
		"pgw_s5c_teid", fmt.Sprintf("0x%08X", result.PGWControlFTEID.TEID),
		"pgw_s5u_teid", fmt.Sprintf("0x%08X", result.PGWS5UFTEID.TEID),
		"ue_ip", result.UEIP,
	)

	return result, nil
}

// DispatchPiggybacks processes PGW-originated frames that were piggybacked on a
// response after the caller has committed session state from the primary frame.
func (c *Client) DispatchPiggybacks(pgwAddr *net.UDPAddr, frames []message.Frame) {
	c.conn.DispatchFrames(pgwAddr, frames)
}

// DeleteSession sends a Delete Session Request to the PGW for the given session
// and returns the cause from the PGW's response.
// Per TS 29.274 Rel-15 §7.2.9 / Table 7.2.9.1-1 (S5/S8-C direction).
// If the session has no PGW S5/S8-C binding (Phase 3 not reached), returns
// CauseRequestAccepted immediately — there is nothing to delete at the PGW.
func (c *Client) DeleteSession(ctx context.Context, sess *session.SGWSession) (uint8, error) {
	return c.deleteSession(ctx, sess, nil)
}

// DeleteSessionFromS11 sends a Delete Session Request to the PGW while preserving
// S11 request IEs that are valid on S5/S8-C, such as Cause and Indication.
func (c *Client) DeleteSessionFromS11(ctx context.Context, sess *session.SGWSession, req *message.DeleteSessionRequest) (uint8, error) {
	return c.deleteSession(ctx, sess, req)
}

func (c *Client) deleteSession(ctx context.Context, sess *session.SGWSession, req *message.DeleteSessionRequest) (uint8, error) {
	if sess.PGWControlFTEID.TEID == 0 {
		return ie.CauseRequestAccepted, nil
	}

	pgwIP4 := sess.PGWControlFTEID.IPv4.As4()
	pgwAddr := &net.UDPAddr{
		IP:   pgwIP4[:],
		Port: 2123,
	}

	seq := c.conn.AllocSeq()
	recIE := c.maybeRecoveryIE(pgwAddr)
	raw, err := buildDSReq(sess, req, seq, recIE)
	if err != nil {
		return 0, fmt.Errorf("build S5/S8-C DSReq: %w", err)
	}

	c.log.Info("S5/S8-C: Delete Session Request",
		"pgw", pgwAddr,
		"pgw_s5c_teid", fmt.Sprintf("0x%08X", sess.PGWControlFTEID.TEID),
		"seq", seq,
	)

	respRaw, err := c.conn.Send(ctx, pgwAddr, raw)
	if err != nil {
		return 0, fmt.Errorf("s5c send DSReq: %w", err)
	}

	h, ies, err := message.Parse(respRaw)
	if err != nil {
		return 0, fmt.Errorf("s5c parse DSResp: %w", err)
	}
	if h.MessageType != message.MsgTypeDeleteSessionResponse {
		return 0, fmt.Errorf("s5c unexpected message type %d (want %d)",
			h.MessageType, message.MsgTypeDeleteSessionResponse)
	}

	resp, err := message.ParseDeleteSessionResponse(h, ies)
	if err != nil {
		return 0, fmt.Errorf("s5c decode DSResp: %w", err)
	}

	cause, _ := resp.Cause.CauseValue()
	c.log.Info("S5/S8-C: Delete Session Response", "pgw", pgwAddr, "cause", cause)

	// A-002 FIX: only release the S5/S8-C TEID when the PGW accepted the deletion.
	// Per TS 29.274 §7.2.9: on rejection the S11 handler retains the session for retry.
	// A retained session still references this TEID; freeing it early risks re-assignment
	// to another session while the old session holds a reference.
	if cause == ie.CauseRequestAccepted && sess.SGWS5CFTEID.TEID != 0 {
		c.teidAlloc.Free(sess.SGWS5CFTEID.TEID)
	}

	return cause, nil
}

// maybeRecoveryIE returns a Recovery IE if this peer has not yet seen our current
// restart counter, per TS 29.274 §7.2.0. Returns nil once the counter has been
// advertised. Always returns non-nil on first contact with a peer.
func (c *Client) maybeRecoveryIE(addr *net.UDPAddr) *ie.IE {
	if c.rc == nil {
		return nil
	}
	cur := c.rc.Value()
	key := addr.String()
	if v, ok := c.peerSeen.Load(key); ok && v.(uint8) == cur {
		return nil
	}
	c.peerSeen.Store(key, cur)
	return ie.NewRecovery(cur)
}

// SetRequestHandler registers a handler for PGW-initiated requests arriving on the
// S5/S8-C connection (e.g., Create Bearer Request, Update Bearer Request, Delete Bearer
// Request per TS 29.274 §7.2.3, §7.2.4, §7.2.10.2).
// Must be called before Serve() to avoid missing requests.
func (c *Client) SetRequestHandler(h transport.Handler) {
	c.conn.SetHandler(h)
}

// ReplyToPGW sends a pre-marshaled response to pgwAddr over the S5/S8-C connection.
// Used by the S11 handler to relay bearer procedure responses back to the PGW after
// processing the corresponding MME response. Caches the response for retransmit detection.
func (c *Client) ReplyToPGW(pgwAddr *net.UDPAddr, raw []byte) error {
	return c.conn.Reply(pgwAddr, raw)
}

// SendToPGW sends a PGW-initiated bearer response request raw bytes to pgwAddr.
// Used for SGW-C initiated messages that need a response (not part of PGW relay).
func (c *Client) SendToPGW(ctx context.Context, pgwAddr *net.UDPAddr, raw []byte) ([]byte, error) {
	return c.conn.Send(ctx, pgwAddr, raw)
}

// LocalIP returns the SGW-C S5/S8-C control-plane IP, used by the S11 handler when
// building Sender F-TEID IEs in relayed bearer procedure responses.
func (c *Client) LocalIP() netip.Addr {
	return c.localIP
}

// AllocTEID allocates a new S5/S8-C control TEID for a dedicated bearer leg.
func (c *Client) AllocTEID() (uint32, error) {
	return c.teidAlloc.Alloc()
}

// FreeTEID releases an S5/S8-C control TEID back to the allocator.
func (c *Client) FreeTEID(teid uint32) {
	c.teidAlloc.Free(teid)
}

// Serve runs the S5/S8-C receive loop until ctx is cancelled.
// Per C9: this must be started in a goroutine before any CreateSession/DeleteSession
// calls — the receive loop is what delivers PGW responses into pending Send() calls.
func (c *Client) Serve(ctx context.Context) error {
	return c.conn.Serve(ctx)
}

// Close shuts down the S5/S8-C listener.
func (c *Client) Close() error {
	return c.conn.Close()
}

// buildCSReq constructs a GTPv2-C Create Session Request for the S5/S8-C interface.
// Per TS 29.274 Rel-15 §7.2.1 / Table 7.2.1-1, S5/S8-C column (SGW-C → PGW-C).
// Header TEID is 0 on the initial request because the PGW's S5/S8-C TEID is not yet
// known per TS 29.274 §5.5.2, which lists "Create Session Request message on
// S2a/S2b/S5/S8" explicitly among the TEID=0 cases.
// recIE is a Recovery IE to include per §7.2.0 on first contact; nil if not needed.
// sgwUS5UFTEID is the SGW-U S5/S8-U F-TEID (C per Table 7.2.1-2, instance 2 within bearer context).
// R15-REAUDIT-001: included after PFCP provisional session allocates the SGW-U S5/S8-U TEID.
func buildCSReq(s11req *message.CreateSessionRequest, sgwS5CTEID uint32, sgwIP netip.Addr, seq uint32, recIE *ie.IE, sgwUS5UFTEID bearer.FTEID) ([]byte, error) {
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           0, // PGW S5/S8-C TEID unknown on initial CSReq per §5.5.2
		SequenceNumber: seq,
	}

	var ies []*ie.IE

	// IMSI: C per Table 7.2.1-1 — forward verbatim.
	if s11req.IMSI != nil {
		ies = append(ies, s11req.IMSI)
	}

	// MSISDN: C — forward verbatim.
	if s11req.MSISDN != nil {
		ies = append(ies, s11req.MSISDN)
	}

	// MEI: C — forward verbatim.
	if s11req.MEI != nil {
		ies = append(ies, s11req.MEI)
	}

	// RAT Type: M per Table 7.2.1-1 — forwarded from MME CSReq.
	ies = append(ies, s11req.RATType)

	// Serving Network: C — forward if present.
	if s11req.ServingNetwork != nil {
		ies = append(ies, s11req.ServingNetwork)
	}

	// ULI: C — forward if present.
	if s11req.ULI != nil {
		ies = append(ies, s11req.ULI)
	}

	// Sender F-TEID for C-plane (instance 0): M per Table 7.2.1-1.
	// This is the SGW-C's S5/S8-C control TEID per TS 29.274 §8.22.
	ies = append(ies, ie.NewFTEID(0, ie.IFTypeS5S8CSGW, sgwS5CTEID, sgwIP))

	// APN: M per Table 7.2.1-1 — forwarded verbatim per Rule C2 (SGW never owns APN).
	ies = append(ies, s11req.APN)

	// PDN Type: M — forwarded.
	ies = append(ies, s11req.PDNType)

	// PAA and AMBR are conditional on S11/S5/S8. Forward them when present,
	// matching Open5GS' tolerant Create Session handling.
	if s11req.PAA != nil {
		ies = append(ies, s11req.PAA)
	}
	if s11req.AMBR != nil {
		ies = append(ies, s11req.AMBR)
	}

	// PCO: C — forward if present.
	if s11req.PCO != nil {
		ies = append(ies, s11req.PCO)
	}

	// APN Restriction: C per Table 7.2.1-1 — forward verbatim when supplied by the MME.
	if s11req.APNRestriction != nil {
		ies = append(ies, s11req.APNRestriction)
	}

	// UE Time Zone: C per Table 7.2.1-1 — forward verbatim when supplied by the MME.
	if s11req.UETimeZone != nil {
		ies = append(ies, s11req.UETimeZone)
	}

	// Charging Characteristics: C per Table 7.2.1-1 — forward verbatim when supplied by the MME.
	if s11req.ChargingChars != nil {
		ies = append(ies, s11req.ChargingChars)
	}

	// Selection Mode: C per Table 7.2.1-1 — forwarded verbatim. The SGW shall not
	// modify this IE per TS 29.274 §8.58.
	if s11req.SelectionMode != nil {
		ies = append(ies, s11req.SelectionMode)
	}

	// Bearer Context to be created: M per Table 7.2.1-1.
	// Contents per Table 7.2.1-2 (S5/S8-C): EBI (M), Bearer Level QoS (M).
	// S5/S8-U SGW F-TEID (C per Table 7.2.1-2): include when SGW-U has allocated its
	// S5/S8-U GTP-U TEID via PFCP provisional session (R15-REAUDIT-001).
	// Instance 2 per Table 7.2.1-2, S5/S8-C column (PGW needs this to send downlink).
	if len(s11req.BearerContexts) > 0 {
		children, err := s11req.BearerContexts[0].ChildIEs()
		if err != nil {
			return nil, fmt.Errorf("parse bearer context: %w", err)
		}
		var bcChildren []*ie.IE
		if ebiIE := ie.FindFirst(children, ie.TypeEBI); ebiIE != nil {
			bcChildren = append(bcChildren, ebiIE)
		}
		if qosIE := ie.FindFirst(children, ie.TypeBearerQoS); qosIE != nil {
			bcChildren = append(bcChildren, qosIE)
		}
		// R15-REAUDIT-001: SGW-U S5/S8-U F-TEID (instance 2 per Table 7.2.1-2).
		// Condition: "This IE shall be included on the S5/S8 interface, if a GTP-U tunnel
		// is to be used between the SGW-U and PGW-U." Include when PFCP has allocated a TEID.
		if sgwUS5UFTEID.TEID != 0 && sgwUS5UFTEID.IPv4.IsValid() {
			bcChildren = append(bcChildren, ie.NewFTEID(2, ie.IFTypeS5S8USGW, sgwUS5UFTEID.TEID, sgwUS5UFTEID.IPv4))
		}
		ies = append(ies, ie.NewBearerContext(0, bcChildren...))
	}

	// Indication: C — forward if present.
	if s11req.Indication != nil {
		ies = append(ies, s11req.Indication)
	}

	// Recovery: CO per Table 7.2.1-1; include on first contact per TS 29.274 §7.2.0.
	if recIE != nil {
		ies = append(ies, recIE)
	}

	return message.Marshal(hdr, ies)
}

type causeDescription struct {
	CauseText           string
	OffendingIEType     uint8
	OffendingIEName     string
	OffendingIEInstance uint8
}

func describeCause(causeIE *ie.IE) causeDescription {
	if causeIE == nil {
		return causeDescription{}
	}
	cause, err := causeIE.CauseValue()
	if err != nil {
		return causeDescription{}
	}
	d := causeDescription{CauseText: causeText(cause)}
	if len(causeIE.Value) >= 6 {
		d.OffendingIEType = causeIE.Value[2]
		d.OffendingIEInstance = causeIE.Value[5] & 0x0F
		d.OffendingIEName = ieName(d.OffendingIEType)
	}
	return d
}

func causeText(cause uint8) string {
	switch cause {
	case ie.CauseRequestAccepted:
		return "Request accepted"
	case ie.CauseRequestAcceptedPartially:
		return "Request accepted partially"
	case ie.CauseContextNotFound:
		return "Context not found"
	case ie.CauseInvalidMessageFormat:
		return "Invalid message format"
	case ie.CauseVersionNotSupported:
		return "Version not supported by next peer"
	case ie.CauseInvalidLength:
		return "Invalid length"
	case ie.CauseMandatoryIEIncorrect:
		return "Mandatory IE incorrect"
	case ie.CauseMandatoryIEMissing:
		return "Mandatory IE missing"
	case ie.CauseSystemFailure:
		return "System failure"
	case ie.CauseNoResourcesAvailable:
		return "No resources available"
	case ie.CauseMissingOrUnknownAPN:
		return "Missing or unknown APN"
	case 103:
		return "Conditional IE missing"
	default:
		return "Unknown cause"
	}
}

func ieName(ieType uint8) string {
	switch ieType {
	case ie.TypeIMSI:
		return "IMSI"
	case ie.TypeCause:
		return "Cause"
	case ie.TypeRecovery:
		return "Recovery"
	case ie.TypeAPN:
		return "APN"
	case ie.TypeAMBR:
		return "AMBR"
	case ie.TypeEBI:
		return "EBI"
	case ie.TypeMEI:
		return "MEI"
	case ie.TypeMSISDN:
		return "MSISDN"
	case ie.TypeIndication:
		return "Indication"
	case ie.TypePCO:
		return "PCO"
	case ie.TypePAA:
		return "PAA"
	case ie.TypeBearerQoS:
		return "Bearer QoS"
	case ie.TypeRATType:
		return "RAT Type"
	case ie.TypeServingNetwork:
		return "Serving Network"
	case ie.TypeULI:
		return "ULI"
	case ie.TypeFTEID:
		return "F-TEID"
	case ie.TypeBearerContext:
		return "Bearer Context"
	case ie.TypeChargingID:
		return "Charging ID"
	case ie.TypeChargingChars:
		return "Charging Characteristics"
	case ie.TypePDNType:
		return "PDN Type"
	case ie.TypePTI:
		return "PTI"
	case ie.TypeUETimeZone:
		return "UE Time Zone"
	case ie.TypeAPNRestriction:
		return "APN Restriction"
	case ie.TypeSelectionMode:
		return "Selection Mode"
	default:
		return "Unknown IE"
	}
}

// buildDSReq constructs a Delete Session Request for the S5/S8-C interface.
// Per TS 29.274 Rel-15 §7.2.9 / Table 7.2.9.1-1 (S5/S8-C, SGW-C → PGW-C).
// Header TEID = PGW's S5/S8-C control TEID per TS 29.274 §5.5.1.
// recIE is a Recovery IE to include per §7.2.0 on first contact; nil if not needed.
func buildDSReq(sess *session.SGWSession, req *message.DeleteSessionRequest, seq uint32, recIE *ie.IE) ([]byte, error) {
	hdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDeleteSessionRequest,
		TEID:           sess.PGWControlFTEID.TEID, // PGW's S5/S8-C TEID per §5.5.1
		SequenceNumber: seq,
	}

	var ies []*ie.IE

	// Cause: C per Table 7.2.9.1-1 in SGW→PGW direction — preserve when present
	// in the triggering S11 DSReq.
	if req != nil && req.Cause != nil {
		ies = append(ies, req.Cause)
	}

	// EBI: C per Table 7.2.9.1-1 — preserve the MME-provided value when present.
	// If absent, keep the existing behavior of identifying the PDN connection with
	// the stored default bearer ID.
	if req != nil && req.EBI != nil {
		ies = append(ies, req.EBI)
	} else {
		ies = append(ies, ie.NewEBI(sess.DefaultBearerID))
	}

	// Indication: C — preserve when supplied by the MME.
	if req != nil && req.Indication != nil {
		ies = append(ies, req.Indication)
	}

	// Recovery: CO per Table 7.2.9.1-1; include on first contact per TS 29.274 §7.2.0.
	if recIE != nil {
		ies = append(ies, recIE)
	}

	return message.Marshal(hdr, ies)
}
