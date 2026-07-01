// bearer_handler.go implements SGW-C handling of PGW-initiated bearer procedures:
// Create Bearer, Update Bearer, and Delete Bearer per 3GPP TS 29.274 Rel-15
// §7.2.3/§7.2.4 (Create), §7.2.15/§7.2.16 (Update), §7.2.9.2/§7.2.10.2 (Delete).
//
// Flow (Create Bearer example):
//  1. PGW sends CBReq on S5/S8-C → HandleS5CInbound dispatches handleCreateBearer
//  2. SGW-C provisions PFCP PDR/FAR on SGW-U (CHOOSE F-TEID for new bearer)
//  3. SGW-C relays CBReq to MME on S11 (includes SGW-U S1-U F-TEID)
//  4. MME responds with CBResp (includes assigned EBI and eNB S1-U F-TEID)
//  5. SGW-C updates PFCP FAR (downlink) with eNB TEID, stores bearer state
//  6. SGW-C relays CBResp to PGW on S5/S8-C
package s11

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"net/netip"
	"time"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/gtpv2/transport"
	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/sgwc/bearer"
	pfcpclient "vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/session"
)

type createBearerTxnStatus string

const (
	createBearerTxnPending   createBearerTxnStatus = "pending"
	createBearerTxnCompleted createBearerTxnStatus = "completed"
	createBearerTxnFailed    createBearerTxnStatus = "failed"
)

type createBearerTxnKey struct {
	peerIP       netip.Addr
	peerPort     uint16
	localS5CTEID uint32
	msgType      uint8
	sequence     uint32
}

type createBearerTxnState struct {
	key                 createBearerTxnKey
	fingerprint         createBearerFingerprintKey
	procedureKey        createBearerProcedureKey
	sessionID           string
	status              createBearerTxnStatus
	originalRequest     []byte
	provisionedBearers  []bearerProvisioning
	pfcpProvisionalDone bool
	pfcpRolledBack      map[createBearerRuleKey]bool
	s5cResponse         []byte
	s5cCause            uint8
	createdAt           time.Time
	updatedAt           time.Time
}

type createBearerFingerprintKey struct {
	peerIP       netip.Addr
	peerPort     uint16
	localS5CTEID uint32
	lbi          uint8
	bodyHash     [32]byte
}

type createBearerProcedureKey struct {
	sessionID    string
	imsi         string
	apn          string
	peerIP       netip.Addr
	peerPort     uint16
	localS5CTEID uint32
	linkedEBI    uint8
	bearerCount  int
	sigHash      [32]byte
}

type createBearerProcedureFailure struct {
	key              createBearerProcedureKey
	state            string
	lastFailureCause uint8
	lastFailureText  string
	offendingIEType  uint8
	offendingIEName  string
	firstSeen        time.Time
	lastSeen         time.Time
	lastSuppressLog  time.Time
	suppressedCount  uint64
	logSuppression   bool
}

type bearerProvisioning struct {
	qosIE        *ie.IE
	tftIE        *ie.IE
	pgwUS5UFTEID bearer.FTEID
	pdrUL        uint16
	pdrDL        uint16
	farUL        uint32
	farDL        uint32
	sgwUS1UFTEID bearer.FTEID // SGW-U allocated S1-U TEID (from Created PDR)
	sgwUS5UFTEID bearer.FTEID // SGW-U allocated S5/8-U TEID (from Created PDR)
}

func buildCreateBearerS5CResponseContext(ebi, cause uint8, prov *bearerProvisioning) *ie.IE {
	children := []*ie.IE{
		ie.NewEBI(ebi),
		ie.NewCause(cause, 0, 0, 0, nil),
	}
	if prov != nil && prov.sgwUS5UFTEID.TEID != 0 && prov.sgwUS5UFTEID.IPv4.IsValid() {
		children = append(children, ie.NewFTEID(2, ie.IFTypeS5S8USGW, prov.sgwUS5UFTEID.TEID, prov.sgwUS5UFTEID.IPv4))
	}
	if prov != nil && prov.pgwUS5UFTEID.TEID != 0 && prov.pgwUS5UFTEID.IPv4.IsValid() {
		children = append(children, ie.NewFTEID(3, ie.IFTypeS5S8UPGW, prov.pgwUS5UFTEID.TEID, prov.pgwUS5UFTEID.IPv4))
	}
	return ie.NewBearerContext(0, children...)
}

func validateCreateBearerResponseResults(resp *message.CreateBearerResponse, expectedContexts int) error {
	if len(resp.BearerContexts) != expectedContexts {
		return fmt.Errorf("CreateBearerResponse: bearer context count = %d; want %d per TS 29.274 Table 7.2.4-1", len(resp.BearerContexts), expectedContexts)
	}
	for idx, bcIE := range resp.BearerContexts {
		children, err := bcIE.ChildIEs()
		if err != nil {
			return fmt.Errorf("CreateBearerResponse: bearer context[%d] malformed: %w", idx, err)
		}
		if ie.FindFirst(children, ie.TypeEBI) == nil {
			return fmt.Errorf("CreateBearerResponse: bearer context[%d] missing M-IE EBI per TS 29.274 Table 7.2.4-2", idx)
		}
		if ie.FindFirst(children, ie.TypeCause) == nil {
			return fmt.Errorf("CreateBearerResponse: bearer context[%d] missing M-IE Cause per TS 29.274 Table 7.2.4-2", idx)
		}
	}
	return nil
}

type createBearerRuleKey struct {
	pdrUL uint16
	pdrDL uint16
	farUL uint32
	farDL uint32
}

type createBearerBuildDiagnostic struct {
	LinkedEBI      uint8                               `json:"linked_ebi"`
	BearerContexts int                                 `json:"bearer_contexts"`
	Bearers        []createBearerBuildBearerDiagnostic `json:"bearers"`
}

type createBearerBuildBearerDiagnostic struct {
	Index           int    `json:"index"`
	GroupedLength   int    `json:"grouped_length"`
	EBI             uint8  `json:"ebi"`
	EBIInstance     uint8  `json:"ebi_instance"`
	HasTFT          bool   `json:"has_tft"`
	TFTLength       int    `json:"tft_length"`
	TFTInstance     uint8  `json:"tft_instance"`
	HasBearerQoS    bool   `json:"has_bearer_qos"`
	BearerQoSLength int    `json:"bearer_qos_length"`
	BearerQoSInst   uint8  `json:"bearer_qos_instance"`
	HasSGWS1UFTEID  bool   `json:"has_sgw_s1u_fteid"`
	SGWS1UIFType    uint8  `json:"sgw_s1u_iftype"`
	SGWS1UTEID      uint32 `json:"sgw_s1u_teid"`
	SGWS1UIP        string `json:"sgw_s1u_ip"`
	HasPGWS5UFTEID  bool   `json:"has_pgw_s5u_fteid"`
	PGWS5UIFType    uint8  `json:"pgw_s5u_iftype"`
	PGWS5UTEID      uint32 `json:"pgw_s5u_teid"`
	PGWS5UIP        string `json:"pgw_s5u_ip"`
}

// HandleS5CInbound is the transport.Handler registered on the S5/S8-C connection.
// It handles PGW-initiated Create/Update/Delete Bearer Requests arriving from the PGW.
// Per C9: this handler is called from the S5/S8-C Serve loop.
func (h *Handler) HandleS5CInbound(conn *transport.Conn, pgwAddr *net.UDPAddr, hdr message.Header, raw []byte) {
	switch hdr.MessageType {
	case message.MsgTypeCreateBearerRequest:
		h.handleCreateBearer(pgwAddr, hdr, raw)
	case message.MsgTypeUpdateBearerRequest:
		h.handleUpdateBearer(pgwAddr, hdr, raw)
	case message.MsgTypeDeleteBearerRequest:
		h.handleDeleteBearer(pgwAddr, hdr, raw)
	default:
		h.log.Warn("S5C inbound: unhandled message type from PGW",
			"from", pgwAddr, "msg_type", hdr.MessageType)
	}
}

type preparedCreateBearerRelay struct {
	pgwAddr     *net.UDPAddr
	hdr         message.Header
	cbReq       *message.CreateBearerRequest
	sess        *session.SGWSession
	txn         *createBearerTxnState
	bearerProvs []bearerProvisioning
	s11Raw      []byte
	s11Seq      uint32
	linkedEBI   uint8
}

func (h *Handler) prepareCreateBearerRelay(pgwAddr *net.UDPAddr, hdr message.Header, raw []byte) (*preparedCreateBearerRelay, bool) {
	cbReq, err := message.ParseCreateBearerRequest(raw)
	if err != nil {
		h.log.Warn("S5C: Create Bearer Request invalid", "from", pgwAddr, "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse, 0, ie.CauseInvalidMessageFormat)
		return nil, false
	}
	sess := h.sessions.FindByS5CTEID(hdr.TEID)
	if sess == nil {
		h.log.Warn("S5C: Create Bearer Request — session not found",
			"teid", fmt.Sprintf("0x%08X", hdr.TEID),
			"from", pgwAddr)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse, 0, ie.CauseContextNotFound)
		return nil, false
	}
	lbi, _ := cbReq.LBI.EBIValue()
	fp := newCreateBearerFingerprintKey(pgwAddr, hdr, lbi, cbReq.BearerContexts)
	procKey := newCreateBearerProcedureKey(pgwAddr, hdr, sess, lbi, cbReq.BearerContexts)
	if txn, txnAction := h.findCreateBearerTxn(pgwAddr, hdr); txn != nil {
		switch txnAction {
		case createBearerTxnActionCached:
			_ = h.s5c.ReplyToPGW(pgwAddr, txn.s5cResponse)
			return nil, false
		case createBearerTxnActionPending:
			return nil, false
		}
	}
	if failure := h.findLatchedCreateBearerProcedureFailure(procKey); failure != nil {
		h.replyCreateBearerRetryGuardFailure(pgwAddr, hdr, cbReq, sess, failure)
		return nil, false
	}
	txn, txnAction := h.beginCreateBearerTxnWithFingerprint(pgwAddr, hdr, raw, sess, fp)
	switch txnAction {
	case createBearerTxnActionCached:
		_ = h.s5c.ReplyToPGW(pgwAddr, txn.s5cResponse)
		return nil, false
	case createBearerTxnActionFingerprintCached:
		resp, err := cloneCreateBearerResponseForSequence(txn.s5cResponse, hdr.SequenceNumber)
		if err == nil {
			_ = h.s5c.ReplyToPGW(pgwAddr, resp)
		}
		return nil, false
	case createBearerTxnActionPending, createBearerTxnActionFingerprintPending:
		return nil, false
	}
	h.setCreateBearerTxnProcedureKey(txn.key, procKey)

	var bearerProvs []bearerProvisioning
	for _, bcIE := range cbReq.BearerContexts {
		children, cErr := bcIE.ChildIEs()
		if cErr != nil {
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseInvalidMessageFormat)
			return nil, false
		}
		var prov bearerProvisioning
		ebiIE := ie.FindFirst(children, ie.TypeEBI)
		if ebiIE == nil {
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEMissing)
			return nil, false
		}
		if ebi, eErr := ebiIE.EBIValue(); eErr != nil || ebi != 0 {
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEIncorrect)
			return nil, false
		}
		prov.qosIE = ie.FindFirst(children, ie.TypeBearerQoS)
		prov.tftIE = ie.FindFirst(children, ie.TypeBearerTFT)
		if prov.qosIE == nil || prov.tftIE == nil {
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEMissing)
			return nil, false
		}
		if pgwUFTEID := ie.FindInstance(children, ie.TypeFTEID, 1); pgwUFTEID != nil {
			if f, fErr := pgwUFTEID.FTEIDValue(); fErr == nil {
				prov.pgwUS5UFTEID = bearer.FTEID{TEID: f.TEID, IPv4: f.IPv4}
			}
		}
		if prov.pgwUS5UFTEID.TEID == 0 || !prov.pgwUS5UFTEID.IPv4.IsValid() {
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEMissing)
			return nil, false
		}
		prov.pdrUL, prov.pdrDL, prov.farUL, prov.farDL = sess.AllocBearerRuleIDs()
		bearerProvs = append(bearerProvs, prov)
	}
	if len(bearerProvs) == 0 {
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseInvalidMessageFormat)
		return nil, false
	}

	var createPDRs, createFARs []*pfcpie.IE
	for _, prov := range bearerProvs {
		createPDRs = append(createPDRs, pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(prov.pdrUL),
			pfcpie.NewPrecedence(100),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SourceInterfaceAccess), pfcpie.NewFTEIDChoose()),
			pfcpie.NewFARID(prov.farUL),
		))
		createPDRs = append(createPDRs, pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(prov.pdrDL),
			pfcpie.NewPrecedence(200),
			pfcpie.NewPDI(pfcpie.NewSourceInterface(pfcpie.SourceInterfaceCore), pfcpie.NewFTEIDChoose()),
			pfcpie.NewFARID(prov.farDL),
		))
		createFARs = append(createFARs, pfcpie.NewCreateFAR(
			pfcpie.NewFARID(prov.farUL),
			pfcpie.NewApplyAction(pfcpie.ApplyActionFORW),
			pfcpie.NewForwardingParameters(
				pfcpie.NewDestinationInterface(pfcpie.DestInterfaceCore),
				pfcpie.NewOuterHeaderCreation(pfcpie.OHCDescGTPUUDPIPv4, prov.pgwUS5UFTEID.TEID, prov.pgwUS5UFTEID.IPv4),
			),
		))
		createFARs = append(createFARs, pfcpie.NewCreateFAR(
			pfcpie.NewFARID(prov.farDL),
			pfcpie.NewApplyAction(pfcpie.ApplyActionDROP),
		))
	}
	createdPDRs, pfcpErr := h.pfcp.AddBearerRulesOnPeer(context.Background(),
		sess.PFCP.SGWUAddr, sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID, createPDRs, createFARs)
	if pfcpErr != nil {
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return nil, false
	}
	for _, cpdrIE := range createdPDRs {
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
		for i, prov := range bearerProvs {
			if pdrID == prov.pdrUL {
				bearerProvs[i].sgwUS1UFTEID = bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4}
			} else if pdrID == prov.pdrDL {
				bearerProvs[i].sgwUS5UFTEID = bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4}
			}
		}
	}
	h.markCreateBearerTxnProvisioned(txn.key, bearerProvs)

	var s11BCs []*ie.IE
	for _, prov := range bearerProvs {
		bcChildren := []*ie.IE{ie.NewEBI(0), prov.tftIE}
		if prov.sgwUS1UFTEID.TEID != 0 && prov.sgwUS1UFTEID.IPv4.IsValid() {
			bcChildren = append(bcChildren, ie.NewFTEID(0, ie.IFTypeS1USGW, prov.sgwUS1UFTEID.TEID, prov.sgwUS1UFTEID.IPv4))
		}
		bcChildren = append(bcChildren, ie.NewFTEID(1, ie.IFTypeS5S8UPGW, prov.pgwUS5UFTEID.TEID, prov.pgwUS5UFTEID.IPv4), prov.qosIE)
		s11BCs = append(s11BCs, ie.NewBearerContext(0, bcChildren...))
	}
	s11CBReqIEs := make([]*ie.IE, 0, 1+len(s11BCs))
	s11CBReqIEs = append(s11CBReqIEs, ie.NewEBI(lbi))
	s11CBReqIEs = append(s11CBReqIEs, s11BCs...)
	s11Seq := h.conn.AllocSeq()
	s11CBReqRaw, err := message.MarshalCreateBearerRequest(sess.MMEControlFTEID.TEID, s11Seq, s11CBReqIEs...)
	if err != nil {
		h.removeAllCreateBearerTxnProvisioning(txn.key, sess, bearerProvs)
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq, sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return nil, false
	}
	return &preparedCreateBearerRelay{
		pgwAddr:     pgwAddr,
		hdr:         hdr,
		cbReq:       cbReq,
		sess:        sess,
		txn:         txn,
		bearerProvs: bearerProvs,
		s11Raw:      s11CBReqRaw,
		s11Seq:      s11Seq,
		linkedEBI:   lbi,
	}, true
}

func (h *Handler) registerPendingS11CreateBearer(mmeAddr *net.UDPAddr, csrspSeq uint32, prep *preparedCreateBearerRelay) {
	h.cbTxnMu.Lock()
	if h.cbS11 == nil {
		h.cbS11 = make(map[s11CreateBearerResponseKey]*pendingS11CreateBearer)
	}
	key := s11CreateBearerResponseKey{peer: mmeAddr.String(), seq: prep.s11Seq}
	h.cbS11[key] = &pendingS11CreateBearer{
		pgwAddr:     prep.pgwAddr,
		mmeAddr:     mmeAddr.String(),
		hdr:         prep.hdr,
		cbReq:       prep.cbReq,
		sess:        prep.sess,
		txn:         prep.txn,
		bearerProvs: prep.bearerProvs,
		csrspSeq:    csrspSeq,
		s11Seq:      prep.s11Seq,
		linkedEBI:   prep.linkedEBI,
		createdAt:   time.Now(),
	}
	h.cbTxnMu.Unlock()

	timeout := h.s11CreateBearerTimeout()
	time.AfterFunc(timeout, func() {
		h.expirePendingS11CreateBearer(key, timeout)
	})
}

func (h *Handler) popPendingS11CreateBearer(mmeAddr *net.UDPAddr, seq uint32) *pendingS11CreateBearer {
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	key := s11CreateBearerResponseKey{peer: mmeAddr.String(), seq: seq}
	pending := h.cbS11[key]
	delete(h.cbS11, key)
	return pending
}

func (h *Handler) s11CreateBearerTimeout() time.Duration {
	if h.cfg == nil || h.cfg.S11.T3ResponseSeconds <= 0 || h.cfg.S11.N3Requests <= 0 {
		return 10 * time.Second
	}
	return time.Duration(h.cfg.S11.T3ResponseSeconds*h.cfg.S11.N3Requests) * time.Second
}

func (h *Handler) expirePendingS11CreateBearer(key s11CreateBearerResponseKey, timeout time.Duration) {
	h.cbTxnMu.Lock()
	pending := h.cbS11[key]
	if pending != nil {
		delete(h.cbS11, key)
	}
	h.cbTxnMu.Unlock()
	if pending == nil {
		return
	}

	h.log.Warn("S11: piggybacked Create Bearer transaction timed out waiting for MME response",
		"session_id", pending.sess.SessionID,
		"imsi", pending.sess.IMSI,
		"apn", pending.sess.APN,
		"mme", pending.mmeAddr,
		"mme_teid", fmt.Sprintf("0x%08X", pending.sess.MMEControlFTEID.TEID),
		"csrsp_seq", pending.csrspSeq,
		"piggyback_seq", pending.s11Seq,
		"linked_ebi", pending.linkedEBI,
		"bearer_contexts", len(pending.cbReq.BearerContexts),
		"elapsed_ms", timeout.Milliseconds(),
	)
	h.removeAllCreateBearerTxnProvisioning(pending.txn.key, pending.sess, pending.bearerProvs)
	procKey := pending.txn.procedureKey
	if procKey == (createBearerProcedureKey{}) {
		procKey = newCreateBearerProcedureKey(pending.pgwAddr, pending.hdr, pending.sess, pending.linkedEBI, pending.cbReq.BearerContexts)
	}
	h.rememberCreateBearerProcedureFailure(procKey, ie.CauseRequestRejected, gtpcCauseDescription{
		CauseText: gtpcCauseText(ie.CauseRequestRejected),
	})
	h.replyCreateBearerTxnError(pending.txn.key, pending.pgwAddr, pending.hdr, pending.cbReq,
		pending.sess.PGWControlFTEID.TEID, ie.CauseRequestRejected)
}

func (h *Handler) handlePiggybackCreateBearerResponse(conn *transport.Conn, mmeAddr *net.UDPAddr, hdr message.Header, raw []byte) {
	pending := h.popPendingS11CreateBearer(mmeAddr, hdr.SequenceNumber)
	if pending == nil {
		h.log.Debug("S11: Create Bearer Response with no pending piggyback transaction",
			"from", mmeAddr, "seq", hdr.SequenceNumber)
		return
	}
	h.completeCreateBearerFromS11Response(pending, raw)
}

func (h *Handler) completeCreateBearerFromS11Response(pending *pendingS11CreateBearer, raw []byte) {
	cbResp, err := message.ParseCreateBearerResponse(raw)
	if err != nil {
		h.log.Error("S5C: Create Bearer — parse piggybacked S11 CBResp failed", "error", err)
		h.removeAllCreateBearerTxnProvisioning(pending.txn.key, pending.sess, pending.bearerProvs)
		h.replyCreateBearerTxnError(pending.txn.key, pending.pgwAddr, pending.hdr, pending.cbReq,
			pending.sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}
	if err := validateCreateBearerResponseResults(cbResp, len(pending.bearerProvs)); err != nil {
		h.log.Warn("S11: piggybacked Create Bearer Response invalid",
			"session_id", pending.sess.SessionID, "error", err)
		h.removeAllCreateBearerTxnProvisioning(pending.txn.key, pending.sess, pending.bearerProvs)
		h.replyCreateBearerTxnError(pending.txn.key, pending.pgwAddr, pending.hdr, pending.cbReq,
			pending.sess.PGWControlFTEID.TEID, ie.CauseInvalidMessageFormat)
		h.rememberCreateBearerProcedureFailure(pending.txn.procedureKey, ie.CauseInvalidMessageFormat, gtpcCauseDescription{CauseText: gtpcCauseText(ie.CauseInvalidMessageFormat)})
		return
	}

	msgCause, _ := cbResp.Cause.CauseValue()
	msgCauseDesc := describeGTPCause(cbResp.Cause)
	fullProcedureReject := msgCause != ie.CauseRequestAccepted && msgCause != ie.CauseRequestAcceptedPartially
	if fullProcedureReject {
		h.removeAllCreateBearerTxnProvisioning(pending.txn.key, pending.sess, pending.bearerProvs)
	}
	outMsgCause := msgCause
	acceptedBearers := 0
	failedBearers := 0
	firstFailureCause := uint8(0)
	var s5cBCIEs []*ie.IE
	for respIndex, bcIE := range cbResp.BearerContexts {
		children, cErr := bcIE.ChildIEs()
		if cErr != nil {
			continue
		}
		ebiIE := ie.FindFirst(children, ie.TypeEBI)
		causeIE := ie.FindFirst(children, ie.TypeCause)
		if ebiIE == nil || causeIE == nil {
			continue
		}
		ebi, _ := ebiIE.EBIValue()
		bcCause, _ := causeIE.CauseValue()
		var enbFTEID bearer.FTEID
		if fteidIE := ie.FindInstance(children, ie.TypeFTEID, 0); fteidIE != nil {
			if f, fErr := fteidIE.FTEIDValue(); fErr == nil {
				enbFTEID = bearer.FTEID{TEID: f.TEID, IPv4: f.IPv4}
			}
		}
		var matchedProv *bearerProvisioning
		if sgwFTEIDIE := ie.FindInstance(children, ie.TypeFTEID, 1); sgwFTEIDIE != nil {
			if f, fErr := sgwFTEIDIE.FTEIDValue(); fErr == nil {
				for i := range pending.bearerProvs {
					if pending.bearerProvs[i].sgwUS1UFTEID.TEID == f.TEID {
						matchedProv = &pending.bearerProvs[i]
						break
					}
				}
			}
		}
		if matchedProv == nil && respIndex < len(pending.bearerProvs) {
			matchedProv = &pending.bearerProvs[respIndex]
		}
		cleanedProvisioning := false
		if bcCause == ie.CauseRequestAccepted && matchedProv != nil && enbFTEID.TEID != 0 && pending.sess.PFCP.Established {
			pfcpModErr := h.pfcp.ModifySessionOnPeer(context.Background(),
				pending.sess.PFCP.SGWUAddr,
				pending.sess.PFCP.LocalFSEID.SEID, pending.sess.PFCP.SGWUFSEID.SEID,
				[]pfcpclient.FARUpdate{{
					FARID:              matchedProv.farDL,
					PDRID:              matchedProv.pdrDL,
					ApplyAction:        pfcpie.ApplyActionFORW,
					DestInterface:      pfcpie.DestInterfaceAccess,
					OuterTEID:          enbFTEID.TEID,
					OuterIP:            enbFTEID.IPv4,
					OuterHeaderRemoval: true,
				}},
			)
			if pfcpModErr != nil {
				h.removeCreateBearerTxnProvisioning(pending.txn.key, pending.sess, matchedProv)
				cleanedProvisioning = true
				bcCause = ie.CauseSystemFailure
			}
			if bcCause == ie.CauseRequestAccepted {
				newBearer := &bearer.Bearer{
					EBI:         ebi,
					ENBS1UFTEID: enbFTEID,
					State:       bearer.BearerStateActive,
					PDRIDs:      [2]uint32{uint32(matchedProv.pdrUL), uint32(matchedProv.pdrDL)},
					FARIDs:      [2]uint32{matchedProv.farUL, matchedProv.farDL},
					SGWS1UFTEID: matchedProv.sgwUS1UFTEID,
					SGWS5UFTEID: matchedProv.sgwUS5UFTEID,
					PGWS5UFTEID: matchedProv.pgwUS5UFTEID,
				}
				if matchedProv.qosIE != nil {
					v := matchedProv.qosIE.Value
					if len(v) >= 2 {
						newBearer.ARP = bearer.ARP{
							PriorityLevel:           (v[0] >> 2) & 0x0F,
							PreemptionCapability:    v[0]&0x40 != 0,
							PreemptionVulnerability: v[0]&0x01 != 0,
						}
						newBearer.QCI = v[1]
					}
				}
				if matchedProv.tftIE != nil {
					tftRaw, _ := matchedProv.tftIE.BearerTFTValue()
					newBearer.TFT = &bearer.TFT{Raw: tftRaw}
				}
				pending.sess.SetBearer(newBearer)
			}
		} else if bcCause == ie.CauseRequestAccepted && matchedProv != nil {
			h.removeCreateBearerTxnProvisioning(pending.txn.key, pending.sess, matchedProv)
			cleanedProvisioning = true
			bcCause = ie.CauseSystemFailure
		}
		if bcCause != ie.CauseRequestAccepted && matchedProv != nil && !cleanedProvisioning && !fullProcedureReject {
			h.removeCreateBearerTxnProvisioning(pending.txn.key, pending.sess, matchedProv)
		}
		if bcCause == ie.CauseRequestAccepted {
			acceptedBearers++
		} else {
			failedBearers++
			if firstFailureCause == 0 {
				firstFailureCause = bcCause
			}
		}
		s5cBCIEs = append(s5cBCIEs, buildCreateBearerS5CResponseContext(ebi, bcCause, matchedProv))
	}
	if failedBearers > 0 {
		if acceptedBearers > 0 {
			outMsgCause = ie.CauseRequestAcceptedPartially
		} else if firstFailureCause != 0 {
			outMsgCause = firstFailureCause
		}
	}
	if outMsgCause != ie.CauseRequestAccepted && outMsgCause != ie.CauseRequestAcceptedPartially {
		h.rememberCreateBearerProcedureFailure(pending.txn.procedureKey, outMsgCause, msgCauseDesc)
	}
	s5cRespIEs := make([]*ie.IE, 0, 1+len(s5cBCIEs))
	s5cRespIEs = append(s5cRespIEs, ie.NewCause(outMsgCause, 0, 0, 0, nil))
	s5cRespIEs = append(s5cRespIEs, s5cBCIEs...)
	s5cResp, err := message.MarshalCreateBearerResponse(pending.sess.PGWControlFTEID.TEID, pending.hdr.SequenceNumber, s5cRespIEs...)
	if err != nil {
		h.log.Error("S5C: Create Bearer — marshal piggybacked S5/S8-C CBResp failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pending.pgwAddr, s5cResp); err != nil {
		h.log.Warn("S5C: Create Bearer — send piggybacked CBResp to PGW failed", "error", err)
	}
	h.completeCreateBearerTxn(pending.txn.key, s5cResp, outMsgCause)
}

// ── Create Bearer ─────────────────────────────────────────────────────────────

func (h *Handler) handleCreateBearer(pgwAddr *net.UDPAddr, hdr message.Header, raw []byte) {
	cbReq, err := message.ParseCreateBearerRequest(raw)
	if err != nil {
		h.log.Warn("S5C: Create Bearer Request invalid", "from", pgwAddr, "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse, 0, ie.CauseInvalidMessageFormat)
		return
	}

	// Header TEID on PGW→SGW-C = SGW's S5/S8-C control TEID per TS 29.274 §5.5.1.
	sess := h.sessions.FindByS5CTEID(hdr.TEID)
	if sess == nil {
		h.log.Warn("S5C: Create Bearer Request — session not found",
			"teid", fmt.Sprintf("0x%08X", hdr.TEID))
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse, 0, ie.CauseContextNotFound)
		return
	}

	lbi, _ := cbReq.LBI.EBIValue()
	fp := newCreateBearerFingerprintKey(pgwAddr, hdr, lbi, cbReq.BearerContexts)
	procKey := newCreateBearerProcedureKey(pgwAddr, hdr, sess, lbi, cbReq.BearerContexts)
	if txn, txnAction := h.findCreateBearerTxn(pgwAddr, hdr); txn != nil {
		h.logCreateBearerTxnDecision(txn, txnAction, hdr)
		switch txnAction {
		case createBearerTxnActionCached:
			if err := h.s5c.ReplyToPGW(pgwAddr, txn.s5cResponse); err != nil {
				h.log.Warn("S5/S8-C: duplicate Create Bearer Request cached response send failed",
					"session_id", txn.sessionID, "seq", hdr.SequenceNumber, "error", err)
			} else {
				h.log.Info("S5/S8-C: duplicate Create Bearer Request answered from cache",
					"session_id", txn.sessionID,
					"seq", hdr.SequenceNumber,
					"teid", fmt.Sprintf("0x%08X", hdr.TEID),
					"cause", txn.s5cCause,
				)
			}
			return
		case createBearerTxnActionPending:
			h.log.Debug("S5/S8-C: duplicate Create Bearer Request suppressed while pending",
				"session_id", txn.sessionID,
				"seq", hdr.SequenceNumber,
				"teid", fmt.Sprintf("0x%08X", hdr.TEID),
				"state", txn.status,
			)
			return
		}
	}
	if failure := h.findLatchedCreateBearerProcedureFailure(procKey); failure != nil {
		h.replyCreateBearerRetryGuardFailure(pgwAddr, hdr, cbReq, sess, failure)
		return
	}
	txn, txnAction := h.beginCreateBearerTxnWithFingerprint(pgwAddr, hdr, raw, sess, fp)
	h.logCreateBearerTxnDecision(txn, txnAction, hdr)
	switch txnAction {
	case createBearerTxnActionCached:
		if err := h.s5c.ReplyToPGW(pgwAddr, txn.s5cResponse); err != nil {
			h.log.Warn("S5/S8-C: duplicate Create Bearer Request cached response send failed",
				"session_id", txn.sessionID, "seq", hdr.SequenceNumber, "error", err)
		} else {
			h.log.Info("S5/S8-C: duplicate Create Bearer Request answered from cache",
				"session_id", txn.sessionID,
				"seq", hdr.SequenceNumber,
				"teid", fmt.Sprintf("0x%08X", hdr.TEID),
				"cause", txn.s5cCause,
			)
		}
		return
	case createBearerTxnActionFingerprintCached:
		resp, err := cloneCreateBearerResponseForSequence(txn.s5cResponse, hdr.SequenceNumber)
		if err != nil {
			h.log.Warn("S5/S8-C: fingerprint Create Bearer cached response clone failed",
				"session_id", txn.sessionID, "seq", hdr.SequenceNumber, "error", err)
			return
		}
		if err := h.s5c.ReplyToPGW(pgwAddr, resp); err != nil {
			h.log.Warn("S5/S8-C: fingerprint Create Bearer cached response send failed",
				"session_id", txn.sessionID, "seq", hdr.SequenceNumber, "error", err)
		} else {
			h.log.Info("S5/S8-C: repeated Create Bearer operation answered from fingerprint cache",
				"session_id", txn.sessionID,
				"seq", hdr.SequenceNumber,
				"teid", fmt.Sprintf("0x%08X", hdr.TEID),
				"cause", txn.s5cCause,
			)
		}
		return
	case createBearerTxnActionPending:
		h.log.Debug("S5/S8-C: duplicate Create Bearer Request suppressed while pending",
			"session_id", txn.sessionID,
			"seq", hdr.SequenceNumber,
			"teid", fmt.Sprintf("0x%08X", hdr.TEID),
			"state", txn.status,
		)
		return
	case createBearerTxnActionFingerprintPending:
		h.log.Debug("S5/S8-C: repeated Create Bearer operation suppressed while pending",
			"session_id", txn.sessionID,
			"seq", hdr.SequenceNumber,
			"teid", fmt.Sprintf("0x%08X", hdr.TEID),
			"state", txn.status,
		)
		return
	}
	h.setCreateBearerTxnProcedureKey(txn.key, procKey)

	// Per bearer: extract QoS, TFT, and PGW-U S5/8-U F-TEID from BC children (S5/S8-C).
	// Table 7.2.3-2 S5/S8-C column:
	//   EBI (inst=0): M — shall be set to 0 in CBReq (MME assigns actual EBI in CBResp)
	//   Bearer TFT (inst=0): M
	//   S5/8-U PGW F-TEID (inst=1): C — present, SGW-C uses it for PFCP uplink FAR
	//   Bearer QoS (inst=0): M
	var bearerProvs []bearerProvisioning
	for _, bcIE := range cbReq.BearerContexts {
		children, cErr := bcIE.ChildIEs()
		if cErr != nil {
			h.log.Warn("S5C: Create Bearer — invalid Bearer Context", "session_id", sess.SessionID, "error", cErr)
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
				sess.PGWControlFTEID.TEID, ie.CauseInvalidMessageFormat)
			return
		}
		var prov bearerProvisioning
		ebiIE := ie.FindFirst(children, ie.TypeEBI)
		if ebiIE == nil {
			h.log.Warn("S5C: Create Bearer — missing mandatory EBI in Bearer Context", "session_id", sess.SessionID)
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
				sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEMissing)
			return
		}
		if ebi, eErr := ebiIE.EBIValue(); eErr != nil || ebi != 0 {
			h.log.Warn("S5C: Create Bearer — invalid EBI in Bearer Context",
				"session_id", sess.SessionID, "ebi", ebi, "error", eErr)
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
				sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEIncorrect)
			return
		}
		prov.qosIE = ie.FindFirst(children, ie.TypeBearerQoS)
		if prov.qosIE == nil {
			h.log.Warn("S5C: Create Bearer — missing mandatory Bearer QoS", "session_id", sess.SessionID)
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
				sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEMissing)
			return
		}
		prov.tftIE = ie.FindFirst(children, ie.TypeBearerTFT)
		if prov.tftIE == nil {
			h.log.Warn("S5C: Create Bearer — missing mandatory Bearer TFT", "session_id", sess.SessionID)
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
				sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEMissing)
			return
		}
		if pgwUFTEID := ie.FindInstance(children, ie.TypeFTEID, 1); pgwUFTEID != nil {
			if f, fErr := pgwUFTEID.FTEIDValue(); fErr == nil {
				prov.pgwUS5UFTEID = bearer.FTEID{TEID: f.TEID, IPv4: f.IPv4}
			}
		}
		if prov.pgwUS5UFTEID.TEID == 0 || !prov.pgwUS5UFTEID.IPv4.IsValid() {
			h.log.Warn("S5C: Create Bearer — missing S5/S8-U PGW F-TEID", "session_id", sess.SessionID)
			h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
				sess.PGWControlFTEID.TEID, ie.CauseMandatoryIEMissing)
			return
		}
		prov.pdrUL, prov.pdrDL, prov.farUL, prov.farDL = sess.AllocBearerRuleIDs()
		bearerProvs = append(bearerProvs, prov)
	}

	if len(bearerProvs) == 0 {
		h.log.Warn("S5C: Create Bearer — no valid Bearer Contexts", "session_id", sess.SessionID)
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
			sess.PGWControlFTEID.TEID, ie.CauseInvalidMessageFormat)
		return
	}
	// Provision PFCP PDR/FAR pairs for each dedicated bearer.
	// PDR UL: Source=Access, CHOOSE F-TEID → SGW-U allocates S1-U TEID.
	// PDR DL: Source=Core, CHOOSE F-TEID → SGW-U allocates S5/8-U TEID.
	// FAR UL: FORW to Core with OHC=(PGW-U S5/8-U TEID) — known from CBReq.
	// FAR DL: DROP initially; updated to FORW with eNB TEID after CBResp.
	var createPDRs, createFARs []*pfcpie.IE
	for _, prov := range bearerProvs {
		pdi := pfcpie.NewPDI(
			pfcpie.NewSourceInterface(pfcpie.SourceInterfaceAccess),
			pfcpie.NewFTEIDChoose(),
		)
		createPDRs = append(createPDRs, pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(prov.pdrUL),
			pfcpie.NewPrecedence(100),
			pdi,
			pfcpie.NewFARID(prov.farUL),
		))

		pdi2 := pfcpie.NewPDI(
			pfcpie.NewSourceInterface(pfcpie.SourceInterfaceCore),
			pfcpie.NewFTEIDChoose(),
		)
		createPDRs = append(createPDRs, pfcpie.NewCreatePDR(
			pfcpie.NewPDRID(prov.pdrDL),
			pfcpie.NewPrecedence(200),
			pdi2,
			pfcpie.NewFARID(prov.farDL),
		))

		// FAR UL: FORW to PGW-U with OHC if PGW-U TEID is known; else DROP.
		if prov.pgwUS5UFTEID.TEID != 0 && prov.pgwUS5UFTEID.IPv4.IsValid() {
			createFARs = append(createFARs, pfcpie.NewCreateFAR(
				pfcpie.NewFARID(prov.farUL),
				pfcpie.NewApplyAction(pfcpie.ApplyActionFORW),
				pfcpie.NewForwardingParameters(
					pfcpie.NewDestinationInterface(pfcpie.DestInterfaceCore),
					pfcpie.NewOuterHeaderCreation(pfcpie.OHCDescGTPUUDPIPv4,
						prov.pgwUS5UFTEID.TEID, prov.pgwUS5UFTEID.IPv4),
				),
			))
		} else {
			createFARs = append(createFARs, pfcpie.NewCreateFAR(
				pfcpie.NewFARID(prov.farUL),
				pfcpie.NewApplyAction(pfcpie.ApplyActionDROP),
			))
		}

		// FAR DL: DROP until eNB TEID arrives.
		createFARs = append(createFARs, pfcpie.NewCreateFAR(
			pfcpie.NewFARID(prov.farDL),
			pfcpie.NewApplyAction(pfcpie.ApplyActionDROP),
		))
	}

	createdPDRs, pfcpErr := h.pfcp.AddBearerRulesOnPeer(context.Background(),
		sess.PFCP.SGWUAddr,
		sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID,
		createPDRs, createFARs)
	if pfcpErr != nil {
		h.log.Error("S5C: Create Bearer PFCP provisioning failed",
			"session_id", sess.SessionID, "error", pfcpErr)
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	// Extract SGW-U allocated TEIDs from Created PDR IEs.
	sgwUS1UTEIDs := make(map[uint16]bearer.FTEID) // pdrID → FTEID
	sgwUS5UTEIDs := make(map[uint16]bearer.FTEID)
	for _, cpdrIE := range createdPDRs {
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
		// Determine whether this PDR is UL or DL by checking which prov it belongs to.
		for i, prov := range bearerProvs {
			if pdrID == prov.pdrUL {
				bearerProvs[i].sgwUS1UFTEID = bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4}
				sgwUS1UTEIDs[pdrID] = bearerProvs[i].sgwUS1UFTEID
			} else if pdrID == prov.pdrDL {
				bearerProvs[i].sgwUS5UFTEID = bearer.FTEID{TEID: fteid.TEID, IPv4: fteid.IPv4}
				sgwUS5UTEIDs[pdrID] = bearerProvs[i].sgwUS5UFTEID
			}
		}
	}
	h.markCreateBearerTxnProvisioned(txn.key, bearerProvs)

	// Build S11 Create Bearer Request to relay to MME.
	// Per Table 7.2.3-1/7.2.3-2 (S11 interface):
	//   LBI: M — forwarded verbatim
	//   Bearer Contexts: M — for each bearer:
	//     EBI (inst=0): M — set to 0 (MME assigns)
	//     Bearer TFT (inst=0): M — forwarded from PGW CBReq
	//     S1-U SGW F-TEID (inst=0): C — SGW-U allocated TEID
	//     S5/8-U PGW F-TEID (inst=1): C — forwarded from PGW CBReq
	//     Bearer QoS (inst=0): M — forwarded from PGW CBReq
	var s11BCs []*ie.IE
	for _, prov := range bearerProvs {
		bcChildren := []*ie.IE{ie.NewEBI(0)} // EBI=0; MME assigns actual EBI
		if prov.tftIE != nil {
			bcChildren = append(bcChildren, prov.tftIE)
		}
		if prov.sgwUS1UFTEID.TEID != 0 && prov.sgwUS1UFTEID.IPv4.IsValid() {
			// S1-U SGW F-TEID: instance 0 per Table 7.2.3-2, S11 column.
			bcChildren = append(bcChildren,
				ie.NewFTEID(0, ie.IFTypeS1USGW,
					prov.sgwUS1UFTEID.TEID, prov.sgwUS1UFTEID.IPv4))
		}
		if prov.pgwUS5UFTEID.TEID != 0 && prov.pgwUS5UFTEID.IPv4.IsValid() {
			bcChildren = append(bcChildren,
				ie.NewFTEID(1, ie.IFTypeS5S8UPGW,
					prov.pgwUS5UFTEID.TEID, prov.pgwUS5UFTEID.IPv4))
		}
		if prov.qosIE != nil {
			bcChildren = append(bcChildren, prov.qosIE)
		}
		s11BCs = append(s11BCs, ie.NewBearerContext(0, bcChildren...))
	}

	s11CBReqIEs := make([]*ie.IE, 0, 1+len(s11BCs))
	s11CBReqIEs = append(s11CBReqIEs, ie.NewEBI(lbi)) // LBI at instance 0
	s11CBReqIEs = append(s11CBReqIEs, s11BCs...)
	diag := describeS11CreateBearerRequestBuild(lbi, s11BCs)
	h.log.Debug("S11: Create Bearer Request built",
		"session_id", sess.SessionID,
		"linked_ebi", diag.LinkedEBI,
		"bearer_contexts", diag.BearerContexts,
		"bearers", diag.Bearers,
	)

	s11Seq := h.conn.AllocSeq()
	s11CBReqRaw, err := message.MarshalCreateBearerRequest(sess.MMEControlFTEID.TEID, s11Seq, s11CBReqIEs...)
	if err != nil {
		h.log.Error("S5C: Create Bearer — marshal S11 CBReq failed", "error", err)
		h.removeAllCreateBearerTxnProvisioning(txn.key, sess, bearerProvs)
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	// Determine MME address from session state.
	mmeIP4 := sess.MMEControlFTEID.IPv4.As4()
	mmeAddr := &net.UDPAddr{IP: mmeIP4[:], Port: 2123}

	s11CBRespRaw, err := h.conn.Send(context.Background(), mmeAddr, s11CBReqRaw)
	if err != nil {
		h.log.Error("S5C: Create Bearer — Send S11 CBReq to MME failed", "error", err)
		h.removeAllCreateBearerTxnProvisioning(txn.key, sess, bearerProvs)
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	cbResp, err := message.ParseCreateBearerResponse(s11CBRespRaw)
	if err != nil {
		h.log.Error("S5C: Create Bearer — parse S11 CBResp failed", "error", err)
		h.removeAllCreateBearerTxnProvisioning(txn.key, sess, bearerProvs)
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}
	if err := validateCreateBearerResponseResults(cbResp, len(bearerProvs)); err != nil {
		h.log.Warn("S11: Create Bearer Response invalid",
			"session_id", sess.SessionID, "error", err)
		h.removeAllCreateBearerTxnProvisioning(txn.key, sess, bearerProvs)
		h.replyCreateBearerTxnError(txn.key, pgwAddr, hdr, cbReq,
			sess.PGWControlFTEID.TEID, ie.CauseInvalidMessageFormat)
		h.rememberCreateBearerProcedureFailure(txn.procedureKey, ie.CauseInvalidMessageFormat, gtpcCauseDescription{CauseText: gtpcCauseText(ie.CauseInvalidMessageFormat)})
		return
	}

	msgCause, _ := cbResp.Cause.CauseValue()
	msgCauseDesc := describeGTPCause(cbResp.Cause)
	fullProcedureReject := msgCause != ie.CauseRequestAccepted && msgCause != ie.CauseRequestAcceptedPartially
	if msgCause != ie.CauseRequestAccepted && msgCause != ie.CauseRequestAcceptedPartially {
		h.log.Warn("S11: Create Bearer Response rejected by MME",
			"session_id", sess.SessionID,
			"cause", msgCause,
			"cause_text", msgCauseDesc.CauseText,
			"offending_ie_type", msgCauseDesc.OffendingIEType,
			"offending_ie", msgCauseDesc.OffendingIEName,
			"offending_ie_instance", msgCauseDesc.OffendingIEInstance,
			"bearer_contexts", len(cbResp.BearerContexts),
		)
		h.removeAllCreateBearerTxnProvisioning(txn.key, sess, bearerProvs)
	}
	outMsgCause := msgCause
	acceptedBearers := 0
	failedBearers := 0
	firstFailureCause := uint8(0)

	// Process each Bearer Context in CBResp from MME.
	// Per Table 7.2.4-2 (S11):
	//   EBI (inst=0): M — actual EBI assigned by MME
	//   Cause (inst=0): M
	//   S1-U eNodeB F-TEID (inst=0): C — eNB's S1-U endpoint
	//   S1-U SGW F-TEID (inst=1): C — echoed back for correlation
	var s5cBCIEs []*ie.IE
	for respIndex, bcIE := range cbResp.BearerContexts {
		children, cErr := bcIE.ChildIEs()
		if cErr != nil {
			continue
		}
		ebiIE := ie.FindFirst(children, ie.TypeEBI)
		causeIE := ie.FindFirst(children, ie.TypeCause)
		if ebiIE == nil || causeIE == nil {
			continue
		}
		ebi, _ := ebiIE.EBIValue()
		bcCause, _ := causeIE.CauseValue()
		bcCauseDesc := describeGTPCause(causeIE)
		h.log.Info("S11: Create Bearer bearer context result",
			"session_id", sess.SessionID,
			"bearer_index", respIndex,
			"cause", bcCause,
			"cause_text", bcCauseDesc.CauseText,
			"offending_ie_type", bcCauseDesc.OffendingIEType,
			"offending_ie", bcCauseDesc.OffendingIEName,
			"offending_ie_instance", bcCauseDesc.OffendingIEInstance,
			"ebi", ebi,
		)

		// C11-equivalent: eNB S1-U F-TEID (inst=0) is C when cause=16.
		var enbFTEID bearer.FTEID
		if fteidIE := ie.FindInstance(children, ie.TypeFTEID, 0); fteidIE != nil {
			if f, fErr := fteidIE.FTEIDValue(); fErr == nil {
				enbFTEID = bearer.FTEID{TEID: f.TEID, IPv4: f.IPv4}
			}
		}

		// Match the provisioning entry by looking at which pdrDL TEID was echoed
		// in the SGW F-TEID (inst=1) from MME CBResp; if not echoed, use positional match.
		// For simplicity (dedicated bearers appear in same order), use index match.
		// More robust: match via inst=1 SGW S1-U TEID.
		var matchedProv *bearerProvisioning
		if sgwFTEIDIE := ie.FindInstance(children, ie.TypeFTEID, 1); sgwFTEIDIE != nil {
			if f, fErr := sgwFTEIDIE.FTEIDValue(); fErr == nil {
				for i := range bearerProvs {
					if bearerProvs[i].sgwUS1UFTEID.TEID == f.TEID {
						matchedProv = &bearerProvs[i]
						break
					}
				}
			}
		}
		if matchedProv == nil && len(bearerProvs) == 1 {
			matchedProv = &bearerProvs[0]
		}
		if matchedProv == nil && respIndex < len(bearerProvs) {
			matchedProv = &bearerProvs[respIndex]
		}

		cleanedProvisioning := false
		// Update PFCP DL FAR with eNB TEID.
		if bcCause == ie.CauseRequestAccepted && matchedProv != nil && enbFTEID.TEID != 0 && sess.PFCP.Established {
			pfcpModErr := h.pfcp.ModifySessionOnPeer(context.Background(),
				sess.PFCP.SGWUAddr,
				sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID,
				[]pfcpclient.FARUpdate{{
					FARID:              matchedProv.farDL,
					PDRID:              matchedProv.pdrDL,
					ApplyAction:        pfcpie.ApplyActionFORW,
					DestInterface:      pfcpie.DestInterfaceAccess,
					OuterTEID:          enbFTEID.TEID,
					OuterIP:            enbFTEID.IPv4,
					OuterHeaderRemoval: true,
				}},
			)
			if pfcpModErr != nil {
				h.log.Warn("S5C: Create Bearer — PFCP DL FAR update failed",
					"session_id", sess.SessionID, "ebi", ebi, "error", pfcpModErr)
				h.removeCreateBearerTxnProvisioning(txn.key, sess, matchedProv)
				cleanedProvisioning = true
				bcCause = ie.CauseSystemFailure
			}

			// Store bearer state.
			if bcCause == ie.CauseRequestAccepted {
				newBearer := &bearer.Bearer{
					EBI:         ebi,
					ENBS1UFTEID: enbFTEID,
					State:       bearer.BearerStateActive,
					PDRIDs:      [2]uint32{uint32(matchedProv.pdrUL), uint32(matchedProv.pdrDL)},
					FARIDs:      [2]uint32{matchedProv.farUL, matchedProv.farDL},
					SGWS1UFTEID: matchedProv.sgwUS1UFTEID,
					SGWS5UFTEID: matchedProv.sgwUS5UFTEID,
					PGWS5UFTEID: matchedProv.pgwUS5UFTEID,
				}
				if matchedProv.qosIE != nil {
					// Decode QoS per §8.15.
					v := matchedProv.qosIE.Value
					if len(v) >= 2 {
						newBearer.ARP = bearer.ARP{
							PriorityLevel:           (v[0] >> 2) & 0x0F,
							PreemptionCapability:    v[0]&0x40 != 0,
							PreemptionVulnerability: v[0]&0x01 != 0,
						}
						newBearer.QCI = v[1]
					}
				}
				if matchedProv.tftIE != nil {
					tftRaw, _ := matchedProv.tftIE.BearerTFTValue()
					newBearer.TFT = &bearer.TFT{Raw: tftRaw}
				}
				sess.SetBearer(newBearer)
			}
		} else if bcCause == ie.CauseRequestAccepted && matchedProv != nil {
			h.removeCreateBearerTxnProvisioning(txn.key, sess, matchedProv)
			cleanedProvisioning = true
			bcCause = ie.CauseSystemFailure
		}

		if bcCause != ie.CauseRequestAccepted && matchedProv != nil && !cleanedProvisioning && !fullProcedureReject {
			h.removeCreateBearerTxnProvisioning(txn.key, sess, matchedProv)
		}
		if bcCause == ie.CauseRequestAccepted {
			acceptedBearers++
		} else {
			failedBearers++
			if firstFailureCause == 0 {
				firstFailureCause = bcCause
			}
		}

		s5cBCIEs = append(s5cBCIEs, buildCreateBearerS5CResponseContext(ebi, bcCause, matchedProv))
	}
	if failedBearers > 0 {
		if acceptedBearers > 0 {
			outMsgCause = ie.CauseRequestAcceptedPartially
		} else if firstFailureCause != 0 {
			outMsgCause = firstFailureCause
		}
	}

	// Build S5/S8-C CBResp per Table 7.2.4-1 and relay to PGW.
	// Response TEID = PGW's S5/S8-C control TEID per C4.
	s5cRespIEs := make([]*ie.IE, 0, 1+len(s5cBCIEs))
	s5cRespIEs = append(s5cRespIEs, ie.NewCause(outMsgCause, 0, 0, 0, nil))
	s5cRespIEs = append(s5cRespIEs, s5cBCIEs...)
	s5cResp, err := message.MarshalCreateBearerResponse(
		sess.PGWControlFTEID.TEID, hdr.SequenceNumber, s5cRespIEs...)
	if err != nil {
		h.log.Error("S5C: Create Bearer — marshal S5/S8-C CBResp failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pgwAddr, s5cResp); err != nil {
		h.log.Warn("S5C: Create Bearer — send CBResp to PGW failed", "error", err)
	}
	if outMsgCause != ie.CauseRequestAccepted && outMsgCause != ie.CauseRequestAcceptedPartially {
		h.rememberCreateBearerProcedureFailure(txn.procedureKey, outMsgCause, msgCauseDesc)
	}
	h.completeCreateBearerTxn(txn.key, s5cResp, outMsgCause)

	h.log.Info("S5C: Create Bearer completed",
		"session_id", sess.SessionID, "msg_cause", outMsgCause, "bearers", len(s5cBCIEs))
}

// ── Update Bearer ─────────────────────────────────────────────────────────────

func (h *Handler) handleUpdateBearer(pgwAddr *net.UDPAddr, hdr message.Header, raw []byte) {
	ubReq, err := message.ParseUpdateBearerRequest(raw)
	if err != nil {
		h.log.Warn("S5C: Update Bearer Request invalid", "from", pgwAddr, "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeUpdateBearerResponse, 0, ie.CauseInvalidMessageFormat)
		return
	}

	sess := h.sessions.FindByS5CTEID(hdr.TEID)
	if sess == nil {
		h.log.Warn("S5C: Update Bearer Request — session not found",
			"teid", fmt.Sprintf("0x%08X", hdr.TEID))
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeUpdateBearerResponse, 0, ie.CauseContextNotFound)
		return
	}

	// Relay Update Bearer Request to MME verbatim.
	// Per Table 7.2.15-1 (S11): Bearer Contexts and AMBR are M; forwarded as-is.
	s11Ies := make([]*ie.IE, 0, len(ubReq.BearerContexts)+1)
	s11Ies = append(s11Ies, ubReq.BearerContexts...)
	if ubReq.AMBR != nil {
		s11Ies = append(s11Ies, ubReq.AMBR)
	}

	s11Seq := h.conn.AllocSeq()
	s11UBReqRaw, err := message.MarshalUpdateBearerRequest(sess.MMEControlFTEID.TEID, s11Seq, s11Ies...)
	if err != nil {
		h.log.Error("S5C: Update Bearer — marshal S11 UBReq failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeUpdateBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	mmeIP4 := sess.MMEControlFTEID.IPv4.As4()
	mmeAddr := &net.UDPAddr{IP: mmeIP4[:], Port: 2123}
	s11UBRespRaw, err := h.conn.Send(context.Background(), mmeAddr, s11UBReqRaw)
	if err != nil {
		h.log.Error("S5C: Update Bearer — Send S11 UBReq failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeUpdateBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	ubResp, err := message.ParseUpdateBearerResponse(s11UBRespRaw)
	if err != nil {
		h.log.Error("S5C: Update Bearer — parse S11 UBResp failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeUpdateBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	msgCause, _ := ubResp.Cause.CauseValue()

	// Update local bearer state for accepted bearers.
	for _, bcIE := range ubResp.BearerContexts {
		children, cErr := bcIE.ChildIEs()
		if cErr != nil {
			continue
		}
		ebiIE := ie.FindFirst(children, ie.TypeEBI)
		causeIE := ie.FindFirst(children, ie.TypeCause)
		if ebiIE == nil || causeIE == nil {
			continue
		}
		ebi, _ := ebiIE.EBIValue()
		bcCause, _ := causeIE.CauseValue()
		if bcCause != ie.CauseRequestAccepted {
			continue
		}
		// Update QoS/TFT in bearer state from UBReq BC.
		b := sess.GetBearer(ebi)
		if b == nil {
			continue
		}
		// Find matching BC from UBReq to get new QoS/TFT.
		for _, reqBC := range ubReq.BearerContexts {
			reqChildren, rErr := reqBC.ChildIEs()
			if rErr != nil {
				continue
			}
			reqEBIIE := ie.FindFirst(reqChildren, ie.TypeEBI)
			if reqEBIIE == nil {
				continue
			}
			reqEBI, _ := reqEBIIE.EBIValue()
			if reqEBI != ebi {
				continue
			}
			if tftIE := ie.FindFirst(reqChildren, ie.TypeBearerTFT); tftIE != nil {
				if raw, rErr := tftIE.BearerTFTValue(); rErr == nil {
					b.TFT = &bearer.TFT{Raw: raw}
				}
			}
			if qosIE := ie.FindFirst(reqChildren, ie.TypeBearerQoS); qosIE != nil && len(qosIE.Value) >= 2 {
				b.ARP = bearer.ARP{
					PriorityLevel:           (qosIE.Value[0] >> 2) & 0x0F,
					PreemptionCapability:    qosIE.Value[0]&0x40 != 0,
					PreemptionVulnerability: qosIE.Value[0]&0x01 != 0,
				}
				b.QCI = qosIE.Value[1]
			}
			sess.SetBearer(b)
			break
		}
	}

	// Build S5/S8-C UBResp and relay to PGW.
	s5cRespIEs := make([]*ie.IE, 0, 1+len(ubResp.BearerContexts))
	s5cRespIEs = append(s5cRespIEs, ie.NewCause(msgCause, 0, 0, 0, nil))
	s5cRespIEs = append(s5cRespIEs, ubResp.BearerContexts...)
	s5cResp, err := message.MarshalUpdateBearerResponse(
		sess.PGWControlFTEID.TEID, hdr.SequenceNumber, s5cRespIEs...)
	if err != nil {
		h.log.Error("S5C: Update Bearer — marshal S5/S8-C UBResp failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pgwAddr, s5cResp); err != nil {
		h.log.Warn("S5C: Update Bearer — send UBResp to PGW failed", "error", err)
	}

	h.log.Info("S5C: Update Bearer completed",
		"session_id", sess.SessionID, "msg_cause", msgCause)
}

// ── Delete Bearer ─────────────────────────────────────────────────────────────

func (h *Handler) handleDeleteBearer(pgwAddr *net.UDPAddr, hdr message.Header, raw []byte) {
	dbReq, err := message.ParseDeleteBearerRequest(raw)
	if err != nil {
		h.log.Warn("S5C: Delete Bearer Request invalid", "from", pgwAddr, "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeDeleteBearerResponse, 0, ie.CauseInvalidMessageFormat)
		return
	}

	sess := h.sessions.FindByS5CTEID(hdr.TEID)
	if sess == nil {
		h.log.Warn("S5C: Delete Bearer Request — session not found",
			"teid", fmt.Sprintf("0x%08X", hdr.TEID))
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeDeleteBearerResponse, 0, ie.CauseContextNotFound)
		return
	}

	// Relay DBReq to MME verbatim.
	var s11Ies []*ie.IE
	if dbReq.LBI != nil {
		s11Ies = append(s11Ies, dbReq.LBI)
	}
	s11Ies = append(s11Ies, dbReq.EBIs...)

	s11Seq := h.conn.AllocSeq()
	s11DBReqRaw, err := message.MarshalDeleteBearerRequest(sess.MMEControlFTEID.TEID, s11Seq, s11Ies...)
	if err != nil {
		h.log.Error("S5C: Delete Bearer — marshal S11 DBReq failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeDeleteBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	mmeIP4 := sess.MMEControlFTEID.IPv4.As4()
	mmeAddr := &net.UDPAddr{IP: mmeIP4[:], Port: 2123}
	s11DBRespRaw, err := h.conn.Send(context.Background(), mmeAddr, s11DBReqRaw)
	if err != nil {
		h.log.Error("S5C: Delete Bearer — Send S11 DBReq failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeDeleteBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	dbResp, err := message.ParseDeleteBearerResponse(s11DBRespRaw)
	if err != nil {
		h.log.Error("S5C: Delete Bearer — parse S11 DBResp failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeDeleteBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	msgCause, _ := dbResp.Cause.CauseValue()

	if msgCause == ie.CauseRequestAccepted || msgCause == ie.CauseRequestAcceptedPartially {
		// Remove PFCP rules and bearer state for each accepted deleted bearer.
		for _, bcIE := range dbResp.BearerContexts {
			children, cErr := bcIE.ChildIEs()
			if cErr != nil {
				continue
			}
			ebiIE := ie.FindFirst(children, ie.TypeEBI)
			causeIE := ie.FindFirst(children, ie.TypeCause)
			if ebiIE == nil || causeIE == nil {
				continue
			}
			ebi, _ := ebiIE.EBIValue()
			bcCause, _ := causeIE.CauseValue()
			if bcCause != ie.CauseRequestAccepted {
				continue
			}
			b := sess.GetBearer(ebi)
			if b != nil && (b.PDRIDs[0] != 0 || b.PDRIDs[1] != 0) {
				// Remove PFCP PDR/FAR rules for this bearer.
				pdrIDs := []uint32{b.PDRIDs[0], b.PDRIDs[1]}
				farIDs := []uint32{b.FARIDs[0], b.FARIDs[1]}
				if pfcpErr := h.pfcp.RemoveBearerRulesOnPeer(context.Background(),
					sess.PFCP.SGWUAddr,
					sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID,
					pdrIDs, farIDs); pfcpErr != nil {
					h.log.Warn("S5C: Delete Bearer — PFCP RemoveBearerRules failed",
						"session_id", sess.SessionID, "ebi", ebi, "error", pfcpErr)
				}
			}
			sess.DeleteBearer(ebi)
		}
	}

	// Build S5/S8-C DBResp and relay to PGW.
	var s5cRespIEs []*ie.IE
	s5cRespIEs = append(s5cRespIEs, ie.NewCause(msgCause, 0, 0, 0, nil))
	if dbResp.LBI != nil {
		s5cRespIEs = append(s5cRespIEs, dbResp.LBI)
	}
	s5cRespIEs = append(s5cRespIEs, dbResp.BearerContexts...)
	s5cResp, err := message.MarshalDeleteBearerResponse(
		sess.PGWControlFTEID.TEID, hdr.SequenceNumber, s5cRespIEs...)
	if err != nil {
		h.log.Error("S5C: Delete Bearer — marshal S5/S8-C DBResp failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pgwAddr, s5cResp); err != nil {
		h.log.Warn("S5C: Delete Bearer — send DBResp to PGW failed", "error", err)
	}

	h.log.Info("S5C: Delete Bearer completed",
		"session_id", sess.SessionID, "msg_cause", msgCause)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func (h *Handler) removeProvisionedBearerRules(sess *session.SGWSession, pdrUL, pdrDL uint16, farUL, farDL uint32) {
	if !sess.PFCP.Established {
		return
	}
	if err := h.pfcp.RemoveBearerRulesOnPeer(context.Background(),
		sess.PFCP.SGWUAddr,
		sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID,
		[]uint32{uint32(pdrUL), uint32(pdrDL)},
		[]uint32{farUL, farDL}); err != nil {
		h.log.Warn("S5C: Create Bearer — PFCP cleanup failed",
			"session_id", sess.SessionID, "pdr_ul", pdrUL, "pdr_dl", pdrDL, "error", err)
	}
}

func (h *Handler) removeAllCreateBearerTxnProvisioning(key createBearerTxnKey, sess *session.SGWSession, provs []bearerProvisioning) {
	var pdrIDs []uint32
	var farIDs []uint32
	for i := range provs {
		prov := provs[i]
		if !h.markCreateBearerTxnRolledBack(key, prov) {
			h.log.Debug("S5C: Create Bearer provisional PFCP rollback already done",
				"session_id", sess.SessionID,
				"pdr_ul", prov.pdrUL,
				"pdr_dl", prov.pdrDL,
				"far_ul", prov.farUL,
				"far_dl", prov.farDL,
			)
			continue
		}
		pdrIDs = append(pdrIDs, uint32(prov.pdrUL), uint32(prov.pdrDL))
		farIDs = append(farIDs, prov.farUL, prov.farDL)
	}
	if len(pdrIDs) == 0 || !sess.PFCP.Established {
		return
	}
	if err := h.pfcp.RemoveBearerRulesOnPeer(context.Background(),
		sess.PFCP.SGWUAddr,
		sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID,
		pdrIDs, farIDs); err != nil {
		h.log.Warn("S5C: Create Bearer — PFCP cleanup failed",
			"session_id", sess.SessionID, "pdrs", pdrIDs, "error", err)
	}
}

func (h *Handler) removeCreateBearerTxnProvisioning(key createBearerTxnKey, sess *session.SGWSession, prov *bearerProvisioning) {
	if prov == nil {
		return
	}
	if !h.markCreateBearerTxnRolledBack(key, *prov) {
		h.log.Debug("S5C: Create Bearer provisional PFCP rollback already done",
			"session_id", sess.SessionID,
			"pdr_ul", prov.pdrUL,
			"pdr_dl", prov.pdrDL,
			"far_ul", prov.farUL,
			"far_dl", prov.farDL,
		)
		return
	}
	h.removeProvisionedBearerRules(sess, prov.pdrUL, prov.pdrDL, prov.farUL, prov.farDL)
}

// replyBearerError sends a minimal error response back to the PGW for a bearer procedure.
// peerTEID is the PGW's S5/S8-C control TEID (response TEID per C4); 0 if unknown.
func (h *Handler) replyBearerError(pgwAddr *net.UDPAddr, hdr message.Header, respType uint8, peerTEID uint32, cause uint8) {
	raw, err := marshalBearerError(hdr, respType, peerTEID, cause)
	if err != nil {
		h.log.Error("S5C: bearer error response marshal failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pgwAddr, raw); err != nil {
		h.log.Warn("S5C: bearer error response send failed", "error", err)
	}
}

func (h *Handler) replyCreateBearerTxnError(txnKey createBearerTxnKey, pgwAddr *net.UDPAddr, hdr message.Header, cbReq *message.CreateBearerRequest, peerTEID uint32, cause uint8) {
	raw, err := marshalCreateBearerErrorResponse(hdr, peerTEID, cause, cbReq)
	if err != nil {
		h.log.Error("S5C: Create Bearer error response marshal failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pgwAddr, raw); err != nil {
		h.log.Warn("S5C: Create Bearer error response send failed", "error", err)
	}
	h.completeCreateBearerTxn(txnKey, raw, cause)
}

func (h *Handler) replyCreateBearerRetryGuardFailure(pgwAddr *net.UDPAddr, hdr message.Header, cbReq *message.CreateBearerRequest, sess *session.SGWSession, failure *createBearerProcedureFailure) {
	cause := failure.lastFailureCause
	if cause == 0 {
		cause = ie.CauseRequestRejected
	}
	raw, err := marshalCreateBearerErrorResponse(hdr, sess.PGWControlFTEID.TEID, cause, cbReq)
	if err != nil {
		h.log.Error("S5/S8-C: Create Bearer retry guard response marshal failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pgwAddr, raw); err != nil {
		h.log.Warn("S5/S8-C: Create Bearer retry guard response send failed", "error", err)
		return
	}
	if !failure.logSuppression {
		return
	}
	h.log.Warn("S5/S8-C: latched failed Create Bearer procedure suppressed",
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"linked_ebi", failure.key.linkedEBI,
		"bearer_contexts", failure.key.bearerCount,
		"pgw_seq", hdr.SequenceNumber,
		"local_s5c_teid", fmt.Sprintf("0x%08X", hdr.TEID),
		"last_failure_cause", cause,
		"offending_ie", failure.offendingIEName,
		"suppressed_count", failure.suppressedCount,
		"protocol_response_sent", true,
		"pfcp_allocated", false,
		"s11_forwarded", false,
	)
}

func marshalCreateBearerErrorResponse(hdr message.Header, peerTEID uint32, cause uint8, cbReq *message.CreateBearerRequest) ([]byte, error) {
	if cbReq == nil || len(cbReq.BearerContexts) == 0 {
		return marshalBearerError(hdr, message.MsgTypeCreateBearerResponse, peerTEID, cause)
	}

	ies := make([]*ie.IE, 0, 1+len(cbReq.BearerContexts))
	ies = append(ies, ie.NewCause(cause, 0, 0, 0, nil))
	for _, reqBC := range cbReq.BearerContexts {
		ebi := uint8(0)
		if children, err := reqBC.ChildIEs(); err == nil {
			if ebiIE := ie.FindFirst(children, ie.TypeEBI); ebiIE != nil {
				if v, vErr := ebiIE.EBIValue(); vErr == nil {
					ebi = v
				}
			}
		}
		ies = append(ies, ie.NewBearerContext(0,
			ie.NewEBI(ebi),
			ie.NewCause(cause, 0, 0, 0, nil),
		))
	}
	return message.MarshalCreateBearerResponse(peerTEID, hdr.SequenceNumber, ies...)
}

func marshalBearerError(hdr message.Header, respType uint8, peerTEID uint32, cause uint8) ([]byte, error) {
	respHdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    respType,
		TEID:           peerTEID,
		SequenceNumber: hdr.SequenceNumber,
	}
	return message.Marshal(respHdr, []*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)})
}

type createBearerTxnAction int

const (
	createBearerTxnActionNew createBearerTxnAction = iota
	createBearerTxnActionPending
	createBearerTxnActionCached
	createBearerTxnActionFingerprintPending
	createBearerTxnActionFingerprintCached
)

func (a createBearerTxnAction) String() string {
	switch a {
	case createBearerTxnActionNew:
		return "new"
	case createBearerTxnActionPending:
		return "pending"
	case createBearerTxnActionCached:
		return "cached"
	case createBearerTxnActionFingerprintPending:
		return "fingerprint_pending"
	case createBearerTxnActionFingerprintCached:
		return "fingerprint_cached"
	default:
		return fmt.Sprintf("unknown(%d)", a)
	}
}

func (h *Handler) beginCreateBearerTxn(pgwAddr *net.UDPAddr, hdr message.Header, raw []byte, sess *session.SGWSession) (*createBearerTxnState, createBearerTxnAction) {
	return h.beginCreateBearerTxnWithFingerprint(pgwAddr, hdr, raw, sess, createBearerFingerprintKey{})
}

func (h *Handler) findCreateBearerTxn(pgwAddr *net.UDPAddr, hdr message.Header) (*createBearerTxnState, createBearerTxnAction) {
	key := newCreateBearerTxnKey(pgwAddr, hdr)
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbTxns == nil {
		return nil, createBearerTxnActionNew
	}
	txn := h.cbTxns[key]
	if txn == nil {
		return nil, createBearerTxnActionNew
	}
	txn.updatedAt = time.Now()
	if len(txn.s5cResponse) > 0 {
		return txn, createBearerTxnActionCached
	}
	return txn, createBearerTxnActionPending
}

func (h *Handler) beginCreateBearerTxnWithFingerprint(pgwAddr *net.UDPAddr, hdr message.Header, raw []byte, sess *session.SGWSession, fp createBearerFingerprintKey) (*createBearerTxnState, createBearerTxnAction) {
	key := newCreateBearerTxnKey(pgwAddr, hdr)

	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbTxns == nil {
		h.cbTxns = make(map[createBearerTxnKey]*createBearerTxnState)
	}
	if h.cbFPs == nil {
		h.cbFPs = make(map[createBearerFingerprintKey]*createBearerTxnState)
	}
	if txn := h.cbTxns[key]; txn != nil {
		txn.updatedAt = time.Now()
		if len(txn.s5cResponse) > 0 {
			return txn, createBearerTxnActionCached
		}
		return txn, createBearerTxnActionPending
	}
	if fp != (createBearerFingerprintKey{}) {
		if txn := h.cbFPs[fp]; txn != nil {
			txn.updatedAt = time.Now()
			if len(txn.s5cResponse) > 0 {
				h.cbTxns[key] = txn
				return txn, createBearerTxnActionFingerprintCached
			}
			h.cbTxns[key] = txn
			return txn, createBearerTxnActionFingerprintPending
		}
	}

	now := time.Now()
	reqCopy := append([]byte(nil), raw...)
	txn := &createBearerTxnState{
		key:             key,
		fingerprint:     fp,
		sessionID:       sess.SessionID,
		status:          createBearerTxnPending,
		originalRequest: reqCopy,
		createdAt:       now,
		updatedAt:       now,
	}
	h.cbTxns[key] = txn
	if fp != (createBearerFingerprintKey{}) {
		h.cbFPs[fp] = txn
	}
	return txn, createBearerTxnActionNew
}

func newCreateBearerTxnKey(pgwAddr *net.UDPAddr, hdr message.Header) createBearerTxnKey {
	var peerIP netip.Addr
	var peerPort uint16
	if pgwAddr != nil {
		peerPort = uint16(pgwAddr.Port)
		if ip4 := pgwAddr.IP.To4(); ip4 != nil {
			peerIP = netip.AddrFrom4([4]byte{ip4[0], ip4[1], ip4[2], ip4[3]})
		} else {
			ap := pgwAddr.AddrPort()
			peerIP = ap.Addr()
			peerPort = ap.Port()
		}
	}
	return createBearerTxnKey{
		peerIP:       peerIP,
		peerPort:     peerPort,
		localS5CTEID: hdr.TEID,
		msgType:      hdr.MessageType,
		sequence:     hdr.SequenceNumber,
	}
}

func newCreateBearerFingerprintKey(pgwAddr *net.UDPAddr, hdr message.Header, lbi uint8, bearerContexts []*ie.IE) createBearerFingerprintKey {
	key := newCreateBearerTxnKey(pgwAddr, hdr)
	h := sha256.New()
	for _, bc := range bearerContexts {
		h.Write(bc.Marshal())
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return createBearerFingerprintKey{
		peerIP:       key.peerIP,
		peerPort:     key.peerPort,
		localS5CTEID: key.localS5CTEID,
		lbi:          lbi,
		bodyHash:     sum,
	}
}

func newCreateBearerProcedureKey(pgwAddr *net.UDPAddr, hdr message.Header, sess *session.SGWSession, lbi uint8, bearerContexts []*ie.IE) createBearerProcedureKey {
	txnKey := newCreateBearerTxnKey(pgwAddr, hdr)
	h := sha256.New()
	for _, bc := range bearerContexts {
		children, err := bc.ChildIEs()
		if err != nil {
			h.Write(bc.Marshal())
			continue
		}
		if tftIE := ie.FindFirst(children, ie.TypeBearerTFT); tftIE != nil {
			h.Write([]byte{1, tftIE.Instance})
			h.Write(tftIE.Value)
		} else {
			h.Write([]byte{0, ie.TypeBearerTFT})
		}
		if qosIE := ie.FindFirst(children, ie.TypeBearerQoS); qosIE != nil {
			h.Write([]byte{1, qosIE.Instance})
			h.Write(qosIE.Value)
		} else {
			h.Write([]byte{0, ie.TypeBearerQoS})
		}
		if pgwUFTEID := ie.FindInstance(children, ie.TypeFTEID, 1); pgwUFTEID != nil {
			if f, fErr := pgwUFTEID.FTEIDValue(); fErr == nil {
				h.Write([]byte{1, f.IntfType})
				if f.IPv4.Is4() {
					ip := f.IPv4.As4()
					h.Write(ip[:])
				}
			}
		} else {
			h.Write([]byte{0, ie.TypeFTEID, 1})
		}
	}
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	return createBearerProcedureKey{
		sessionID:    sess.SessionID,
		imsi:         sess.IMSI,
		apn:          sess.APN,
		peerIP:       txnKey.peerIP,
		peerPort:     txnKey.peerPort,
		localS5CTEID: txnKey.localS5CTEID,
		linkedEBI:    lbi,
		bearerCount:  len(bearerContexts),
		sigHash:      sum,
	}
}

func (h *Handler) createBearerRetryGuardEnabled() bool {
	if h.cfg == nil {
		return true
	}
	return h.cfg.GTPC.CreateBearerRetryGuard.Enabled
}

func (h *Handler) findLatchedCreateBearerProcedureFailure(key createBearerProcedureKey) *createBearerProcedureFailure {
	if !h.createBearerRetryGuardEnabled() || key == (createBearerProcedureKey{}) {
		return nil
	}
	now := time.Now()
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbProcFailures == nil {
		return nil
	}
	failure := h.cbProcFailures[key]
	if failure == nil {
		return nil
	}
	failure.lastSeen = now
	failure.suppressedCount++
	failure.logSuppression = failure.suppressedCount <= 3 || now.Sub(failure.lastSuppressLog) >= 5*time.Second
	if failure.logSuppression {
		failure.lastSuppressLog = now
	}
	snapshot := *failure
	return &snapshot
}

func (h *Handler) rememberCreateBearerProcedureFailure(key createBearerProcedureKey, cause uint8, causeDesc gtpcCauseDescription) {
	if !h.createBearerRetryGuardEnabled() || key == (createBearerProcedureKey{}) {
		return
	}
	now := time.Now()
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbProcFailures == nil {
		h.cbProcFailures = make(map[createBearerProcedureKey]*createBearerProcedureFailure)
	}
	if failure := h.cbProcFailures[key]; failure != nil {
		failure.state = "failed_latched"
		failure.lastFailureCause = cause
		failure.lastFailureText = causeDesc.CauseText
		failure.offendingIEType = causeDesc.OffendingIEType
		failure.offendingIEName = causeDesc.OffendingIEName
		failure.lastSeen = now
		return
	}
	h.cbProcFailures[key] = &createBearerProcedureFailure{
		key:              key,
		state:            "failed_latched",
		lastFailureCause: cause,
		lastFailureText:  causeDesc.CauseText,
		offendingIEType:  causeDesc.OffendingIEType,
		offendingIEName:  causeDesc.OffendingIEName,
		firstSeen:        now,
		lastSeen:         now,
	}
	if h.log != nil {
		h.log.Warn("S5/S8-C: Create Bearer procedure latched failed",
			"session_id", key.sessionID,
			"imsi", key.imsi,
			"apn", key.apn,
			"linked_ebi", key.linkedEBI,
			"bearer_contexts", key.bearerCount,
			"failure_cause", cause,
			"offending_ie", causeDesc.OffendingIEName,
			"guard_state", "failed_latched",
		)
	}
}

func (h *Handler) clearCreateBearerProcedureFailuresForSession(sessionID, reason string) {
	if sessionID == "" {
		return
	}
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	cleared := 0
	for key := range h.cbProcFailures {
		if key.sessionID == sessionID {
			delete(h.cbProcFailures, key)
			cleared++
		}
	}
	if cleared > 0 && h.log != nil {
		h.log.Info("S5/S8-C: clearing latched Create Bearer failure",
			"session_id", sessionID,
			"reason", reason,
			"cleared", cleared,
		)
	}
}

func cloneCreateBearerResponseForSequence(raw []byte, seq uint32) ([]byte, error) {
	hdr, ies, err := message.Parse(raw)
	if err != nil {
		return nil, err
	}
	hdr.SequenceNumber = seq
	return message.Marshal(hdr, ies)
}

func (h *Handler) logCreateBearerTxnDecision(txn *createBearerTxnState, action createBearerTxnAction, hdr message.Header) {
	if h.log == nil || txn == nil {
		return
	}
	key := txn.key
	h.log.Debug("S5/S8-C: Create Bearer transaction decision",
		"session_id", txn.sessionID,
		"action", action.String(),
		"state", txn.status,
		"peer_ip", key.peerIP.String(),
		"peer_port", key.peerPort,
		"local_s5c_teid", fmt.Sprintf("0x%08X", key.localS5CTEID),
		"msg_type", key.msgType,
		"sequence", key.sequence,
		"request_teid", fmt.Sprintf("0x%08X", hdr.TEID),
		"has_cached_response", len(txn.s5cResponse) > 0,
		"pfcp_provisional_done", txn.pfcpProvisionalDone,
		"provisional_bearers", len(txn.provisionedBearers),
	)
}

func (h *Handler) markCreateBearerTxnProvisioned(key createBearerTxnKey, provs []bearerProvisioning) {
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbTxns == nil {
		return
	}
	txn := h.cbTxns[key]
	if txn == nil {
		return
	}
	txn.provisionedBearers = append([]bearerProvisioning(nil), provs...)
	txn.pfcpProvisionalDone = true
	if txn.pfcpRolledBack == nil {
		txn.pfcpRolledBack = make(map[createBearerRuleKey]bool)
	}
	txn.updatedAt = time.Now()
}

func (h *Handler) setCreateBearerTxnProcedureKey(key createBearerTxnKey, procKey createBearerProcedureKey) {
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbTxns == nil {
		return
	}
	txn := h.cbTxns[key]
	if txn == nil {
		return
	}
	txn.procedureKey = procKey
	txn.updatedAt = time.Now()
}

func (h *Handler) markCreateBearerTxnRolledBack(key createBearerTxnKey, prov bearerProvisioning) bool {
	ruleKey := createBearerRuleKey{
		pdrUL: prov.pdrUL,
		pdrDL: prov.pdrDL,
		farUL: prov.farUL,
		farDL: prov.farDL,
	}

	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbTxns == nil {
		return true
	}
	txn := h.cbTxns[key]
	if txn == nil {
		return true
	}
	if txn.pfcpRolledBack == nil {
		txn.pfcpRolledBack = make(map[createBearerRuleKey]bool)
	}
	if txn.pfcpRolledBack[ruleKey] {
		txn.updatedAt = time.Now()
		return false
	}
	txn.pfcpRolledBack[ruleKey] = true
	txn.updatedAt = time.Now()
	return true
}

func (h *Handler) completeCreateBearerTxn(key createBearerTxnKey, response []byte, cause uint8) {
	h.cbTxnMu.Lock()
	defer h.cbTxnMu.Unlock()
	if h.cbTxns == nil {
		return
	}
	txn := h.cbTxns[key]
	if txn == nil {
		return
	}
	txn.s5cResponse = append([]byte(nil), response...)
	txn.s5cCause = cause
	if cause == ie.CauseRequestAccepted || cause == ie.CauseRequestAcceptedPartially {
		txn.status = createBearerTxnCompleted
	} else {
		txn.status = createBearerTxnFailed
	}
	txn.updatedAt = time.Now()
}

func describeS11CreateBearerRequestBuild(lbi uint8, bearerContexts []*ie.IE) createBearerBuildDiagnostic {
	out := createBearerBuildDiagnostic{
		LinkedEBI:      lbi,
		BearerContexts: len(bearerContexts),
		Bearers:        make([]createBearerBuildBearerDiagnostic, 0, len(bearerContexts)),
	}
	for index, bcIE := range bearerContexts {
		b := createBearerBuildBearerDiagnostic{
			Index:         index,
			GroupedLength: len(bcIE.Value),
		}
		children, err := bcIE.ChildIEs()
		if err != nil {
			out.Bearers = append(out.Bearers, b)
			continue
		}
		if ebiIE := ie.FindFirst(children, ie.TypeEBI); ebiIE != nil {
			b.EBIInstance = ebiIE.Instance
			if ebi, eErr := ebiIE.EBIValue(); eErr == nil {
				b.EBI = ebi
			}
		}
		if tftIE := ie.FindFirst(children, ie.TypeBearerTFT); tftIE != nil {
			b.HasTFT = true
			b.TFTLength = len(tftIE.Value)
			b.TFTInstance = tftIE.Instance
		}
		if qosIE := ie.FindFirst(children, ie.TypeBearerQoS); qosIE != nil {
			b.HasBearerQoS = true
			b.BearerQoSLength = len(qosIE.Value)
			b.BearerQoSInst = qosIE.Instance
		}
		if fteidIE := ie.FindInstance(children, ie.TypeFTEID, 0); fteidIE != nil {
			b.HasSGWS1UFTEID = true
			if len(fteidIE.Value) > 0 {
				b.SGWS1UIFType = fteidIE.Value[0] & 0x3F
			}
			if fteid, fErr := fteidIE.FTEIDValue(); fErr == nil {
				b.SGWS1UTEID = fteid.TEID
				b.SGWS1UIP = fteid.IPv4.String()
			}
		}
		if fteidIE := ie.FindInstance(children, ie.TypeFTEID, 1); fteidIE != nil {
			b.HasPGWS5UFTEID = true
			if len(fteidIE.Value) > 0 {
				b.PGWS5UIFType = fteidIE.Value[0] & 0x3F
			}
			if fteid, fErr := fteidIE.FTEIDValue(); fErr == nil {
				b.PGWS5UTEID = fteid.TEID
				b.PGWS5UIP = fteid.IPv4.String()
			}
		}
		out.Bearers = append(out.Bearers, b)
	}
	return out
}

type gtpcCauseDescription struct {
	CauseText           string
	OffendingIEType     uint8
	OffendingIEName     string
	OffendingIEInstance uint8
}

func describeGTPCause(causeIE *ie.IE) gtpcCauseDescription {
	if causeIE == nil {
		return gtpcCauseDescription{}
	}
	cause, err := causeIE.CauseValue()
	if err != nil {
		return gtpcCauseDescription{}
	}
	out := gtpcCauseDescription{CauseText: gtpcCauseText(cause)}
	if len(causeIE.Value) >= 6 {
		out.OffendingIEType = causeIE.Value[2]
		out.OffendingIEInstance = causeIE.Value[5] & 0x0F
		out.OffendingIEName = gtpcIEName(out.OffendingIEType)
	}
	return out
}

func gtpcCauseText(cause uint8) string {
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

func gtpcIEName(ieType uint8) string {
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
		return "EPS Bearer ID"
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
	case ie.TypeBearerTFT:
		return "Bearer TFT"
	default:
		return "Unknown IE"
	}
}
