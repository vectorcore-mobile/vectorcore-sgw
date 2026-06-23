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
	"fmt"
	"net"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/gtpv2/transport"
	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	pfcpclient "vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/bearer"
)

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

	// Per bearer: extract QoS, TFT, and PGW-U S5/8-U F-TEID from BC children (S5/S8-C).
	// Table 7.2.3-2 S5/S8-C column:
	//   EBI (inst=0): M — shall be set to 0 in CBReq (MME assigns actual EBI in CBResp)
	//   Bearer TFT (inst=0): M
	//   S5/8-U PGW F-TEID (inst=1): C — present, SGW-C uses it for PFCP uplink FAR
	//   Bearer QoS (inst=0): M
	type bearerProvisioning struct {
		qosIE       *ie.IE
		tftIE       *ie.IE
		pgwUS5UFTEID bearer.FTEID
		pdrUL       uint16
		pdrDL       uint16
		farUL       uint32
		farDL       uint32
		sgwUS1UFTEID bearer.FTEID // SGW-U allocated S1-U TEID (from Created PDR)
		sgwUS5UFTEID bearer.FTEID // SGW-U allocated S5/8-U TEID (from Created PDR)
	}

	var bearerProvs []bearerProvisioning
	for _, bcIE := range cbReq.BearerContexts {
		children, cErr := bcIE.ChildIEs()
		if cErr != nil {
			continue
		}
		var prov bearerProvisioning
		prov.qosIE = ie.FindFirst(children, ie.TypeBearerQoS)
		prov.tftIE = ie.FindFirst(children, ie.TypeBearerTFT)
		if pgwUFTEID := ie.FindInstance(children, ie.TypeFTEID, 1); pgwUFTEID != nil {
			if f, fErr := pgwUFTEID.FTEIDValue(); fErr == nil {
				prov.pgwUS5UFTEID = bearer.FTEID{TEID: f.TEID, IPv4: f.IPv4}
			}
		}
		prov.pdrUL, prov.pdrDL, prov.farUL, prov.farDL = sess.AllocBearerRuleIDs()
		bearerProvs = append(bearerProvs, prov)
	}

	if len(bearerProvs) == 0 {
		h.log.Warn("S5C: Create Bearer — no valid Bearer Contexts", "session_id", sess.SessionID)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse,
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

	createdPDRs, pfcpErr := h.pfcp.AddBearerRules(context.Background(),
		sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID,
		createPDRs, createFARs)
	if pfcpErr != nil {
		h.log.Error("S5C: Create Bearer PFCP provisioning failed",
			"session_id", sess.SessionID, "error", pfcpErr)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse,
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
		if prov.pgwUS5UFTEID.TEID != 0 {
			// S5/8-U PGW F-TEID: instance 1 per Table 7.2.3-2.
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

	s11Seq := h.conn.AllocSeq()
	s11CBReqRaw, err := message.MarshalCreateBearerRequest(sess.MMEControlFTEID.TEID, s11Seq, s11CBReqIEs...)
	if err != nil {
		h.log.Error("S5C: Create Bearer — marshal S11 CBReq failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	// Determine MME address from session state.
	mmeIP4 := sess.MMEControlFTEID.IPv4.As4()
	mmeAddr := &net.UDPAddr{IP: mmeIP4[:], Port: 2123}

	s11CBRespRaw, err := h.conn.Send(context.Background(), mmeAddr, s11CBReqRaw)
	if err != nil {
		h.log.Error("S5C: Create Bearer — Send S11 CBReq to MME failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	cbResp, err := message.ParseCreateBearerResponse(s11CBRespRaw)
	if err != nil {
		h.log.Error("S5C: Create Bearer — parse S11 CBResp failed", "error", err)
		h.replyBearerError(pgwAddr, hdr, message.MsgTypeCreateBearerResponse,
			sess.PGWControlFTEID.TEID, ie.CauseSystemFailure)
		return
	}

	msgCause, _ := cbResp.Cause.CauseValue()

	// Process each Bearer Context in CBResp from MME.
	// Per Table 7.2.4-2 (S11):
	//   EBI (inst=0): M — actual EBI assigned by MME
	//   Cause (inst=0): M
	//   S1-U eNodeB F-TEID (inst=0): C — eNB's S1-U endpoint
	//   S1-U SGW F-TEID (inst=1): C — echoed back for correlation
	var s5cBCIEs []*ie.IE
	for _, bcIE := range cbResp.BearerContexts {
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
			// Bearer rejected: relay rejection, skip PFCP update.
			s5cBCIEs = append(s5cBCIEs, ie.NewBearerContext(0,
				ie.NewEBI(ebi),
				ie.NewCause(bcCause, 0, 0, 0, nil),
			))
			continue
		}

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

		// Update PFCP DL FAR with eNB TEID.
		if matchedProv != nil && enbFTEID.TEID != 0 && sess.PFCP.Established {
			pfcpModErr := h.pfcp.ModifySession(context.Background(),
				sess.PFCP.LocalFSEID.SEID, sess.PFCP.SGWUFSEID.SEID,
				[]pfcpclient.FARUpdate{{
					FARID:         matchedProv.farDL,
					ApplyAction:   pfcpie.ApplyActionFORW,
					DestInterface: pfcpie.DestInterfaceAccess,
					OuterTEID:     enbFTEID.TEID,
					OuterIP:       enbFTEID.IPv4,
				}},
			)
			if pfcpModErr != nil {
				h.log.Warn("S5C: Create Bearer — PFCP DL FAR update failed",
					"session_id", sess.SessionID, "ebi", ebi, "error", pfcpModErr)
			}

			// Store bearer state.
			newBearer := &bearer.Bearer{
				EBI:          ebi,
				ENBS1UFTEID:  enbFTEID,
				State:        bearer.BearerStateActive,
				PDRIDs:       [2]uint32{uint32(matchedProv.pdrUL), uint32(matchedProv.pdrDL)},
				FARIDs:       [2]uint32{matchedProv.farUL, matchedProv.farDL},
				SGWS1UFTEID:  matchedProv.sgwUS1UFTEID,
				SGWS5UFTEID:  matchedProv.sgwUS5UFTEID,
				PGWS5UFTEID:  matchedProv.pgwUS5UFTEID,
			}
			if matchedProv.qosIE != nil {
				// Decode QoS per §8.15.
				v := matchedProv.qosIE.Value
				if len(v) >= 2 {
					newBearer.ARP = bearer.ARP{
						PriorityLevel:        (v[0] >> 2) & 0x0F,
						PreemptionCapability: v[0]&0x40 != 0,
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

		// Build the BC IE for S5/S8-C CBResp.
		// Per Table 7.2.4-2 (S5/S8-C direction SGW-C→PGW):
		//   EBI (inst=0): M
		//   Cause (inst=0): M
		//   S5/8-U SGW F-TEID (inst=2): C — SGW-U's S5/8-U endpoint
		bcRespChildren := []*ie.IE{
			ie.NewEBI(ebi),
			ie.NewCause(bcCause, 0, 0, 0, nil),
		}
		if matchedProv != nil && matchedProv.sgwUS5UFTEID.TEID != 0 {
			bcRespChildren = append(bcRespChildren,
				ie.NewFTEID(2, ie.IFTypeS5S8USGW,
					matchedProv.sgwUS5UFTEID.TEID, matchedProv.sgwUS5UFTEID.IPv4))
		}
		s5cBCIEs = append(s5cBCIEs, ie.NewBearerContext(0, bcRespChildren...))
	}

	// Build S5/S8-C CBResp per Table 7.2.4-1 and relay to PGW.
	// Response TEID = PGW's S5/S8-C control TEID per C4.
	s5cRespIEs := make([]*ie.IE, 0, 1+len(s5cBCIEs))
	s5cRespIEs = append(s5cRespIEs, ie.NewCause(msgCause, 0, 0, 0, nil))
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

	h.log.Info("S5C: Create Bearer completed",
		"session_id", sess.SessionID, "msg_cause", msgCause, "bearers", len(s5cBCIEs))
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
					PriorityLevel:        (qosIE.Value[0] >> 2) & 0x0F,
					PreemptionCapability: qosIE.Value[0]&0x40 != 0,
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

	if msgCause == ie.CauseRequestAccepted {
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
				if pfcpErr := h.pfcp.RemoveBearerRules(context.Background(),
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

// replyBearerError sends a minimal error response back to the PGW for a bearer procedure.
// peerTEID is the PGW's S5/S8-C control TEID (response TEID per C4); 0 if unknown.
func (h *Handler) replyBearerError(pgwAddr *net.UDPAddr, hdr message.Header, respType uint8, peerTEID uint32, cause uint8) {
	respHdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    respType,
		TEID:           peerTEID,
		SequenceNumber: hdr.SequenceNumber,
	}
	raw, err := message.Marshal(respHdr, []*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)})
	if err != nil {
		h.log.Error("S5C: bearer error response marshal failed", "error", err)
		return
	}
	if err := h.s5c.ReplyToPGW(pgwAddr, raw); err != nil {
		h.log.Warn("S5C: bearer error response send failed", "error", err)
	}
}

