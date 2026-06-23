// Package pfcpserver handles PFCP messages (Association Setup, Heartbeat, and
// Session Establishment/Modification/Deletion) on the SGW-U per TS 29.244 Rel-15.
//
// The server:
//   - Listens for Association Setup Requests from allowed SGW-C peers (§7.4.1/§7.4.2)
//   - Responds to Heartbeat Requests (§7.2.2/§7.2.3)
//   - Handles Session Establishment Requests (§7.5.2): allocates TEIDs via CHOOSE bit,
//     stores PDRs and FARs, returns Created PDRs with allocated TEIDs
//   - Handles Session Modification Requests (§7.5.4): updates FAR forwarding actions
//   - Handles Session Deletion Requests (§7.5.6): removes session state
//   - Tracks SGW-C peer state and detects restarts via Recovery Time Stamp changes
//   - Filters inbound traffic by allowed_sgwc ACL from config
package pfcpserver

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	sgwuconfig "vectorcore-sgw/internal/config/sgwu"
	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	pfcpmsg "vectorcore-sgw/internal/pfcp/message"
	pfcptransport "vectorcore-sgw/internal/pfcp/transport"
	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

// EndMarkerSender is implemented by the GTP-U forwarder to send an End Marker
// to a downstream peer (e.g., eNB) on tunnel switch per TS 29.281 §7.3.2.
// R15-REAUDIT-009: the PFCP server calls this when a FAR outer header creation
// changes (indicating a handover), so the old eNB receives an End Marker.
type EndMarkerSender interface {
	SendEndMarker(teid uint32, dstIP netip.Addr)
}

// BPFRuleInstaller is implemented by the TC-BPF dataplane to install, update,
// and remove GTP-U forwarding rules derived from PFCP PDR/FAR state (Phase 7).
// Called after session establishment, modification, and deletion.
type BPFRuleInstaller interface {
	InstallSession(sess *sgwusession.Session) error
	UpdateSession(sess *sgwusession.Session) error
	RemoveSession(sess *sgwusession.Session) error
}

// ntpEpochOffset is the seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01)
// per TS 29.244 Rel-15 §8.2.11.
const ntpEpochOffset uint32 = 2208988800

// PeerRecord tracks a known SGW-C peer's state on the SGW-U.
// Keyed by Node ID (per TS 29.244 §8.2.8), not UDP source address, because the
// Node ID is the stable peer identity — the UDP source address can change.
type PeerRecord struct {
	mu         sync.RWMutex
	nodeIDKey  string // canonical peer identity from Node ID IE
	recoveryTS uint32
	lastSeen   time.Time
	lastAddr   *net.UDPAddr // last known UDP address for outbound Node Report Requests
}

// Server listens for PFCP messages from SGW-C peers on the SGW-U.
type Server struct {
	conn        *pfcptransport.Conn
	localNodeID net.IP
	localIP     netip.Addr // SGW-U GTP-U data-plane IP (used in Created PDR F-TEID)
	localTS     uint32     // NTP timestamp when this process started (Recovery Time Stamp)
	allowedNets []*net.IPNet
	peers       sync.Map         // nodeIDKey string → *PeerRecord (keyed by Node ID per §8.2.8)
	sessions    *sgwusession.Store
	log         *slog.Logger
	emSender    EndMarkerSender // optional; wired after both server and forwarder are created
	bpfInstall  BPFRuleInstaller // optional; wired when TC-BPF dataplane is active (Phase 7)
}

// SetEndMarkerSender wires the GTP-U forwarder so that PFCP-triggered tunnel
// switches (FAR outer header changes) result in End Markers being sent to the
// old downstream peer per TS 29.281 §7.3.2 and R15-REAUDIT-009.
func (s *Server) SetEndMarkerSender(sender EndMarkerSender) {
	s.emSender = sender
}

// SetBPFInstaller wires the TC-BPF rule compiler so that PFCP session events
// are reflected in the kernel BPF forwarding maps (Phase 7).
func (s *Server) SetBPFInstaller(installer BPFRuleInstaller) {
	s.bpfInstall = installer
}

// New creates an SGW-U PFCP server ready to serve.
// startTime is used as the Recovery Time Stamp in all outbound messages.
func New(cfg *sgwuconfig.Config, startTime time.Time, log *slog.Logger) (*Server, error) {
	conn, err := pfcptransport.Listen(cfg.PFCP.Listen, 5, 3, log)
	if err != nil {
		return nil, fmt.Errorf("PFCP server listen %s: %w", cfg.PFCP.Listen, err)
	}

	localIP, err := extractIPv4(cfg.PFCP.Listen)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("PFCP server: derive Node ID from %q: %w", cfg.PFCP.Listen, err)
	}

	// Build allowlist from allowed_sgwc entries (plain IPs or CIDRs).
	var allowedNets []*net.IPNet
	for _, entry := range cfg.PFCP.AllowedSGWC {
		if _, ipnet, parseErr := net.ParseCIDR(entry); parseErr == nil {
			allowedNets = append(allowedNets, ipnet)
		} else if ip := net.ParseIP(entry); ip != nil {
			mask := net.CIDRMask(32, 32)
			allowedNets = append(allowedNets, &net.IPNet{IP: ip.Mask(mask), Mask: mask})
		} else {
			_ = conn.Close()
			return nil, fmt.Errorf("PFCP server: invalid allowed_sgwc entry %q", entry)
		}
	}

	localNetipAddr := netip.AddrFrom4([4]byte(localIP))

	s := &Server{
		conn:        conn,
		localNodeID: localIP,
		localIP:     localNetipAddr,
		localTS:     uint32(startTime.Unix()) + ntpEpochOffset,
		allowedNets: allowedNets,
		sessions:    sgwusession.NewStore(),
		log:         log,
	}
	s.conn.SetHandler(s.handle)
	return s, nil
}

// Serve starts the PFCP inbound read loop. Blocks until ctx is cancelled.
func (s *Server) Serve(ctx context.Context) error {
	s.log.Info("PFCP server listening", "addr", s.conn.LocalAddr())
	return s.conn.Serve(ctx)
}

// Close shuts down the server transport.
func (s *Server) Close() error {
	return s.conn.Close()
}

// SessionStore returns the PFCP session store shared with the GTP-U forwarder.
// Phase 6: the forwarder reads PDR/FAR state to resolve TEIDs and forwarding actions.
func (s *Server) SessionStore() *sgwusession.Store {
	return s.sessions
}

func (s *Server) handle(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	if !s.isAllowed(addr.IP) {
		s.log.Warn("PFCP request from disallowed source — dropped", "from", addr)
		return
	}
	switch hdr.MessageType {
	case pfcpmsg.MsgTypeAssociationSetupRequest:
		s.handleAssocSetup(conn, addr, hdr, raw)
	case pfcpmsg.MsgTypeHeartbeatRequest:
		s.handleHeartbeat(conn, addr, hdr, raw)
	case pfcpmsg.MsgTypeSessionEstablishmentRequest:
		s.handleSessionEstablishment(conn, addr, hdr, raw)
	case pfcpmsg.MsgTypeSessionModificationRequest:
		s.handleSessionModification(conn, addr, hdr, raw)
	case pfcpmsg.MsgTypeSessionDeletionRequest:
		s.handleSessionDeletion(conn, addr, hdr, raw)
	case pfcpmsg.MsgTypeAssociationReleaseRequest:
		s.handleAssociationRelease(conn, addr, hdr, raw)
	default:
		s.log.Warn("PFCP unhandled message type", "from", addr, "type", hdr.MessageType)
	}
}

// nodeIDKey returns a canonical string key for a Node ID IE per TS 29.244 §8.2.8.
// The Node ID is the stable peer identity per the spec; the UDP source address
// is not reliable as a peer identity.
func nodeIDKey(nodeID *pfcpie.IE) string {
	if nodeID == nil {
		return ""
	}
	if ip := nodeID.NodeIDIPv4(); ip != nil {
		return "ipv4:" + ip.String()
	}
	return ""
}

// handleAssocSetup processes an Association Setup Request per TS 29.244 §5.2.1/§7.4.1.
func (s *Server) handleAssocSetup(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	req, err := pfcpmsg.ParseAssociationSetupRequest(raw)
	if err != nil {
		s.log.Warn("PFCP AssociationSetupRequest parse error", "from", addr, "error", err)
		// Gap 4: send rejection response with RequestRejected cause per TS 29.244 §7.4.1.
		rejHdr := pfcpmsg.Header{
			Version:        1,
			MessageType:    pfcpmsg.MsgTypeAssociationSetupResponse,
			SequenceNumber: hdr.SequenceNumber,
		}
		rejRaw, marshalErr := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{
			pfcpie.NewNodeIDIPv4(s.localNodeID),
			pfcpie.NewCause(pfcpie.CauseRequestRejected),
			pfcpie.NewRecoveryTimeStamp(s.localTS),
		})
		if marshalErr == nil {
			conn.Reply(addr, rejRaw) //nolint:errcheck
		}
		return
	}

	peerTS, _ := req.RecoveryTimeStamp.RecoveryTimeStampValue()
	// Key by Node ID IE per TS 29.244 §8.2.8 — the stable peer identity.
	peerKey := nodeIDKey(req.NodeID)
	if peerKey == "" {
		// Node ID parsed but type unsupported (e.g., FQDN); fall back to addr.
		peerKey = "addr:" + addr.String()
	}

	if v, ok := s.peers.Load(peerKey); ok {
		pr := v.(*PeerRecord)
		pr.mu.Lock()
		// Restart detection per TS 29.244 §5.2.1.
		if pr.recoveryTS != 0 && peerTS != pr.recoveryTS {
			s.log.Warn("PFCP SGW-C peer restarted",
				"from", addr, "node_id", peerKey, "old_ts", pr.recoveryTS, "new_ts", peerTS)
		}
		pr.recoveryTS = peerTS
		pr.lastSeen = time.Now()
		pr.lastAddr = addr
		pr.mu.Unlock()
	} else {
		s.peers.Store(peerKey, &PeerRecord{
			nodeIDKey:  peerKey,
			recoveryTS: peerTS,
			lastSeen:   time.Now(),
			lastAddr:   addr,
		})
	}

	s.log.Info("PFCP association established with SGW-C", "from", addr)

	// R15-007 FIX: advertise FTUP in UP Function Features IE per TS 29.244 §5.5.1 / §6.2.6.2.2:
	// "shall send an PFCP Association Setup Response with a successful cause, its Node ID, and
	// information of all supported optional features in the UP function".
	// Table 8.2.25-1: "5/5, FTUP" = 0x10 — F-TEID allocation in UP function supported.
	// Build Association Setup Response per Table 7.4.2-1: Node ID (M), Cause (M), Recovery TS (M),
	// UP Function Features (CO — included per §6.2.6.2.2 to advertise FTUP).
	respHdr := pfcpmsg.Header{
		Version:        1,
		MessageType:    pfcpmsg.MsgTypeAssociationSetupResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respRaw, err := pfcpmsg.Marshal(respHdr, []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(s.localNodeID),
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
		pfcpie.NewRecoveryTimeStamp(s.localTS),
		pfcpie.NewUPFunctionFeatures(pfcpie.UPFunctionFeaturesFTUP),
	})
	if err != nil {
		s.log.Error("PFCP marshal AssociationSetupResponse failed", "error", err)
		return
	}
	if err := conn.Reply(addr, respRaw); err != nil {
		s.log.Warn("PFCP send AssociationSetupResponse failed", "to", addr, "error", err)
	}
}

// handleHeartbeat processes a Heartbeat Request per TS 29.244 §6.1/§7.2.2.
func (s *Server) handleHeartbeat(conn *pfcptransport.Conn, addr *net.UDPAddr, _ pfcpmsg.Header, raw []byte) {
	req, err := pfcpmsg.ParseHeartbeatRequest(raw)
	if err != nil {
		// ParseHeartbeatRequest enforces Recovery TS as M; error means malformed.
		s.log.Warn("PFCP HeartbeatRequest parse error", "from", addr, "error", err)
		return
	}

	// Update peer state and detect restarts via Recovery TS.
	// Recovery TS is M per TS 29.244 §7.4.2 so req.RecoveryTimeStamp is always non-nil here.
	peerTS, _ := req.RecoveryTimeStamp.RecoveryTimeStampValue()
	// R15-010 FIX: associations are keyed by "ipv4:<ip>" (set during AssocSetup via nodeIDKey()).
	// Heartbeat must use the same key so restart detection can find the peer record.
	// Heartbeat does not carry a Node ID IE, so we derive the key from the source address.
	heartbeatKey := "ipv4:" + addr.IP.String()
	if v, ok := s.peers.Load(heartbeatKey); ok {
		pr := v.(*PeerRecord)
		pr.mu.Lock()
		if pr.recoveryTS != 0 && peerTS != pr.recoveryTS {
			// R15-010: peer restarted — mark sessions from this peer as stale.
			// Session reconciliation: delete all sessions for this CP peer so stale
			// forwarding state does not persist after restart.
			s.log.Warn("PFCP SGW-C restarted (detected via heartbeat) — invalidating sessions",
				"from", addr, "old_ts", pr.recoveryTS, "new_ts", peerTS)
			// AUD-02: collect deleted sessions and remove their BPF rules so the
			// fast path does not keep forwarding for stale sessions after CP restart.
			deleted := s.sessions.DeleteByCPNodeKey(heartbeatKey)
			if s.bpfInstall != nil {
				for _, sess := range deleted {
					if bpfErr := s.bpfInstall.RemoveSession(sess); bpfErr != nil {
						s.log.Error("BPF cleanup failed for restarted peer session",
							"cp_seid", sess.CPSEID, "error", bpfErr)
					}
				}
			}
		}
		pr.recoveryTS = peerTS
		pr.lastSeen = time.Now()
		pr.mu.Unlock()
	}

	// Build Heartbeat Response per Table 7.4.3.2-1: Recovery TS is M per TS 29.244 §7.4.2.
	respHdr := pfcpmsg.Header{
		Version:        1,
		MessageType:    pfcpmsg.MsgTypeHeartbeatResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respRaw, err := pfcpmsg.Marshal(respHdr, []*pfcpie.IE{
		pfcpie.NewRecoveryTimeStamp(s.localTS),
	})
	if err != nil {
		s.log.Error("PFCP marshal HeartbeatResponse failed", "error", err)
		return
	}
	if err := conn.Reply(addr, respRaw); err != nil {
		s.log.Warn("PFCP send HeartbeatResponse failed", "to", addr, "error", err)
	}
}

// hasAssociation returns true if the source address has an established PFCP association.
// Per TS 29.244 §6.2.6 / §6.3: "The CP function shall only initiate PFCP Session related
// signalling procedures toward a UP function after it has sent the PFCP Association Setup
// Response with a successful cause." R15-009 fix.
func (s *Server) hasAssociation(addr *net.UDPAddr) bool {
	key := "ipv4:" + addr.IP.String()
	_, ok := s.peers.Load(key)
	return ok
}

// handleSessionEstablishment processes a PFCP Session Establishment Request
// per TS 29.244 Rel-15 §7.5.2 / Table 7.5.2.2-1.
//
// For each Create PDR whose F-TEID carries CH=1 (CHOOSE), the SGW-U allocates a
// local TEID and returns it in a Created PDR IE per Table 7.5.3.1-1.
// The SGW-U allocates a UP-SEID and includes it in the UP F-SEID IE (M on success).
func (s *Server) handleSessionEstablishment(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	// R15-009 FIX: reject session signalling without an established PFCP association.
	// Per TS 29.244 §6.2.6: association must be established before session procedures.
	// Cause 72 = "No established PFCP Association" per Table 8.2.1-1.
	if !s.hasAssociation(addr) {
		s.log.Warn("PFCP SER: no established association — rejecting", "from", addr)
		s.replySessionEstNoAssoc(conn, addr, hdr)
		return
	}

	req, err := pfcpmsg.ParseSessionEstablishmentRequest(raw)
	if err != nil {
		s.log.Warn("PFCP SessionEstablishmentRequest parse error", "from", addr, "error", err)
		s.replySessionEstRejection(conn, addr, hdr)
		return
	}

	// Extract CP-SEID from the CP F-SEID IE (M per Table 7.5.2.2-1).
	cpFSEID, err := req.CPSEID.FSEIDValue()
	if err != nil {
		s.log.Warn("PFCP SER: invalid CP F-SEID IE", "from", addr, "error", err)
		s.replySessionEstRejection(conn, addr, hdr)
		return
	}

	// Allocate a new UP-SEID for this session.
	upSEID := s.sessions.AllocSEID()

	// R15-003 FIX: validate ALL PDRs and FARs before allocating any resources.
	// Per TS 29.244 §6.3.2.3: "if at least one rule failed to be stored or applied,
	// return an appropriate error cause value with the Rule ID of the Rule causing the
	// first error, discard all the received rules and not create any PFCP session context."
	// Validation pass — no side effects (no TEID allocation, no session creation).
	for _, cpdrIE := range req.CreatePDRs {
		children, cErr := cpdrIE.Children()
		if cErr != nil {
			s.log.Warn("PFCP SER: Create PDR children parse error — rejecting whole request", "error", cErr)
			s.replySessionEstRejection(conn, addr, hdr)
			return
		}
		// R15-REAUDIT-012: FAR ID in Create PDR is C per Table 7.5.2.2-1:
		// "This IE shall be present if the Activate Predefined Rules IE is not included
		// or if it is included but it does not result in activating a predefined FAR."
		// (docs/specs/29244-fa0.docx, Table row extracted)
		// Since this implementation does not support predefined rules, FAR ID is functionally
		// required — reject if both FAR ID and Activate Predefined Rules are absent.
		hasFARID := pfcpie.Find(children, pfcpie.TypeFARID) != nil
		hasActivatePredefined := pfcpie.Find(children, pfcpie.TypeActivatePredefinedRules) != nil
		if pfcpie.Find(children, pfcpie.TypePDRID) == nil ||
			pfcpie.Find(children, pfcpie.TypePrecedence) == nil ||
			pfcpie.Find(children, pfcpie.TypePDI) == nil {
			s.log.Warn("PFCP SER: Create PDR missing mandatory child IE (PDR ID/Precedence/PDI) — rejecting whole request")
			s.replySessionEstRuleFailure(conn, addr, hdr)
			return
		}
		if !hasFARID && !hasActivatePredefined {
			s.log.Warn("PFCP SER: Create PDR missing FAR ID and no Activate Predefined Rules — rejecting")
			s.replySessionEstRuleFailure(conn, addr, hdr)
			return
		}
		pdiIE := pfcpie.Find(children, pfcpie.TypePDI)
		pdiChildren, pdiErr := pdiIE.Children()
		if pdiErr != nil || pfcpie.Find(pdiChildren, pfcpie.TypeSourceInterface) == nil {
			s.log.Warn("PFCP SER: PDI missing mandatory Source Interface IE — rejecting whole request")
			s.replySessionEstRuleFailure(conn, addr, hdr)
			return
		}
	}
	for _, cfarIE := range req.CreateFARs {
		children, cErr := cfarIE.Children()
		if cErr != nil {
			s.log.Warn("PFCP SER: Create FAR children parse error — rejecting whole request", "error", cErr)
			s.replySessionEstRejection(conn, addr, hdr)
			return
		}
		// FAR ID: M per Table 7.5.2.2-2 (identifies the FAR being created).
		// Apply Action: M per Table 7.5.2.2-2.
		if pfcpie.Find(children, pfcpie.TypeFARID) == nil ||
			pfcpie.Find(children, pfcpie.TypeApplyAction) == nil {
			s.log.Warn("PFCP SER: Create FAR missing mandatory child IE (FAR ID/Apply Action) — rejecting whole request")
			s.replySessionEstRuleFailure(conn, addr, hdr)
			return
		}
		// R15-REAUDIT-005: Forwarding Parameters: C per Table 7.5.2.3-1:
		// "This IE shall be present when the Apply Action requests the packets to be forwarded."
		// Within Forwarding Parameters, Destination Interface: M per Table 7.5.2.3-1:
		// "This IE shall identify the destination interface of the outgoing packet."
		aaIE := pfcpie.Find(children, pfcpie.TypeApplyAction)
		aa, _ := aaIE.ApplyActionValue()
		if aa&pfcpie.ApplyActionFORW != 0 {
			fpIE := pfcpie.Find(children, pfcpie.TypeForwardingParameters)
			if fpIE == nil {
				s.log.Warn("PFCP SER: Create FAR with FORW action missing mandatory ForwardingParameters IE — rejecting")
				s.replySessionEstRuleFailure(conn, addr, hdr)
				return
			}
			fpChildren, fpErr := fpIE.Children()
			if fpErr != nil || pfcpie.Find(fpChildren, pfcpie.TypeDestinationInterface) == nil {
				s.log.Warn("PFCP SER: Create FAR ForwardingParameters missing mandatory Destination Interface IE — rejecting")
				s.replySessionEstRuleFailure(conn, addr, hdr)
				return
			}
		}
	}

	// All rules validated. Now allocate resources and build session.
	// Per §6.3.2.3: commit only after all rules pass.
	var pdrs []sgwusession.PDR
	var createdPDRIEs []*pfcpie.IE

	for _, cpdrIE := range req.CreatePDRs {
		children, _ := cpdrIE.Children() // already validated above
		pdrIDIE := pfcpie.Find(children, pfcpie.TypePDRID)
		precIE := pfcpie.Find(children, pfcpie.TypePrecedence)
		farIDIE := pfcpie.Find(children, pfcpie.TypeFARID)
		pdiIE := pfcpie.Find(children, pfcpie.TypePDI)

		pdrID, _ := pdrIDIE.PDRIDValue()
		farID, _ := farIDIE.FARIDValue()

		pdiChildren, _ := pdiIE.Children()
		srcIfaceIE := pfcpie.Find(pdiChildren, pfcpie.TypeSourceInterface)
		srcIface, _ := srcIfaceIE.SourceInterfaceValue() // non-nil, validated above

		pdr := sgwusession.PDR{
			ID:              pdrID,
			SourceInterface: srcIface,
			FARID:           farID,
		}
		if precIE != nil && len(precIE.Value) >= 4 {
			pdr.Precedence = (uint32(precIE.Value[0]) << 24) | (uint32(precIE.Value[1]) << 16) |
				(uint32(precIE.Value[2]) << 8) | uint32(precIE.Value[3])
		}

		// Check for F-TEID with CHOOSE bit in PDI per §8.2.3.
		fteidIE := pfcpie.Find(pdiChildren, pfcpie.TypeFTEID)
		if fteidIE != nil {
			_, isCH, fteidErr := fteidIE.FTEIDPFCPValue()
			if fteidErr != nil {
				// R15-REAUDIT-011: FTEIDPFCPValue() returns an error when CH=1 but neither
				// V4 nor V6 is set (§8.2.3). Reject the whole request — no partial allocation.
				s.log.Warn("PFCP SER: Create PDR F-TEID invalid (e.g. CH=1 without V4/V6) — rejecting whole request",
					"error", fteidErr)
				s.replySessionEstRuleFailure(conn, addr, hdr)
				return
			}
			if isCH {
				// Allocate a TEID for this PDR's GTP-U receive endpoint.
				allocTEID := s.sessions.AllocTEID()
				pdr.LocalTEID = allocTEID
				pdr.LocalIP = s.localIP

				// Build Created PDR IE: PDR ID (M) + F-TEID (C: allocated TEID+IP).
				createdPDRIEs = append(createdPDRIEs,
					pfcpie.NewCreatedPDR(
						pfcpie.NewPDRID(pdrID),
						pfcpie.NewFTEIDv4(allocTEID, s.localIP),
					),
				)
			}
		}
		pdrs = append(pdrs, pdr)
	}

	// Decode Create FAR IEs into in-memory FAR structs.
	var fars []sgwusession.FAR
	for _, cfarIE := range req.CreateFARs {
		children, _ := cfarIE.Children() // already validated above
		farIDIE := pfcpie.Find(children, pfcpie.TypeFARID)
		aaIE := pfcpie.Find(children, pfcpie.TypeApplyAction)

		farID, _ := farIDIE.FARIDValue()
		applyAction, _ := aaIE.ApplyActionValue()

		far := sgwusession.FAR{
			ID:          farID,
			ApplyAction: applyAction,
		}

		// Extract Forwarding Parameters if FORW is set per §7.5.2.4.
		fwdParamsIE := pfcpie.Find(children, pfcpie.TypeForwardingParameters)
		if fwdParamsIE != nil && (applyAction&pfcpie.ApplyActionFORW != 0) {
			fpChildren, fpErr := fwdParamsIE.Children()
			if fpErr == nil {
				dstIfaceIE := pfcpie.Find(fpChildren, pfcpie.TypeDestinationInterface)
				ohcIE := pfcpie.Find(fpChildren, pfcpie.TypeOuterHeaderCreation)
				if dstIfaceIE != nil {
					far.DestInterface, _ = dstIfaceIE.DestinationInterfaceValue()
				}
				if ohcIE != nil {
					ohc, ohcErr := ohcIE.OuterHeaderCreationValue()
					if ohcErr == nil {
						far.OuterTEID = ohc.TEID
						far.OuterIP = ohc.IPv4
					}
				}
			}
		}
		fars = append(fars, far)
	}

	// Store the session.
	sess := &sgwusession.Session{
		CPSEID:    cpFSEID.SEID,
		UPSEID:    upSEID,
		PDRs:      pdrs,
		FARs:      fars,
		CPNodeKey: "ipv4:" + addr.IP.String(), // R15-010: track CP node for restart reconciliation
	}
	if storeErr := s.sessions.Create(sess); storeErr != nil {
		s.log.Warn("PFCP SER: session store failed", "cp_seid", cpFSEID.SEID, "error", storeErr)
		s.replySessionEstRejection(conn, addr, hdr)
		return
	}

	// Phase 7: install BPF forwarding rules for all allocated TEIDs in this session.
	// AUD-01: BPF failure is fatal for SER — roll back the session and reject the request.
	// Per TS 29.244 §6.3.2.3: if a rule cannot be applied, return an error cause and
	// discard all received rules; do not create the PFCP session context.
	if s.bpfInstall != nil {
		if bpfErr := s.bpfInstall.InstallSession(sess); bpfErr != nil {
			s.log.Error("BPF rule install failed — rolling back session and rejecting SER",
				"cp_seid", cpFSEID.SEID, "error", bpfErr)
			s.sessions.DeleteByCPSEID(cpFSEID.SEID)
			s.replySessionEstRuleFailure(conn, addr, hdr)
			return
		}
	}

	s.log.Info("PFCP session established",
		"from", addr,
		"cp_seid", cpFSEID.SEID,
		"up_seid", upSEID,
		"pdrs", len(pdrs),
		"fars", len(fars),
	)

	// Build Session Establishment Response per Table 7.5.3.1-1.
	// M-IEs: Node ID, Cause, UP F-SEID (C on success per Table 7.5.3.1-1).
	// C-IEs: Created PDR (present when CHOOSE was set in Create PDR F-TEID).
	upFSEID := pfcpie.NewFSEID(upSEID, s.localIP)
	respIEs := []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(s.localNodeID),
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
		upFSEID,
	}
	respIEs = append(respIEs, createdPDRIEs...)

	// Session-level response: SEID = CP-SEID (so SGW-C can correlate the response).
	respHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           cpFSEID.SEID,
		MessageType:    pfcpmsg.MsgTypeSessionEstablishmentResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respRaw, err := pfcpmsg.Marshal(respHdr, respIEs)
	if err != nil {
		s.log.Error("PFCP marshal SessionEstablishmentResponse failed", "error", err)
		return
	}
	if err := conn.Reply(addr, respRaw); err != nil {
		s.log.Warn("PFCP send SessionEstablishmentResponse failed", "to", addr, "error", err)
	}
}

// replySessionEstRejection sends a Session Establishment Response with RequestRejected cause.
func (s *Server) replySessionEstRejection(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header) {
	rejHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0,
		MessageType:    pfcpmsg.MsgTypeSessionEstablishmentResponse,
		SequenceNumber: hdr.SequenceNumber,
	}
	raw, err := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(s.localNodeID),
		pfcpie.NewCause(pfcpie.CauseRequestRejected),
	})
	if err == nil {
		conn.Reply(addr, raw) //nolint:errcheck
	}
}

// replySessionEstNoAssoc sends a Session Establishment Response with Cause=72
// "No established PFCP Association" per TS 29.244 Table 8.2.1-1.
// R15-009: session signalling arrived before PFCP association was established.
func (s *Server) replySessionEstNoAssoc(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header) {
	rejHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0,
		MessageType:    pfcpmsg.MsgTypeSessionEstablishmentResponse,
		SequenceNumber: hdr.SequenceNumber,
	}
	raw, err := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(s.localNodeID),
		pfcpie.NewCause(pfcpie.CauseNoEstablishedAssociation),
	})
	if err == nil {
		conn.Reply(addr, raw) //nolint:errcheck
	}
}

// replySessionEstRuleFailure sends a Session Establishment Response with Cause=73
// "Rule creation/modification Failure" per TS 29.244 Table 8.2.1-1.
// R15-003: a Create PDR or FAR failed mandatory IE validation; the whole request
// is rejected and no session or TEID allocations are committed.
func (s *Server) replySessionEstRuleFailure(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header) {
	rejHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0,
		MessageType:    pfcpmsg.MsgTypeSessionEstablishmentResponse,
		SequenceNumber: hdr.SequenceNumber,
	}
	raw, err := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(s.localNodeID),
		pfcpie.NewCause(pfcpie.CauseRuleCreationFailure),
	})
	if err == nil {
		conn.Reply(addr, raw) //nolint:errcheck
	}
}

// handleSessionModification processes a PFCP Session Modification Request
// per TS 29.244 Rel-15 §7.5.4 / Table 7.5.4.1-1.
//
// The primary use is updating the Core→Access FAR after the SGW-C receives an
// eNB TEID via Modify Bearer Request. The FAR's Apply Action changes from DROP to
// FORW and the Outer Header Creation is populated with the eNB TEID.
func (s *Server) handleSessionModification(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	// R15-009 FIX: reject session signalling without an established PFCP association.
	// Per TS 29.244 §6.3: sessions must be bound to an established association.
	// Use header sequence number here — request hasn't been parsed yet.
	if !s.hasAssociation(addr) {
		s.log.Warn("PFCP SMR: no established association — rejecting", "from", addr)
		rejHdr := pfcpmsg.Header{
			Version:        1,
			HasSEID:        true,
			SEID:           0,
			MessageType:    pfcpmsg.MsgTypeSessionModificationResponse,
			SequenceNumber: hdr.SequenceNumber,
		}
		if raw2, err := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseNoEstablishedAssociation)}); err == nil {
			conn.Reply(addr, raw2) //nolint:errcheck
		}
		return
	}

	req, err := pfcpmsg.ParseSessionModificationRequest(raw)
	if err != nil {
		s.log.Warn("PFCP SessionModificationRequest parse error", "from", addr, "error", err)
		return
	}

	// The session is identified by the SEID in the message header (= UP-SEID).
	sess := s.sessions.FindByUPSEID(req.SEID)
	if sess == nil {
		s.log.Warn("PFCP SMR: session not found", "up_seid", req.SEID)
		s.replySessionModRejection(conn, addr, req)
		return
	}

	// R15-004 FIX: validate ALL Update FARs before applying any.
	// Per TS 29.244 §6.3.3.3: "reject a modification request which would relate to a
	// rule not existing in the UP function; discard any updates on the PFCP session context."
	// Validation pass — no mutation of session state.
	type parsedFARUpdate struct {
		farID       uint32
		applyAction *pfcpie.IE
		ufpIE       *pfcpie.IE
	}
	var updates []parsedFARUpdate
	for _, ufarIE := range req.UpdateFARs {
		children, cErr := ufarIE.Children()
		if cErr != nil {
			s.log.Warn("PFCP SMR: Update FAR children parse error — rejecting whole request", "error", cErr)
			s.replySessionModRuleFailure(conn, addr, req)
			return
		}
		farIDIE := pfcpie.Find(children, pfcpie.TypeFARID)
		if farIDIE == nil {
			s.log.Warn("PFCP SMR: Update FAR missing mandatory FAR ID IE — rejecting whole request")
			s.replySessionModRuleFailure(conn, addr, req)
			return
		}
		farID, _ := farIDIE.FARIDValue()

		// Per §6.3.3.3: reject if the FAR does not exist in this session.
		found := false
		for _, f := range sess.FARs {
			if f.ID == farID {
				found = true
				break
			}
		}
		if !found {
			s.log.Warn("PFCP SMR: Update FAR references non-existent FAR — rejecting whole request",
				"up_seid", req.SEID, "far_id", farID)
			s.replySessionModRuleFailure(conn, addr, req)
			return
		}
		updates = append(updates, parsedFARUpdate{
			farID:       farID,
			applyAction: pfcpie.Find(children, pfcpie.TypeApplyAction),
			ufpIE:       pfcpie.Find(children, pfcpie.TypeUpdateForwardingParameters),
		})
	}

	// All updates validated — apply atomically per §6.3.3.3.
	// AUD-07: hold the session write-lock so the GTP-U forwarder cannot read FARs
	// concurrently while we are modifying them.
	sess.Mu.Lock()
	for _, u := range updates {
		for i := range sess.FARs {
			if sess.FARs[i].ID != u.farID {
				continue
			}
			// R15-REAUDIT-009: capture old OHC before applying the update.
			// If the outer header changes (tunnel switch), send End Marker to old downstream peer.
			oldOuterTEID := sess.FARs[i].OuterTEID
			oldOuterIP := sess.FARs[i].OuterIP

			if u.applyAction != nil {
				sess.FARs[i].ApplyAction, _ = u.applyAction.ApplyActionValue()
			}
			if u.ufpIE != nil {
				fpChildren, fpErr := u.ufpIE.Children()
				if fpErr == nil {
					if dstIE := pfcpie.Find(fpChildren, pfcpie.TypeDestinationInterface); dstIE != nil {
						sess.FARs[i].DestInterface, _ = dstIE.DestinationInterfaceValue()
					}
					if ohcIE := pfcpie.Find(fpChildren, pfcpie.TypeOuterHeaderCreation); ohcIE != nil {
						ohc, ohcErr := ohcIE.OuterHeaderCreationValue()
						if ohcErr == nil {
							sess.FARs[i].OuterTEID = ohc.TEID
							sess.FARs[i].OuterIP = ohc.IPv4
						}
					}
				}
			}

			// R15-REAUDIT-009: if the outer header changed and we had a valid old destination,
			// send End Marker to old downstream (eNB) per TS 29.281 §7.3.2.
			newOuterTEID := sess.FARs[i].OuterTEID
			newOuterIP := sess.FARs[i].OuterIP
			if s.emSender != nil &&
				oldOuterTEID != 0 && oldOuterIP.IsValid() &&
				(oldOuterTEID != newOuterTEID || oldOuterIP != newOuterIP) {
				s.log.Debug("PFCP SMR: FAR outer header changed — sending End Marker to old downstream",
					"far_id", u.farID, "old_teid", oldOuterTEID, "old_ip", oldOuterIP)
				s.emSender.SendEndMarker(oldOuterTEID, oldOuterIP)
			}

			s.log.Info("PFCP SMR: FAR updated",
				"up_seid", req.SEID,
				"far_id", u.farID,
				"apply_action", sess.FARs[i].ApplyAction,
			)
			break
		}
	}
	sess.Mu.Unlock() // AUD-07: release after all FAR writes are complete

	// Persist the updated session.
	if updateErr := s.sessions.Update(sess); updateErr != nil {
		s.log.Warn("PFCP SMR: session update failed", "up_seid", req.SEID, "error", updateErr)
		s.replySessionModRejection(conn, addr, req)
		return
	}

	// Phase 7: re-install BPF forwarding rules with updated FAR values.
	// AUD-01: BPF failure means the fast path did not apply the modification.
	// Return CauseRuleCreationFailure so the SGW-C knows the update did not take effect.
	// Note: the in-memory session is already updated; the SGW-C will retry or tear down.
	if s.bpfInstall != nil {
		if bpfErr := s.bpfInstall.UpdateSession(sess); bpfErr != nil {
			s.log.Error("BPF rule update failed after SMR — fast path has stale rules; returning failure",
				"up_seid", req.SEID, "error", bpfErr)
			s.replySessionModRuleFailure(conn, addr, req)
			return
		}
	}

	// Build Session Modification Response per Table 7.5.5.1-1: Cause is M.
	respHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           sess.CPSEID, // response SEID = CP-SEID per §7.5.4
		MessageType:    pfcpmsg.MsgTypeSessionModificationResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respRaw, err := pfcpmsg.Marshal(respHdr, []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseRequestAccepted)})
	if err != nil {
		s.log.Error("PFCP marshal SessionModificationResponse failed", "error", err)
		return
	}
	if err := conn.Reply(addr, respRaw); err != nil {
		s.log.Warn("PFCP send SessionModificationResponse failed", "to", addr, "error", err)
	}
}

// replySessionModRejection sends a Session Modification Response with RequestRejected.
func (s *Server) replySessionModRejection(conn *pfcptransport.Conn, addr *net.UDPAddr, req *pfcpmsg.SessionModificationRequest) {
	rejHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0,
		MessageType:    pfcpmsg.MsgTypeSessionModificationResponse,
		SequenceNumber: req.SequenceNumber,
	}
	raw, err := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseRequestRejected)})
	if err == nil {
		conn.Reply(addr, raw) //nolint:errcheck
	}
}

// replySessionModRuleFailure sends a Session Modification Response with Cause=73
// "Rule creation/modification Failure" per TS 29.244 Table 8.2.1-1.
// R15-004: an Update FAR references a non-existent or malformed rule; the whole
// transaction is rejected and no session state is modified.
func (s *Server) replySessionModRuleFailure(conn *pfcptransport.Conn, addr *net.UDPAddr, req *pfcpmsg.SessionModificationRequest) {
	rejHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0,
		MessageType:    pfcpmsg.MsgTypeSessionModificationResponse,
		SequenceNumber: req.SequenceNumber,
	}
	raw, err := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseRuleCreationFailure)})
	if err == nil {
		conn.Reply(addr, raw) //nolint:errcheck
	}
}

// handleSessionDeletion processes a PFCP Session Deletion Request
// per TS 29.244 Rel-15 §7.5.6 / Table 7.5.6.1-1.
// The request body is empty; the UP-SEID in the header identifies the session.
func (s *Server) handleSessionDeletion(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	// R15-009 FIX: reject session signalling without an established PFCP association.
	// Per TS 29.244 §6.3: sessions must be bound to an established association.
	if !s.hasAssociation(addr) {
		s.log.Warn("PFCP SDR: no established association — rejecting", "from", addr)
		rejHdr := pfcpmsg.Header{
			Version:        1,
			HasSEID:        true,
			SEID:           0,
			MessageType:    pfcpmsg.MsgTypeSessionDeletionResponse,
			SequenceNumber: hdr.SequenceNumber,
		}
		if raw2, err := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseNoEstablishedAssociation)}); err == nil {
			conn.Reply(addr, raw2) //nolint:errcheck
		}
		return
	}

	req, err := pfcpmsg.ParseSessionDeletionRequest(raw)
	if err != nil {
		s.log.Warn("PFCP SessionDeletionRequest parse error", "from", addr, "error", err)
		return
	}

	sess := s.sessions.FindByUPSEID(req.SEID)
	if sess == nil {
		s.log.Warn("PFCP SDR: session not found", "up_seid", req.SEID)
		// Per §7.5.6: respond with RequestRejected if session not found.
		rejHdr := pfcpmsg.Header{
			Version:        1,
			HasSEID:        true,
			SEID:           0,
			MessageType:    pfcpmsg.MsgTypeSessionDeletionResponse,
			SequenceNumber: req.SequenceNumber,
		}
		rejRaw, rejErr := pfcpmsg.Marshal(rejHdr, []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseRequestRejected)})
		if rejErr == nil {
			conn.Reply(addr, rejRaw) //nolint:errcheck
		}
		return
	}

	cpSEID := sess.CPSEID

	// Phase 7: remove BPF forwarding rules before deleting the session.
	if s.bpfInstall != nil {
		if bpfErr := s.bpfInstall.RemoveSession(sess); bpfErr != nil {
			s.log.Warn("BPF rule remove failed after SDR — stale fast-path rules may remain",
				"up_seid", req.SEID, "error", bpfErr)
		}
	}

	s.sessions.DeleteByUPSEID(req.SEID)

	s.log.Info("PFCP session deleted", "up_seid", req.SEID, "cp_seid", cpSEID)

	// Build Session Deletion Response per Table 7.5.7.1-1: Cause is M.
	respHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           cpSEID,
		MessageType:    pfcpmsg.MsgTypeSessionDeletionResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respRaw, err := pfcpmsg.Marshal(respHdr, []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseRequestAccepted)})
	if err != nil {
		s.log.Error("PFCP marshal SessionDeletionResponse failed", "error", err)
		return
	}
	if err := conn.Reply(addr, respRaw); err != nil {
		s.log.Warn("PFCP send SessionDeletionResponse failed", "to", addr, "error", err)
	}
}

// handleAssociationRelease processes a PFCP Association Release Request per TS 29.244 §7.4.4.5/§6.2.8.
// Per §6.2.8.3: "The UP function shall always accept a PFCP Association Release Request."
// The UP function deletes all PFCP sessions associated with the peer, removes BPF rules,
// removes the peer record, and replies with an Association Release Response.
func (s *Server) handleAssociationRelease(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	req, err := pfcpmsg.ParseAssociationReleaseRequest(raw)
	if err != nil {
		s.log.Warn("PFCP AssociationReleaseRequest parse error", "from", addr, "error", err)
		return
	}

	peerKey := nodeIDKey(req.NodeID)
	if peerKey == "" {
		peerKey = "addr:" + addr.String()
	}

	// Delete all sessions for the peer (AUD-02 pattern: return sessions so BPF can be cleaned up).
	heartbeatKey := "addr:" + addr.String()
	deleted := s.sessions.DeleteByCPNodeKey(heartbeatKey)
	s.log.Info("PFCP AssociationReleaseRequest: sessions deleted",
		"from", addr, "peer", peerKey, "sessions", len(deleted))
	if s.bpfInstall != nil {
		for _, sess := range deleted {
			if bpfErr := s.bpfInstall.RemoveSession(sess); bpfErr != nil {
				s.log.Warn("BPF cleanup failed for released session",
					"cp_seid", sess.CPSEID, "error", bpfErr)
			}
		}
	}

	// Remove the peer association record.
	s.peers.Delete(peerKey)

	// Send Association Release Response per Table 7.4.4.6-1: Node ID (M), Cause (M).
	respHdr := pfcpmsg.Header{
		Version:        1,
		MessageType:    pfcpmsg.MsgTypeAssociationReleaseResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respRaw, marshalErr := pfcpmsg.Marshal(respHdr, []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(s.localNodeID),
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
	})
	if marshalErr != nil {
		s.log.Error("PFCP marshal AssociationReleaseResponse failed", "error", marshalErr)
		return
	}
	if err := conn.Reply(addr, respRaw); err != nil {
		s.log.Warn("PFCP send AssociationReleaseResponse failed", "to", addr, "error", err)
	}
}

// HandlePathFailure sends a PFCP Node Report Request to all established SGW-C peers
// reporting a user-plane path failure toward failedPeer per TS 29.244 §7.4.5.1.
// Called by the GTP-U PathProber when N3-REQUESTS retries are exhausted without an Echo Response.
// Per Table 7.4.5.1.1-1: Node ID (M), Node Report Type (M), User Plane Path Failure Report (C when UPFR=1).
func (s *Server) HandlePathFailure(ctx context.Context, failedPeer netip.Addr) {
	ip4 := failedPeer.As4()
	failedPeerIP := net.IP(ip4[:])
	s.peers.Range(func(key, val any) bool {
		pr := val.(*PeerRecord)
		pr.mu.RLock()
		peerAddr := pr.lastAddr
		pr.mu.RUnlock()
		if peerAddr == nil {
			return true
		}

		seq := s.conn.AllocSeq()
		hdr := pfcpmsg.Header{
			Version:        1,
			MessageType:    pfcpmsg.MsgTypeNodeReportRequest,
			SequenceNumber: seq,
		}
		raw, marshalErr := pfcpmsg.Marshal(hdr, []*pfcpie.IE{
			pfcpie.NewNodeIDIPv4(s.localNodeID),
			pfcpie.NewNodeReportType(pfcpie.NodeReportTypeUPFR),
			pfcpie.NewUserPlanPathFailureReport(
				pfcpie.NewRemoteGTPUPeerIPv4(failedPeerIP),
			),
		})
		if marshalErr != nil {
			s.log.Error("PFCP marshal NodeReportRequest failed", "error", marshalErr)
			return true
		}
		respRaw, sendErr := s.conn.Send(ctx, peerAddr, raw)
		if sendErr != nil {
			s.log.Warn("PFCP NodeReportRequest send failed",
				"to", peerAddr, "failed_peer", failedPeerIP, "error", sendErr)
			return true
		}
		resp, parseErr := pfcpmsg.ParseNodeReportResponse(respRaw)
		if parseErr != nil {
			s.log.Warn("PFCP NodeReportResponse parse failed",
				"from", peerAddr, "error", parseErr)
			return true
		}
		cause, _ := resp.Cause.CauseValue()
		s.log.Info("PFCP Node Report acknowledged",
			"peer", peerAddr, "failed_peer", failedPeerIP, "cause", cause)
		return true
	})
}

func (s *Server) isAllowed(ip net.IP) bool {
	if len(s.allowedNets) == 0 {
		return true
	}
	for _, n := range s.allowedNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// extractIPv4 parses the host portion of "ip:port" and returns the IPv4.
func extractIPv4(addrPort string) (net.IP, error) {
	host, _, err := net.SplitHostPort(addrPort)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, fmt.Errorf("invalid IP: %q", host)
	}
	v4 := ip.To4()
	if v4 == nil {
		return nil, fmt.Errorf("PFCP Node ID requires IPv4, got: %q", host)
	}
	return v4, nil
}
