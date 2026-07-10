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

// BPFRuleInstaller is implemented by the eBPF dataplane to install, update,
// and remove GTP-U forwarding rules derived from PFCP PDR/FAR state (Phase 7).
// Called after session establishment, modification, and deletion.
type BPFRuleInstaller interface {
	InstallSession(sess *sgwusession.Session) error
	UpdateSession(sess *sgwusession.Session) error
	RemoveSession(sess *sgwusession.Session) error
}

// PathPeerTracker receives remote GTP-U peer addresses that should be echo-probed.
type PathPeerTracker interface {
	Add(peer netip.Addr)
}

type parsedFARUpdate struct {
	farID       uint32
	applyAction *pfcpie.IE
	ufpIE       *pfcpie.IE
}

type endMarkerEvent struct {
	farID uint32
	teid  uint32
	dstIP netip.Addr
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

// PeerView is a point-in-time API view of one established SGW-C PFCP
// association on the SGW-U. PFCP association identity is the Node ID from TS
// 29.244 Rel-15 §8.2.8, and restart detection is based on the Recovery Time
// Stamp from §8.2.11.
type PeerView struct {
	NodeIDKey         string    `json:"node_id_key"`
	State             string    `json:"state"`
	RecoveryTimestamp uint32    `json:"recovery_timestamp"`
	LastSeen          time.Time `json:"last_seen"`
	LastAddr          string    `json:"last_addr,omitempty"`
	SessionCount      int       `json:"session_count"`
}

// Server listens for PFCP messages from SGW-C peers on the SGW-U.
type Server struct {
	conn        *pfcptransport.Conn
	localNodeID net.IP
	localIP     netip.Addr // SGW-U PFCP IP (Node ID / UP F-SEID endpoint)
	accessIP    netip.Addr // SGW-U S1-U GTP-U IP (Access-side local F-TEID)
	coreIP      netip.Addr // SGW-U S5/S8-U GTP-U IP (Core-side local F-TEID)
	localTS     uint32     // NTP timestamp when this process started (Recovery Time Stamp)
	allowedNets []*net.IPNet
	peers       sync.Map // nodeIDKey string → *PeerRecord (keyed by Node ID per §8.2.8)
	sessions    *sgwusession.Store
	log         *slog.Logger
	emSender    EndMarkerSender  // optional; wired after both server and forwarder are created
	bpfInstall  BPFRuleInstaller // optional; wired when eBPF dataplane is active
	pathPeers   PathPeerTracker  // optional; learns remote GTP-U peers from FARs
}

// SetEndMarkerSender wires the GTP-U forwarder so that PFCP-triggered tunnel
// switches (FAR outer header changes) result in End Markers being sent to the
// old downstream peer per TS 29.281 §7.3.2 and R15-REAUDIT-009.
func (s *Server) SetEndMarkerSender(sender EndMarkerSender) {
	s.emSender = sender
}

// SetBPFInstaller wires the BPF rule compiler so that PFCP session events are
// reflected in the kernel BPF forwarding maps.
func (s *Server) SetBPFInstaller(installer BPFRuleInstaller) {
	s.bpfInstall = installer
}

// SetPathPeerTracker wires GTP-U path probing to PFCP session state.
func (s *Server) SetPathPeerTracker(tracker PathPeerTracker) {
	s.pathPeers = tracker
}

// New creates an SGW-U PFCP server ready to serve.
// startTime is used as the Recovery Time Stamp in all outbound messages.
func New(cfg *sgwuconfig.Config, startTime time.Time, log *slog.Logger) (*Server, error) {
	conn, err := pfcptransport.Listen(cfg.PFCP.Listen, 5, 3, log)
	if err != nil {
		return nil, fmt.Errorf("PFCP server listen %s: %w", cfg.PFCP.Listen, err)
	}
	if cfg.QoS.OuterMarking.Enabled && cfg.QoS.OuterMarking.PFCP.Enabled {
		if err := conn.SetDSCP(uint8(cfg.QoS.OuterMarking.PFCP.DSCP)); err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("PFCP server QoS outer marking: %w", err)
		}
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
	accessIP, err := cfg.S1ULocalAddr()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("PFCP server: invalid S1-U listen address: %w", err)
	}
	coreIP, err := cfg.S5ULocalAddr()
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("PFCP server: invalid S5/S8-U listen address: %w", err)
	}

	s := &Server{
		conn:        conn,
		localNodeID: localIP,
		localIP:     localNetipAddr,
		accessIP:    accessIP,
		coreIP:      coreIP,
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

// Peers returns a stable snapshot of SGW-C PFCP associations currently known
// by this SGW-U. Entries are added by Association Setup and removed by
// Association Release, so every returned peer is an established association.
func (s *Server) Peers() []PeerView {
	var peers []PeerView
	seen := make(map[*PeerRecord]bool)
	s.peers.Range(func(_, val any) bool {
		pr := val.(*PeerRecord)
		if seen[pr] {
			return true
		}
		seen[pr] = true
		pr.mu.RLock()
		view := PeerView{
			NodeIDKey:         pr.nodeIDKey,
			State:             "Established",
			RecoveryTimestamp: pr.recoveryTS,
			LastSeen:          pr.lastSeen,
			SessionCount:      s.sessions.CountByCPNodeKey(pr.nodeIDKey),
		}
		if pr.lastAddr != nil {
			view.LastAddr = pr.lastAddr.String()
		}
		pr.mu.RUnlock()
		peers = append(peers, view)
		return true
	})
	return peers
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

func cpNodeKey(nodeID *pfcpie.IE, addr *net.UDPAddr) string {
	if key := nodeIDKey(nodeID); key != "" {
		return key
	}
	if addr == nil {
		return ""
	}
	return "ipv4:" + addr.IP.String()
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
	sourceKey := "ipv4:" + addr.IP.String()

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
		if sourceKey != peerKey {
			s.peers.Store(sourceKey, pr)
		}
	} else {
		pr := &PeerRecord{
			nodeIDKey:  peerKey,
			recoveryTS: peerTS,
			lastSeen:   time.Now(),
			lastAddr:   addr,
		}
		s.peers.Store(peerKey, pr)
		if sourceKey != peerKey {
			s.peers.Store(sourceKey, pr)
		}
	}

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
		return
	}
	s.log.Info("PFCP association established with SGW-C",
		"from", addr,
		"peer_node_id", peerKey,
		"local_node_id", s.localNodeID.String(),
		"peer_recovery_ts", peerTS)
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
			s.deletePeerSessions(heartbeatKey, "restarted peer session")
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

func (s *Server) deletePeerSessions(peerKey, reason string) int {
	deleted := s.sessions.DeleteByCPNodeKey(peerKey)
	if s.bpfInstall != nil {
		for _, sess := range deleted {
			if bpfErr := s.bpfInstall.RemoveSession(sess); bpfErr != nil {
				s.log.Error("BPF cleanup failed for "+reason,
					"cp_seid", sess.CPSEID, "error", bpfErr)
			}
		}
	}
	return len(deleted)
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
		if qosIE := pfcpie.Find(children, pfcpie.TypeVectorCoreQoSMarking); qosIE != nil {
			ebi, qci, valid, qosErr := qosIE.VectorCoreQoSMarkingValue()
			if qosErr != nil {
				s.log.Warn("PFCP SER: VectorCore QoS metadata invalid — rejecting whole request", "error", qosErr)
				s.replySessionEstRuleFailure(conn, addr, hdr)
				return
			}
			pdr.EBI = ebi
			pdr.QCI = qci
			pdr.QoSValid = valid
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
				localFTEIDIP, createdPDR, ipErr := s.newCreatedPDRForSource(pdrID, allocTEID, srcIface)
				if ipErr != nil {
					s.log.Warn("PFCP SER: Create PDR source interface cannot be mapped to a GTP-U local IP — rejecting whole request",
						"source_interface", srcIface, "error", ipErr)
					s.replySessionEstRuleFailure(conn, addr, hdr)
					return
				}
				pdr.LocalTEID = allocTEID
				pdr.LocalIP = localFTEIDIP

				// Build Created PDR IE: PDR ID (M) + F-TEID (C: allocated TEID+IP).
				createdPDRIEs = append(createdPDRIEs, createdPDR)
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
	s.trackSessionPathPeers(sess)

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

	createdPDRIEs, endMarkers, applyErr := s.applySessionModification(sess, req)
	if applyErr != nil {
		s.log.Error("PFCP SMR rejected before session commit",
			"up_seid", req.SEID, "error", applyErr)
		s.replySessionModRuleFailure(conn, addr, req)
		return
	}
	s.trackSessionPathPeers(sess)

	for _, ev := range endMarkers {
		if s.emSender == nil {
			continue
		}
		s.log.Debug("PFCP SMR: FAR outer header changed — sending End Marker to old downstream",
			"far_id", ev.farID, "old_teid", ev.teid, "old_ip", ev.dstIP)
		s.emSender.SendEndMarker(ev.teid, ev.dstIP)
	}

	// Build Session Modification Response per Table 7.5.5.1-1: Cause is M;
	// Created PDR is present when new PDRs used CHOOSE F-TEID.
	respHdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           sess.CPSEID, // response SEID = CP-SEID per §7.5.4
		MessageType:    pfcpmsg.MsgTypeSessionModificationResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respIEs := []*pfcpie.IE{pfcpie.NewCause(pfcpie.CauseRequestAccepted)}
	respIEs = append(respIEs, createdPDRIEs...)
	respRaw, err := pfcpmsg.Marshal(respHdr, respIEs)
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

func (s *Server) applySessionModification(sess *sgwusession.Session, req *pfcpmsg.SessionModificationRequest) ([]*pfcpie.IE, []endMarkerEvent, error) {
	sess.Mu.Lock()
	defer sess.Mu.Unlock()

	candidate := &sgwusession.Session{
		CPSEID:    sess.CPSEID,
		UPSEID:    sess.UPSEID,
		CPNodeKey: sess.CPNodeKey,
		PDRs:      append([]sgwusession.PDR(nil), sess.PDRs...),
		FARs:      append([]sgwusession.FAR(nil), sess.FARs...),
	}

	for _, cfarIE := range req.CreateFARs {
		far, err := parseCreateFAR(cfarIE)
		if err != nil {
			return nil, nil, err
		}
		for _, existing := range candidate.FARs {
			if existing.ID == far.ID {
				return nil, nil, fmt.Errorf("FAR %d already exists", far.ID)
			}
		}
		candidate.FARs = append(candidate.FARs, far)
	}

	var createdPDRIEs []*pfcpie.IE
	for _, cpdrIE := range req.CreatePDRs {
		pdr, choose, err := parseCreatePDR(cpdrIE)
		if err != nil {
			return nil, nil, err
		}
		for _, existing := range candidate.PDRs {
			if existing.ID == pdr.ID {
				return nil, nil, fmt.Errorf("PDR %d already exists", pdr.ID)
			}
		}
		if choose {
			allocTEID := s.sessions.AllocTEID()
			localFTEIDIP, createdPDR, ipErr := s.newCreatedPDRForSource(pdr.ID, allocTEID, pdr.SourceInterface)
			if ipErr != nil {
				return nil, nil, ipErr
			}
			pdr.LocalTEID = allocTEID
			pdr.LocalIP = localFTEIDIP
			createdPDRIEs = append(createdPDRIEs, createdPDR)
		}
		candidate.PDRs = append(candidate.PDRs, pdr)
	}

	for _, rpdrIE := range req.RemovePDRs {
		children, err := rpdrIE.Children()
		if err != nil {
			return nil, nil, fmt.Errorf("Remove PDR children: %w", err)
		}
		pdrIDIE := pfcpie.Find(children, pfcpie.TypePDRID)
		if pdrIDIE == nil {
			return nil, nil, fmt.Errorf("Remove PDR missing PDR ID")
		}
		pdrID, _ := pdrIDIE.PDRIDValue()
		found := false
		out := candidate.PDRs[:0]
		for _, pdr := range candidate.PDRs {
			if pdr.ID == pdrID {
				found = true
				continue
			}
			out = append(out, pdr)
		}
		if !found {
			return nil, nil, fmt.Errorf("PDR %d does not exist", pdrID)
		}
		candidate.PDRs = out
	}

	for _, rfarIE := range req.RemoveFARs {
		children, err := rfarIE.Children()
		if err != nil {
			return nil, nil, fmt.Errorf("Remove FAR children: %w", err)
		}
		farIDIE := pfcpie.Find(children, pfcpie.TypeFARID)
		if farIDIE == nil {
			return nil, nil, fmt.Errorf("Remove FAR missing FAR ID")
		}
		farID, _ := farIDIE.FARIDValue()
		found := false
		out := candidate.FARs[:0]
		for _, far := range candidate.FARs {
			if far.ID == farID {
				found = true
				continue
			}
			out = append(out, far)
		}
		if !found {
			return nil, nil, fmt.Errorf("FAR %d does not exist", farID)
		}
		candidate.FARs = out
	}

	updates, err := parseUpdateFARs(req.UpdateFARs, candidate.FARs)
	if err != nil {
		return nil, nil, err
	}
	endMarkers, err := applyFARUpdatesToCandidate(candidate.FARs, updates)
	if err != nil {
		return nil, nil, err
	}

	if s.bpfInstall != nil {
		if err := s.bpfInstall.UpdateSession(candidate); err != nil {
			return nil, nil, err
		}
	}

	sess.PDRs = candidate.PDRs
	sess.FARs = candidate.FARs
	return createdPDRIEs, endMarkers, nil
}

func (s *Server) trackSessionPathPeers(sess *sgwusession.Session) {
	if s.pathPeers == nil || sess == nil {
		return
	}
	sess.Mu.RLock()
	defer sess.Mu.RUnlock()
	seen := make(map[netip.Addr]bool, len(sess.FARs))
	for _, far := range sess.FARs {
		if !far.OuterIP.IsValid() || !far.OuterIP.Is4() || seen[far.OuterIP] {
			continue
		}
		seen[far.OuterIP] = true
		s.pathPeers.Add(far.OuterIP)
	}
}

func parseCreatePDR(cpdrIE *pfcpie.IE) (sgwusession.PDR, bool, error) {
	children, err := cpdrIE.Children()
	if err != nil {
		return sgwusession.PDR{}, false, fmt.Errorf("Create PDR children: %w", err)
	}
	pdrIDIE := pfcpie.Find(children, pfcpie.TypePDRID)
	precIE := pfcpie.Find(children, pfcpie.TypePrecedence)
	farIDIE := pfcpie.Find(children, pfcpie.TypeFARID)
	pdiIE := pfcpie.Find(children, pfcpie.TypePDI)
	if pdrIDIE == nil || precIE == nil || farIDIE == nil || pdiIE == nil {
		return sgwusession.PDR{}, false, fmt.Errorf("Create PDR missing PDR ID, Precedence, FAR ID, or PDI")
	}
	pdrID, _ := pdrIDIE.PDRIDValue()
	farID, _ := farIDIE.FARIDValue()
	pdiChildren, err := pdiIE.Children()
	if err != nil {
		return sgwusession.PDR{}, false, fmt.Errorf("PDI children: %w", err)
	}
	srcIfaceIE := pfcpie.Find(pdiChildren, pfcpie.TypeSourceInterface)
	if srcIfaceIE == nil {
		return sgwusession.PDR{}, false, fmt.Errorf("PDI missing Source Interface")
	}
	srcIface, _ := srcIfaceIE.SourceInterfaceValue()
	pdr := sgwusession.PDR{ID: pdrID, FARID: farID, SourceInterface: srcIface}
	if qosIE := pfcpie.Find(children, pfcpie.TypeVectorCoreQoSMarking); qosIE != nil {
		ebi, qci, valid, err := qosIE.VectorCoreQoSMarkingValue()
		if err != nil {
			return sgwusession.PDR{}, false, fmt.Errorf("VectorCore QoS metadata: %w", err)
		}
		pdr.EBI = ebi
		pdr.QCI = qci
		pdr.QoSValid = valid
	}
	if len(precIE.Value) >= 4 {
		pdr.Precedence = (uint32(precIE.Value[0]) << 24) | (uint32(precIE.Value[1]) << 16) |
			(uint32(precIE.Value[2]) << 8) | uint32(precIE.Value[3])
	}
	choose := false
	if fteidIE := pfcpie.Find(pdiChildren, pfcpie.TypeFTEID); fteidIE != nil {
		fteid, isCH, err := fteidIE.FTEIDPFCPValue()
		if err != nil {
			return sgwusession.PDR{}, false, fmt.Errorf("PDI F-TEID: %w", err)
		}
		choose = isCH
		if !isCH {
			pdr.LocalTEID = fteid.TEID
			pdr.LocalIP = fteid.IPv4
		}
	}
	return pdr, choose, nil
}

func parseCreateFAR(cfarIE *pfcpie.IE) (sgwusession.FAR, error) {
	children, err := cfarIE.Children()
	if err != nil {
		return sgwusession.FAR{}, fmt.Errorf("Create FAR children: %w", err)
	}
	farIDIE := pfcpie.Find(children, pfcpie.TypeFARID)
	aaIE := pfcpie.Find(children, pfcpie.TypeApplyAction)
	if farIDIE == nil || aaIE == nil {
		return sgwusession.FAR{}, fmt.Errorf("Create FAR missing FAR ID or Apply Action")
	}
	farID, _ := farIDIE.FARIDValue()
	applyAction, _ := aaIE.ApplyActionValue()
	far := sgwusession.FAR{ID: farID, ApplyAction: applyAction}
	if applyAction&pfcpie.ApplyActionFORW == 0 {
		return far, nil
	}
	fpIE := pfcpie.Find(children, pfcpie.TypeForwardingParameters)
	if fpIE == nil {
		return sgwusession.FAR{}, fmt.Errorf("Create FAR with FORW missing Forwarding Parameters")
	}
	fpChildren, err := fpIE.Children()
	if err != nil {
		return sgwusession.FAR{}, fmt.Errorf("Forwarding Parameters children: %w", err)
	}
	dstIfaceIE := pfcpie.Find(fpChildren, pfcpie.TypeDestinationInterface)
	if dstIfaceIE == nil {
		return sgwusession.FAR{}, fmt.Errorf("Forwarding Parameters missing Destination Interface")
	}
	far.DestInterface, _ = dstIfaceIE.DestinationInterfaceValue()
	if ohcIE := pfcpie.Find(fpChildren, pfcpie.TypeOuterHeaderCreation); ohcIE != nil {
		ohc, err := ohcIE.OuterHeaderCreationValue()
		if err != nil {
			return sgwusession.FAR{}, err
		}
		far.OuterTEID = ohc.TEID
		far.OuterIP = ohc.IPv4
	}
	return far, nil
}

func parseUpdateFARs(updateFARs []*pfcpie.IE, fars []sgwusession.FAR) ([]parsedFARUpdate, error) {
	var updates []parsedFARUpdate
	for _, ufarIE := range updateFARs {
		children, cErr := ufarIE.Children()
		if cErr != nil {
			return nil, fmt.Errorf("Update FAR children: %w", cErr)
		}
		farIDIE := pfcpie.Find(children, pfcpie.TypeFARID)
		if farIDIE == nil {
			return nil, fmt.Errorf("Update FAR missing FAR ID")
		}
		farID, _ := farIDIE.FARIDValue()
		found := false
		for _, f := range fars {
			if f.ID == farID {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("FAR %d does not exist", farID)
		}
		updates = append(updates, parsedFARUpdate{
			farID:       farID,
			applyAction: pfcpie.Find(children, pfcpie.TypeApplyAction),
			ufpIE:       pfcpie.Find(children, pfcpie.TypeUpdateForwardingParameters),
		})
	}
	return updates, nil
}

// applyFARUpdates applies all FAR changes as one transaction per TS 29.244
// Rel-15 §6.3.3.3: if any requested update is rejected, the existing PFCP
// session context remains as if the request had not been received.
func (s *Server) applyFARUpdates(sess *sgwusession.Session, updates []parsedFARUpdate) ([]endMarkerEvent, error) {
	sess.Mu.Lock()
	defer sess.Mu.Unlock()

	candidate := &sgwusession.Session{
		CPSEID:    sess.CPSEID,
		UPSEID:    sess.UPSEID,
		CPNodeKey: sess.CPNodeKey,
		PDRs:      append([]sgwusession.PDR(nil), sess.PDRs...),
		FARs:      append([]sgwusession.FAR(nil), sess.FARs...),
	}

	endMarkers, err := applyFARUpdatesToCandidate(candidate.FARs, updates)
	if err != nil {
		return nil, err
	}

	// TS 29.244 Rel-15 §6.3.3 requires acceptance only when all requested
	// modifications are performed successfully. Updating BPF against the candidate
	// before committing keeps memory and fast path aligned on failure.
	if s.bpfInstall != nil {
		if err := s.bpfInstall.UpdateSession(candidate); err != nil {
			return nil, err
		}
	}

	sess.FARs = candidate.FARs
	return endMarkers, nil
}

func applyFARUpdatesToCandidate(fars []sgwusession.FAR, updates []parsedFARUpdate) ([]endMarkerEvent, error) {
	var endMarkers []endMarkerEvent
	for _, u := range updates {
		found := false
		for i := range fars {
			if fars[i].ID != u.farID {
				continue
			}
			found = true
			oldOuterTEID := fars[i].OuterTEID
			oldOuterIP := fars[i].OuterIP

			if u.applyAction != nil {
				applyAction, err := u.applyAction.ApplyActionValue()
				if err != nil {
					return nil, fmt.Errorf("apply action for FAR %d: %w", u.farID, err)
				}
				oldAction := fars[i].ApplyAction
				oldDestInterface := fars[i].DestInterface
				fars[i].ApplyAction = applyAction
				switch {
				case applyAction&pfcpie.ApplyActionFORW != 0:
					fars[i].DropReason = sgwusession.DropReasonNone
				case applyAction&pfcpie.ApplyActionDROP != 0 &&
					oldAction&pfcpie.ApplyActionFORW != 0 &&
					oldDestInterface == pfcpie.DestInterfaceAccess:
					fars[i].DropReason = sgwusession.DropReasonReleaseAccessBearers
				case applyAction&pfcpie.ApplyActionDROP != 0 && fars[i].DropReason == "":
					fars[i].DropReason = sgwusession.DropReasonPolicy
				}
			}
			if u.ufpIE != nil {
				fpChildren, err := u.ufpIE.Children()
				if err != nil {
					return nil, fmt.Errorf("update forwarding parameters for FAR %d: %w", u.farID, err)
				}
				if dstIE := pfcpie.Find(fpChildren, pfcpie.TypeDestinationInterface); dstIE != nil {
					dstInterface, err := dstIE.DestinationInterfaceValue()
					if err != nil {
						return nil, fmt.Errorf("destination interface for FAR %d: %w", u.farID, err)
					}
					fars[i].DestInterface = dstInterface
				}
				if ohcIE := pfcpie.Find(fpChildren, pfcpie.TypeOuterHeaderCreation); ohcIE != nil {
					ohc, err := ohcIE.OuterHeaderCreationValue()
					if err != nil {
						return nil, fmt.Errorf("outer header creation for FAR %d: %w", u.farID, err)
					}
					fars[i].OuterTEID = ohc.TEID
					fars[i].OuterIP = ohc.IPv4
				}
			}

			newOuterTEID := fars[i].OuterTEID
			newOuterIP := fars[i].OuterIP
			if oldOuterTEID != 0 && oldOuterIP.IsValid() &&
				(oldOuterTEID != newOuterTEID || oldOuterIP != newOuterIP) {
				endMarkers = append(endMarkers, endMarkerEvent{
					farID: u.farID,
					teid:  oldOuterTEID,
					dstIP: oldOuterIP,
				})
			}
			break
		}
		if !found {
			return nil, fmt.Errorf("FAR %d does not exist", u.farID)
		}
	}
	return endMarkers, nil
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

	peerKey := cpNodeKey(req.NodeID, addr)

	// Delete all sessions for the peer (AUD-02 pattern: return sessions so BPF can be cleaned up).
	deleted := s.sessions.DeleteByCPNodeKey(peerKey)
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

func (s *Server) ReportIdleDownlink(event sgwusession.IdleDownlinkEvent) {
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		s.reportIdleDownlink(ctx, event)
	}()
}

func (s *Server) reportIdleDownlink(ctx context.Context, event sgwusession.IdleDownlinkEvent) {
	report := pfcpie.VectorCoreIdleDownlinkReport{
		CPSEID:          event.CPSEID,
		UPSEID:          event.UPSEID,
		PDRID:           event.PDRID,
		FARID:           event.FARID,
		LocalTEID:       event.LocalTEID,
		EBI:             event.EBI,
		QCI:             event.QCI,
		SourceInterface: event.SourceInterface,
		QoSValid:        event.QoSValid,
		DropReason:      idleDownlinkDropReasonCode(event.DropReason),
	}
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
			HasSEID:        true,
			MessageType:    pfcpmsg.MsgTypeSessionReportRequest,
			SEID:           event.CPSEID,
			SequenceNumber: seq,
		}
		raw, marshalErr := pfcpmsg.Marshal(hdr, []*pfcpie.IE{
			pfcpie.NewVectorCoreIdleDownlinkReport(report),
		})
		if marshalErr != nil {
			s.log.Error("PFCP marshal SessionReportRequest idle downlink failed", "error", marshalErr)
			return true
		}
		respRaw, sendErr := s.conn.Send(ctx, peerAddr, raw)
		if sendErr != nil {
			s.log.Warn("PFCP SessionReportRequest idle downlink send failed",
				"to", peerAddr,
				"cp_seid", event.CPSEID,
				"up_seid", event.UPSEID,
				"pdr_id", event.PDRID,
				"far_id", event.FARID,
				"local_teid", fmt.Sprintf("0x%08X", event.LocalTEID),
				"error", sendErr)
			return true
		}
		resp, parseErr := pfcpmsg.ParseSessionReportResponse(respRaw)
		if parseErr != nil {
			s.log.Warn("PFCP SessionReportResponse idle downlink parse failed",
				"from", peerAddr, "error", parseErr)
			return true
		}
		cause, _ := resp.Cause.CauseValue()
		s.log.Info("PFCP Session Report idle downlink acknowledged",
			"peer", peerAddr,
			"cp_seid", event.CPSEID,
			"up_seid", event.UPSEID,
			"pdr_id", event.PDRID,
			"far_id", event.FARID,
			"local_teid", fmt.Sprintf("0x%08X", event.LocalTEID),
			"ebi", event.EBI,
			"qci", event.QCI,
			"cause", cause)
		return true
	})
}

func idleDownlinkDropReasonCode(reason sgwusession.DropReason) uint8 {
	switch reason {
	case sgwusession.DropReasonReleaseAccessBearers:
		return pfcpie.VectorCoreIdleDownlinkDropReleaseAccessBearers
	default:
		return 0
	}
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

// localGTPUIPForSource maps a PFCP PDR Source Interface to the SGW-U local
// GTP-U address that must be returned in Created PDR F-TEID when CHOOSE is set.
//
// TS 29.244 Rel-15 §5.5.3: "The Source Interface IE indicates for which
// interface the F-TEID is to be assigned." For this SGW-U, Access means S1-U
// and Core means S5/S8-U.
func (s *Server) localGTPUIPForSource(sourceInterface uint8) (netip.Addr, error) {
	switch sourceInterface {
	case pfcpie.SourceInterfaceAccess:
		return s.accessIP, nil
	case pfcpie.SourceInterfaceCore:
		return s.coreIP, nil
	default:
		return netip.Addr{}, fmt.Errorf("unsupported Source Interface %d", sourceInterface)
	}
}

func (s *Server) newCreatedPDRForSource(pdrID uint16, teid uint32, sourceInterface uint8) (netip.Addr, *pfcpie.IE, error) {
	localFTEIDIP, err := s.localGTPUIPForSource(sourceInterface)
	if err != nil {
		return netip.Addr{}, nil, err
	}
	return localFTEIDIP, pfcpie.NewCreatedPDR(
		pfcpie.NewPDRID(pdrID),
		pfcpie.NewFTEIDv4(teid, localFTEIDIP),
	), nil
}
