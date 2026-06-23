// Package pfcpclient manages PFCP/Sxa associations between SGW-C and SGW-U peers
// per TS 29.244 Rel-15 §5.2 and TS 23.214 Rel-15 §6.1/§6.2.
//
// For each configured SGW-U peer the client:
//   - Establishes a PFCP Association per §5.2.1 (Table 7.4.1-1 / Table 7.4.2-1)
//   - Sends periodic Heartbeat Requests per §6.1 (Table 7.2.2-1 / Table 7.2.3-1)
//   - Detects peer restarts via Recovery Time Stamp changes (§5.2.1)
//   - Re-establishes the association when a peer goes Down
//
// Session lifecycle:
//   - EstablishSession: PFCP Session Establishment per §7.5.2
//   - ModifySession: PFCP Session Modification per §7.5.4 (update FARs)
//   - DeleteSession: PFCP Session Deletion per §7.5.6
package pfcpclient

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	pfcpmsg "vectorcore-sgw/internal/pfcp/message"
	pfcptransport "vectorcore-sgw/internal/pfcp/transport"
)

// ntpEpochOffset is the seconds between NTP epoch (1900-01-01) and Unix epoch (1970-01-01)
// per TS 29.244 Rel-15 §8.2.11 Recovery Time Stamp encoding.
const ntpEpochOffset uint32 = 2208988800

// PeerState represents the current state of the Sxa association with a single SGW-U.
type PeerState string

const (
	PeerStatePending     PeerState = "Pending"
	PeerStateEstablished PeerState = "Established"
	PeerStateDown        PeerState = "Down"
)

// peer holds per-SGW-U association state.
type peer struct {
	mu             sync.RWMutex
	cfg            sgwcconfig.SGWUPeer
	addr           *net.UDPAddr
	state          PeerState
	peerNodeID     net.IP
	peerRecoveryTS uint32 // last known NTP recovery timestamp from this peer
	lastSeen       time.Time
}

// PeerView is the API/observability representation of a PFCP peer association.
type PeerView struct {
	Name       string    `json:"name"`
	Addr       string    `json:"addr"`
	State      string    `json:"state"`
	PeerNodeID string    `json:"peer_node_id,omitempty"`
	LastSeen   time.Time `json:"last_seen,omitempty"`
}

// SessionParams describes the PDRs and FARs to establish in a PFCP session.
// Used by EstablishSession.
type SessionParams struct {
	// LocalIP is the SGW-C control-plane IP, carried in the CP F-SEID IE.
	LocalIP netip.Addr
	// CPFSEID is the 64-bit SEID that the SGW-C assigns for this session.
	CPFSEID uint64
	// CreatePDRs are the Create PDR grouped IEs (built by the caller from §7.5.2.2-1 rules).
	CreatePDRs []*pfcpie.IE
	// CreateFARs are the Create FAR grouped IEs.
	CreateFARs []*pfcpie.IE
}

// SessionResult holds the outcome of a successful PFCP Session Establishment.
type SessionResult struct {
	// UPSEID is the SEID the SGW-U assigned for this session (from UP F-SEID IE).
	UPSEID    uint64
	// CreatedPDRs hold the Created PDR IEs from the response, each containing the
	// PDR ID and the SGW-U-allocated F-TEID (when CHOOSE was set in the request).
	CreatedPDRs []*pfcpie.IE
}

// FARUpdate describes a single FAR update for use with ModifySession.
type FARUpdate struct {
	// FARID is the FAR to update (must match a FAR created at establishment).
	FARID       uint32
	// ApplyAction is the new Apply Action flags (e.g., FORW after eNB TEID arrives).
	ApplyAction uint8
	// DestInterface is the destination interface (0=Access, 1=Core).
	DestInterface uint8
	// OuterTEID is the peer's GTP-U TEID for outer header creation (e.g., eNB TEID).
	OuterTEID   uint32
	// OuterIP is the peer's GTP-U IP for outer header creation.
	OuterIP     netip.Addr
}

// Client manages PFCP associations from SGW-C to all configured SGW-U peers.
type Client struct {
	conn        *pfcptransport.Conn
	localNodeID net.IP
	localTS     uint32 // NTP timestamp when this process started
	peers       []*peer
	hbInterval  time.Duration
	hbTimeout   time.Duration
	seidCounter atomic.Uint64 // CP-SEID allocator; starts at 1
	log         *slog.Logger

	// onPeerStateChange fires when a peer transitions between Established and Down.
	// Called with (peerName, peerAddr, newState). Safe to set before Serve().
	onPeerStateChange func(peerName, peerAddr string, state PeerState)
}

// New creates a PFCP client ready for use. Call Serve(ctx) to begin association
// establishment and heartbeat management.
// startTime is the process start time; it becomes the local Recovery Time Stamp.
func New(cfg *sgwcconfig.Config, startTime time.Time, log *slog.Logger) (*Client, error) {
	// T1=5s, N1=3 for PFCP transactions per TS 29.244 §7.6.
	conn, err := pfcptransport.Listen(cfg.PFCP.LocalAddr, 5, 3, log)
	if err != nil {
		return nil, fmt.Errorf("PFCP client listen %s: %w", cfg.PFCP.LocalAddr, err)
	}

	localIP, err := extractIPv4(cfg.PFCP.LocalAddr)
	if err != nil {
		_ = conn.Close()
		return nil, fmt.Errorf("PFCP client: derive local Node ID from %q: %w", cfg.PFCP.LocalAddr, err)
	}

	hbInterval := time.Duration(cfg.PFCP.HeartbeatIntervalSeconds) * time.Second
	if hbInterval == 0 {
		hbInterval = 10 * time.Second
	}
	hbTimeout := time.Duration(cfg.PFCP.HeartbeatTimeoutSeconds) * time.Second
	if hbTimeout == 0 {
		hbTimeout = 30 * time.Second
	}

	peers := make([]*peer, 0, len(cfg.PFCP.SGWU))
	for _, p := range cfg.PFCP.SGWU {
		addr, err := net.ResolveUDPAddr("udp4", p.Addr)
		if err != nil {
			_ = conn.Close()
			return nil, fmt.Errorf("PFCP client: resolve peer %q addr %q: %w", p.Name, p.Addr, err)
		}
		peers = append(peers, &peer{
			cfg:   p,
			addr:  addr,
			state: PeerStatePending,
		})
	}

	return &Client{
		conn:        conn,
		localNodeID: localIP,
		localTS:     uint32(startTime.Unix()) + ntpEpochOffset,
		peers:       peers,
		hbInterval:  hbInterval,
		hbTimeout:   hbTimeout,
		log:         log,
	}, nil
}

// SetPeerStateCallback registers a callback that fires when a peer transitions
// between Established and Down states. Must be called before Serve().
func (c *Client) SetPeerStateCallback(fn func(peerName, peerAddr string, state PeerState)) {
	c.onPeerStateChange = fn
}

// Peers returns a snapshot of all PFCP peer states for API/observability.
func (c *Client) Peers() []PeerView {
	views := make([]PeerView, 0, len(c.peers))
	for _, p := range c.peers {
		p.mu.RLock()
		v := PeerView{
			Name:     p.cfg.Name,
			Addr:     p.cfg.Addr,
			State:    string(p.state),
			LastSeen: p.lastSeen,
		}
		if p.peerNodeID != nil {
			v.PeerNodeID = p.peerNodeID.String()
		}
		p.mu.RUnlock()
		views = append(views, v)
	}
	return views
}

// Serve starts the PFCP inbound read loop (C9) and the per-peer association
// lifecycle goroutines. Blocks until ctx is cancelled.
func (c *Client) Serve(ctx context.Context) error {
	// Register inbound handler before starting the read loop (C9).
	// This enables the SGW-C to receive Node Report Requests from SGW-U peers
	// reporting GTP-U path failures per TS 29.244 §7.4.5.
	c.conn.SetHandler(c.handle)

	// C9: start Serve loop before any Send() calls in managePeer goroutines.
	serveErrCh := make(chan error, 1)
	go func() {
		serveErrCh <- c.conn.Serve(ctx)
	}()

	var wg sync.WaitGroup
	for _, p := range c.peers {
		wg.Add(1)
		go func(pr *peer) {
			defer wg.Done()
			c.managePeer(ctx, pr)
		}(p)
	}
	wg.Wait()

	if err := <-serveErrCh; err != nil {
		return err
	}
	return nil
}

// managePeer drives the full association lifecycle for one SGW-U peer:
// attempt association → heartbeat loop → re-associate on failure.
func (c *Client) managePeer(ctx context.Context, p *peer) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if err := c.associate(ctx, p); err != nil {
			c.log.Warn("PFCP association failed — retrying in 5s",
				"peer", p.cfg.Name, "addr", p.cfg.Addr, "error", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		c.log.Info("PFCP association established", "peer", p.cfg.Name, "addr", p.cfg.Addr)
		c.heartbeatLoop(ctx, p)
		c.log.Warn("PFCP peer Down — re-attempting association",
			"peer", p.cfg.Name, "addr", p.cfg.Addr)
	}
}

// associate sends an Association Setup Request and processes the response per §5.2.1.
func (c *Client) associate(ctx context.Context, p *peer) error {
	seq := c.conn.AllocSeq()
	hdr := pfcpmsg.Header{
		Version:        1,
		MessageType:    pfcpmsg.MsgTypeAssociationSetupRequest,
		SequenceNumber: seq,
	}
	raw, err := pfcpmsg.Marshal(hdr, []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(c.localNodeID),
		pfcpie.NewRecoveryTimeStamp(c.localTS),
	})
	if err != nil {
		return fmt.Errorf("marshal AssociationSetupRequest: %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	respRaw, err := c.conn.Send(ctx2, p.addr, raw)
	if err != nil {
		p.mu.Lock()
		p.state = PeerStateDown
		p.mu.Unlock()
		return fmt.Errorf("AssociationSetupRequest to %s: %w", p.cfg.Addr, err)
	}

	resp, err := pfcpmsg.ParseAssociationSetupResponse(respRaw)
	if err != nil {
		return fmt.Errorf("parse AssociationSetupResponse from %s: %w", p.cfg.Addr, err)
	}

	// C11-equivalent: Cause is M per Table 7.4.2-1; already validated in ParseAssociationSetupResponse.
	cause, _ := resp.Cause.CauseValue()
	if cause != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("PFCP association rejected by %s: cause=%d", p.cfg.Addr, cause)
	}

	peerTS, _ := resp.RecoveryTimeStamp.RecoveryTimeStampValue()
	peerNodeID := resp.NodeID.NodeIDIPv4()

	p.mu.Lock()
	// Restart detection per TS 29.244 §5.2.1: Recovery Time Stamp change = peer restarted.
	if p.peerRecoveryTS != 0 && peerTS != p.peerRecoveryTS {
		c.log.Warn("PFCP peer restarted — Recovery Time Stamp changed",
			"peer", p.cfg.Name, "old_ts", p.peerRecoveryTS, "new_ts", peerTS)
	}
	p.state = PeerStateEstablished
	p.peerNodeID = peerNodeID
	p.peerRecoveryTS = peerTS
	p.lastSeen = time.Now()
	p.mu.Unlock()

	if c.onPeerStateChange != nil {
		c.onPeerStateChange(p.cfg.Name, p.cfg.Addr, PeerStateEstablished)
	}
	return nil
}

// heartbeatLoop sends periodic Heartbeat Requests per §6.1 until the peer is unreachable.
func (c *Client) heartbeatLoop(ctx context.Context, p *peer) {
	ticker := time.NewTicker(c.hbInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := c.heartbeat(ctx, p); err != nil {
				c.log.Warn("PFCP heartbeat failed",
					"peer", p.cfg.Name, "error", err)
				p.mu.Lock()
				p.state = PeerStateDown
				p.mu.Unlock()
				if c.onPeerStateChange != nil {
					c.onPeerStateChange(p.cfg.Name, p.cfg.Addr, PeerStateDown)
				}
				return
			}
		}
	}
}

// heartbeat sends a single Heartbeat Request and validates the response per §7.2.2/§7.2.3.
func (c *Client) heartbeat(ctx context.Context, p *peer) error {
	seq := c.conn.AllocSeq()
	hdr := pfcpmsg.Header{
		Version:        1,
		MessageType:    pfcpmsg.MsgTypeHeartbeatRequest,
		SequenceNumber: seq,
	}
	raw, err := pfcpmsg.Marshal(hdr, []*pfcpie.IE{
		pfcpie.NewRecoveryTimeStamp(c.localTS),
	})
	if err != nil {
		return fmt.Errorf("marshal HeartbeatRequest: %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, c.hbTimeout)
	defer cancel()
	respRaw, err := c.conn.Send(ctx2, p.addr, raw)
	if err != nil {
		return err
	}

	resp, err := pfcpmsg.ParseHeartbeatResponse(respRaw)
	if err != nil {
		return fmt.Errorf("parse HeartbeatResponse: %w", err)
	}

	p.mu.Lock()
	if resp.RecoveryTimeStamp != nil {
		peerTS, _ := resp.RecoveryTimeStamp.RecoveryTimeStampValue()
		// R15-REAUDIT-006: restart detection via heartbeat per TS 29.244 §6.1 / §5.2.1.
		// When Recovery Time Stamp changes, the peer has restarted and all its PFCP sessions
		// are invalid. Return an error to trigger peer Down state and re-association, which
		// ensures PFCP sessions are re-established after the peer recovers.
		if p.peerRecoveryTS != 0 && peerTS != p.peerRecoveryTS {
			oldTS := p.peerRecoveryTS
			p.peerRecoveryTS = peerTS
			p.lastSeen = time.Now()
			p.mu.Unlock()
			return fmt.Errorf("PFCP peer %s restarted: Recovery Time Stamp changed from %d to %d — triggering re-association",
				p.cfg.Name, oldTS, peerTS)
		}
		p.peerRecoveryTS = peerTS
	}
	p.lastSeen = time.Now()
	p.mu.Unlock()

	return nil
}

// AllocCPSEID allocates a new monotonically increasing CP-SEID for a PFCP session.
// SEID 0 is reserved per TS 29.244 §8.2.37; counter starts at 1.
func (c *Client) AllocCPSEID() uint64 {
	return c.seidCounter.Add(1)
}

// SelectPeer returns the first established SGW-U peer for session management.
// Returns an error if no peer is in the Established state.
// In Phase 5, only a single SGW-U peer is supported.
func (c *Client) SelectPeer() (*peer, error) {
	for _, p := range c.peers {
		p.mu.RLock()
		state := p.state
		addr := p.addr
		p.mu.RUnlock()
		if state == PeerStateEstablished {
			return &peer{cfg: p.cfg, addr: addr, state: state}, nil
		}
	}
	return nil, fmt.Errorf("PFCP: no SGW-U peer in Established state")
}

// EstablishSession sends a PFCP Session Establishment Request to the selected SGW-U peer
// per TS 29.244 Rel-15 §7.5.2 / Table 7.5.2.2-1.
// Returns a SessionResult with the UP-SEID and Created PDR IEs (allocated TEIDs).
func (c *Client) EstablishSession(ctx context.Context, params SessionParams) (*SessionResult, error) {
	p, err := c.SelectPeer()
	if err != nil {
		return nil, err
	}

	seq := c.conn.AllocSeq()
	hdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0, // initial SER: header SEID=0 per TS 29.244 §7.5.2
		MessageType:    pfcpmsg.MsgTypeSessionEstablishmentRequest,
		SequenceNumber: seq,
	}

	// CP F-SEID IE (M per Table 7.5.2.2-1): carries SGW-C's local SEID and IP.
	cpFSEID := pfcpie.NewFSEID(params.CPFSEID, params.LocalIP)

	ies := make([]*pfcpie.IE, 0, 2+len(params.CreatePDRs)+len(params.CreateFARs))
	ies = append(ies, pfcpie.NewNodeIDIPv4(c.localNodeID))
	ies = append(ies, cpFSEID)
	ies = append(ies, params.CreatePDRs...)
	ies = append(ies, params.CreateFARs...)

	raw, err := pfcpmsg.Marshal(hdr, ies)
	if err != nil {
		return nil, fmt.Errorf("marshal PFCP SessionEstablishmentRequest: %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	respRaw, err := c.conn.Send(ctx2, p.addr, raw)
	if err != nil {
		return nil, fmt.Errorf("PFCP SessionEstablishmentRequest to %s: %w", p.cfg.Addr, err)
	}

	resp, err := pfcpmsg.ParseSessionEstablishmentResponse(respRaw)
	if err != nil {
		return nil, fmt.Errorf("parse PFCP SessionEstablishmentResponse: %w", err)
	}

	cause, _ := resp.Cause.CauseValue()
	if cause != pfcpie.CauseRequestAccepted {
		return nil, fmt.Errorf("PFCP Session Establishment rejected by %s: cause=%d", p.cfg.Addr, cause)
	}

	// C11: UP F-SEID is validated as present on success by ParseSessionEstablishmentResponse.
	upFSEID, err := resp.UPSEID.FSEIDValue()
	if err != nil {
		return nil, fmt.Errorf("PFCP SessionEstablishmentResponse: decode UP F-SEID: %w", err)
	}

	c.log.Info("PFCP session established",
		"peer", p.cfg.Addr,
		"cp_seid", params.CPFSEID,
		"up_seid", upFSEID.SEID,
		"created_pdrs", len(resp.CreatedPDRs),
	)

	return &SessionResult{
		UPSEID:      upFSEID.SEID,
		CreatedPDRs: resp.CreatedPDRs,
	}, nil
}

// ModifySession sends a PFCP Session Modification Request per TS 29.244 Rel-15 §7.5.4.
// The upSEID is the SGW-U's UP-SEID returned at establishment (carried in the header).
// updates is the list of FAR changes to apply.
func (c *Client) ModifySession(ctx context.Context, cpSEID, upSEID uint64, updates []FARUpdate) error {
	p, err := c.SelectPeer()
	if err != nil {
		return err
	}

	var updateFARIEs []*pfcpie.IE
	for _, u := range updates {
		var ufpChildren []*pfcpie.IE
		ufpChildren = append(ufpChildren, pfcpie.NewDestinationInterface(u.DestInterface))
		if u.OuterTEID != 0 && u.OuterIP.IsValid() {
			ufpChildren = append(ufpChildren,
				pfcpie.NewOuterHeaderCreation(pfcpie.OHCDescGTPUUDPIPv4, u.OuterTEID, u.OuterIP))
		}
		updateFARIEs = append(updateFARIEs, pfcpie.NewUpdateFAR(
			pfcpie.NewFARID(u.FARID),
			pfcpie.NewApplyAction(u.ApplyAction),
			pfcpie.NewUpdateForwardingParameters(ufpChildren...),
		))
	}

	seq := c.conn.AllocSeq()
	hdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           upSEID, // Modification: header SEID = UP-SEID per §7.5.4
		MessageType:    pfcpmsg.MsgTypeSessionModificationRequest,
		SequenceNumber: seq,
	}

	raw, err := pfcpmsg.Marshal(hdr, updateFARIEs)
	if err != nil {
		return fmt.Errorf("marshal PFCP SessionModificationRequest: %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	respRaw, err := c.conn.Send(ctx2, p.addr, raw)
	if err != nil {
		return fmt.Errorf("PFCP SessionModificationRequest to %s: %w", p.cfg.Addr, err)
	}

	resp, err := pfcpmsg.ParseSessionModificationResponse(respRaw)
	if err != nil {
		return fmt.Errorf("parse PFCP SessionModificationResponse: %w", err)
	}

	cause, _ := resp.Cause.CauseValue()
	if cause != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("PFCP Session Modification rejected by %s: cause=%d (cp_seid=%d)", p.cfg.Addr, cause, cpSEID)
	}

	c.log.Info("PFCP session modified", "peer", p.cfg.Addr, "cp_seid", cpSEID, "up_seid", upSEID)
	return nil
}

// AddBearerRules sends a PFCP Session Modification Request to provision new PDR/FAR pairs
// for a dedicated bearer per TS 29.244 Rel-15 §7.5.4 / Table 7.5.4.1-1.
// createPDRs and createFARs are the grouped IEs built by the caller.
// Returns the Created PDR IEs from the response (carrying UP-allocated TEIDs).
func (c *Client) AddBearerRules(ctx context.Context, cpSEID, upSEID uint64, createPDRs, createFARs []*pfcpie.IE) ([]*pfcpie.IE, error) {
	p, err := c.SelectPeer()
	if err != nil {
		return nil, err
	}

	ies := make([]*pfcpie.IE, 0, len(createPDRs)+len(createFARs))
	ies = append(ies, createPDRs...)
	ies = append(ies, createFARs...)

	seq := c.conn.AllocSeq()
	hdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           upSEID,
		MessageType:    pfcpmsg.MsgTypeSessionModificationRequest,
		SequenceNumber: seq,
	}

	raw, err := pfcpmsg.Marshal(hdr, ies)
	if err != nil {
		return nil, fmt.Errorf("marshal PFCP SessionModificationRequest (AddBearerRules): %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	respRaw, err := c.conn.Send(ctx2, p.addr, raw)
	if err != nil {
		return nil, fmt.Errorf("PFCP SessionModificationRequest (AddBearerRules) to %s: %w", p.cfg.Addr, err)
	}

	resp, err := pfcpmsg.ParseSessionModificationResponse(respRaw)
	if err != nil {
		return nil, fmt.Errorf("parse PFCP SessionModificationResponse (AddBearerRules): %w", err)
	}

	cause, _ := resp.Cause.CauseValue()
	if cause != pfcpie.CauseRequestAccepted {
		return nil, fmt.Errorf("PFCP AddBearerRules rejected by %s: cause=%d (cp_seid=%d)", p.cfg.Addr, cause, cpSEID)
	}

	c.log.Info("PFCP bearer rules added", "peer", p.cfg.Addr, "cp_seid", cpSEID, "up_seid", upSEID)
	return resp.CreatedPDRs, nil
}

// RemoveBearerRules sends a PFCP Session Modification Request to remove PDR/FAR pairs
// for a dedicated bearer being deleted per TS 29.244 Rel-15 §7.5.4 / Table 7.5.4.1-1.
// pdrIDs and farIDs are the IDs assigned at creation time.
func (c *Client) RemoveBearerRules(ctx context.Context, cpSEID, upSEID uint64, pdrIDs, farIDs []uint32) error {
	p, err := c.SelectPeer()
	if err != nil {
		return err
	}

	ies := make([]*pfcpie.IE, 0, len(pdrIDs)+len(farIDs))
	for _, id := range pdrIDs {
		ies = append(ies, pfcpie.NewRemovePDR(pfcpie.NewPDRID(uint16(id))))
	}
	for _, id := range farIDs {
		ies = append(ies, pfcpie.NewRemoveFAR(pfcpie.NewFARID(id)))
	}

	seq := c.conn.AllocSeq()
	hdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           upSEID,
		MessageType:    pfcpmsg.MsgTypeSessionModificationRequest,
		SequenceNumber: seq,
	}

	raw, err := pfcpmsg.Marshal(hdr, ies)
	if err != nil {
		return fmt.Errorf("marshal PFCP SessionModificationRequest (RemoveBearerRules): %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	respRaw, err := c.conn.Send(ctx2, p.addr, raw)
	if err != nil {
		return fmt.Errorf("PFCP SessionModificationRequest (RemoveBearerRules) to %s: %w", p.cfg.Addr, err)
	}

	resp, err := pfcpmsg.ParseSessionModificationResponse(respRaw)
	if err != nil {
		return fmt.Errorf("parse PFCP SessionModificationResponse (RemoveBearerRules): %w", err)
	}

	cause, _ := resp.Cause.CauseValue()
	if cause != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("PFCP RemoveBearerRules rejected by %s: cause=%d (cp_seid=%d)", p.cfg.Addr, cause, cpSEID)
	}

	c.log.Info("PFCP bearer rules removed", "peer", p.cfg.Addr, "cp_seid", cpSEID, "up_seid", upSEID)
	return nil
}

// DeleteSession sends a PFCP Session Deletion Request per TS 29.244 Rel-15 §7.5.6.
// The upSEID is the SGW-U's UP-SEID returned at establishment (carried in the header).
// Per Table 7.5.6.1-1 the request body is empty.
func (c *Client) DeleteSession(ctx context.Context, cpSEID, upSEID uint64) error {
	p, err := c.SelectPeer()
	if err != nil {
		return err
	}

	seq := c.conn.AllocSeq()
	hdr := pfcpmsg.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           upSEID, // Deletion: header SEID = UP-SEID per §7.5.6
		MessageType:    pfcpmsg.MsgTypeSessionDeletionRequest,
		SequenceNumber: seq,
	}

	// Per Table 7.5.6.1-1: no IEs in the deletion request body.
	raw, err := pfcpmsg.Marshal(hdr, nil)
	if err != nil {
		return fmt.Errorf("marshal PFCP SessionDeletionRequest: %w", err)
	}

	ctx2, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	respRaw, err := c.conn.Send(ctx2, p.addr, raw)
	if err != nil {
		return fmt.Errorf("PFCP SessionDeletionRequest to %s: %w", p.cfg.Addr, err)
	}

	resp, err := pfcpmsg.ParseSessionDeletionResponse(respRaw)
	if err != nil {
		return fmt.Errorf("parse PFCP SessionDeletionResponse: %w", err)
	}

	cause, _ := resp.Cause.CauseValue()
	if cause != pfcpie.CauseRequestAccepted {
		return fmt.Errorf("PFCP Session Deletion rejected by %s: cause=%d (cp_seid=%d)", p.cfg.Addr, cause, cpSEID)
	}

	c.log.Info("PFCP session deleted", "peer", p.cfg.Addr, "cp_seid", cpSEID, "up_seid", upSEID)
	return nil
}

// handle is the inbound PFCP request handler for the SGW-C.
// The SGW-C receives Node Report Requests from SGW-U peers per TS 29.244 §7.4.5.
func (c *Client) handle(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	switch hdr.MessageType {
	case pfcpmsg.MsgTypeNodeReportRequest:
		c.handleNodeReportRequest(conn, addr, hdr, raw)
	default:
		c.log.Warn("PFCP unhandled inbound message type from SGW-U",
			"from", addr, "type", hdr.MessageType)
	}
}

// handleNodeReportRequest processes a PFCP Node Report Request from the SGW-U
// per TS 29.244 §7.4.5.1 / Table 7.4.5.1.1-1.
// Per §7.4.5.2: the CP function shall send a Node Report Response.
func (c *Client) handleNodeReportRequest(conn *pfcptransport.Conn, addr *net.UDPAddr, hdr pfcpmsg.Header, raw []byte) {
	req, err := pfcpmsg.ParseNodeReportRequest(raw)
	if err != nil {
		c.log.Warn("PFCP NodeReportRequest parse error", "from", addr, "error", err)
		return
	}

	flags, _ := req.NodeReportType.NodeReportTypeFlags()
	if flags&pfcpie.NodeReportTypeUPFR != 0 && req.UserPlanPathFailureReport != nil {
		children, childErr := req.UserPlanPathFailureReport.Children()
		if childErr == nil {
			for _, child := range children {
				if ip := child.RemoteGTPUPeerIPv4(); ip != nil {
					c.log.Warn("PFCP Node Report: user-plane path failure detected",
						"sgwu", addr, "failed_gtp_peer", ip)
				}
			}
		}
	}

	// Send Node Report Response per Table 7.4.5.2.1-1: Node ID (M), Cause (M).
	respHdr := pfcpmsg.Header{
		Version:        1,
		MessageType:    pfcpmsg.MsgTypeNodeReportResponse,
		SequenceNumber: req.SequenceNumber,
	}
	respRaw, marshalErr := pfcpmsg.Marshal(respHdr, []*pfcpie.IE{
		pfcpie.NewNodeIDIPv4(c.localNodeID),
		pfcpie.NewCause(pfcpie.CauseRequestAccepted),
	})
	if marshalErr != nil {
		c.log.Error("PFCP marshal NodeReportResponse failed", "error", marshalErr)
		return
	}
	if err := conn.Reply(addr, respRaw); err != nil {
		c.log.Warn("PFCP send NodeReportResponse failed", "to", addr, "error", err)
	}
}

// Close shuts down the PFCP transport.
func (c *Client) Close() error {
	return c.conn.Close()
}

// extractIPv4 parses the host portion of an "ip:port" string and returns its IPv4.
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
