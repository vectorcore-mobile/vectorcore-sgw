// Package session holds the SGW-C session and bearer state model
// per 3GPP TS 23.401 and TS 23.214.
package session

import (
	"net/netip"
	"sync"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/collision"
)

// SessionState is the lifecycle state of an SGW-C session.
type SessionState string

const (
	StatePending    SessionState = "pending"    // CSReq received; PGW and PFCP setup not yet complete
	StateActive     SessionState = "active"     // fully established; data path live
	StateModifying  SessionState = "modifying"  // bearer modification in progress
	StateRecovering SessionState = "recovering" // SGW-U PFCP binding invalidated after restart/loss
	StateDeleting   SessionState = "deleting"   // deletion in progress
	StateDeleted    SessionState = "deleted"    // fully cleaned up
)

const (
	BearerActivitySourceCreateSession = "create_session"
	BearerActivitySourceSetBearer     = "set_bearer"
	BearerActivitySourceDeleteBearer  = "delete_bearer"
	BearerActivitySourceReleaseAccess = "release_access_bearers"
)

// FTEID is a decoded F-TEID used in session state.
// Interface type and CHOOSE bit are consumed at decode time and not stored here.
type FTEID struct {
	TEID uint32
	IPv4 netip.Addr
}

// FSEID is a PFCP F-SEID (Session Endpoint Identifier) per TS 29.244 Section 8.2.37.
type FSEID struct {
	SEID uint64
	IPv4 netip.Addr
}

// PFCPSessionBinding holds the Sxa/PFCP binding for a session.
// Populated during Phase 4/5; zero value means not yet established.
type PFCPSessionBinding struct {
	LocalFSEID  FSEID
	SGWUFSEID   FSEID
	SGWUName    string
	SGWUAddr    string
	Established bool
}

type PFCPReconciliationState string

const (
	PFCPReconciliationUnknown      PFCPReconciliationState = "unknown"
	PFCPReconciliationMatched      PFCPReconciliationState = "matched"
	PFCPReconciliationMissing      PFCPReconciliationState = "missing"
	PFCPReconciliationMismatched   PFCPReconciliationState = "mismatched"
	PFCPReconciliationUnverifiable PFCPReconciliationState = "unverifiable"
	PFCPReconciliationNoBinding    PFCPReconciliationState = "no_binding"
)

type PFCPReconciliationStatus struct {
	State  PFCPReconciliationState
	At     time.Time
	Reason string
}

// PGWPathState records SGW-C's view of the S5/S8-C PGW path for this PDN.
type PGWPathState string

const (
	PGWPathStateUnknown   PGWPathState = "unknown"
	PGWPathStateUp        PGWPathState = "up"
	PGWPathStateDegraded  PGWPathState = "degraded"
	PGWPathStateSuspect   PGWPathState = "suspect"
	PGWPathStateDown      PGWPathState = "down"
	PGWPathStateRestarted PGWPathState = "restarted"
)

// PGWFailureStatus is an API-safe snapshot of PGW path/restart state.
type PGWFailureStatus struct {
	PathState         PGWPathState
	PGWAddr           string
	PathDownAt        time.Time
	RestartDetectedAt time.Time
	RecoverySeen      bool
	RecoveryCounter   uint8
}

// MMERestorationState records SGW-C's view of the S11/S4 MME path for
// TS 23.007 MME restoration / Network Triggered Service Restoration.
type MMERestorationState string

const (
	MMERestorationStateUnknown            MMERestorationState = "unknown"
	MMERestorationStateUp                 MMERestorationState = "up"
	MMERestorationStateDegraded           MMERestorationState = "degraded"
	MMERestorationStateSuspect            MMERestorationState = "suspect"
	MMERestorationStateDown               MMERestorationState = "down"
	MMERestorationStateRestarted          MMERestorationState = "restarted"
	MMERestorationStateRestorationPending MMERestorationState = "restoration_pending"
)

// MMERestorationPolicyAction records the operator policy decision for an
// MME restoration candidate. Later restoration phases enforce this decision.
type MMERestorationPolicyAction string

const (
	MMERestorationPolicyUnknown  MMERestorationPolicyAction = "unknown"
	MMERestorationPolicyPreserve MMERestorationPolicyAction = "preserve"
	MMERestorationPolicyDelete   MMERestorationPolicyAction = "delete"
)

// MMERestorationStatus is an API-safe snapshot of MME restart/path state.
type MMERestorationStatus struct {
	State               MMERestorationState
	MMEAddr             string
	PathDownAt          time.Time
	RestartDetectedAt   time.Time
	RecoverySeen        bool
	RecoveryCounter     uint8
	RestorationPending  bool
	PolicyAction        MMERestorationPolicyAction
	PolicyReason        string
	DDNTriggered        bool
	DDNTriggeredAt      time.Time
	DDNSequence         uint32
	DDNAcked            bool
	DDNAckedAt          time.Time
	DDNAckCause         uint8
	DDNFailureAt        time.Time
	DDNFailureCause     uint8
	DDNFailureReason    string
	DDNControlAction    string
	DDNControlPriority  string
	DDNControlReason    string
	DDNControlRetryAt   time.Time
	DDNControlDecidedAt time.Time
	StopPagingSent      bool
	StopPagingSentAt    time.Time
	StopPagingSequence  uint32
	UserPlaneRestored   bool
	UserPlaneRestoredAt time.Time
	RestoredEBI         uint8
}

// SecondaryRATUsageDataReport records an opaque Rel-15 Secondary RAT Usage
// Data Report IE payload received on S11. Interpretation/forwarding is handled
// by higher procedure phases; session state keeps the exact report bytes.
type SecondaryRATUsageDataReport struct {
	ReceivedAt      time.Time
	SourceProcedure string
	MMEPeer         string
	SGWS11TEID      uint32
	SequenceNumber  uint32
	Payload         []byte
}

// SGWSession is the SGW-C control-plane state for one PDN session
// per 3GPP TS 23.401 Section 5.3.2 and TS 23.214.
type SGWSession struct {
	mu sync.RWMutex

	SessionID      string
	IMSI           string
	APN            string
	RATType        uint8
	ServingNetwork string // "MCC-MNC" e.g. "311-435"

	// S11 F-TEIDs
	MMEControlFTEID FTEID // MME's S11 control TEID
	SGWS11FTEID     FTEID // SGW-C's own S11 control TEID

	// S5/S8-C F-TEIDs (set in Phase 3)
	PGWControlFTEID FTEID
	SGWS5CFTEID     FTEID

	UEIPv4          netip.Addr // assigned by PGW in PAA (set in Phase 3)
	DefaultBearerID uint8

	Bearers                      map[uint8]*bearer.Bearer // keyed by EBI
	PFCP                         PFCPSessionBinding
	PFCPReconciliation           PFCPReconciliationStatus
	Procedures                   *collision.Tracker
	SecondaryRATUsageDataReports []SecondaryRATUsageDataReport
	PGWFailure                   PGWFailureStatus
	MMERestoration               MMERestorationStatus
	checkpointSink               CheckpointSink

	State     SessionState
	CreatedAt time.Time
	UpdatedAt time.Time

	// nextRuleID tracks the next PFCP PDR/FAR ID pair.
	// IDs 1 and 2 are reserved for the default bearer PDRs/FARs at session creation.
	// Each dedicated bearer consumes 2 IDs (uplink + downlink).
	nextRuleID uint32
}

// AllocBearerRuleIDs atomically allocates the next PDR ID pair (uplink, downlink)
// and FAR ID pair (uplink, downlink) for a dedicated bearer's PFCP rules.
// Default bearer uses IDs 1 (UL PDR/FAR) and 2 (DL PDR/FAR); dedicated bearers start at 3.
func (s *SGWSession) AllocBearerRuleIDs() (pdrUL, pdrDL uint16, farUL, farDL uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.nextRuleID == 0 {
		s.nextRuleID = 3 // 1 and 2 are the default bearer
	}
	base := s.nextRuleID
	s.nextRuleID += 2
	return uint16(base), uint16(base + 1), base, base + 1
}

// Transition moves the session to the given state.
// Returns false if the transition is not valid from the current state.
func (s *SGWSession) Transition(next SessionState) bool {
	s.mu.Lock()
	if !validTransition(s.State, next) {
		s.mu.Unlock()
		return false
	}
	s.State = next
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
	return true
}

// GetState returns the current session state safely.
func (s *SGWSession) GetState() SessionState {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.State
}

func (s *SGWSession) ProcedureTracker() *collision.Tracker {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.Procedures == nil {
		s.Procedures = collision.NewTracker()
	}
	return s.Procedures
}

// PFCPBinding returns a snapshot of the current PFCP binding.
func (s *SGWSession) PFCPBinding() PFCPSessionBinding {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PFCP
}

func (s *SGWSession) PFCPReconciliationSnapshot() PFCPReconciliationStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PFCPReconciliation
}

func (s *SGWSession) SetSGWS5CFTEID(f FTEID) {
	s.mu.Lock()
	s.SGWS5CFTEID = f
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
}

func (s *SGWSession) SetPGWControlFTEID(f FTEID) {
	s.mu.Lock()
	s.PGWControlFTEID = f
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
}

func (s *SGWSession) SetUEIPv4(addr netip.Addr) {
	s.mu.Lock()
	s.UEIPv4 = addr
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
}

func (s *SGWSession) SetPFCPBinding(binding PFCPSessionBinding) {
	s.mu.Lock()
	s.PFCP = binding
	s.PFCPReconciliation = PFCPReconciliationStatus{}
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
}

func (s *SGWSession) MarkPFCPReconciliation(state PFCPReconciliationState, reason string, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.PFCPReconciliation = PFCPReconciliationStatus{State: state, At: at, Reason: reason}
	switch state {
	case PFCPReconciliationMatched:
		if s.State == StateRecovering {
			s.State = StateActive
		}
		s.PFCP.Established = true
	case PFCPReconciliationMissing, PFCPReconciliationMismatched, PFCPReconciliationUnverifiable, PFCPReconciliationNoBinding:
		if s.State != StateDeleting && s.State != StateDeleted {
			s.State = StateRecovering
		}
	}
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// GetBearer returns the bearer for the given EBI, or nil.
func (s *SGWSession) GetBearer(ebi uint8) *bearer.Bearer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Bearers[ebi]
}

// BearerList returns a snapshot slice of all bearers in this session,
// safe for concurrent use while other goroutines hold s.mu for writes.
func (s *SGWSession) BearerList() []*bearer.Bearer {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*bearer.Bearer, 0, len(s.Bearers))
	for _, b := range s.Bearers {
		list = append(list, b)
	}
	return list
}

// SetBearer stores a bearer under its EBI.
func (s *SGWSession) SetBearer(b *bearer.Bearer) {
	s.mu.Lock()
	now := time.Now()
	markBearerControlActivityLocked(b, BearerActivitySourceSetBearer, now)
	s.Bearers[b.EBI] = b
	s.UpdatedAt = now
	s.mu.Unlock()
	s.checkpoint()
}

// MarkBearerControlActivity records GTP-C/control-plane activity for one bearer.
func (s *SGWSession) MarkBearerControlActivity(ebi uint8, source string, at time.Time) bool {
	s.mu.Lock()
	b := s.Bearers[ebi]
	if b == nil {
		s.mu.Unlock()
		return false
	}
	if at.IsZero() {
		at = time.Now()
	}
	markBearerControlActivityLocked(b, source, at)
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
	return true
}

// MarkBearerUserPlaneActivity records user-plane activity for one bearer. Later
// phases will feed this from PFCP usage reports or eBPF counters.
func (s *SGWSession) MarkBearerUserPlaneActivity(ebi uint8, source string, at time.Time) bool {
	s.mu.Lock()
	b := s.Bearers[ebi]
	if b == nil {
		s.mu.Unlock()
		return false
	}
	if at.IsZero() {
		at = time.Now()
	}
	b.LastUserPlaneActivityAt = at
	if source != "" {
		b.LastActivitySource = source
	}
	b.InactiveSince = time.Time{}
	b.CleanupEligible = false
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
	return true
}

// BearerCount returns the number of bearers currently in this session.
func (s *SGWSession) BearerCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.Bearers)
}

// ClearENBFTEIDs removes eNodeB S1-U addresses and TEIDs from all bearers.
// Per TS 23.401 Rel-15 §5.3.5, on Release Access Bearers the SGW releases
// eNodeB-related state while retaining all other session and bearer information.
func (s *SGWSession) ClearENBFTEIDs() {
	s.mu.Lock()
	now := time.Now()
	for _, b := range s.Bearers {
		b.ENBS1UFTEID = bearer.FTEID{}
		markBearerControlActivityLocked(b, BearerActivitySourceReleaseAccess, now)
	}
	s.UpdatedAt = now
	s.mu.Unlock()
	s.checkpoint()
}

// InvalidatePFCPBinding clears PFCP state learned from an SGW-U that has
// restarted or lost its association. TS 29.244 Rel-15 §6.2.2 heartbeat
// liveness and §7.4.2 Recovery Time Stamp changes mean the peer PFCP context
// is no longer safe to reuse; SGW-U allocated F-TEIDs must not be advertised.
func (s *SGWSession) InvalidatePFCPBinding() bool {
	s.mu.Lock()
	hadPFCP := s.PFCP.Established || s.PFCP.LocalFSEID.SEID != 0 || s.PFCP.SGWUFSEID.SEID != 0
	if !hadPFCP {
		s.mu.Unlock()
		return false
	}
	s.PFCP = PFCPSessionBinding{}
	s.PFCPReconciliation = PFCPReconciliationStatus{
		State:  PFCPReconciliationMissing,
		At:     time.Now(),
		Reason: "pfcp-binding-invalidated",
	}
	for _, b := range s.Bearers {
		b.SGWS1UFTEID = bearer.FTEID{}
		b.SGWS5UFTEID = bearer.FTEID{}
	}
	if s.State != StateDeleting && s.State != StateDeleted {
		s.State = StateRecovering
	}
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
	return true
}

// InvalidatePFCPBindingForPeer clears PFCP state only when the session is bound
// to the affected SGW-U peer. This preserves sessions on unrelated SGW-U peers
// when one PFCP association is lost or restarted.
func (s *SGWSession) InvalidatePFCPBindingForPeer(peerName, peerAddr string) bool {
	s.mu.RLock()
	matches := s.PFCP.SGWUName == peerName && s.PFCP.SGWUAddr == peerAddr
	s.mu.RUnlock()
	if !matches {
		return false
	}
	return s.InvalidatePFCPBinding()
}

// DeleteBearer removes the bearer with the given EBI.
func (s *SGWSession) DeleteBearer(ebi uint8) {
	s.mu.Lock()
	if b := s.Bearers[ebi]; b != nil {
		markBearerControlActivityLocked(b, BearerActivitySourceDeleteBearer, time.Now())
	}
	delete(s.Bearers, ebi)
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
}

func markBearerControlActivityLocked(b *bearer.Bearer, source string, at time.Time) {
	if b == nil {
		return
	}
	if at.IsZero() {
		at = time.Now()
	}
	b.LastControlActivityAt = at
	if source != "" {
		b.LastActivitySource = source
	}
	b.InactiveSince = time.Time{}
	b.CleanupEligible = false
}

// RecordSecondaryRATUsageDataReports appends opaque NSA/DCNR usage reports to
// the PDN session with defensive payload copies.
func (s *SGWSession) RecordSecondaryRATUsageDataReports(reports []SecondaryRATUsageDataReport) {
	if len(reports) == 0 {
		return
	}
	s.mu.Lock()
	for _, report := range reports {
		copied := report
		copied.Payload = append([]byte(nil), report.Payload...)
		if copied.ReceivedAt.IsZero() {
			copied.ReceivedAt = time.Now()
		}
		s.SecondaryRATUsageDataReports = append(s.SecondaryRATUsageDataReports, copied)
	}
	s.UpdatedAt = time.Now()
	s.mu.Unlock()
	s.checkpoint()
}

// SecondaryRATUsageReports returns a copy of stored NSA/DCNR usage reports.
func (s *SGWSession) SecondaryRATUsageReports() []SecondaryRATUsageDataReport {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]SecondaryRATUsageDataReport, len(s.SecondaryRATUsageDataReports))
	for i, report := range s.SecondaryRATUsageDataReports {
		out[i] = report
		out[i].Payload = append([]byte(nil), report.Payload...)
	}
	return out
}

// PGWFailureSnapshot returns the current PGW path/restart state for this session.
func (s *SGWSession) PGWFailureSnapshot() PGWFailureStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PGWFailure
}

// MMERestorationSnapshot returns the current MME path/restart state for this session.
func (s *SGWSession) MMERestorationSnapshot() MMERestorationStatus {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.MMERestoration
}

// SetPGWPathState updates this session's PGW path state.
func (s *SGWSession) SetPGWPathState(state PGWPathState, pgwAddr string, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.PGWFailure.PathState = state
	if pgwAddr != "" {
		s.PGWFailure.PGWAddr = pgwAddr
	}
	if state == PGWPathStateDown && s.PGWFailure.PathDownAt.IsZero() {
		s.PGWFailure.PathDownAt = at
	}
	if state == PGWPathStateUp {
		s.PGWFailure.PathDownAt = time.Time{}
	}
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkPGWRestart records that the owning PGW has advertised a changed Recovery IE.
func (s *SGWSession) MarkPGWRestart(pgwAddr string, recovery uint8, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.PGWFailure.PathState = PGWPathStateRestarted
	s.PGWFailure.PGWAddr = pgwAddr
	s.PGWFailure.RestartDetectedAt = at
	s.PGWFailure.RecoverySeen = true
	s.PGWFailure.RecoveryCounter = recovery
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// SetMMEPathState updates this session's MME S11/S4 path state.
func (s *SGWSession) SetMMEPathState(state MMERestorationState, mmeAddr string, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.State = state
	if mmeAddr != "" {
		s.MMERestoration.MMEAddr = mmeAddr
	}
	if state == MMERestorationStateDown && s.MMERestoration.PathDownAt.IsZero() {
		s.MMERestoration.PathDownAt = at
	}
	if state == MMERestorationStateUp {
		s.MMERestoration.PathDownAt = time.Time{}
	}
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestart records that the owning MME advertised a changed Recovery IE.
// TS 23.007 §16.1A.1 lets SGW either delete affected contexts or follow NTSR;
// Phase 2 only marks the contexts so later phases can apply policy.
func (s *SGWSession) MarkMMERestart(mmeAddr string, recovery uint8, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.State = MMERestorationStateRestorationPending
	s.MMERestoration.MMEAddr = mmeAddr
	s.MMERestoration.RestartDetectedAt = at
	s.MMERestoration.RecoverySeen = true
	s.MMERestoration.RecoveryCounter = recovery
	s.MMERestoration.RestorationPending = true
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// SetMMERestorationPolicy records the policy decision for a pending MME
// restoration candidate without enforcing it.
func (s *SGWSession) SetMMERestorationPolicy(action MMERestorationPolicyAction, reason string, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.PolicyAction = action
	s.MMERestoration.PolicyReason = reason
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestorationDDNTriggered records that SGW-C sent a DDN for NTSR.
func (s *SGWSession) MarkMMERestorationDDNTriggered(seq uint32, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.DDNTriggered = true
	s.MMERestoration.DDNTriggeredAt = at
	s.MMERestoration.DDNSequence = seq
	s.MMERestoration.DDNFailureReason = ""
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestorationDDNFailed records that DDN trigger send failed before an
// MME response could be expected.
func (s *SGWSession) MarkMMERestorationDDNFailed(reason string, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.DDNFailureReason = reason
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestorationDDNControlDecision records the DDN throttling/priority
// decision made before SGW-C attempts an S11 DDN send.
func (s *SGWSession) MarkMMERestorationDDNControlDecision(action, priority, reason string, retryAfter time.Duration, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.DDNControlAction = action
	s.MMERestoration.DDNControlPriority = priority
	s.MMERestoration.DDNControlReason = reason
	s.MMERestoration.DDNControlDecidedAt = at
	if retryAfter > 0 {
		s.MMERestoration.DDNControlRetryAt = at.Add(retryAfter)
	} else {
		s.MMERestoration.DDNControlRetryAt = time.Time{}
	}
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestorationDDNAck records an MME DDN Ack response.
func (s *SGWSession) MarkMMERestorationDDNAck(cause uint8, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.DDNAcked = true
	s.MMERestoration.DDNAckedAt = at
	s.MMERestoration.DDNAckCause = cause
	s.MMERestoration.DDNFailureReason = ""
	if cause == 16 && s.State != StateDeleting && s.State != StateDeleted {
		s.State = StateRecovering
	}
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestorationDDNFailureIndication records an MME DDN Failure Indication.
func (s *SGWSession) MarkMMERestorationDDNFailureIndication(cause uint8, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.DDNFailureAt = at
	s.MMERestoration.DDNFailureCause = cause
	s.MMERestoration.DDNFailureReason = "ddn-failure-indication"
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestorationStopPagingSent records an SGW-C Stop Paging Indication.
func (s *SGWSession) MarkMMERestorationStopPagingSent(seq uint32, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.StopPagingSent = true
	s.MMERestoration.StopPagingSentAt = at
	s.MMERestoration.StopPagingSequence = seq
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

// MarkMMERestorationUserPlaneRestored records that normal Modify Bearer resume
// restored access-side forwarding for a preserved MME restoration session.
func (s *SGWSession) MarkMMERestorationUserPlaneRestored(ebi uint8, at time.Time) {
	s.mu.Lock()
	if at.IsZero() {
		at = time.Now()
	}
	s.MMERestoration.UserPlaneRestored = true
	s.MMERestoration.UserPlaneRestoredAt = at
	s.MMERestoration.RestoredEBI = ebi
	s.MMERestoration.RestorationPending = false
	s.MMERestoration.State = MMERestorationStateUp
	if s.State == StateRecovering {
		s.State = StateActive
	}
	s.UpdatedAt = at
	s.mu.Unlock()
	s.checkpoint()
}

func validTransition(from, to SessionState) bool {
	switch from {
	case StatePending:
		return to == StateActive || to == StateRecovering || to == StateDeleting || to == StateDeleted
	case StateActive:
		return to == StateModifying || to == StateRecovering || to == StateDeleting
	case StateModifying:
		return to == StateActive || to == StateRecovering || to == StateDeleting
	case StateRecovering:
		return to == StateActive || to == StateDeleting || to == StateDeleted
	case StateDeleting:
		return to == StateDeleted
	}
	return false
}
