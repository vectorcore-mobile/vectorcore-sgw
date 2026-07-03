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
	Procedures                   *collision.Tracker
	SecondaryRATUsageDataReports []SecondaryRATUsageDataReport

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
	defer s.mu.Unlock()
	if !validTransition(s.State, next) {
		return false
	}
	s.State = next
	s.UpdatedAt = time.Now()
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
	defer s.mu.Unlock()
	s.Bearers[b.EBI] = b
	s.UpdatedAt = time.Now()
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
	defer s.mu.Unlock()
	for _, b := range s.Bearers {
		b.ENBS1UFTEID = bearer.FTEID{}
	}
	s.UpdatedAt = time.Now()
}

// InvalidatePFCPBinding clears PFCP state learned from an SGW-U that has
// restarted or lost its association. TS 29.244 Rel-15 §6.2.2 heartbeat
// liveness and §7.4.2 Recovery Time Stamp changes mean the peer PFCP context
// is no longer safe to reuse; SGW-U allocated F-TEIDs must not be advertised.
func (s *SGWSession) InvalidatePFCPBinding() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	hadPFCP := s.PFCP.Established || s.PFCP.LocalFSEID.SEID != 0 || s.PFCP.SGWUFSEID.SEID != 0
	if !hadPFCP {
		return false
	}
	s.PFCP = PFCPSessionBinding{}
	for _, b := range s.Bearers {
		b.SGWS1UFTEID = bearer.FTEID{}
		b.SGWS5UFTEID = bearer.FTEID{}
	}
	if s.State != StateDeleting && s.State != StateDeleted {
		s.State = StateRecovering
	}
	s.UpdatedAt = time.Now()
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
	defer s.mu.Unlock()
	delete(s.Bearers, ebi)
	s.UpdatedAt = time.Now()
}

// RecordSecondaryRATUsageDataReports appends opaque NSA/DCNR usage reports to
// the PDN session with defensive payload copies.
func (s *SGWSession) RecordSecondaryRATUsageDataReports(reports []SecondaryRATUsageDataReport) {
	if len(reports) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, report := range reports {
		copied := report
		copied.Payload = append([]byte(nil), report.Payload...)
		if copied.ReceivedAt.IsZero() {
			copied.ReceivedAt = time.Now()
		}
		s.SecondaryRATUsageDataReports = append(s.SecondaryRATUsageDataReports, copied)
	}
	s.UpdatedAt = time.Now()
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
