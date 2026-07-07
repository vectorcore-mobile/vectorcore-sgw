// Package session holds the SGW-U data-plane session state per TS 29.244 Rel-15 §5.3.
//
// The SGW-U maintains PDRs and FARs for each session established by the SGW-C
// via PFCP Session Establishment Request (Table 7.5.2.1-1). The store is the
// in-memory model; actual GTP-U forwarding uses this state.
package session

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
)

// PDR is a Packet Detection Rule per TS 29.244 Rel-15 §5.2.1.
// Minimal fields for Phase 5: only what is needed for TEID-based GTP-U matching.
type PDR struct {
	ID              uint16     // PDR ID — 16-bit per §8.2.1 (Table 8.1.2-1)
	Precedence      uint32     // lower value = higher priority per §8.2.2
	SourceInterface uint8      // 0=Access,1=Core per §8.2.2
	LocalTEID       uint32     // allocated TEID (when CHOOSE was set in F-TEID IE)
	LocalIP         netip.Addr // SGW-U GTP-U IP for this PDR
	FARID           uint32     // FAR ID to apply on match
	EBI             uint8      // EPS Bearer ID carried by VectorCore PFCP metadata
	QCI             uint8      // EPS bearer QCI carried by VectorCore PFCP metadata
	QoSValid        bool       // true when EBI/QCI metadata was supplied by SGW-C
}

// FAR is a Forwarding Action Rule per TS 29.244 Rel-15 §5.2.1.
type FAR struct {
	ID            uint32     // FAR ID — 32-bit per TS 29.244 §8.2.74 / Table 8.1.2-1 row 108
	ApplyAction   uint8      // bit flags: DROP=0x01, FORW=0x02 per §8.2.26
	DestInterface uint8      // destination interface (0=Access, 1=Core)
	OuterTEID     uint32     // outer header creation TEID (for GTP-U encapsulation)
	OuterIP       netip.Addr // outer header creation peer IP
}

// Session is a PFCP session binding on the SGW-U per TS 29.244 Rel-15 §5.3.
// Established by PFCP Session Establishment Request and stored here.
type Session struct {
	// CPSEID is the SGW-C's CP-SEID — the primary key used to look up sessions.
	// Derived from the CP F-SEID IE in the Session Establishment Request.
	CPSEID uint64
	// UPSEID is the SGW-U's own SEID, allocated locally at establishment.
	// Carried in the UP F-SEID IE of the Session Establishment Response.
	UPSEID uint64
	// CPNodeKey is the canonical node key of the SGW-C that established this session,
	// e.g., "ipv4:192.168.0.1". Used for restart reconciliation (R15-010): when a
	// CP peer restarts, all sessions with this key are invalidated.
	CPNodeKey string
	// Mu protects PDRs and FARs from concurrent read/write between the PFCP SMR
	// handler (writer) and the GTP-U forwarder (reader). AUD-07.
	Mu   sync.RWMutex
	PDRs []PDR
	FARs []FAR
}

// Store holds all active PFCP sessions on the SGW-U.
type Store struct {
	mu          sync.RWMutex
	byCPSEID    map[uint64]*Session // keyed by CP-SEID
	byUPSEID    map[uint64]*Session // keyed by UP-SEID (for incoming mod/del from SGW-C)
	seidCounter atomic.Uint64
}

// NewStore creates an initialized SGW-U session store.
func NewStore() *Store {
	return &Store{
		byCPSEID: make(map[uint64]*Session),
		byUPSEID: make(map[uint64]*Session),
	}
}

// AllocSEID allocates a new monotonically increasing UP-SEID.
// SEIDs start at 1 (0 is reserved per TS 29.244 §8.2.37).
func (s *Store) AllocSEID() uint64 {
	return s.seidCounter.Add(1)
}

// AllocTEID allocates a random non-zero TEID for the local GTP-U endpoint.
// Randomisation per AUD-05 prevents sequential TEID guessing attacks.
// Per TS 29.281 §5.1, TEID=0 is reserved and must not be allocated.
func (s *Store) AllocTEID() uint32 {
	for {
		var b [4]byte
		if _, err := rand.Read(b[:]); err != nil {
			panic(fmt.Sprintf("AllocTEID: rand.Read: %v", err))
		}
		if v := binary.BigEndian.Uint32(b[:]); v != 0 && !s.localTEIDInUse(v) {
			return v
		}
	}
}

func (s *Store) localTEIDInUse(teid uint32) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.localTEIDInUseLocked(teid)
}

func (s *Store) localTEIDInUseLocked(teid uint32) bool {
	for _, sess := range s.byCPSEID {
		for i := range sess.PDRs {
			if sess.PDRs[i].LocalTEID == teid {
				return true
			}
		}
	}
	return false
}

// Create stores a new session. Returns an error if a session with the same CP-SEID
// already exists (caller must delete first for re-establishment).
func (s *Store) Create(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byCPSEID[sess.CPSEID]; exists {
		return fmt.Errorf("PFCP session already exists for CP-SEID %d", sess.CPSEID)
	}
	s.byCPSEID[sess.CPSEID] = sess
	s.byUPSEID[sess.UPSEID] = sess
	return nil
}

// FindByCPSEID looks up a session by CP-SEID.
func (s *Store) FindByCPSEID(cpSEID uint64) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byCPSEID[cpSEID]
}

// All returns a snapshot slice of every session currently in the store,
// keyed once by CP-SEID (byCPSEID and byUPSEID both point at the same
// Session, so iterating only one avoids duplicates).
func (s *Store) All() []*Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	list := make([]*Session, 0, len(s.byCPSEID))
	for _, sess := range s.byCPSEID {
		list = append(list, sess)
	}
	return list
}

// FindByUPSEID looks up a session by UP-SEID.
// The UP-SEID is the value carried in inbound session-level PFCP message headers.
func (s *Store) FindByUPSEID(upSEID uint64) *Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.byUPSEID[upSEID]
}

// Update replaces the session for the given CP-SEID.
// Returns an error if no session exists with that CP-SEID.
func (s *Store) Update(sess *Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	old, exists := s.byCPSEID[sess.CPSEID]
	if !exists {
		return fmt.Errorf("PFCP session not found for CP-SEID %d", sess.CPSEID)
	}
	// Remove old UP-SEID index if it changed.
	if old.UPSEID != sess.UPSEID {
		delete(s.byUPSEID, old.UPSEID)
	}
	s.byCPSEID[sess.CPSEID] = sess
	s.byUPSEID[sess.UPSEID] = sess
	return nil
}

// DeleteByCPSEID removes a session by CP-SEID. No-op if not found.
func (s *Store) DeleteByCPSEID(cpSEID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byCPSEID[cpSEID]; ok {
		delete(s.byUPSEID, sess.UPSEID)
		delete(s.byCPSEID, cpSEID)
	}
}

// DeleteByUPSEID removes a session by UP-SEID. No-op if not found.
func (s *Store) DeleteByUPSEID(upSEID uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.byUPSEID[upSEID]; ok {
		delete(s.byCPSEID, sess.CPSEID)
		delete(s.byUPSEID, upSEID)
	}
}

// DeleteByCPNodeKey removes all sessions established by the CP node identified by nodeKey
// (e.g., "ipv4:192.168.0.1") and returns the deleted sessions.
// Used for restart reconciliation per TS 29.244 §5.2.1 / R15-010: when a CP peer's
// Recovery Time Stamp changes, all its PFCP sessions must be invalidated. The caller
// receives the deleted sessions so it can trigger BPF cleanup (AUD-02).
func (s *Store) DeleteByCPNodeKey(nodeKey string) []*Session {
	s.mu.Lock()
	defer s.mu.Unlock()
	var toDelete []uint64
	for cpSEID, sess := range s.byCPSEID {
		if sess.CPNodeKey == nodeKey {
			toDelete = append(toDelete, cpSEID)
		}
	}
	deleted := make([]*Session, 0, len(toDelete))
	for _, cpSEID := range toDelete {
		if sess, ok := s.byCPSEID[cpSEID]; ok {
			deleted = append(deleted, sess)
			delete(s.byUPSEID, sess.UPSEID)
			delete(s.byCPSEID, cpSEID)
		}
	}
	return deleted
}

// FindByLocalTEID looks up the Session and a copy of the PDR for an incoming
// GTP-U G-PDU by searching for a PDR whose LocalTEID matches teid.
// Returns nil, zero PDR, false when not found.
// Used by the GTP-U forwarder (Phase 6) to resolve forwarding state.
func (s *Store) FindByLocalTEID(teid uint32) (*Session, PDR, bool) {
	if teid == 0 {
		return nil, PDR{}, false
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, sess := range s.byCPSEID {
		sess.Mu.RLock()
		for i := range sess.PDRs {
			if sess.PDRs[i].LocalTEID == teid {
				pdr := sess.PDRs[i]
				sess.Mu.RUnlock()
				return sess, pdr, true
			}
		}
		sess.Mu.RUnlock()
	}
	return nil, PDR{}, false
}

// Count returns the number of active sessions. Used for diagnostics.
func (s *Store) Count() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.byCPSEID)
}

// CountByCPNodeKey returns the number of active sessions established by the CP
// node identified by nodeKey. This is used by SGW-U API diagnostics so PFCP
// association state can be correlated with the session contexts bound to that
// CP function.
func (s *Store) CountByCPNodeKey(nodeKey string) int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var count int
	for _, sess := range s.byCPSEID {
		if sess.CPNodeKey == nodeKey {
			count++
		}
	}
	return count
}
