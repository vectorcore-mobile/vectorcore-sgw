package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/collision"
	"vectorcore-sgw/internal/sgwc/teid"
)

// pdnKey identifies a PDN connection for collision detection.
// Per TS 29.274 Rel-15 §7.2.1: collision is detected when a new CSReq carries
// the same IMSI (or MEI for emergency UEs) and the same EPS Bearer ID (EBI)
// as an existing session. Using EBI instead of APN matches the spec definition.
type pdnKey struct {
	imsi string // IMSI, or "mei:<IMEI>" for emergency UEs
	ebi  uint8  // Default bearer EBI (identifies the PDN connection per §7.2.1)
}

// Manager is the thread-safe SGW-C session store.
// Sessions are indexed by session ID, by SGW S11 control TEID, by SGW S5/S8-C control TEID,
// by IMSI (most recent), and by PDN connection identity (IMSI+EBI) for re-attach collision detection.
type Manager struct {
	mu        sync.RWMutex
	byID      map[string]*SGWSession
	byS11     map[uint32][]*SGWSession // SGW S11 TEID → PDN sessions sharing the UE/MME S11 context
	byS5C     map[uint32]*SGWSession   // SGW S5/S8-C TEID → session (for PGW-initiated procedures)
	byPGW     map[string]map[string]*SGWSession
	byIMSI    map[string]*SGWSession // IMSI → most recent session (any APN)
	byPDN     map[pdnKey]*SGWSession // (IMSI+EBI) → active PDN connection
	teidAlloc *teid.Allocator
}

// NewManager creates a ready-to-use session manager.
func NewManager() *Manager {
	return &Manager{
		byID:      make(map[string]*SGWSession),
		byS11:     make(map[uint32][]*SGWSession),
		byS5C:     make(map[uint32]*SGWSession),
		byPGW:     make(map[string]map[string]*SGWSession),
		byIMSI:    make(map[string]*SGWSession),
		byPDN:     make(map[pdnKey]*SGWSession),
		teidAlloc: teid.NewAllocator(),
	}
}

// CreateParams holds the values needed to create a new session from a CSReq.
type CreateParams struct {
	IMSI             string
	APN              string
	RATType          uint8
	ServingNetwork   string
	MMEControlFTEID  FTEID
	ReuseSGWS11FTEID FTEID
	DefaultEBI       uint8
	QCI              uint8
	ARP              bearer.ARP
	MBRUplink        uint64
	MBRDownlink      uint64
}

// Create allocates a new pending session and its SGW S11 control TEID.
// If an existing PDN connection for the same IMSI+APN is found, it is evicted
// and returned as the second value so the caller can perform remote cleanup
// (PGW Delete Session, PFCP Session Deletion) per C13.
func (m *Manager) Create(p CreateParams) (sess *SGWSession, evicted *SGWSession, err error) {
	sgwFTEID := p.ReuseSGWS11FTEID
	allocatedS11TEID := false
	if sgwFTEID.TEID == 0 {
		sgwTEID, allocErr := m.teidAlloc.Alloc()
		if allocErr != nil {
			return nil, nil, fmt.Errorf("session create: %w", allocErr)
		}
		sgwFTEID = FTEID{TEID: sgwTEID}
		allocatedS11TEID = true
	}

	id, err := newSessionID()
	if err != nil {
		if allocatedS11TEID {
			m.teidAlloc.Free(sgwFTEID.TEID)
		}
		return nil, nil, fmt.Errorf("session create: %w", err)
	}

	defaultBearer := &bearer.Bearer{
		EBI:         p.DefaultEBI,
		QCI:         p.QCI,
		ARP:         p.ARP,
		MBRUplink:   p.MBRUplink,
		MBRDownlink: p.MBRDownlink,
		State:       bearer.BearerStatePending,
	}

	sess = &SGWSession{
		SessionID:       id,
		IMSI:            p.IMSI,
		APN:             p.APN,
		RATType:         p.RATType,
		ServingNetwork:  p.ServingNetwork,
		MMEControlFTEID: p.MMEControlFTEID,
		SGWS11FTEID:     sgwFTEID,
		DefaultBearerID: p.DefaultEBI,
		Bearers:         map[uint8]*bearer.Bearer{p.DefaultEBI: defaultBearer},
		Procedures:      collision.NewTracker(),
		State:           StatePending,
		CreatedAt:       time.Now(),
		UpdatedAt:       time.Now(),
	}

	m.mu.Lock()
	// Per TS 29.274 Rel-15 §7.2.1: collision detection uses (IMSI, EBI).
	// The evicted session is returned so the caller can trigger
	// PGW Delete Session and PFCP Session Deletion per C13.
	pdn := pdnKey{imsi: p.IMSI, ebi: p.DefaultEBI}
	if old, exists := m.byPDN[pdn]; exists {
		evicted = old
		m.removeLocked(old)
		if old.SGWS11FTEID.TEID != sgwFTEID.TEID && len(m.byS11[old.SGWS11FTEID.TEID]) == 0 {
			m.teidAlloc.Free(old.SGWS11FTEID.TEID)
		}
	}
	m.byID[id] = sess
	m.byS11[sgwFTEID.TEID] = append(m.byS11[sgwFTEID.TEID], sess)
	m.byPDN[pdn] = sess
	m.byIMSI[p.IMSI] = sess
	m.mu.Unlock()

	return sess, evicted, nil
}

// Find returns the session with the given ID, or nil.
func (m *Manager) Find(id string) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byID[id]
}

// FindByS11TEID returns the most recently registered session whose SGW S11 TEID
// matches, or nil. S11 procedures carrying bearer EBIs should prefer
// FindByS11TEIDAndBearer or FindByS11TEIDAndDefaultBearer because a UE can have
// multiple PDN sessions sharing the same SGW S11 TEID.
// This is the TEID the MME addresses when sending MBReq/DSReq/RABReq.
func (m *Manager) FindByS11TEID(t uint32) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := m.byS11[t]
	if len(sessions) == 0 {
		return nil
	}
	return sessions[len(sessions)-1]
}

// FindByS11TEIDAndBearer returns the PDN session under SGW S11 TEID t that owns
// ebi. EBI values are scoped to a UE/MME S11 context, not globally unique.
func (m *Manager) FindByS11TEIDAndBearer(t uint32, ebi uint8) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := m.byS11[t]
	for i := len(sessions) - 1; i >= 0; i-- {
		if sessions[i].GetBearer(ebi) != nil {
			return sessions[i]
		}
	}
	return nil
}

// FindByS11TEIDAndDefaultBearer returns the PDN session whose default bearer EBI
// matches ebi under SGW S11 TEID t.
func (m *Manager) FindByS11TEIDAndDefaultBearer(t uint32, ebi uint8) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := m.byS11[t]
	for i := len(sessions) - 1; i >= 0; i-- {
		if sessions[i].DefaultBearerID == ebi {
			return sessions[i]
		}
	}
	return nil
}

// FindAllByS11TEID returns all PDN sessions sharing an SGW S11 TEID.
func (m *Manager) FindAllByS11TEID(t uint32) []*SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := m.byS11[t]
	out := make([]*SGWSession, len(sessions))
	copy(out, sessions)
	return out
}

// FindByIMSI returns the most recent session for the given IMSI, or nil.
func (m *Manager) FindByIMSI(imsi string) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byIMSI[imsi]
}

// RegisterS5CTEID registers the SGW's local S5/S8-C control TEID for a session,
// enabling PGW-initiated procedure lookup (Create Bearer, Update Bearer, Delete
// Bearer Requests). It must be called before the TEID is advertised in the
// S5/S8-C Create Session Request because the PGW may immediately address a
// response or piggybacked request to that local TEID.
func (m *Manager) RegisterS5CTEID(sessionID string, s5cTEID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess, ok := m.byID[sessionID]; ok {
		m.byS5C[s5cTEID] = sess
	}
}

// RegisterPGW indexes a session under the canonical PGW S5/S8-C endpoint.
func (m *Manager) RegisterPGW(sessionID, pgwAddr string) {
	canonical := CanonicalGTPCEndpoint(pgwAddr)
	if canonical == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.byID[sessionID]
	if !ok {
		return
	}
	if sess.PGWFailure.PGWAddr != "" && sess.PGWFailure.PGWAddr != canonical {
		m.removePGWLocked(sess.PGWFailure.PGWAddr, sessionID)
	}
	if m.byPGW[canonical] == nil {
		m.byPGW[canonical] = make(map[string]*SGWSession)
	}
	m.byPGW[canonical][sessionID] = sess
	sess.SetPGWPathState(PGWPathStateUp, canonical, time.Now())
}

// FindByPGW returns all sessions indexed under the canonical PGW endpoint.
func (m *Manager) FindByPGW(pgwAddr string) []*SGWSession {
	canonical := CanonicalGTPCEndpoint(pgwAddr)
	if canonical == "" {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	sessions := m.byPGW[canonical]
	out := make([]*SGWSession, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, sess)
	}
	return out
}

func (m *Manager) MarkPGWPathState(pgwAddr string, state PGWPathState, at time.Time) int {
	sessions := m.FindByPGW(pgwAddr)
	canonical := CanonicalGTPCEndpoint(pgwAddr)
	for _, sess := range sessions {
		sess.SetPGWPathState(state, canonical, at)
	}
	return len(sessions)
}

func (m *Manager) MarkPGWRestart(pgwAddr string, recovery uint8, at time.Time) int {
	sessions := m.FindByPGW(pgwAddr)
	canonical := CanonicalGTPCEndpoint(pgwAddr)
	for _, sess := range sessions {
		sess.MarkPGWRestart(canonical, recovery, at)
	}
	return len(sessions)
}

// FindByS5CTEID returns the session whose SGW S5/S8-C TEID matches, or nil.
// This is the TEID the PGW addresses when sending CBReq/UBReq/DBReq.
func (m *Manager) FindByS5CTEID(t uint32) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byS5C[t]
}

// Delete removes a session and frees its allocated TEID.
func (m *Manager) Delete(id string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	sess, ok := m.byID[id]
	if !ok {
		return
	}
	sgwS11TEID := sess.SGWS11FTEID.TEID
	m.removeLocked(sess)
	if len(m.byS11[sgwS11TEID]) == 0 {
		m.teidAlloc.Free(sgwS11TEID)
	}
}

func (m *Manager) removeLocked(sess *SGWSession) {
	delete(m.byID, sess.SessionID)
	if sessions := m.byS11[sess.SGWS11FTEID.TEID]; len(sessions) > 0 {
		filtered := sessions[:0]
		for _, candidate := range sessions {
			if candidate != sess {
				filtered = append(filtered, candidate)
			}
		}
		if len(filtered) == 0 {
			delete(m.byS11, sess.SGWS11FTEID.TEID)
		} else {
			m.byS11[sess.SGWS11FTEID.TEID] = filtered
		}
	}
	if sess.SGWS5CFTEID.TEID != 0 {
		delete(m.byS5C, sess.SGWS5CFTEID.TEID)
	}
	if sess.PGWFailure.PGWAddr != "" {
		m.removePGWLocked(sess.PGWFailure.PGWAddr, sess.SessionID)
	} else if sess.PGWControlFTEID.IPv4.IsValid() {
		m.removePGWLocked(CanonicalGTPCEndpoint(sess.PGWControlFTEID.IPv4.String()), sess.SessionID)
	}
	pdn := pdnKey{imsi: sess.IMSI, ebi: sess.DefaultBearerID}
	if m.byPDN[pdn] == sess {
		delete(m.byPDN, pdn)
	}
	if m.byIMSI[sess.IMSI] == sess {
		delete(m.byIMSI, sess.IMSI)
		var newest *SGWSession
		for _, candidate := range m.byID {
			if candidate.IMSI == sess.IMSI {
				if newest == nil || candidate.CreatedAt.After(newest.CreatedAt) {
					newest = candidate
				}
			}
		}
		if newest != nil {
			m.byIMSI[sess.IMSI] = newest
		}
	}
}

func (m *Manager) removePGWLocked(pgwAddr, sessionID string) {
	canonical := CanonicalGTPCEndpoint(pgwAddr)
	if canonical == "" {
		return
	}
	sessions := m.byPGW[canonical]
	if len(sessions) == 0 {
		return
	}
	delete(sessions, sessionID)
	if len(sessions) == 0 {
		delete(m.byPGW, canonical)
	}
}

// List returns a snapshot of all sessions.
func (m *Manager) List() []*SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]*SGWSession, 0, len(m.byID))
	for _, s := range m.byID {
		out = append(out, s)
	}
	return out
}

// InvalidatePFCPBindings clears all SGW-U PFCP bindings from locally retained
// SGW-C sessions. It is retained for whole-client shutdown paths and tests;
// peer-specific PFCP failures should use InvalidatePFCPBindingsForPeer.
func (m *Manager) InvalidatePFCPBindings() int {
	sessions := m.List()
	invalidated := 0
	for _, sess := range sessions {
		if sess.InvalidatePFCPBinding() {
			invalidated++
		}
	}
	return invalidated
}

// InvalidatePFCPBindingsForPeer clears only the PFCP bindings owned by the
// affected SGW-U peer, preserving sessions placed on other SGW-U nodes.
func (m *Manager) InvalidatePFCPBindingsForPeer(peerName, peerAddr string) int {
	sessions := m.List()
	invalidated := 0
	for _, sess := range sessions {
		if sess.InvalidatePFCPBindingForPeer(peerName, peerAddr) {
			invalidated++
		}
	}
	return invalidated
}

// Count returns the number of active sessions.
func (m *Manager) Count() int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.byID)
}

func newSessionID() (string, error) {
	var b [8]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// CanonicalGTPCEndpoint returns the stable GTPv2-C endpoint used for PGW/MME
// health and failure indexing. GTPv2-C peers are probed on UDP/2123 even when a
// packet was observed from a transient source port.
func CanonicalGTPCEndpoint(addr string) string {
	if addr == "" {
		return ""
	}
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host == "" {
		return ""
	}
	return net.JoinHostPort(host, strconv.Itoa(2123))
}
