package session

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
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
	byS11     map[uint32]*SGWSession  // SGW S11 TEID → session
	byS5C     map[uint32]*SGWSession  // SGW S5/S8-C TEID → session (for PGW-initiated procedures)
	byIMSI    map[string]*SGWSession  // IMSI → most recent session (any APN)
	byPDN     map[pdnKey]*SGWSession  // (IMSI+EBI) → active PDN connection
	teidAlloc *teid.Allocator
}

// NewManager creates a ready-to-use session manager.
func NewManager() *Manager {
	return &Manager{
		byID:      make(map[string]*SGWSession),
		byS11:     make(map[uint32]*SGWSession),
		byS5C:     make(map[uint32]*SGWSession),
		byIMSI:    make(map[string]*SGWSession),
		byPDN:     make(map[pdnKey]*SGWSession),
		teidAlloc: teid.NewAllocator(),
	}
}

// CreateParams holds the values needed to create a new session from a CSReq.
type CreateParams struct {
	IMSI           string
	APN            string
	RATType        uint8
	ServingNetwork string
	MMEControlFTEID FTEID
	DefaultEBI     uint8
	QCI            uint8
	ARP            bearer.ARP
	MBRUplink      uint64
	MBRDownlink    uint64
}

// Create allocates a new pending session and its SGW S11 control TEID.
// If an existing PDN connection for the same IMSI+APN is found, it is evicted
// and returned as the second value so the caller can perform remote cleanup
// (PGW Delete Session, PFCP Session Deletion) per C13.
func (m *Manager) Create(p CreateParams) (sess *SGWSession, evicted *SGWSession, err error) {
	sgwTEID, err := m.teidAlloc.Alloc()
	if err != nil {
		return nil, nil, fmt.Errorf("session create: %w", err)
	}

	id, err := newSessionID()
	if err != nil {
		m.teidAlloc.Free(sgwTEID)
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
		SGWS11FTEID:     FTEID{TEID: sgwTEID},
		DefaultBearerID: p.DefaultEBI,
		Bearers:         map[uint8]*bearer.Bearer{p.DefaultEBI: defaultBearer},
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
		delete(m.byID, old.SessionID)
		delete(m.byS11, old.SGWS11FTEID.TEID)
		// AUD-09: also clean the S5/S8-C TEID index; omitting it leaves a stale
		// entry that causes FindByS5CTEID to return the wrong (evicted) session.
		if old.SGWS5CFTEID.TEID != 0 {
			delete(m.byS5C, old.SGWS5CFTEID.TEID)
		}
		delete(m.byPDN, pdn)
		if m.byIMSI[old.IMSI] == old {
			delete(m.byIMSI, old.IMSI)
		}
		m.teidAlloc.Free(old.SGWS11FTEID.TEID)
	}
	m.byID[id] = sess
	m.byS11[sgwTEID] = sess
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

// FindByS11TEID returns the session whose SGW S11 TEID matches, or nil.
// This is the TEID the MME addresses when sending MBReq/DSReq/RABReq.
func (m *Manager) FindByS11TEID(t uint32) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byS11[t]
}

// FindByIMSI returns the most recent session for the given IMSI, or nil.
func (m *Manager) FindByIMSI(imsi string) *SGWSession {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.byIMSI[imsi]
}

// RegisterS5CTEID registers the SGW's S5/S8-C control TEID for a session, enabling
// PGW-initiated procedure lookup (Create Bearer, Update Bearer, Delete Bearer Requests).
// Must be called after CreateSession establishes the PGW binding.
func (m *Manager) RegisterS5CTEID(sessionID string, s5cTEID uint32) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if sess, ok := m.byID[sessionID]; ok {
		m.byS5C[s5cTEID] = sess
	}
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
	delete(m.byID, id)
	delete(m.byS11, sess.SGWS11FTEID.TEID)
	if sess.SGWS5CFTEID.TEID != 0 {
		delete(m.byS5C, sess.SGWS5CFTEID.TEID)
	}
	pdn := pdnKey{imsi: sess.IMSI, ebi: sess.DefaultBearerID}
	if m.byPDN[pdn] == sess {
		delete(m.byPDN, pdn)
	}
	if m.byIMSI[sess.IMSI] == sess {
		delete(m.byIMSI, sess.IMSI)
	}
	m.teidAlloc.Free(sess.SGWS11FTEID.TEID)
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
