package session

import (
	"fmt"
	"net/netip"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/collision"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

type RestoreResult struct {
	Loaded          int
	Restored        int
	SkippedDeleted  int
	SkippedInvalid  int
	ReservedS11TEID int
}

// RestoreSnapshots rebuilds the manager from durable checkpoint snapshots.
// Restored sessions are intentionally placed in StateRecovering; later phases
// reconcile PFCP/SGW-U state before any session is treated as fully active.
func (m *Manager) RestoreSnapshots(snapshots []sessioncheckpoint.SessionSnapshot) (RestoreResult, error) {
	result := RestoreResult{Loaded: len(snapshots)}
	next := NewManager()
	next.checkpointSink = m.checkpointSink

	for _, snapshot := range snapshots {
		if snapshot.SessionID == "" || snapshot.IMSI == "" || snapshot.DefaultBearerID == 0 || snapshot.SGWS11FTEID.TEID == 0 {
			result.SkippedInvalid++
			continue
		}
		if snapshot.State == string(StateDeleted) {
			result.SkippedDeleted++
			continue
		}
		if _, exists := next.byID[snapshot.SessionID]; exists {
			return result, fmt.Errorf("restore session %q: duplicate session_id", snapshot.SessionID)
		}
		pdn := pdnKey{imsi: snapshot.IMSI, ebi: snapshot.DefaultBearerID}
		if _, exists := next.byPDN[pdn]; exists {
			return result, fmt.Errorf("restore session %q: duplicate PDN key imsi=%s ebi=%d", snapshot.SessionID, snapshot.IMSI, snapshot.DefaultBearerID)
		}
		if snapshot.SGWS5CFTEID.TEID != 0 {
			if _, exists := next.byS5C[snapshot.SGWS5CFTEID.TEID]; exists {
				return result, fmt.Errorf("restore session %q: duplicate SGW S5-C TEID 0x%08X", snapshot.SessionID, snapshot.SGWS5CFTEID.TEID)
			}
		}
		sess, err := sessionFromSnapshot(snapshot, next.checkpointSink)
		if err != nil {
			result.SkippedInvalid++
			continue
		}
		next.byID[sess.SessionID] = sess
		next.byS11[sess.SGWS11FTEID.TEID] = append(next.byS11[sess.SGWS11FTEID.TEID], sess)
		if sess.SGWS5CFTEID.TEID != 0 {
			next.byS5C[sess.SGWS5CFTEID.TEID] = sess
		}
		if sess.PGWFailure.PGWAddr != "" {
			canonical := CanonicalGTPCEndpoint(sess.PGWFailure.PGWAddr)
			if canonical != "" {
				if next.byPGW[canonical] == nil {
					next.byPGW[canonical] = make(map[string]*SGWSession)
				}
				next.byPGW[canonical][sess.SessionID] = sess
			}
		} else if sess.PGWControlFTEID.IPv4.IsValid() {
			canonical := CanonicalGTPCEndpoint(sess.PGWControlFTEID.IPv4.String())
			if canonical != "" {
				if next.byPGW[canonical] == nil {
					next.byPGW[canonical] = make(map[string]*SGWSession)
				}
				next.byPGW[canonical][sess.SessionID] = sess
			}
		}
		next.byPDN[pdn] = sess
		if current := next.byIMSI[sess.IMSI]; current == nil || sess.CreatedAt.After(current.CreatedAt) {
			next.byIMSI[sess.IMSI] = sess
		}
		if next.teidAlloc.Reserve(sess.SGWS11FTEID.TEID) {
			result.ReservedS11TEID++
		}
		result.Restored++
	}

	m.mu.Lock()
	m.byID = next.byID
	m.byS11 = next.byS11
	m.byS5C = next.byS5C
	m.byPGW = next.byPGW
	m.byIMSI = next.byIMSI
	m.byPDN = next.byPDN
	m.teidAlloc = next.teidAlloc
	m.mu.Unlock()

	return result, nil
}

func sessionFromSnapshot(snapshot sessioncheckpoint.SessionSnapshot, sink CheckpointSink) (*SGWSession, error) {
	bearers := make(map[uint8]*bearer.Bearer, len(snapshot.Bearers))
	for _, b := range snapshot.Bearers {
		if b.EBI == 0 {
			return nil, fmt.Errorf("bearer snapshot missing EBI")
		}
		if _, exists := bearers[b.EBI]; exists {
			return nil, fmt.Errorf("duplicate bearer EBI %d", b.EBI)
		}
		bearers[b.EBI] = bearerFromSnapshot(b)
	}
	if _, ok := bearers[snapshot.DefaultBearerID]; !ok {
		return nil, fmt.Errorf("default bearer EBI %d missing", snapshot.DefaultBearerID)
	}
	createdAt := snapshot.CreatedAt
	if createdAt.IsZero() {
		createdAt = time.Now()
	}
	updatedAt := snapshot.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = createdAt
	}
	return &SGWSession{
		SessionID:       snapshot.SessionID,
		IMSI:            snapshot.IMSI,
		APN:             snapshot.APN,
		RATType:         snapshot.RATType,
		ServingNetwork:  snapshot.ServingNetwork,
		MMEControlFTEID: fteidFromSnapshot(snapshot.MMEControlFTEID),
		SGWS11FTEID:     fteidFromSnapshot(snapshot.SGWS11FTEID),
		PGWControlFTEID: fteidFromSnapshot(snapshot.PGWControlFTEID),
		SGWS5CFTEID:     fteidFromSnapshot(snapshot.SGWS5CFTEID),
		UEIPv4:          addrFromString(snapshot.UEIPv4),
		DefaultBearerID: snapshot.DefaultBearerID,
		Bearers:         bearers,
		PFCP: PFCPSessionBinding{
			LocalFSEID:  fseidFromSnapshot(snapshot.PFCP.LocalFSEID),
			SGWUFSEID:   fseidFromSnapshot(snapshot.PFCP.SGWUFSEID),
			SGWUName:    snapshot.PFCP.SGWUName,
			SGWUAddr:    snapshot.PFCP.SGWUAddr,
			Established: snapshot.PFCP.Established,
		},
		PFCPReconciliation: pfcpReconciliationFromSnapshot(snapshot.PFCPReconciliation),
		Procedures:         collision.NewTracker(),
		PGWFailure:         pgwFailureFromSnapshot(snapshot.PGWFailure),
		MMERestoration:     mmeRestorationFromSnapshot(snapshot.MMERestoration),
		State:              StateRecovering,
		CreatedAt:          createdAt,
		UpdatedAt:          updatedAt,
		nextRuleID:         nextRuleIDFromSnapshot(snapshot),
		checkpointSink:     sink,
	}, nil
}

func bearerFromSnapshot(snapshot sessioncheckpoint.BearerSnapshot) *bearer.Bearer {
	var tft *bearer.TFT
	if len(snapshot.TFTRaw) > 0 {
		tft = &bearer.TFT{Raw: append([]byte(nil), snapshot.TFTRaw...)}
	}
	return &bearer.Bearer{
		EBI:                     snapshot.EBI,
		QCI:                     snapshot.QCI,
		ARP:                     snapshot.ARP,
		ENBS1UFTEID:             bearerFTEIDFromSnapshot(snapshot.ENBS1UFTEID),
		SGWS1UFTEID:             bearerFTEIDFromSnapshot(snapshot.SGWS1UFTEID),
		PGWS5UFTEID:             bearerFTEIDFromSnapshot(snapshot.PGWS5UFTEID),
		SGWS5UFTEID:             bearerFTEIDFromSnapshot(snapshot.SGWS5UFTEID),
		MBRUplink:               snapshot.MBRUplink,
		MBRDownlink:             snapshot.MBRDownlink,
		GBRUplink:               snapshot.GBRUplink,
		GBRDownlink:             snapshot.GBRDownlink,
		TFT:                     tft,
		State:                   snapshot.State,
		PDRIDs:                  snapshot.PDRIDs,
		FARIDs:                  snapshot.FARIDs,
		LastControlActivityAt:   snapshot.LastControlActivityAt,
		LastUserPlaneActivityAt: snapshot.LastUserPlaneActivityAt,
		LastActivitySource:      snapshot.LastActivitySource,
		InactiveSince:           snapshot.InactiveSince,
		CleanupEligible:         snapshot.CleanupEligible,
	}
}

func nextRuleIDFromSnapshot(snapshot sessioncheckpoint.SessionSnapshot) uint32 {
	if snapshot.NextRuleID != 0 {
		return snapshot.NextRuleID
	}
	var maxRule uint32 = 2
	for _, b := range snapshot.Bearers {
		for _, id := range b.PDRIDs {
			if id > maxRule {
				maxRule = id
			}
		}
		for _, id := range b.FARIDs {
			if id > maxRule {
				maxRule = id
			}
		}
	}
	return maxRule + 1
}

func fteidFromSnapshot(snapshot sessioncheckpoint.FTEIDSnapshot) FTEID {
	return FTEID{TEID: snapshot.TEID, IPv4: addrFromString(snapshot.IPv4)}
}

func bearerFTEIDFromSnapshot(snapshot sessioncheckpoint.FTEIDSnapshot) bearer.FTEID {
	return bearer.FTEID{TEID: snapshot.TEID, IPv4: addrFromString(snapshot.IPv4)}
}

func fseidFromSnapshot(snapshot sessioncheckpoint.FSEIDSnapshot) FSEID {
	return FSEID{SEID: snapshot.SEID, IPv4: addrFromString(snapshot.IPv4)}
}

func pfcpReconciliationFromSnapshot(snapshot sessioncheckpoint.PFCPReconciliationSnapshot) PFCPReconciliationStatus {
	return PFCPReconciliationStatus{
		State:  PFCPReconciliationState(snapshot.State),
		At:     snapshot.At,
		Reason: snapshot.Reason,
	}
}

func pgwFailureFromSnapshot(snapshot sessioncheckpoint.PGWFailureSnapshot) PGWFailureStatus {
	return PGWFailureStatus{
		PathState:         PGWPathState(snapshot.PathState),
		PGWAddr:           snapshot.PGWAddr,
		PathDownAt:        snapshot.PathDownAt,
		RestartDetectedAt: snapshot.RestartDetectedAt,
		RecoverySeen:      snapshot.RecoverySeen,
		RecoveryCounter:   snapshot.RecoveryCounter,
	}
}

func mmeRestorationFromSnapshot(snapshot sessioncheckpoint.MMERestorationSnapshot) MMERestorationStatus {
	return MMERestorationStatus{
		State:               MMERestorationState(snapshot.State),
		MMEAddr:             snapshot.MMEAddr,
		PathDownAt:          snapshot.PathDownAt,
		RestartDetectedAt:   snapshot.RestartDetectedAt,
		RecoverySeen:        snapshot.RecoverySeen,
		RecoveryCounter:     snapshot.RecoveryCounter,
		RestorationPending:  snapshot.RestorationPending,
		PolicyAction:        MMERestorationPolicyAction(snapshot.PolicyAction),
		PolicyReason:        snapshot.PolicyReason,
		DDNTriggered:        snapshot.DDNTriggered,
		DDNTriggeredAt:      snapshot.DDNTriggeredAt,
		DDNSequence:         snapshot.DDNSequence,
		DDNAcked:            snapshot.DDNAcked,
		DDNAckedAt:          snapshot.DDNAckedAt,
		DDNAckCause:         snapshot.DDNAckCause,
		DDNFailureAt:        snapshot.DDNFailureAt,
		DDNFailureCause:     snapshot.DDNFailureCause,
		DDNFailureReason:    snapshot.DDNFailureReason,
		DDNControlAction:    snapshot.DDNControlAction,
		DDNControlPriority:  snapshot.DDNControlPriority,
		DDNControlReason:    snapshot.DDNControlReason,
		DDNControlRetryAt:   snapshot.DDNControlRetryAt,
		DDNControlDecidedAt: snapshot.DDNControlDecidedAt,
		StopPagingSent:      snapshot.StopPagingSent,
		StopPagingSentAt:    snapshot.StopPagingSentAt,
		StopPagingSequence:  snapshot.StopPagingSequence,
		UserPlaneRestored:   snapshot.UserPlaneRestored,
		UserPlaneRestoredAt: snapshot.UserPlaneRestoredAt,
		RestoredEBI:         snapshot.RestoredEBI,
	}
}

func addrFromString(value string) netip.Addr {
	if value == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(value)
	if err != nil {
		return netip.Addr{}
	}
	return addr
}
