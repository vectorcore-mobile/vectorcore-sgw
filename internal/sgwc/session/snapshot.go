package session

import (
	"net/netip"
	"sort"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

// Snapshot returns the durable, backend-neutral subset of this SGW-C session.
// It holds the session lock while copying bearer maps and private allocator
// state so checkpoint writers do not observe partially updated session data.
func (s *SGWSession) Snapshot() sessioncheckpoint.SessionSnapshot {
	s.mu.RLock()
	defer s.mu.RUnlock()

	bearers := make([]sessioncheckpoint.BearerSnapshot, 0, len(s.Bearers))
	ebis := make([]int, 0, len(s.Bearers))
	for ebi := range s.Bearers {
		ebis = append(ebis, int(ebi))
	}
	sort.Ints(ebis)
	for _, ebi := range ebis {
		if b := s.Bearers[uint8(ebi)]; b != nil {
			bearers = append(bearers, bearerSnapshot(b))
		}
	}

	return sessioncheckpoint.SessionSnapshot{
		SchemaVersion:   sessioncheckpoint.CurrentSchemaVersion,
		SessionID:       s.SessionID,
		IMSI:            s.IMSI,
		APN:             s.APN,
		RATType:         s.RATType,
		ServingNetwork:  s.ServingNetwork,
		MMEControlFTEID: fteidSnapshot(s.MMEControlFTEID),
		SGWS11FTEID:     fteidSnapshot(s.SGWS11FTEID),
		PGWControlFTEID: fteidSnapshot(s.PGWControlFTEID),
		SGWS5CFTEID:     fteidSnapshot(s.SGWS5CFTEID),
		UEIPv4:          addrString(s.UEIPv4),
		DefaultBearerID: s.DefaultBearerID,
		Bearers:         bearers,
		PFCP: sessioncheckpoint.PFCPSessionBindingSnapshot{
			LocalFSEID:  fseidSnapshot(s.PFCP.LocalFSEID),
			SGWUFSEID:   fseidSnapshot(s.PFCP.SGWUFSEID),
			SGWUName:    s.PFCP.SGWUName,
			SGWUAddr:    s.PFCP.SGWUAddr,
			Established: s.PFCP.Established,
		},
		PFCPReconciliation: pfcpReconciliationSnapshot(s.PFCPReconciliation),
		PGWFailure:         pgwFailureSnapshot(s.PGWFailure),
		MMERestoration:     mmeRestorationSnapshot(s.MMERestoration),
		State:              string(s.State),
		CreatedAt:          s.CreatedAt,
		UpdatedAt:          s.UpdatedAt,
		NextRuleID:         s.nextRuleID,
	}
}

func bearerSnapshot(b *bearer.Bearer) sessioncheckpoint.BearerSnapshot {
	var tftRaw []byte
	if b.TFT != nil {
		tftRaw = append([]byte(nil), b.TFT.Raw...)
	}
	return sessioncheckpoint.BearerSnapshot{
		EBI:                     b.EBI,
		QCI:                     b.QCI,
		ARP:                     b.ARP,
		ENBS1UFTEID:             bearerFTEIDSnapshot(b.ENBS1UFTEID),
		SGWS1UFTEID:             bearerFTEIDSnapshot(b.SGWS1UFTEID),
		PGWS5UFTEID:             bearerFTEIDSnapshot(b.PGWS5UFTEID),
		SGWS5UFTEID:             bearerFTEIDSnapshot(b.SGWS5UFTEID),
		MBRUplink:               b.MBRUplink,
		MBRDownlink:             b.MBRDownlink,
		GBRUplink:               b.GBRUplink,
		GBRDownlink:             b.GBRDownlink,
		TFTRaw:                  tftRaw,
		State:                   b.State,
		PDRIDs:                  b.PDRIDs,
		FARIDs:                  b.FARIDs,
		LastControlActivityAt:   b.LastControlActivityAt,
		LastUserPlaneActivityAt: b.LastUserPlaneActivityAt,
		LastActivitySource:      b.LastActivitySource,
		InactiveSince:           b.InactiveSince,
		CleanupEligible:         b.CleanupEligible,
	}
}

func fteidSnapshot(f FTEID) sessioncheckpoint.FTEIDSnapshot {
	return sessioncheckpoint.FTEIDSnapshot{TEID: f.TEID, IPv4: addrString(f.IPv4)}
}

func bearerFTEIDSnapshot(f bearer.FTEID) sessioncheckpoint.FTEIDSnapshot {
	return sessioncheckpoint.FTEIDSnapshot{TEID: f.TEID, IPv4: addrString(f.IPv4)}
}

func fseidSnapshot(f FSEID) sessioncheckpoint.FSEIDSnapshot {
	return sessioncheckpoint.FSEIDSnapshot{SEID: f.SEID, IPv4: addrString(f.IPv4)}
}

func pfcpReconciliationSnapshot(in PFCPReconciliationStatus) sessioncheckpoint.PFCPReconciliationSnapshot {
	return sessioncheckpoint.PFCPReconciliationSnapshot{
		State:  string(in.State),
		At:     in.At,
		Reason: in.Reason,
	}
}

func pgwFailureSnapshot(in PGWFailureStatus) sessioncheckpoint.PGWFailureSnapshot {
	return sessioncheckpoint.PGWFailureSnapshot{
		PathState:         string(in.PathState),
		PGWAddr:           in.PGWAddr,
		PathDownAt:        in.PathDownAt,
		RestartDetectedAt: in.RestartDetectedAt,
		RecoverySeen:      in.RecoverySeen,
		RecoveryCounter:   in.RecoveryCounter,
	}
}

func mmeRestorationSnapshot(in MMERestorationStatus) sessioncheckpoint.MMERestorationSnapshot {
	return sessioncheckpoint.MMERestorationSnapshot{
		State:               string(in.State),
		MMEAddr:             in.MMEAddr,
		PathDownAt:          in.PathDownAt,
		RestartDetectedAt:   in.RestartDetectedAt,
		RecoverySeen:        in.RecoverySeen,
		RecoveryCounter:     in.RecoveryCounter,
		RestorationPending:  in.RestorationPending,
		PolicyAction:        string(in.PolicyAction),
		PolicyReason:        in.PolicyReason,
		DDNTriggered:        in.DDNTriggered,
		DDNTriggeredAt:      in.DDNTriggeredAt,
		DDNSequence:         in.DDNSequence,
		DDNAcked:            in.DDNAcked,
		DDNAckedAt:          in.DDNAckedAt,
		DDNAckCause:         in.DDNAckCause,
		DDNFailureAt:        in.DDNFailureAt,
		DDNFailureCause:     in.DDNFailureCause,
		DDNFailureReason:    in.DDNFailureReason,
		DDNControlAction:    in.DDNControlAction,
		DDNControlPriority:  in.DDNControlPriority,
		DDNControlReason:    in.DDNControlReason,
		DDNControlRetryAt:   in.DDNControlRetryAt,
		DDNControlDecidedAt: in.DDNControlDecidedAt,
		StopPagingSent:      in.StopPagingSent,
		StopPagingSentAt:    in.StopPagingSentAt,
		StopPagingSequence:  in.StopPagingSequence,
		UserPlaneRestored:   in.UserPlaneRestored,
		UserPlaneRestoredAt: in.UserPlaneRestoredAt,
		RestoredEBI:         in.RestoredEBI,
	}
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}
