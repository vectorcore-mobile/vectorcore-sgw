package session

import (
	"fmt"
	"sort"
	"time"
)

type PFCPInventory interface {
	FindPFCPReconciliationSession(binding PFCPSessionBinding) (PFCPInventorySession, bool, error)
}

type PFCPInventorySession struct {
	PeerName string
	PeerAddr string
	CPSEID   uint64
	UPSEID   uint64
	PDRIDs   []uint32
	FARIDs   []uint32
}

type PFCPReconciliationResult struct {
	Checked      int
	Matched      int
	Missing      int
	Mismatched   int
	Unverifiable int
	NoBinding    int
}

func (m *Manager) ReconcilePFCPBindings(inv PFCPInventory, at time.Time) PFCPReconciliationResult {
	if at.IsZero() {
		at = time.Now()
	}
	sessions := m.List()
	result := PFCPReconciliationResult{Checked: len(sessions)}
	for _, sess := range sessions {
		state, reason := reconcileSessionPFCP(sess, inv)
		sess.MarkPFCPReconciliation(state, reason, at)
		switch state {
		case PFCPReconciliationMatched:
			result.Matched++
		case PFCPReconciliationMissing:
			result.Missing++
		case PFCPReconciliationMismatched:
			result.Mismatched++
		case PFCPReconciliationUnverifiable:
			result.Unverifiable++
		case PFCPReconciliationNoBinding:
			result.NoBinding++
		}
	}
	return result
}

func reconcileSessionPFCP(sess *SGWSession, inv PFCPInventory) (PFCPReconciliationState, string) {
	binding := sess.PFCPBinding()
	if !binding.Established || binding.LocalFSEID.SEID == 0 || binding.SGWUFSEID.SEID == 0 {
		return PFCPReconciliationNoBinding, "no-established-pfcp-binding"
	}
	if inv == nil {
		return PFCPReconciliationUnverifiable, "pfcp-inventory-unavailable"
	}
	actual, ok, err := inv.FindPFCPReconciliationSession(binding)
	if err != nil {
		return PFCPReconciliationUnverifiable, err.Error()
	}
	if !ok {
		return PFCPReconciliationMissing, fmt.Sprintf("sgwu-session-not-found cp_seid=0x%016X up_seid=0x%016X", binding.LocalFSEID.SEID, binding.SGWUFSEID.SEID)
	}
	if actual.CPSEID != binding.LocalFSEID.SEID || actual.UPSEID != binding.SGWUFSEID.SEID {
		return PFCPReconciliationMismatched, fmt.Sprintf("seid-mismatch expected_cp=0x%016X expected_up=0x%016X actual_cp=0x%016X actual_up=0x%016X", binding.LocalFSEID.SEID, binding.SGWUFSEID.SEID, actual.CPSEID, actual.UPSEID)
	}
	expectedPDRs, expectedFARs := sess.expectedPFCPRuleIDs()
	missingPDRs := missingIDs(expectedPDRs, actual.PDRIDs)
	missingFARs := missingIDs(expectedFARs, actual.FARIDs)
	if len(missingPDRs) > 0 || len(missingFARs) > 0 {
		return PFCPReconciliationMismatched, fmt.Sprintf("rule-mismatch missing_pdrs=%v missing_fars=%v", missingPDRs, missingFARs)
	}
	return PFCPReconciliationMatched, "pfcp-session-and-rule-ids-match"
}

func (s *SGWSession) expectedPFCPRuleIDs() ([]uint32, []uint32) {
	bearers := s.BearerList()
	pdrSet := make(map[uint32]struct{})
	farSet := make(map[uint32]struct{})
	for _, b := range bearers {
		for _, id := range b.PDRIDs {
			if id != 0 {
				pdrSet[id] = struct{}{}
			}
		}
		for _, id := range b.FARIDs {
			if id != 0 {
				farSet[id] = struct{}{}
			}
		}
	}
	return sortedIDs(pdrSet), sortedIDs(farSet)
}

func missingIDs(expected, actual []uint32) []uint32 {
	actualSet := make(map[uint32]struct{}, len(actual))
	for _, id := range actual {
		if id != 0 {
			actualSet[id] = struct{}{}
		}
	}
	var missing []uint32
	for _, id := range expected {
		if _, ok := actualSet[id]; !ok {
			missing = append(missing, id)
		}
	}
	return missing
}

func sortedIDs(set map[uint32]struct{}) []uint32 {
	ids := make([]uint32, 0, len(set))
	for id := range set {
		ids = append(ids, id)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
	return ids
}
