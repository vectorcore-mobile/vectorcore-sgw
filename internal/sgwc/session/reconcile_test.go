package session_test

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

func TestReconcilePFCPBindingsMarksMatchedSessionActive(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	at := time.Unix(500, 0).UTC()
	inv := fakePFCPInventory{sessions: map[uint64]session.PFCPInventorySession{
		11: {
			PeerName: "sgw-u-1",
			PeerAddr: "10.90.250.11:8805",
			CPSEID:   11,
			UPSEID:   22,
			PDRIDs:   []uint32{1, 2, 3, 4},
			FARIDs:   []uint32{1, 2, 3, 4},
		},
	}}

	result := m.ReconcilePFCPBindings(inv, at)
	if result.Matched != 1 || result.Checked != 1 {
		t.Fatalf("reconcile result = %+v; want one matched", result)
	}
	if got := sess.GetState(); got != session.StateActive {
		t.Fatalf("session state = %q; want active after PFCP match", got)
	}
	status := sess.PFCPReconciliationSnapshot()
	if status.State != session.PFCPReconciliationMatched || status.At != at {
		t.Fatalf("reconciliation status = %+v", status)
	}
}

func TestReconcilePFCPBindingsMarksMissingAndKeepsRecovering(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	result := m.ReconcilePFCPBindings(fakePFCPInventory{sessions: map[uint64]session.PFCPInventorySession{}}, time.Unix(500, 0).UTC())
	if result.Missing != 1 {
		t.Fatalf("reconcile result = %+v; want one missing", result)
	}
	if got := sess.GetState(); got != session.StateRecovering {
		t.Fatalf("session state = %q; want recovering", got)
	}
	status := sess.PFCPReconciliationSnapshot()
	if status.State != session.PFCPReconciliationMissing || !strings.Contains(status.Reason, "sgwu-session-not-found") {
		t.Fatalf("reconciliation status = %+v", status)
	}
	if binding := sess.PFCPBinding(); binding.LocalFSEID.SEID != 11 || binding.SGWUFSEID.SEID != 22 {
		t.Fatalf("PFCP binding was destroyed by reconciliation: %+v", binding)
	}
}

func TestReconcilePFCPBindingsMarksRuleMismatch(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	result := m.ReconcilePFCPBindings(fakePFCPInventory{sessions: map[uint64]session.PFCPInventorySession{
		11: {CPSEID: 11, UPSEID: 22, PDRIDs: []uint32{1, 2}, FARIDs: []uint32{1, 2, 3}},
	}}, time.Unix(500, 0).UTC())
	if result.Mismatched != 1 {
		t.Fatalf("reconcile result = %+v; want one mismatched", result)
	}
	status := sess.PFCPReconciliationSnapshot()
	if status.State != session.PFCPReconciliationMismatched || !strings.Contains(status.Reason, "rule-mismatch") {
		t.Fatalf("reconciliation status = %+v", status)
	}
}

func TestReconcilePFCPBindingsNilInventoryIsUnverifiable(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	result := m.ReconcilePFCPBindings(nil, time.Unix(500, 0).UTC())
	if result.Unverifiable != 1 {
		t.Fatalf("reconcile result = %+v; want one unverifiable", result)
	}
	if got := sess.GetState(); got != session.StateRecovering {
		t.Fatalf("session state = %q; want recovering", got)
	}
	status := sess.PFCPReconciliationSnapshot()
	if status.State != session.PFCPReconciliationUnverifiable || status.Reason != "pfcp-inventory-unavailable" {
		t.Fatalf("reconciliation status = %+v", status)
	}
}

func TestReconcilePFCPBindingsNoBinding(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !sess.Transition(session.StateRecovering) {
		t.Fatal("Transition recovering failed")
	}
	result := m.ReconcilePFCPBindings(fakePFCPInventory{}, time.Unix(500, 0).UTC())
	if result.NoBinding != 1 {
		t.Fatalf("reconcile result = %+v; want no binding", result)
	}
	status := sess.PFCPReconciliationSnapshot()
	if status.State != session.PFCPReconciliationNoBinding {
		t.Fatalf("reconciliation status = %+v", status)
	}
}

func TestReconcilePFCPBindingsInventoryError(t *testing.T) {
	m, sess := managerWithPFCPBinding(t)
	result := m.ReconcilePFCPBindings(fakePFCPInventory{err: errors.New("sgwu API timeout")}, time.Unix(500, 0).UTC())
	if result.Unverifiable != 1 {
		t.Fatalf("reconcile result = %+v; want unverifiable", result)
	}
	status := sess.PFCPReconciliationSnapshot()
	if status.State != session.PFCPReconciliationUnverifiable || status.Reason != "sgwu API timeout" {
		t.Fatalf("reconciliation status = %+v", status)
	}
}

func managerWithPFCPBinding(t *testing.T) (*session.Manager, *session.SGWSession) {
	t.Helper()
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !sess.Transition(session.StateRecovering) {
		t.Fatal("Transition recovering failed")
	}
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 11, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 22, IPv4: netip.MustParseAddr("10.90.250.11")},
		SGWUName:    "sgw-u-1",
		SGWUAddr:    "10.90.250.11:8805",
		Established: true,
	})
	defaultBearer := sess.GetBearer(5)
	defaultBearer.PDRIDs = [2]uint32{1, 2}
	defaultBearer.FARIDs = [2]uint32{1, 2}
	sess.SetBearer(defaultBearer)
	sess.SetBearer(&bearer.Bearer{
		EBI:    7,
		QCI:    1,
		State:  bearer.BearerStateActive,
		PDRIDs: [2]uint32{3, 4},
		FARIDs: [2]uint32{3, 4},
	})
	return m, sess
}

type fakePFCPInventory struct {
	sessions map[uint64]session.PFCPInventorySession
	err      error
}

func (f fakePFCPInventory) FindPFCPReconciliationSession(binding session.PFCPSessionBinding) (session.PFCPInventorySession, bool, error) {
	if f.err != nil {
		return session.PFCPInventorySession{}, false, f.err
	}
	got, ok := f.sessions[binding.LocalFSEID.SEID]
	return got, ok, nil
}
