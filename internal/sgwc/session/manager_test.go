package session_test

import (
	"net/netip"
	"testing"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

func defaultParams() session.CreateParams {
	return session.CreateParams{
		IMSI:           "311430000000001",
		APN:            "internet",
		RATType:        6, // EUTRAN
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0xAABBCCDD,
			IPv4: netip.MustParseAddr("10.1.1.1"),
		},
		DefaultEBI:  5,
		QCI:         9,
		ARP:         bearer.ARP{PriorityLevel: 9},
		MBRUplink:   256000,
		MBRDownlink: 256000,
	}
}

func TestCreateAndFind(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.SessionID == "" {
		t.Error("SessionID is empty")
	}
	if sess.SGWS11FTEID.TEID == 0 {
		t.Error("SGW S11 TEID not allocated")
	}
	if sess.GetState() != session.StatePending {
		t.Errorf("state: got %q, want %q", sess.GetState(), session.StatePending)
	}

	got := m.Find(sess.SessionID)
	if got != sess {
		t.Error("Find returned wrong session")
	}
}

func TestFindByS11TEID(t *testing.T) {
	m := session.NewManager()
	sess, _, _ := m.Create(defaultParams())

	got := m.FindByS11TEID(sess.SGWS11FTEID.TEID)
	if got != sess {
		t.Error("FindByS11TEID returned wrong session")
	}

	if m.FindByS11TEID(0xDEAD) != nil {
		t.Error("FindByS11TEID should return nil for unknown TEID")
	}
}

func TestFindByIMSI(t *testing.T) {
	m := session.NewManager()
	sess, _, _ := m.Create(defaultParams())

	got := m.FindByIMSI("311430000000001")
	if got != sess {
		t.Error("FindByIMSI returned wrong session")
	}
	if m.FindByIMSI("000000000000000") != nil {
		t.Error("FindByIMSI should return nil for unknown IMSI")
	}
}

func TestDelete(t *testing.T) {
	m := session.NewManager()
	sess, _, _ := m.Create(defaultParams())
	teid := sess.SGWS11FTEID.TEID
	id := sess.SessionID

	m.Delete(id)

	if m.Find(id) != nil {
		t.Error("session still present after Delete")
	}
	if m.FindByS11TEID(teid) != nil {
		t.Error("S11 TEID index not cleaned up after Delete")
	}
	if m.FindByIMSI("311430000000001") != nil {
		t.Error("IMSI index not cleaned up after Delete")
	}
	if m.Count() != 0 {
		t.Errorf("Count: got %d, want 0", m.Count())
	}
}

func TestList(t *testing.T) {
	m := session.NewManager()
	p1, p2 := defaultParams(), defaultParams()
	p2.IMSI = "311430000000002"

	m.Create(p1) //nolint:errcheck
	m.Create(p2) //nolint:errcheck

	list := m.List()
	if len(list) != 2 {
		t.Errorf("List: got %d sessions, want 2", len(list))
	}
}

func TestStateTransition(t *testing.T) {
	m := session.NewManager()
	sess, _, _ := m.Create(defaultParams())

	if !sess.Transition(session.StateActive) {
		t.Error("Pending -> Active should be valid")
	}
	if sess.GetState() != session.StateActive {
		t.Errorf("state: got %q, want Active", sess.GetState())
	}
	if sess.Transition(session.StatePending) {
		t.Error("Active -> Pending should be invalid")
	}
}

func TestBearerSetAndGet(t *testing.T) {
	m := session.NewManager()
	sess, _, _ := m.Create(defaultParams())

	b := sess.GetBearer(5)
	if b == nil {
		t.Fatal("default bearer not present")
	}
	if b.EBI != 5 {
		t.Errorf("EBI: got %d, want 5", b.EBI)
	}
	if b.QCI != 9 {
		t.Errorf("QCI: got %d, want 9", b.QCI)
	}

	// Update the eNodeB S1-U F-TEID (simulates Modify Bearer Request)
	b.ENBS1UFTEID = bearer.FTEID{TEID: 0x12345678, IPv4: netip.MustParseAddr("10.2.3.4")}
	sess.SetBearer(b)

	updated := sess.GetBearer(5)
	if updated.ENBS1UFTEID.TEID != 0x12345678 {
		t.Errorf("eNodeB TEID not updated: got 0x%08X", updated.ENBS1UFTEID.TEID)
	}
}

func TestUniqueTEIDsAcrossSessions(t *testing.T) {
	m := session.NewManager()
	seen := make(map[uint32]bool)
	for i := 0; i < 100; i++ {
		p := defaultParams()
		p.IMSI = "31143000000" + string(rune('0'+i%10)) + string(rune('0'+i/10))
		sess, _, err := m.Create(p)
		if err != nil {
			t.Fatalf("Create #%d: %v", i, err)
		}
		if seen[sess.SGWS11FTEID.TEID] {
			t.Fatalf("duplicate TEID 0x%08X at session %d", sess.SGWS11FTEID.TEID, i)
		}
		seen[sess.SGWS11FTEID.TEID] = true
	}
}
