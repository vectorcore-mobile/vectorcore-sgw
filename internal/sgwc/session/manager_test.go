package session_test

import (
	"bytes"
	"net/netip"
	"testing"
	"time"

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

func TestCreateReusesExistingSGWS11FTEIDForAdditionalPDN(t *testing.T) {
	m := session.NewManager()
	defaultSess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create default session: %v", err)
	}

	params := defaultParams()
	params.APN = "ims"
	params.DefaultEBI = 6
	params.QCI = 5
	params.ReuseSGWS11FTEID = defaultSess.SGWS11FTEID

	imsSess, evicted, err := m.Create(params)
	if err != nil {
		t.Fatalf("Create IMS session: %v", err)
	}
	if evicted != nil {
		t.Fatalf("evicted = %v; want nil for different default EBI", evicted.SessionID)
	}
	if imsSess.SGWS11FTEID != defaultSess.SGWS11FTEID {
		t.Fatalf("IMS SGW S11 F-TEID = %+v; want reused %+v", imsSess.SGWS11FTEID, defaultSess.SGWS11FTEID)
	}
	if got := m.FindByS11TEID(defaultSess.SGWS11FTEID.TEID); got != imsSess {
		t.Fatalf("FindByS11TEID returned %+v; want newest IMS PDN session for legacy lookup", got)
	}
	if got := m.FindByS11TEIDAndBearer(defaultSess.SGWS11FTEID.TEID, 5); got != defaultSess {
		t.Fatalf("FindByS11TEIDAndBearer EBI 5 returned %+v; want default PDN session", got)
	}
	if got := m.FindByS11TEIDAndBearer(defaultSess.SGWS11FTEID.TEID, 6); got != imsSess {
		t.Fatalf("FindByS11TEIDAndBearer EBI 6 returned %+v; want IMS PDN session", got)
	}
	if got := m.FindByS11TEIDAndDefaultBearer(defaultSess.SGWS11FTEID.TEID, 5); got != defaultSess {
		t.Fatalf("FindByS11TEIDAndDefaultBearer EBI 5 returned %+v; want default PDN session", got)
	}
	if got := m.FindByS11TEIDAndDefaultBearer(defaultSess.SGWS11FTEID.TEID, 6); got != imsSess {
		t.Fatalf("FindByS11TEIDAndDefaultBearer EBI 6 returned %+v; want IMS PDN session", got)
	}
	if got := m.FindAllByS11TEID(defaultSess.SGWS11FTEID.TEID); len(got) != 2 {
		t.Fatalf("FindAllByS11TEID returned %d sessions; want 2", len(got))
	}
	if got := m.Count(); got != 2 {
		t.Fatalf("Count = %d; want both PDN sessions", got)
	}
}

func TestDeleteSharedS11TEIDKeepsOtherPDNIndexed(t *testing.T) {
	m := session.NewManager()
	defaultSess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create default session: %v", err)
	}

	params := defaultParams()
	params.APN = "ims"
	params.DefaultEBI = 6
	params.ReuseSGWS11FTEID = defaultSess.SGWS11FTEID
	imsSess, _, err := m.Create(params)
	if err != nil {
		t.Fatalf("Create IMS session: %v", err)
	}

	m.Delete(imsSess.SessionID)

	if got := m.FindByS11TEID(defaultSess.SGWS11FTEID.TEID); got != defaultSess {
		t.Fatalf("FindByS11TEID after deleting IMS = %+v; want default session", got)
	}
	if got := m.FindByS11TEIDAndBearer(defaultSess.SGWS11FTEID.TEID, 5); got != defaultSess {
		t.Fatalf("FindByS11TEIDAndBearer EBI 5 after deleting IMS = %+v; want default session", got)
	}
	if got := m.FindByS11TEIDAndBearer(defaultSess.SGWS11FTEID.TEID, 6); got != nil {
		t.Fatalf("FindByS11TEIDAndBearer EBI 6 after deleting IMS = %+v; want nil", got)
	}
}

func TestSecondaryRATUsageReportsAreCopied(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	payload := []byte{0x01, 0x02, 0x03}
	sess.RecordSecondaryRATUsageDataReports([]session.SecondaryRATUsageDataReport{{
		ReceivedAt:      time.Unix(1, 0),
		SourceProcedure: "s11_modify_bearer_request",
		MMEPeer:         "10.90.250.77:2123",
		SGWS11TEID:      sess.SGWS11FTEID.TEID,
		SequenceNumber:  0x123456,
		Payload:         payload,
	}})
	payload[0] = 0xff

	reports := sess.SecondaryRATUsageReports()
	if len(reports) != 1 {
		t.Fatalf("reports = %d, want 1", len(reports))
	}
	want := []byte{0x01, 0x02, 0x03}
	if !bytes.Equal(reports[0].Payload, want) {
		t.Fatalf("stored payload = %x, want %x", reports[0].Payload, want)
	}
	reports[0].Payload[0] = 0xee
	reports = sess.SecondaryRATUsageReports()
	if !bytes.Equal(reports[0].Payload, want) {
		t.Fatalf("returned payload was aliased: got %x want %x", reports[0].Payload, want)
	}
	if reports[0].SourceProcedure != "s11_modify_bearer_request" {
		t.Fatalf("SourceProcedure = %q", reports[0].SourceProcedure)
	}
}

func TestRegisterS5CTEIDFindsPendingSession(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sess.GetState() != session.StatePending {
		t.Fatalf("state = %q; want pending", sess.GetState())
	}

	const sgwS5CTEID uint32 = 0x0BE02E49
	sess.SGWS5CFTEID = session.FTEID{TEID: sgwS5CTEID, IPv4: netip.MustParseAddr("10.90.250.59")}
	m.RegisterS5CTEID(sess.SessionID, sgwS5CTEID)

	got := m.FindByS5CTEID(sgwS5CTEID)
	if got != sess {
		t.Fatalf("FindByS5CTEID returned %p; want pending session %p", got, sess)
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

func TestInvalidatePFCPBindingsClearsStaleSGWUState(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 10, IPv4: netip.MustParseAddr("192.0.2.10")},
		SGWUFSEID:   session.FSEID{SEID: 20, IPv4: netip.MustParseAddr("192.0.2.20")},
		SGWUName:    "sgwu-a",
		SGWUAddr:    "192.0.2.20:8805",
		Established: true,
	}
	b := sess.GetBearer(5)
	b.SGWS1UFTEID = bearer.FTEID{TEID: 0x11111111, IPv4: netip.MustParseAddr("10.0.0.1")}
	b.SGWS5UFTEID = bearer.FTEID{TEID: 0x22222222, IPv4: netip.MustParseAddr("10.0.0.2")}
	b.ENBS1UFTEID = bearer.FTEID{TEID: 0x33333333, IPv4: netip.MustParseAddr("10.0.0.3")}
	b.PGWS5UFTEID = bearer.FTEID{TEID: 0x44444444, IPv4: netip.MustParseAddr("10.0.0.4")}
	sess.SetBearer(b)

	if got := m.InvalidatePFCPBindings(); got != 1 {
		t.Fatalf("InvalidatePFCPBindings = %d; want 1", got)
	}
	if sess.PFCP.Established || sess.PFCP.LocalFSEID.SEID != 0 || sess.PFCP.SGWUFSEID.SEID != 0 {
		t.Fatalf("PFCP binding still present after invalidation: %+v", sess.PFCP)
	}
	if got := sess.GetState(); got != session.StateRecovering {
		t.Fatalf("session state after invalidation = %q; want %q", got, session.StateRecovering)
	}
	gotBearer := sess.GetBearer(5)
	if gotBearer.SGWS1UFTEID.TEID != 0 || gotBearer.SGWS5UFTEID.TEID != 0 {
		t.Fatalf("SGW-U F-TEIDs still present after invalidation: %+v", gotBearer)
	}
	if gotBearer.ENBS1UFTEID.TEID != 0x33333333 {
		t.Fatalf("eNodeB F-TEID was cleared unexpectedly: %+v", gotBearer.ENBS1UFTEID)
	}
	if gotBearer.PGWS5UFTEID.TEID != 0x44444444 {
		t.Fatalf("PGW F-TEID was cleared unexpectedly: %+v", gotBearer.PGWS5UFTEID)
	}
	if got := m.InvalidatePFCPBindings(); got != 0 {
		t.Fatalf("second InvalidatePFCPBindings = %d; want 0", got)
	}
}

func TestInvalidatePFCPBindingsForPeerOnlyClearsAffectedSGWU(t *testing.T) {
	m := session.NewManager()
	sessA, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create A: %v", err)
	}
	paramsB := defaultParams()
	paramsB.IMSI = "311430000000002"
	sessB, _, err := m.Create(paramsB)
	if err != nil {
		t.Fatalf("Create B: %v", err)
	}

	sessA.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 10, IPv4: netip.MustParseAddr("192.0.2.1")},
		SGWUFSEID:   session.FSEID{SEID: 20, IPv4: netip.MustParseAddr("192.0.2.10")},
		SGWUName:    "sgwu-a",
		SGWUAddr:    "192.0.2.10:8805",
		Established: true,
	}
	sessB.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 11, IPv4: netip.MustParseAddr("192.0.2.1")},
		SGWUFSEID:   session.FSEID{SEID: 21, IPv4: netip.MustParseAddr("192.0.2.11")},
		SGWUName:    "sgwu-b",
		SGWUAddr:    "192.0.2.11:8805",
		Established: true,
	}

	if got := m.InvalidatePFCPBindingsForPeer("sgwu-a", "192.0.2.10:8805"); got != 1 {
		t.Fatalf("InvalidatePFCPBindingsForPeer = %d; want 1", got)
	}
	if sessA.PFCP.Established || sessA.PFCP.SGWUFSEID.SEID != 0 {
		t.Fatalf("affected PFCP binding still present: %+v", sessA.PFCP)
	}
	if got := sessA.GetState(); got != session.StateRecovering {
		t.Fatalf("affected session state = %q; want %q", got, session.StateRecovering)
	}
	if !sessB.PFCP.Established || sessB.PFCP.SGWUFSEID.SEID != 21 {
		t.Fatalf("unaffected PFCP binding was changed: %+v", sessB.PFCP)
	}
	if got := sessB.GetState(); got != session.StatePending {
		t.Fatalf("unaffected session state = %q; want %q", got, session.StatePending)
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
