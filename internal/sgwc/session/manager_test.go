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

func TestRegisterPGWIndexesCanonicalEndpoint(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	m.RegisterPGW(sess.SessionID, "10.90.250.92:30064")

	got := m.FindByPGW("10.90.250.92:2123")
	if len(got) != 1 || got[0] != sess {
		t.Fatalf("FindByPGW canonical = %+v; want session", got)
	}
	got = m.FindByPGW("10.90.250.92:39999")
	if len(got) != 1 || got[0] != sess {
		t.Fatalf("FindByPGW transient = %+v; want session", got)
	}
	status := sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateUp || status.PGWAddr != "10.90.250.92:2123" {
		t.Fatalf("PGW failure status = %+v; want up at canonical PGW", status)
	}
}

func TestRegisterPGWIndexesMultipleSessionsPerPGW(t *testing.T) {
	m := session.NewManager()
	defaultSess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create default: %v", err)
	}
	imsParams := defaultParams()
	imsParams.APN = "ims"
	imsParams.DefaultEBI = 6
	imsParams.QCI = 5
	imsParams.ReuseSGWS11FTEID = defaultSess.SGWS11FTEID
	imsSess, _, err := m.Create(imsParams)
	if err != nil {
		t.Fatalf("Create IMS: %v", err)
	}
	otherParams := defaultParams()
	otherParams.IMSI = "311430000000002"
	otherSess, _, err := m.Create(otherParams)
	if err != nil {
		t.Fatalf("Create other UE: %v", err)
	}

	m.RegisterPGW(defaultSess.SessionID, "10.90.250.92:2123")
	m.RegisterPGW(imsSess.SessionID, "10.90.250.92:30064")
	m.RegisterPGW(otherSess.SessionID, "10.90.250.93:2123")

	samePGW := m.FindByPGW("10.90.250.92:2123")
	if len(samePGW) != 2 {
		t.Fatalf("sessions on PGW .92 = %d; want 2", len(samePGW))
	}
	otherPGW := m.FindByPGW("10.90.250.93:2123")
	if len(otherPGW) != 1 || otherPGW[0] != otherSess {
		t.Fatalf("sessions on PGW .93 = %+v; want other UE session", otherPGW)
	}
}

func TestDeleteRemovesPGWIndex(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.RegisterPGW(sess.SessionID, "10.90.250.92:2123")

	m.Delete(sess.SessionID)

	if got := m.FindByPGW("10.90.250.92:2123"); len(got) != 0 {
		t.Fatalf("FindByPGW after delete = %+v; want empty", got)
	}
}

func TestPGWFailureStateSnapshot(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	downAt := time.Unix(100, 0).UTC()
	sess.SetPGWPathState(session.PGWPathStateDown, "10.90.250.92:2123", downAt)
	status := sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateDown || !status.PathDownAt.Equal(downAt) {
		t.Fatalf("down status = %+v; want down at %s", status, downAt)
	}
	restartAt := time.Unix(200, 0).UTC()
	sess.MarkPGWRestart("10.90.250.92:2123", 12, restartAt)
	status = sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateRestarted || !status.RestartDetectedAt.Equal(restartAt) ||
		!status.RecoverySeen || status.RecoveryCounter != 12 {
		t.Fatalf("restart status = %+v; want restarted recovery 12", status)
	}
}

func TestMarkPGWPathStateUpdatesIndexedSessions(t *testing.T) {
	m := session.NewManager()
	first, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	secondParams := defaultParams()
	secondParams.IMSI = "311430000000002"
	second, _, err := m.Create(secondParams)
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	otherParams := defaultParams()
	otherParams.IMSI = "311430000000003"
	other, _, err := m.Create(otherParams)
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}
	m.RegisterPGW(first.SessionID, "10.90.250.92:2123")
	m.RegisterPGW(second.SessionID, "10.90.250.92:30064")
	m.RegisterPGW(other.SessionID, "10.90.250.93:2123")

	downAt := time.Unix(300, 0).UTC()
	if got := m.MarkPGWPathState("10.90.250.92:39999", session.PGWPathStateDown, downAt); got != 2 {
		t.Fatalf("MarkPGWPathState affected = %d; want 2", got)
	}
	for _, sess := range []*session.SGWSession{first, second} {
		status := sess.PGWFailureSnapshot()
		if status.PathState != session.PGWPathStateDown || !status.PathDownAt.Equal(downAt) ||
			status.PGWAddr != "10.90.250.92:2123" {
			t.Fatalf("indexed session status = %+v; want down on canonical PGW", status)
		}
	}
	if status := other.PGWFailureSnapshot(); status.PathState != session.PGWPathStateUp {
		t.Fatalf("other PGW session status = %+v; want unchanged up", status)
	}

	upAt := time.Unix(400, 0).UTC()
	if got := m.MarkPGWPathState("10.90.250.92:2123", session.PGWPathStateUp, upAt); got != 2 {
		t.Fatalf("MarkPGWPathState up affected = %d; want 2", got)
	}
	if status := first.PGWFailureSnapshot(); status.PathState != session.PGWPathStateUp || !status.PathDownAt.IsZero() {
		t.Fatalf("recovered status = %+v; want up with cleared PathDownAt", status)
	}
}

func TestMarkPGWRestartUpdatesIndexedSessions(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	m.RegisterPGW(sess.SessionID, "10.90.250.92:30064")

	restartAt := time.Unix(500, 0).UTC()
	if got := m.MarkPGWRestart("10.90.250.92:2123", 17, restartAt); got != 1 {
		t.Fatalf("MarkPGWRestart affected = %d; want 1", got)
	}
	status := sess.PGWFailureSnapshot()
	if status.PathState != session.PGWPathStateRestarted || status.PGWAddr != "10.90.250.92:2123" ||
		!status.RecoverySeen || status.RecoveryCounter != 17 || !status.RestartDetectedAt.Equal(restartAt) {
		t.Fatalf("restart status = %+v; want restarted recovery 17", status)
	}
}

func TestMarkMMERestartUpdatesMatchingMMESessions(t *testing.T) {
	m := session.NewManager()
	firstParams := defaultParams()
	firstParams.MMEControlFTEID.IPv4 = netip.MustParseAddr("10.90.250.77")
	first, _, err := m.Create(firstParams)
	if err != nil {
		t.Fatalf("Create first: %v", err)
	}
	secondParams := defaultParams()
	secondParams.IMSI = "311430000000002"
	secondParams.MMEControlFTEID.IPv4 = netip.MustParseAddr("10.90.250.77")
	second, _, err := m.Create(secondParams)
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	otherParams := defaultParams()
	otherParams.IMSI = "311430000000003"
	otherParams.MMEControlFTEID.IPv4 = netip.MustParseAddr("10.90.250.78")
	other, _, err := m.Create(otherParams)
	if err != nil {
		t.Fatalf("Create other: %v", err)
	}

	restartAt := time.Unix(600, 0).UTC()
	if got := m.MarkMMERestart("10.90.250.77:30032", 25, restartAt); got != 2 {
		t.Fatalf("MarkMMERestart affected = %d; want 2", got)
	}
	for _, sess := range []*session.SGWSession{first, second} {
		status := sess.MMERestorationSnapshot()
		if status.State != session.MMERestorationStateRestorationPending ||
			status.MMEAddr != "10.90.250.77:2123" ||
			!status.RecoverySeen ||
			status.RecoveryCounter != 25 ||
			!status.RestartDetectedAt.Equal(restartAt) ||
			!status.RestorationPending {
			t.Fatalf("indexed session MME status = %+v; want restoration pending recovery 25", status)
		}
	}
	if status := other.MMERestorationSnapshot(); status.RecoverySeen {
		t.Fatalf("other MME session status = %+v; want unchanged", status)
	}
}

func TestMarkMMEPathStateUpdatesMatchingMMESessions(t *testing.T) {
	m := session.NewManager()
	params := defaultParams()
	params.MMEControlFTEID.IPv4 = netip.MustParseAddr("10.90.250.77")
	sess, _, err := m.Create(params)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	downAt := time.Unix(700, 0).UTC()
	if got := m.MarkMMEPathState("10.90.250.77:39999", session.MMERestorationStateDown, downAt); got != 1 {
		t.Fatalf("MarkMMEPathState affected = %d; want 1", got)
	}
	status := sess.MMERestorationSnapshot()
	if status.State != session.MMERestorationStateDown ||
		status.MMEAddr != "10.90.250.77:2123" ||
		!status.PathDownAt.Equal(downAt) {
		t.Fatalf("down status = %+v; want down on canonical MME", status)
	}

	upAt := time.Unix(800, 0).UTC()
	if got := m.MarkMMEPathState("10.90.250.77:2123", session.MMERestorationStateUp, upAt); got != 1 {
		t.Fatalf("MarkMMEPathState up affected = %d; want 1", got)
	}
	status = sess.MMERestorationSnapshot()
	if status.State != session.MMERestorationStateUp || !status.PathDownAt.IsZero() {
		t.Fatalf("up status = %+v; want up with cleared PathDownAt", status)
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

func TestFindByPFCPSEID(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 101},
		SGWUFSEID:   session.FSEID{SEID: 202},
		Established: true,
	})
	if got := m.FindByPFCPSEID(101, 202); got != sess {
		t.Fatalf("FindByPFCPSEID = %v; want session", got)
	}
	if got := m.FindByPFCPSEID(101, 0); got != sess {
		t.Fatalf("FindByPFCPSEID by CP = %v; want session", got)
	}
	if got := m.FindByPFCPSEID(101, 999); got != nil {
		t.Fatalf("FindByPFCPSEID mismatched UP = %v; want nil", got)
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
	if updated.LastControlActivityAt.IsZero() || updated.LastActivitySource != session.BearerActivitySourceSetBearer {
		t.Fatalf("SetBearer activity = %s/%q; want control activity source set_bearer",
			updated.LastControlActivityAt, updated.LastActivitySource)
	}
}

func TestBearerActivityTracking(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	defaultBearer := sess.GetBearer(5)
	if defaultBearer == nil {
		t.Fatal("default bearer missing")
	}
	if defaultBearer.LastControlActivityAt.IsZero() {
		t.Fatal("default bearer LastControlActivityAt is zero after create")
	}
	if defaultBearer.LastActivitySource != session.BearerActivitySourceCreateSession {
		t.Fatalf("default bearer activity source = %q; want create_session", defaultBearer.LastActivitySource)
	}

	controlAt := time.Unix(100, 0).UTC()
	if !sess.MarkBearerControlActivity(5, "modify_bearer", controlAt) {
		t.Fatal("MarkBearerControlActivity returned false")
	}
	defaultBearer = sess.GetBearer(5)
	if !defaultBearer.LastControlActivityAt.Equal(controlAt) || defaultBearer.LastActivitySource != "modify_bearer" {
		t.Fatalf("control activity = %s/%q; want %s/modify_bearer",
			defaultBearer.LastControlActivityAt, defaultBearer.LastActivitySource, controlAt)
	}

	userAt := time.Unix(110, 0).UTC()
	if !sess.MarkBearerUserPlaneActivity(5, "pfcp_usage_report", userAt) {
		t.Fatal("MarkBearerUserPlaneActivity returned false")
	}
	defaultBearer = sess.GetBearer(5)
	if !defaultBearer.LastUserPlaneActivityAt.Equal(userAt) || defaultBearer.LastActivitySource != "pfcp_usage_report" {
		t.Fatalf("user-plane activity = %s/%q; want %s/pfcp_usage_report",
			defaultBearer.LastUserPlaneActivityAt, defaultBearer.LastActivitySource, userAt)
	}

	if sess.MarkBearerControlActivity(9, "missing", time.Now()) {
		t.Fatal("MarkBearerControlActivity succeeded for missing bearer")
	}
	if sess.MarkBearerUserPlaneActivity(9, "missing", time.Now()) {
		t.Fatal("MarkBearerUserPlaneActivity succeeded for missing bearer")
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
