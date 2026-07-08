package session_test

import (
	"net/netip"
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

func TestRestoreSnapshotsRebuildsIndexesAsRecovering(t *testing.T) {
	source := session.NewManager()
	internet, _, err := source.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create internet: %v", err)
	}
	internet.SetSGWS5CFTEID(session.FTEID{TEID: 0x5001, IPv4: netip.MustParseAddr("10.90.250.10")})
	internet.SetPGWControlFTEID(session.FTEID{TEID: 0x9001, IPv4: netip.MustParseAddr("10.90.250.92")})
	internet.SetUEIPv4(netip.MustParseAddr("172.16.1.10"))
	internet.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 11, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 22, IPv4: netip.MustParseAddr("10.90.250.11")},
		SGWUName:    "sgw-u-1",
		SGWUAddr:    "10.90.250.11:8805",
		Established: true,
	})
	source.RegisterS5CTEID(internet.SessionID, internet.SGWS5CFTEID.TEID)
	source.RegisterPGW(internet.SessionID, "10.90.250.92:30064")

	imsParams := defaultParams()
	imsParams.APN = "ims.mnc435.mcc311.gprs"
	imsParams.DefaultEBI = 6
	imsParams.QCI = 5
	imsParams.ReuseSGWS11FTEID = internet.SGWS11FTEID
	ims, _, err := source.Create(imsParams)
	if err != nil {
		t.Fatalf("Create IMS: %v", err)
	}
	ims.SetSGWS5CFTEID(session.FTEID{TEID: 0x5002, IPv4: netip.MustParseAddr("10.90.250.10")})
	source.RegisterS5CTEID(ims.SessionID, ims.SGWS5CFTEID.TEID)
	source.RegisterPGW(ims.SessionID, "10.90.250.92:2123")
	for _, ebi := range []uint8{7, 8, 9} {
		pdrUL, pdrDL, farUL, farDL := ims.AllocBearerRuleIDs()
		ims.SetBearer(&bearer.Bearer{
			EBI:    ebi,
			QCI:    1,
			State:  bearer.BearerStateActive,
			PDRIDs: [2]uint32{uint32(pdrUL), uint32(pdrDL)},
			FARIDs: [2]uint32{farUL, farDL},
			TFT:    &bearer.TFT{Raw: []byte{ebi, 0xaa}},
		})
	}
	at := time.Unix(100, 0).UTC()
	ims.MarkMMERestart("10.90.250.77:2123", 9, at)
	ims.MarkMMERestorationDDNTriggered(0x1234, at)

	restored := session.NewManager()
	result, err := restored.RestoreSnapshots(source.Snapshots())
	if err != nil {
		t.Fatalf("RestoreSnapshots: %v", err)
	}
	if result.Loaded != 2 || result.Restored != 2 || result.ReservedS11TEID != 1 {
		t.Fatalf("restore result = %+v; want loaded/restored 2 and one shared S11 TEID reservation", result)
	}
	if restored.Count() != 2 {
		t.Fatalf("restored Count = %d; want 2", restored.Count())
	}
	if got := restored.Find(internet.SessionID); got == nil || got.GetState() != session.StateRecovering {
		t.Fatalf("internet restored session = %+v; want recovering", got)
	}
	if got := restored.FindByS11TEIDAndDefaultBearer(internet.SGWS11FTEID.TEID, 5); got == nil || got.SessionID != internet.SessionID {
		t.Fatalf("FindByS11TEIDAndDefaultBearer EBI 5 = %+v", got)
	}
	if got := restored.FindByS11TEIDAndDefaultBearer(internet.SGWS11FTEID.TEID, 6); got == nil || got.SessionID != ims.SessionID {
		t.Fatalf("FindByS11TEIDAndDefaultBearer EBI 6 = %+v", got)
	}
	if got := restored.FindByS5CTEID(0x5002); got == nil || got.SessionID != ims.SessionID {
		t.Fatalf("FindByS5CTEID IMS = %+v", got)
	}
	if got := restored.FindByPGW("10.90.250.92:39999"); len(got) != 2 {
		t.Fatalf("FindByPGW restored = %d sessions; want 2", len(got))
	}
	imsRestored := restored.Find(ims.SessionID)
	if imsRestored == nil {
		t.Fatal("IMS restored session missing")
	}
	if imsRestored.PFCPBinding().Established {
		t.Fatal("IMS PFCP binding unexpectedly established; test source did not set it")
	}
	imsSnap := imsRestored.Snapshot()
	if len(imsSnap.Bearers) != 4 {
		t.Fatalf("IMS restored bearer count = %d; want 4", len(imsSnap.Bearers))
	}
	if imsSnap.MMERestoration.State != string(session.MMERestorationStateRestorationPending) ||
		imsSnap.MMERestoration.DDNSequence != 0x1234 {
		t.Fatalf("IMS restoration snapshot = %+v", imsSnap.MMERestoration)
	}
	if imsSnap.Bearers[1].TFTRaw[0] != 7 {
		t.Fatalf("dedicated bearer TFT not restored: %+v", imsSnap.Bearers[1])
	}
}

func TestRestoreSnapshotsSkipsDeletedAndInvalidSnapshots(t *testing.T) {
	valid := sessioncheckpoint.SessionSnapshot{
		SchemaVersion:   sessioncheckpoint.CurrentSchemaVersion,
		SessionID:       "valid",
		IMSI:            "00101",
		APN:             "ims",
		SGWS11FTEID:     sessioncheckpoint.FTEIDSnapshot{TEID: 100},
		DefaultBearerID: 6,
		State:           string(session.StateActive),
		Bearers:         []sessioncheckpoint.BearerSnapshot{{EBI: 6, QCI: 5}},
	}
	deleted := valid
	deleted.SessionID = "deleted"
	deleted.SGWS11FTEID.TEID = 101
	deleted.State = string(session.StateDeleted)
	invalid := valid
	invalid.SessionID = "invalid"
	invalid.SGWS11FTEID.TEID = 0

	m := session.NewManager()
	result, err := m.RestoreSnapshots([]sessioncheckpoint.SessionSnapshot{valid, deleted, invalid})
	if err != nil {
		t.Fatalf("RestoreSnapshots: %v", err)
	}
	if result.Restored != 1 || result.SkippedDeleted != 1 || result.SkippedInvalid != 1 {
		t.Fatalf("restore result = %+v; want one restored/deleted/invalid", result)
	}
	if m.Count() != 1 || m.Find("valid") == nil {
		t.Fatalf("restored manager count/find = %d/%+v", m.Count(), m.Find("valid"))
	}
}

func TestRestoreSnapshotsRejectsDuplicateIndexes(t *testing.T) {
	first := sessioncheckpoint.SessionSnapshot{
		SchemaVersion:   sessioncheckpoint.CurrentSchemaVersion,
		SessionID:       "first",
		IMSI:            "00101",
		APN:             "ims",
		SGWS11FTEID:     sessioncheckpoint.FTEIDSnapshot{TEID: 100},
		SGWS5CFTEID:     sessioncheckpoint.FTEIDSnapshot{TEID: 200},
		DefaultBearerID: 6,
		State:           string(session.StateActive),
		Bearers:         []sessioncheckpoint.BearerSnapshot{{EBI: 6, QCI: 5}},
	}
	second := first
	second.SessionID = "second"
	second.IMSI = "00102"
	second.SGWS11FTEID.TEID = 101

	m := session.NewManager()
	if _, err := m.RestoreSnapshots([]sessioncheckpoint.SessionSnapshot{first, second}); err == nil {
		t.Fatal("RestoreSnapshots succeeded with duplicate S5-C TEID")
	}
}
