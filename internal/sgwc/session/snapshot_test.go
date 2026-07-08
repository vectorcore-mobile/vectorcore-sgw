package session_test

import (
	"net/netip"
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

func TestSessionSnapshotExportsDurableState(t *testing.T) {
	m := session.NewManager()
	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.SetPGWControlFTEID(session.FTEID{TEID: 0x80000001, IPv4: netip.MustParseAddr("10.90.250.92")})
	sess.SetSGWS5CFTEID(session.FTEID{TEID: 0x70000001, IPv4: netip.MustParseAddr("10.90.250.10")})
	sess.SetUEIPv4(netip.MustParseAddr("172.16.1.10"))
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 0x101, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 0x202, IPv4: netip.MustParseAddr("10.90.250.11")},
		SGWUName:    "sgw-u-1",
		SGWUAddr:    "10.90.250.11:8805",
		Established: true,
	})
	pdrUL, pdrDL, farUL, farDL := sess.AllocBearerRuleIDs()
	sess.SetBearer(&bearer.Bearer{
		EBI:         7,
		QCI:         1,
		ARP:         bearer.ARP{PriorityLevel: 2, PreemptionCapability: true},
		ENBS1UFTEID: bearer.FTEID{TEID: 0x1111, IPv4: netip.MustParseAddr("192.168.105.247")},
		SGWS1UFTEID: bearer.FTEID{TEID: 0x2222, IPv4: netip.MustParseAddr("10.90.250.11")},
		PGWS5UFTEID: bearer.FTEID{TEID: 0x3333, IPv4: netip.MustParseAddr("10.90.250.92")},
		SGWS5UFTEID: bearer.FTEID{TEID: 0x4444, IPv4: netip.MustParseAddr("10.90.250.11")},
		MBRUplink:   128000,
		MBRDownlink: 128000,
		GBRUplink:   64000,
		GBRDownlink: 64000,
		TFT:         &bearer.TFT{Raw: []byte{0x01, 0x02, 0x03}},
		State:       bearer.BearerStateActive,
		PDRIDs:      [2]uint32{uint32(pdrUL), uint32(pdrDL)},
		FARIDs:      [2]uint32{farUL, farDL},
	})
	at := time.Unix(200, 0).UTC()
	sess.MarkPGWRestart("10.90.250.92:2123", 4, at)
	sess.MarkMMERestart("10.90.250.77:2123", 8, at)
	sess.SetMMERestorationPolicy(session.MMERestorationPolicyPreserve, "preserve IMS", at)
	sess.MarkMMERestorationDDNControlDecision("send_now", "high", "qci-1", 0, at)
	sess.MarkMMERestorationDDNTriggered(1234, at)

	snap := sess.Snapshot()
	if snap.SchemaVersion != sessioncheckpoint.CurrentSchemaVersion {
		t.Fatalf("schema version = %d; want %d", snap.SchemaVersion, sessioncheckpoint.CurrentSchemaVersion)
	}
	if snap.SessionID != sess.SessionID || snap.IMSI != defaultParams().IMSI || snap.APN != "internet" {
		t.Fatalf("unexpected identity snapshot: %+v", snap)
	}
	if snap.SGWS11FTEID.TEID != sess.SGWS11FTEID.TEID || snap.PGWControlFTEID.IPv4 != "10.90.250.92" {
		t.Fatalf("unexpected control F-TEIDs: %+v %+v", snap.SGWS11FTEID, snap.PGWControlFTEID)
	}
	if snap.UEIPv4 != "172.16.1.10" {
		t.Fatalf("UEIPv4 = %q; want 172.16.1.10", snap.UEIPv4)
	}
	if !snap.PFCP.Established || snap.PFCP.LocalFSEID.SEID != 0x101 || snap.PFCP.SGWUName != "sgw-u-1" {
		t.Fatalf("unexpected PFCP snapshot: %+v", snap.PFCP)
	}
	if snap.PGWFailure.PathState != string(session.PGWPathStateRestarted) || snap.PGWFailure.RecoveryCounter != 4 {
		t.Fatalf("unexpected PGW failure snapshot: %+v", snap.PGWFailure)
	}
	if snap.MMERestoration.State != string(session.MMERestorationStateRestorationPending) ||
		!snap.MMERestoration.DDNTriggered ||
		snap.MMERestoration.DDNSequence != 1234 ||
		snap.MMERestoration.DDNControlPriority != "high" {
		t.Fatalf("unexpected MME restoration snapshot: %+v", snap.MMERestoration)
	}
	if snap.NextRuleID != 5 {
		t.Fatalf("NextRuleID = %d; want 5 after one dedicated bearer allocation", snap.NextRuleID)
	}
	if len(snap.Bearers) != 2 {
		t.Fatalf("bearer count = %d; want default + dedicated", len(snap.Bearers))
	}
	if snap.Bearers[0].EBI != 5 || snap.Bearers[1].EBI != 7 {
		t.Fatalf("bearer order/EBIs = %+v; want sorted EBIs 5,7", snap.Bearers)
	}
	dedicated := snap.Bearers[1]
	if dedicated.QCI != 1 || dedicated.ENBS1UFTEID.TEID != 0x1111 || dedicated.PDRIDs != [2]uint32{3, 4} {
		t.Fatalf("unexpected dedicated bearer snapshot: %+v", dedicated)
	}
	if len(dedicated.TFTRaw) != 3 || dedicated.TFTRaw[0] != 0x01 {
		t.Fatalf("TFT raw = %x", dedicated.TFTRaw)
	}

	sess.GetBearer(7).TFT.Raw[0] = 0xff
	if dedicated.TFTRaw[0] != 0x01 {
		t.Fatal("snapshot TFT raw aliases live bearer state")
	}
}

func TestManagerSnapshotsExportMultiPDNAndDedicatedIMSBearers(t *testing.T) {
	m := session.NewManager()
	internet, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create internet: %v", err)
	}
	imsParams := defaultParams()
	imsParams.APN = "ims.mnc435.mcc311.gprs"
	imsParams.DefaultEBI = 6
	imsParams.QCI = 5
	imsParams.ReuseSGWS11FTEID = internet.SGWS11FTEID
	ims, _, err := m.Create(imsParams)
	if err != nil {
		t.Fatalf("Create IMS: %v", err)
	}
	for _, ebi := range []uint8{7, 8, 9} {
		pdrUL, pdrDL, farUL, farDL := ims.AllocBearerRuleIDs()
		ims.SetBearer(&bearer.Bearer{
			EBI:    ebi,
			QCI:    1,
			State:  bearer.BearerStateActive,
			PDRIDs: [2]uint32{uint32(pdrUL), uint32(pdrDL)},
			FARIDs: [2]uint32{farUL, farDL},
		})
	}

	snapshots := m.Snapshots()
	if len(snapshots) != 2 {
		t.Fatalf("snapshot count = %d; want internet + IMS", len(snapshots))
	}
	byAPN := map[string]sessioncheckpoint.SessionSnapshot{}
	for _, snap := range snapshots {
		byAPN[snap.APN] = snap
	}
	if byAPN["internet"].DefaultBearerID != 5 || len(byAPN["internet"].Bearers) != 1 {
		t.Fatalf("internet snapshot = %+v; want only default EBI 5", byAPN["internet"])
	}
	imsSnap := byAPN["ims.mnc435.mcc311.gprs"]
	if imsSnap.DefaultBearerID != 6 || len(imsSnap.Bearers) != 4 {
		t.Fatalf("IMS snapshot = %+v; want default EBI 6 plus 7/8/9", imsSnap)
	}
	wantEBIs := []uint8{6, 7, 8, 9}
	for i, want := range wantEBIs {
		if imsSnap.Bearers[i].EBI != want {
			t.Fatalf("IMS bearer[%d] EBI = %d; want %d in sorted snapshot", i, imsSnap.Bearers[i].EBI, want)
		}
	}
	if imsSnap.Bearers[0].PDRIDs != [2]uint32{0, 0} {
		t.Fatalf("IMS default bearer PDR IDs = %+v; dedicated IDs should not overwrite default", imsSnap.Bearers[0].PDRIDs)
	}
	if imsSnap.Bearers[1].PDRIDs != [2]uint32{3, 4} ||
		imsSnap.Bearers[2].PDRIDs != [2]uint32{5, 6} ||
		imsSnap.Bearers[3].PDRIDs != [2]uint32{7, 8} {
		t.Fatalf("IMS dedicated bearer PDR IDs = %+v %+v %+v; want preserved per bearer",
			imsSnap.Bearers[1].PDRIDs, imsSnap.Bearers[2].PDRIDs, imsSnap.Bearers[3].PDRIDs)
	}
}
