package s11

import (
	"net/netip"
	"testing"

	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

func newIdleResumeTestSession(t *testing.T) *session.SGWSession {
	t.Helper()
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:            "001010123456789",
		APN:             "ims",
		MMEControlFTEID: session.FTEID{TEID: 0x10000001, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
	})
	if err != nil {
		t.Fatalf("Create session: %v", err)
	}
	return sess
}

func TestDownlinkPFCPRuleIDsAllowDefaultFallbackOnly(t *testing.T) {
	sess := newIdleResumeTestSession(t)

	defaultBearer := sess.GetBearer(6)
	pdrID, farID, ok := downlinkPFCPRuleIDs(sess, defaultBearer)
	if !ok || pdrID != 2 || farID != 2 {
		t.Fatalf("default bearer rule IDs = (%d,%d,%v); want (2,2,true)", pdrID, farID, ok)
	}

	dedicated := &bearer.Bearer{EBI: 7, PDRIDs: [2]uint32{3, 4}, FARIDs: [2]uint32{3, 4}}
	pdrID, farID, ok = downlinkPFCPRuleIDs(sess, dedicated)
	if !ok || pdrID != 4 || farID != 4 {
		t.Fatalf("dedicated bearer rule IDs = (%d,%d,%v); want (4,4,true)", pdrID, farID, ok)
	}

	missingDedicated := &bearer.Bearer{EBI: 8}
	if _, _, ok := downlinkPFCPRuleIDs(sess, missingDedicated); ok {
		t.Fatal("dedicated bearer without rule IDs used default fallback")
	}
}

func TestReleaseAccessBearerFARUpdatesCoverEveryBearer(t *testing.T) {
	sess := newIdleResumeTestSession(t)
	sess.SetBearer(&bearer.Bearer{EBI: 7, PDRIDs: [2]uint32{3, 4}, FARIDs: [2]uint32{3, 4}})

	updates, err := releaseAccessBearerFARUpdates(sess)
	if err != nil {
		t.Fatalf("releaseAccessBearerFARUpdates: %v", err)
	}
	if len(updates) != 2 {
		t.Fatalf("updates = %d; want 2", len(updates))
	}

	seen := map[uint32]bool{}
	for _, update := range updates {
		if update.ApplyAction != pfcpie.ApplyActionDROP {
			t.Fatalf("ApplyAction = %d; want DROP", update.ApplyAction)
		}
		seen[update.FARID] = true
	}
	if !seen[2] || !seen[4] {
		t.Fatalf("FAR updates = %+v; want default FAR 2 and dedicated FAR 4", updates)
	}
}

func TestReleaseAccessBearerFARUpdatesRejectMissingDedicatedRuleIDs(t *testing.T) {
	sess := newIdleResumeTestSession(t)
	sess.SetBearer(&bearer.Bearer{EBI: 7})

	if _, err := releaseAccessBearerFARUpdates(sess); err == nil {
		t.Fatal("releaseAccessBearerFARUpdates accepted dedicated bearer without PFCP rule IDs")
	}
}
