package bearerinactivity

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

func TestExecutorCleansDedicatedBearerRulesAndState(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	mgr, sess := cleanupManager(t)
	addCleanupBearer(t, sess, 7, [2]uint32{3, 4}, [2]uint32{5, 6})
	sess.MarkBearerControlActivity(7, "test", now.Add(-10*time.Minute))
	pfcp := &recordingPFCPRemover{}

	result := Executor{
		Sessions:  mgr,
		PFCP:      pfcp,
		Evaluator: NewEvaluator(testConfig(true)),
	}.Apply(context.Background(), now)

	if result.Cleaned != 1 || result.Failed != 0 {
		t.Fatalf("result = %+v; want one cleaned", result)
	}
	if pfcp.calls != 1 ||
		pfcp.peerAddr != "192.0.2.20:8805" ||
		pfcp.cpSEID != 0x101 ||
		pfcp.upSEID != 0x202 ||
		!equalUint32s(pfcp.pdrIDs, []uint32{3, 4}) ||
		!equalUint32s(pfcp.farIDs, []uint32{5, 6}) {
		t.Fatalf("PFCP call = %+v; want exact dedicated rule removal", pfcp)
	}
	if sess.GetBearer(7) != nil {
		t.Fatal("dedicated bearer still present after cleanup")
	}
	if sess.GetBearer(5) == nil {
		t.Fatal("default bearer was removed by dedicated cleanup")
	}
}

func TestExecutorRefusesDefaultBearerCleanup(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	mgr, sess := cleanupManager(t)
	defaultBearer := sess.GetBearer(5)
	defaultBearer.PDRIDs = [2]uint32{1, 2}
	defaultBearer.FARIDs = [2]uint32{1, 2}
	sess.SetBearer(defaultBearer)
	sess.MarkBearerControlActivity(5, "test", now.Add(-10*time.Minute))
	cfg := testConfig(true)
	cfg.DeleteDefaultBearers = true
	cfg.DefaultBearerIdleSeconds = 300
	cfg.Cleanup = append(cfg.Cleanup, cleanupDefaultRule())
	pfcp := &recordingPFCPRemover{}

	result := Executor{
		Sessions:  mgr,
		PFCP:      pfcp,
		Evaluator: NewEvaluator(cfg),
	}.Apply(context.Background(), now)

	if result.DeniedDefault == 0 || result.Cleaned != 0 || pfcp.calls != 0 {
		t.Fatalf("result=%+v pfcp_calls=%d; want default denied without PFCP", result, pfcp.calls)
	}
	if sess.GetBearer(5) == nil {
		t.Fatal("default bearer removed despite denial")
	}
}

func TestExecutorRejectsMissingRuleIDs(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	mgr, sess := cleanupManager(t)
	addCleanupBearer(t, sess, 7, [2]uint32{3, 0}, [2]uint32{5, 6})
	sess.MarkBearerControlActivity(7, "test", now.Add(-10*time.Minute))
	pfcp := &recordingPFCPRemover{}

	result := Executor{
		Sessions:  mgr,
		PFCP:      pfcp,
		Evaluator: NewEvaluator(testConfig(true)),
	}.Apply(context.Background(), now)

	if result.Failed != 1 || result.MissingRules != 1 || pfcp.calls != 0 {
		t.Fatalf("result=%+v pfcp_calls=%d; want missing rule failure without PFCP", result, pfcp.calls)
	}
	if sess.GetBearer(7) == nil {
		t.Fatal("bearer removed despite missing rule IDs")
	}
}

func TestExecutorRequiresPFCPBinding(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	mgr, sess := cleanupManager(t)
	sess.SetPFCPBinding(session.PFCPSessionBinding{})
	addCleanupBearer(t, sess, 7, [2]uint32{3, 4}, [2]uint32{5, 6})
	sess.MarkBearerControlActivity(7, "test", now.Add(-10*time.Minute))
	pfcp := &recordingPFCPRemover{}

	result := Executor{
		Sessions:  mgr,
		PFCP:      pfcp,
		Evaluator: NewEvaluator(testConfig(true)),
	}.Apply(context.Background(), now)

	if result.Failed != 1 || pfcp.calls != 0 {
		t.Fatalf("result=%+v pfcp_calls=%d; want PFCP binding failure", result, pfcp.calls)
	}
	if sess.GetBearer(7) == nil {
		t.Fatal("bearer removed despite missing PFCP binding")
	}
}

func TestExecutorKeepsBearerWhenPFCPRemovalFails(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	mgr, sess := cleanupManager(t)
	addCleanupBearer(t, sess, 7, [2]uint32{3, 4}, [2]uint32{5, 6})
	sess.MarkBearerControlActivity(7, "test", now.Add(-10*time.Minute))
	pfcp := &recordingPFCPRemover{err: errors.New("pfcp timeout")}

	result := Executor{
		Sessions:  mgr,
		PFCP:      pfcp,
		Evaluator: NewEvaluator(testConfig(true)),
	}.Apply(context.Background(), now)

	if result.Failed != 1 || result.Cleaned != 0 || pfcp.calls != 1 {
		t.Fatalf("result=%+v pfcp_calls=%d; want PFCP failure", result, pfcp.calls)
	}
	if sess.GetBearer(7) == nil {
		t.Fatal("bearer removed despite PFCP failure")
	}
}

func TestExecutorPreservesQCI1BearerEvenWhenIdle(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	mgr, sess := cleanupManager(t)
	addCleanupBearerWithQCI(t, sess, 7, 1, [2]uint32{3, 4}, [2]uint32{5, 6})
	sess.MarkBearerControlActivity(7, "test", now.Add(-30*time.Minute))
	pfcp := &recordingPFCPRemover{}

	result := Executor{
		Sessions:  mgr,
		PFCP:      pfcp,
		Evaluator: NewEvaluator(testConfig(true)),
	}.Apply(context.Background(), now)

	if result.Cleaned != 0 || result.Failed != 0 || pfcp.calls != 0 {
		t.Fatalf("result=%+v pfcp_calls=%d; want preserved QCI 1 without cleanup", result, pfcp.calls)
	}
	if sess.GetBearer(7) == nil {
		t.Fatal("QCI 1 bearer was removed despite preserve policy")
	}
}

func TestExecutorCleanupIsSessionScopedWhenEBIsOverlap(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	mgr, first := cleanupManager(t)
	addCleanupBearer(t, first, 7, [2]uint32{3, 4}, [2]uint32{5, 6})
	sess2, _, err := mgr.Create(testCreateParams("311430000000002", "internet", 5))
	if err != nil {
		t.Fatalf("Create second: %v", err)
	}
	sess2.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 0x303, IPv4: netip.MustParseAddr("192.0.2.30")},
		SGWUFSEID:   session.FSEID{SEID: 0x404, IPv4: netip.MustParseAddr("192.0.2.40")},
		SGWUName:    "sgwu-b",
		SGWUAddr:    "192.0.2.40:8805",
		Established: true,
	})
	addCleanupBearer(t, sess2, 7, [2]uint32{11, 12}, [2]uint32{13, 14})
	pfcp := &recordingPFCPRemover{}

	err = Executor{Sessions: mgr, PFCP: pfcp}.cleanupDedicatedBearer(context.Background(), Decision{
		SessionID:  first.SessionID,
		IMSI:       first.IMSI,
		APN:        first.APN,
		EBI:        7,
		BearerType: "dedicated",
		Reason:     "test-scoped-cleanup",
	})
	if err != nil {
		t.Fatalf("cleanupDedicatedBearer: %v", err)
	}

	if first.GetBearer(7) != nil {
		t.Fatal("target session EBI 7 still present after cleanup")
	}
	if sess2.GetBearer(7) == nil {
		t.Fatal("same EBI on a different UE/session was removed")
	}
	if pfcp.peerAddr != "192.0.2.20:8805" ||
		!equalUint32s(pfcp.pdrIDs, []uint32{3, 4}) ||
		!equalUint32s(pfcp.farIDs, []uint32{5, 6}) {
		t.Fatalf("PFCP removal = %+v; want first session dedicated rules only at %s", pfcp, now)
	}
}

func TestExecutorCleanupRemovesOnlyTargetDedicatedBearer(t *testing.T) {
	mgr, sess := cleanupManager(t)
	defaultBearer := sess.GetBearer(5)
	defaultBearer.PDRIDs = [2]uint32{1, 2}
	defaultBearer.FARIDs = [2]uint32{1, 2}
	sess.SetBearer(defaultBearer)
	addCleanupBearer(t, sess, 7, [2]uint32{3, 4}, [2]uint32{5, 6})
	addCleanupBearer(t, sess, 8, [2]uint32{7, 8}, [2]uint32{9, 10})
	pfcp := &recordingPFCPRemover{}

	err := Executor{Sessions: mgr, PFCP: pfcp}.cleanupDedicatedBearer(context.Background(), Decision{
		SessionID:  sess.SessionID,
		IMSI:       sess.IMSI,
		APN:        sess.APN,
		EBI:        7,
		BearerType: "dedicated",
		Reason:     "test-target-only",
	})
	if err != nil {
		t.Fatalf("cleanupDedicatedBearer: %v", err)
	}

	if sess.GetBearer(7) != nil {
		t.Fatal("target dedicated bearer still present")
	}
	if sess.GetBearer(5) == nil {
		t.Fatal("default bearer was removed by target dedicated cleanup")
	}
	if sess.GetBearer(8) == nil {
		t.Fatal("non-target dedicated bearer was removed")
	}
	if !equalUint32s(pfcp.pdrIDs, []uint32{3, 4}) || !equalUint32s(pfcp.farIDs, []uint32{5, 6}) {
		t.Fatalf("PFCP rules removed = pdr:%+v far:%+v; want target EBI 7 only", pfcp.pdrIDs, pfcp.farIDs)
	}
}

type recordingPFCPRemover struct {
	calls    int
	peerAddr string
	cpSEID   uint64
	upSEID   uint64
	pdrIDs   []uint32
	farIDs   []uint32
	err      error
}

func (r *recordingPFCPRemover) RemoveBearerRulesOnPeer(_ context.Context, peerAddr string, cpSEID, upSEID uint64, pdrIDs, farIDs []uint32) error {
	r.calls++
	r.peerAddr = peerAddr
	r.cpSEID = cpSEID
	r.upSEID = upSEID
	r.pdrIDs = append([]uint32(nil), pdrIDs...)
	r.farIDs = append([]uint32(nil), farIDs...)
	return r.err
}

func cleanupManager(t *testing.T) (*session.Manager, *session.SGWSession) {
	t.Helper()
	mgr := session.NewManager()
	sess, _, err := mgr.Create(testCreateParams("311430000000001", "internet", 5))
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 0x101, IPv4: netip.MustParseAddr("192.0.2.10")},
		SGWUFSEID:   session.FSEID{SEID: 0x202, IPv4: netip.MustParseAddr("192.0.2.20")},
		SGWUName:    "sgwu-a",
		SGWUAddr:    "192.0.2.20:8805",
		Established: true,
	})
	return mgr, sess
}

func addCleanupBearer(t *testing.T, sess *session.SGWSession, ebi uint8, pdrIDs, farIDs [2]uint32) {
	t.Helper()
	addCleanupBearerWithQCI(t, sess, ebi, 9, pdrIDs, farIDs)
}

func addCleanupBearerWithQCI(t *testing.T, sess *session.SGWSession, ebi, qci uint8, pdrIDs, farIDs [2]uint32) {
	t.Helper()
	sess.SetBearer(&bearer.Bearer{
		EBI:    ebi,
		QCI:    qci,
		ARP:    bearer.ARP{PriorityLevel: 9},
		State:  bearer.BearerStateActive,
		PDRIDs: pdrIDs,
		FARIDs: farIDs,
	})
}

func cleanupDefaultRule() sgwcconfig.BearerInactivityRuleConfig {
	return sgwcconfig.BearerInactivityRuleConfig{BearerType: "default", IdleSeconds: 300, Reason: "default-idle"}
}

func equalUint32s(a, b []uint32) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
