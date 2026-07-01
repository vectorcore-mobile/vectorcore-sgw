package bpf

import (
	"context"
	"log/slog"
	"net/netip"
	"testing"

	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/sgwu/session"
)

func newTestLogger(t *testing.T) *slog.Logger {
	t.Helper()
	return slog.Default()
}

type captureHandler struct {
	records []slog.Record
}

func (h *captureHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *captureHandler) Handle(_ context.Context, r slog.Record) error {
	clone := r.Clone()
	h.records = append(h.records, clone)
	return nil
}

func (h *captureHandler) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *captureHandler) WithGroup(string) slog.Handler      { return h }

// TestBuildKeyUplinkAccess verifies that an uplink PDR (SourceInterface=Access)
// produces a map key using the S1-U interface index.
// PFCP Source Interface=Access (0) per TS 29.244 Table 8.2.2-1: "Access | 0".
func TestBuildKeyUplinkAccess(t *testing.T) {
	c := &Compiler{
		dp: &TCDataplane{s1uIfindex: 10, s5uIfindex: 20},
	}
	pdr := &session.PDR{
		ID:              1,
		LocalTEID:       0xDEADBEEF,
		SourceInterface: pfcpie.SourceInterfaceAccess, // 0 per TS 29.244 Table 8.2.2-1
	}
	key, err := c.buildKey(pdr)
	if err != nil {
		t.Fatalf("buildKey: unexpected error: %v", err)
	}
	if key.Teid != 0xDEADBEEF {
		t.Errorf("Teid: got %#x, want %#x", key.Teid, uint32(0xDEADBEEF))
	}
	// Access PDR → packet enters on S1-U (ifindex=10)
	if key.Ifindex != 10 {
		t.Errorf("Ifindex: got %d, want 10 (S1-U)", key.Ifindex)
	}
}

// TestBuildKeyDownlinkCore verifies that a downlink PDR (SourceInterface=Core)
// produces a map key using the S5/S8-U interface index.
// PFCP Source Interface=Core (1) per TS 29.244 Table 8.2.2-1: "Core | 1".
func TestBuildKeyDownlinkCore(t *testing.T) {
	c := &Compiler{
		dp: &TCDataplane{s1uIfindex: 10, s5uIfindex: 20},
	}
	pdr := &session.PDR{
		ID:              2,
		LocalTEID:       0x00000042,
		SourceInterface: pfcpie.SourceInterfaceCore, // 1 per TS 29.244 Table 8.2.2-1
	}
	key, err := c.buildKey(pdr)
	if err != nil {
		t.Fatalf("buildKey: unexpected error: %v", err)
	}
	if key.Teid != 0x00000042 {
		t.Errorf("Teid: got %#x, want 0x00000042", key.Teid)
	}
	// Core PDR → packet enters on S5/S8-U (ifindex=20)
	if key.Ifindex != 20 {
		t.Errorf("Ifindex: got %d, want 20 (S5/S8-U)", key.Ifindex)
	}
}

// TestBuildValueFORWUplink verifies that an uplink FORW FAR produces:
//   - action=ACTION_FORWARD (1)
//   - outer_src_ip = S5/S8-U local IP (SGW-U egress for uplink)
//   - outer_dst_ip = FAR.OuterIP (PGW-U IP)
//   - new_teid = FAR.OuterTEID (PGW-U TEID)
//   - egress_ifindex = S5/S8-U ifindex
//
// Apply Action FORW (0x02) per TS 29.244 Figure 8.2.26-1: "Bit 2 FORW=0x02".
func TestBuildValueFORWUplink(t *testing.T) {
	s5uLocalIP := netip.MustParseAddr("10.0.1.2")
	c := &Compiler{
		dp:         &TCDataplane{s1uIfindex: 10, s5uIfindex: 20},
		s1uLocalIP: netip.MustParseAddr("10.0.0.1"),
		s5uLocalIP: s5uLocalIP,
	}
	pdr := &session.PDR{
		ID:              1,
		LocalTEID:       100,
		SourceInterface: pfcpie.SourceInterfaceAccess,
	}
	pgwIP := netip.MustParseAddr("192.168.2.1")
	far := &session.FAR{
		ID:          1,
		ApplyAction: pfcpie.ApplyActionFORW, // 0x02 per Figure 8.2.26-1
		OuterTEID:   0xAABBCCDD,
		OuterIP:     pgwIP,
	}

	val, err := c.buildValue(pdr, far)
	if err != nil {
		t.Fatalf("buildValue: unexpected error: %v", err)
	}

	if val.Action != actionForward {
		t.Errorf("Action: got %d, want %d (ACTION_FORWARD)", val.Action, actionForward)
	}

	wantSrc := s5uLocalIP.As4()
	if val.OuterSrcIp != wantSrc {
		t.Errorf("OuterSrcIp: got %v, want %v (S5/S8-U local IP for uplink egress)", val.OuterSrcIp, wantSrc)
	}

	wantDst := pgwIP.As4()
	if val.OuterDstIp != wantDst {
		t.Errorf("OuterDstIp: got %v, want %v (PGW-U IP)", val.OuterDstIp, wantDst)
	}

	if val.NewTeid != 0xAABBCCDD {
		t.Errorf("NewTeid: got %#x, want 0xAABBCCDD", val.NewTeid)
	}

	if val.EgressIfindex != 20 {
		t.Errorf("EgressIfindex: got %d, want 20 (S5/S8-U)", val.EgressIfindex)
	}

	if val.CounterId != 100 {
		t.Errorf("CounterId: got %d, want 100 (PDR.LocalTEID)", val.CounterId)
	}
}

// TestBuildValueFORWDownlink verifies that a downlink FORW FAR produces:
//   - outer_src_ip = S1-U local IP (SGW-U egress for downlink)
//   - outer_dst_ip = FAR.OuterIP (eNB IP)
//   - egress_ifindex = S1-U ifindex
func TestBuildValueFORWDownlink(t *testing.T) {
	s1uLocalIP := netip.MustParseAddr("10.0.0.1")
	c := &Compiler{
		dp:         &TCDataplane{s1uIfindex: 10, s5uIfindex: 20},
		s1uLocalIP: s1uLocalIP,
		s5uLocalIP: netip.MustParseAddr("10.0.1.2"),
	}
	pdr := &session.PDR{
		ID:              2,
		LocalTEID:       200,
		SourceInterface: pfcpie.SourceInterfaceCore,
	}
	enbIP := netip.MustParseAddr("172.16.1.100")
	far := &session.FAR{
		ID:          2,
		ApplyAction: pfcpie.ApplyActionFORW, // 0x02
		OuterTEID:   0x11223344,
		OuterIP:     enbIP,
	}

	val, err := c.buildValue(pdr, far)
	if err != nil {
		t.Fatalf("buildValue: unexpected error: %v", err)
	}

	if val.Action != actionForward {
		t.Errorf("Action: got %d, want %d", val.Action, actionForward)
	}

	wantSrc := s1uLocalIP.As4()
	if val.OuterSrcIp != wantSrc {
		t.Errorf("OuterSrcIp: got %v, want %v (S1-U local IP for downlink egress)", val.OuterSrcIp, wantSrc)
	}

	wantDst := enbIP.As4()
	if val.OuterDstIp != wantDst {
		t.Errorf("OuterDstIp: got %v, want %v (eNB IP)", val.OuterDstIp, wantDst)
	}

	if val.NewTeid != 0x11223344 {
		t.Errorf("NewTeid: got %#x, want 0x11223344", val.NewTeid)
	}

	if val.EgressIfindex != 10 {
		t.Errorf("EgressIfindex: got %d, want 10 (S1-U)", val.EgressIfindex)
	}
}

// TestBuildValueDROP verifies that a DROP FAR produces action=ACTION_DROP (2).
// Apply Action DROP (0x01) per TS 29.244 Figure 8.2.26-1: "Bit 1 DROP=0x01".
func TestBuildValueDROP(t *testing.T) {
	c := &Compiler{
		dp: &TCDataplane{s1uIfindex: 10, s5uIfindex: 20},
	}
	pdr := &session.PDR{ID: 1, LocalTEID: 1, SourceInterface: pfcpie.SourceInterfaceAccess}
	far := &session.FAR{
		ID:          1,
		ApplyAction: pfcpie.ApplyActionDROP, // 0x01 per Figure 8.2.26-1
	}
	val, err := c.buildValue(pdr, far)
	if err != nil {
		t.Fatalf("buildValue: unexpected error: %v", err)
	}
	if val.Action != actionDrop {
		t.Errorf("Action: got %d, want %d (ACTION_DROP)", val.Action, actionDrop)
	}
}

// TestBuildValueFORWNoIP verifies that a FORW FAR without an outer IP
// (initial state before eNB TEID arrives) produces ACTION_PUNT.
// This prevents the BPF program from forwarding to the zero address.
func TestBuildValueFORWNoIP(t *testing.T) {
	c := &Compiler{
		dp:         &TCDataplane{s1uIfindex: 10, s5uIfindex: 20},
		s1uLocalIP: netip.MustParseAddr("10.0.0.1"),
		s5uLocalIP: netip.MustParseAddr("10.0.1.2"),
	}
	pdr := &session.PDR{ID: 1, LocalTEID: 1, SourceInterface: pfcpie.SourceInterfaceAccess}
	far := &session.FAR{
		ID:          1,
		ApplyAction: pfcpie.ApplyActionFORW, // FORW but no OuterIP yet
		// OuterIP is zero value (not valid) — simulates initial SER with DROP→FORW not yet modified
	}
	val, err := c.buildValue(pdr, far)
	if err != nil {
		t.Fatalf("buildValue: unexpected error: %v", err)
	}
	if val.Action != actionPunt {
		t.Errorf("Action: got %d, want %d (ACTION_PUNT — no peer IP yet)", val.Action, actionPunt)
	}
}

// TestSyncRulesSkipsZeroTEID verifies that PDRs without an allocated TEID
// (LocalTEID=0) are skipped by syncRules. TEIDs start at 1 per session store.
func TestSyncRulesSkipsZeroTEID(t *testing.T) {
	dp := &TCDataplane{s1uIfindex: 10, s5uIfindex: 20}
	// Replace maps with nil to catch any accidental Put calls
	c := &Compiler{dp: dp, log: newTestLogger(t)}
	sess := &session.Session{
		CPSEID: 1,
		PDRs: []session.PDR{
			{ID: 1, LocalTEID: 0, SourceInterface: pfcpie.SourceInterfaceAccess, FARID: 1},
		},
		FARs: []session.FAR{
			{ID: 1, ApplyAction: pfcpie.ApplyActionFORW},
		},
	}
	// syncRules with remove=false should not panic on nil maps because it skips TEID=0.
	// We expect no error (no Put attempted).
	err := c.syncRules(sess, false)
	if err != nil {
		t.Errorf("syncRules with zero TEID: unexpected error: %v", err)
	}
}

func TestSyncRulesReportsUnchangedRulesWithoutReinstallNoise(t *testing.T) {
	h := &captureHandler{}
	c := &Compiler{
		dp: &TCDataplane{
			s1uIfindex: 10,
			s5uIfindex: 20,
			testRules:  make(map[TcSgwGtpuSgwRuleKey]TcSgwGtpuSgwRuleValue),
		},
		log: slog.New(h),
	}
	sess := &session.Session{
		CPSEID: 1,
		PDRs: []session.PDR{{
			ID:              1,
			LocalTEID:       0x1000,
			SourceInterface: pfcpie.SourceInterfaceAccess,
			FARID:           1,
		}},
		FARs: []session.FAR{{
			ID:          1,
			ApplyAction: pfcpie.ApplyActionDROP,
		}},
	}

	if err := c.UpdateSession(sess); err != nil {
		t.Fatalf("first UpdateSession: %v", err)
	}
	if err := c.UpdateSession(sess); err != nil {
		t.Fatalf("second UpdateSession: %v", err)
	}
	if err := c.RemoveSession(sess); err != nil {
		t.Fatalf("RemoveSession: %v", err)
	}
	if err := c.RemoveSession(sess); err != nil {
		t.Fatalf("second RemoveSession: %v", err)
	}

	summaries := syncSummaries(h.records)
	if len(summaries) != 4 {
		t.Fatalf("sync summaries = %d; want 4", len(summaries))
	}
	assertSummaryCounts(t, summaries[0], 1, 0, 0, 0)
	assertSummaryCounts(t, summaries[1], 0, 0, 0, 1)
	assertSummaryCounts(t, summaries[2], 0, 0, 1, 0)
	assertSummaryCounts(t, summaries[3], 0, 0, 0, 1)
	if got := countLogMessage(h.records, "BPF compiler: rule added"); got != 1 {
		t.Fatalf("rule added logs = %d; want 1", got)
	}
	if got := countLogMessage(h.records, "BPF compiler: rule updated"); got != 0 {
		t.Fatalf("rule updated logs = %d; want 0", got)
	}
	if got := countLogMessage(h.records, "BPF compiler: rule removed"); got != 1 {
		t.Fatalf("rule removed logs = %d; want 1", got)
	}
}

func syncSummaries(records []slog.Record) []map[string]int {
	var out []map[string]int
	for _, r := range records {
		if r.Message != "BPF compiler: sync summary" {
			continue
		}
		m := map[string]int{}
		r.Attrs(func(a slog.Attr) bool {
			switch a.Key {
			case "rules_added", "rules_updated", "rules_removed", "rules_unchanged":
				m[a.Key] = int(a.Value.Int64())
			}
			return true
		})
		out = append(out, m)
	}
	return out
}

func assertSummaryCounts(t *testing.T, summary map[string]int, added, updated, removed, unchanged int) {
	t.Helper()
	if summary["rules_added"] != added ||
		summary["rules_updated"] != updated ||
		summary["rules_removed"] != removed ||
		summary["rules_unchanged"] != unchanged {
		t.Fatalf("summary = %+v; want added=%d updated=%d removed=%d unchanged=%d",
			summary, added, updated, removed, unchanged)
	}
}

func countLogMessage(records []slog.Record, msg string) int {
	var count int
	for _, r := range records {
		if r.Message == msg {
			count++
		}
	}
	return count
}
