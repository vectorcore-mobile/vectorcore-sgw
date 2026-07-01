//go:build linux

package bpf

// Runtime validation exercises the real compiled XDP GTP-U BPF
// object against the kernel, closing the acceptance criteria that could not
// be tested on a host without BPF capability (see docs/vectorcore-sgw-project.md
// Phase 7 "Acceptance Criteria"):
//   - BPF attach/detach
//   - uplink traffic forwarded by BPF
//   - downlink traffic forwarded by BPF
//   - counters increment per rule
// plus the ACTION_DROP and unknown-TEID-punt paths, which the BPF program
// supports per ebpf/tc_sgw_gtpu.c but had no runtime coverage at all.

import (
	"net"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	sgwugtpu "vectorcore-sgw/internal/sgwu/gtpu"
)

const testTimeout = 2 * time.Second

// TestBPFAttachDetach verifies the XDP-BPF program attaches to both the S1-U
// and S5/S8-U interfaces and detaches cleanly, per Phase 7 acceptance
// criterion "SGW-U programs BPF entries..." (attach is a prerequisite) and
// C9 (every transport-facing kernel hook must have a verified lifecycle).
func TestBPFAttachDetach(t *testing.T) {
	h := newHarness(t)

	dp, err := New(h.s1u.name, h.s5u.name, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if dp.S1UIfindex() != uint32(h.s1u.ifindex) {
		t.Errorf("S1UIfindex: got %d, want %d", dp.S1UIfindex(), h.s1u.ifindex)
	}
	if dp.S5UIfindex() != uint32(h.s5u.ifindex) {
		t.Errorf("S5UIfindex: got %d, want %d", dp.S5UIfindex(), h.s5u.ifindex)
	}
	if err := dp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestBPFAttachDetachSingleInterface verifies single-NIC deployments where
// S1-U and S5/S8-U are logical roles on the same Linux interface. Rework
// Phase 2 requires one TC attach for the shared ifindex, not a duplicate attach
// attempt that can fail at startup.
func TestBPFAttachDetachSingleInterface(t *testing.T) {
	h := newHarness(t)

	dp, err := New(h.s1u.name, h.s1u.name, 1024)
	if err != nil {
		t.Fatalf("New shared interface: %v", err)
	}
	if !dp.SharedInterface() {
		t.Fatalf("SharedInterface = false, want true")
	}
	if dp.S1UIfindex() != uint32(h.s1u.ifindex) {
		t.Errorf("S1UIfindex: got %d, want %d", dp.S1UIfindex(), h.s1u.ifindex)
	}
	if dp.S5UIfindex() != uint32(h.s1u.ifindex) {
		t.Errorf("S5UIfindex: got %d, want %d", dp.S5UIfindex(), h.s1u.ifindex)
	}
	if err := dp.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}
}

// TestBPFForwardUplink sends a real G-PDU frame into the S1-U-facing veth
// and verifies the kernel BPF program rewrites the outer IP/TEID and
// redirects it out the S5/S8-U-facing veth, with the per-rule counter
// incrementing — Phase 7 acceptance: "Uplink traffic is forwarded by BPF"
// and "Counters increment per rule".
func TestBPFForwardUplink(t *testing.T) {
	h := newHarness(t)
	dp, err := New(h.s1u.name, h.s5u.name, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { dp.Close() })

	const (
		localTEID = 0x1000
		newTEID   = 0x2000
		counterID = 7
	)
	key := TcSgwGtpuSgwRuleKey{Teid: localTEID, Ifindex: dp.S1UIfindex()}
	val := TcSgwGtpuSgwRuleValue{
		Action:        actionForward,
		EgressIfindex: dp.S5UIfindex(),
		NewTeid:       newTEID,
		CounterId:     counterID,
	}
	copy(val.OuterSrcIp[:], h.s5u.ip.To4())
	copy(val.OuterDstIp[:], h.s5uPeer.ip.To4())
	if err := dp.InitStats(counterID); err != nil {
		t.Fatalf("InitStats: %v", err)
	}
	if err := dp.InstallRule(key, val); err != nil {
		t.Fatalf("InstallRule: %v", err)
	}

	payload := []byte("uplink-test-tpdu-payload")
	frame := buildGPDUFrame(h.s1uPeer.mac, h.s1u.mac, h.s1uPeer.ip, h.s1u.ip, 33000, localTEID, payload)

	captureFd := openRawSocket(t, h.s5uPeer.ifindex, unix.ETH_P_ALL, testTimeout)
	injectFd := openRawSocket(t, h.s1uPeer.ifindex, unix.ETH_P_ALL, 0)
	if err := unix.Send(injectFd, frame, 0); err != nil {
		t.Fatalf("inject: %v", err)
	}

	got, ok := captureGPDU(captureFd)
	if !ok {
		t.Fatalf("capture on %s: no G-PDU arrived within %s (expected rewritten G-PDU)", h.s5uPeer.name, testTimeout)
	}
	if !got.srcIP.Equal(h.s5u.ip) {
		t.Errorf("outer src IP: got %s, want %s", got.srcIP, h.s5u.ip)
	}
	if !got.dstIP.Equal(h.s5uPeer.ip) {
		t.Errorf("outer dst IP: got %s, want %s", got.dstIP, h.s5uPeer.ip)
	}
	if got.teid != newTEID {
		t.Errorf("TEID: got %#x, want %#x", got.teid, newTEID)
	}
	if string(got.payload) != string(payload) {
		t.Errorf("payload: got %q, want %q", got.payload, payload)
	}
	maybeWritePCAP(t, "bpf-uplink-rewrite.pcap", frame, got.raw)

	packets, bytes, ok := dp.ReadStats(counterID)
	if !ok {
		t.Fatalf("ReadStats(%d): no entry found", counterID)
	}
	if packets != 1 {
		t.Errorf("packets: got %d, want 1", packets)
	}
	if bytes == 0 {
		t.Errorf("bytes: got 0, want > 0")
	}
}

// TestBPFForwardDownlink mirrors TestBPFForwardUplink in the opposite
// direction (S5/S8-U ingress -> S1-U egress) — Phase 7 acceptance:
// "Downlink traffic is forwarded by BPF".
func TestBPFForwardDownlink(t *testing.T) {
	h := newHarness(t)
	dp, err := New(h.s1u.name, h.s5u.name, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { dp.Close() })

	const (
		localTEID = 0x3000
		newTEID   = 0x4000
		counterID = 9
	)
	key := TcSgwGtpuSgwRuleKey{Teid: localTEID, Ifindex: dp.S5UIfindex()}
	val := TcSgwGtpuSgwRuleValue{
		Action:        actionForward,
		EgressIfindex: dp.S1UIfindex(),
		NewTeid:       newTEID,
		CounterId:     counterID,
	}
	copy(val.OuterSrcIp[:], h.s1u.ip.To4())
	copy(val.OuterDstIp[:], h.s1uPeer.ip.To4())
	if err := dp.InitStats(counterID); err != nil {
		t.Fatalf("InitStats: %v", err)
	}
	if err := dp.InstallRule(key, val); err != nil {
		t.Fatalf("InstallRule: %v", err)
	}

	payload := []byte("downlink-test-tpdu-payload")
	frame := buildGPDUFrame(h.s5uPeer.mac, h.s5u.mac, h.s5uPeer.ip, h.s5u.ip, 33001, localTEID, payload)

	captureFd := openRawSocket(t, h.s1uPeer.ifindex, unix.ETH_P_ALL, testTimeout)
	injectFd := openRawSocket(t, h.s5uPeer.ifindex, unix.ETH_P_ALL, 0)
	if err := unix.Send(injectFd, frame, 0); err != nil {
		t.Fatalf("inject: %v", err)
	}

	got, ok := captureGPDU(captureFd)
	if !ok {
		t.Fatalf("capture on %s: no G-PDU arrived within %s (expected rewritten G-PDU)", h.s1uPeer.name, testTimeout)
	}
	if !got.srcIP.Equal(h.s1u.ip) || !got.dstIP.Equal(h.s1uPeer.ip) || got.teid != newTEID {
		t.Errorf("got src=%s dst=%s teid=%#x, want src=%s dst=%s teid=%#x",
			got.srcIP, got.dstIP, got.teid, h.s1u.ip, h.s1uPeer.ip, newTEID)
	}
	maybeWritePCAP(t, "bpf-downlink-rewrite.pcap", frame, got.raw)

	packets, _, ok := dp.ReadStats(counterID)
	if !ok || packets != 1 {
		t.Errorf("ReadStats(%d): got ok=%v packets=%d, want ok=true packets=1", counterID, ok, packets)
	}
}

// TestBPFActionDrop installs an ACTION_DROP rule and verifies the matching
// packet does not emerge on any egress link (TC_ACT_SHOT). The BPF program
// supports three action codes (ACTION_FORWARD/DROP/PUNT);
// only FORWARD had any runtime coverage before this phase.
func TestBPFActionDrop(t *testing.T) {
	h := newHarness(t)
	dp, err := New(h.s1u.name, h.s5u.name, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { dp.Close() })

	const localTEID = 0x5000
	key := TcSgwGtpuSgwRuleKey{Teid: localTEID, Ifindex: dp.S1UIfindex()}
	val := TcSgwGtpuSgwRuleValue{Action: actionDrop}
	if err := dp.InstallRule(key, val); err != nil {
		t.Fatalf("InstallRule: %v", err)
	}

	frame := buildGPDUFrame(h.s1uPeer.mac, h.s1u.mac, h.s1uPeer.ip, h.s1u.ip, 33002, localTEID, []byte("dropped"))

	// Capture window is short and noise-tolerant (captureGPDU discards
	// anything that doesn't parse as our G-PDU, e.g. background IPv6 NDP on
	// the link); finding none within the window confirms TC_ACT_SHOT, not
	// just that the very first captured frame happened to be unrelated.
	captureFd := openRawSocket(t, h.s5uPeer.ifindex, unix.ETH_P_ALL, 500*time.Millisecond)
	injectFd := openRawSocket(t, h.s1uPeer.ifindex, unix.ETH_P_ALL, 0)
	if err := unix.Send(injectFd, frame, 0); err != nil {
		t.Fatalf("inject: %v", err)
	}

	if got, ok := captureGPDU(captureFd); ok {
		t.Fatalf("expected no G-PDU on %s after ACTION_DROP, but got teid=%#x", h.s5uPeer.name, got.teid)
	}
}

// TestBPFPuntUnknownTEID verifies that a G-PDU with no matching forwarding
// rule is punted to the normal kernel stack (TC_ACT_OK) rather than dropped
// or redirected, matching the project's "punt unsupported packets to
// userspace" design (docs/vectorcore-sgw-project.md Phase 7 step 9). A real
// UDP listener bound on the S1-U device's own address stands in for the
// Phase 6 userspace GTP-U forwarder that would receive the punted packet in
// production.
func TestBPFPuntUnknownTEID(t *testing.T) {
	h := newHarness(t)
	dp, err := New(h.s1u.name, h.s5u.name, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { dp.Close() })
	// No rule installed for this TEID — the BPF map lookup misses and the
	// program must return TC_ACT_OK (punt), not drop or redirect.

	listener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: h.s1u.ip, Port: sgwugtpu.Port})
	if err != nil {
		t.Fatalf("ListenUDP on %s:%d: %v", h.s1u.ip, sgwugtpu.Port, err)
	}
	t.Cleanup(func() { listener.Close() })
	listener.SetReadDeadline(time.Now().Add(testTimeout))

	frame := buildGPDUFrame(h.s1uPeer.mac, h.s1u.mac, h.s1uPeer.ip, h.s1u.ip, 33003, 0xDEAD, []byte("punted"))
	injectFd := openRawSocket(t, h.s1uPeer.ifindex, unix.ETH_P_ALL, 0)
	if err := unix.Send(injectFd, frame, 0); err != nil {
		t.Fatalf("inject: %v", err)
	}

	buf := make([]byte, 2048)
	n, _, err := listener.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("punted packet did not reach local UDP stack: %v", err)
	}
	hdr, _, err := sgwugtpu.Parse(buf[:n])
	if err != nil {
		t.Fatalf("parse punted GTP-U payload: %v", err)
	}
	if hdr.TEID != 0xDEAD {
		t.Errorf("punted TEID: got %#x, want %#x", hdr.TEID, 0xDEAD)
	}
}

// TestBPFMapCapacityAndRuleChurn validates the operator-facing map capacity
// setting and repeated install/delete churn. Phase 15 requires proving that
// rule capacity failures are visible and that normal rule deletion returns the
// map to an empty state.
func TestBPFMapCapacityAndRuleChurn(t *testing.T) {
	h := newHarness(t)
	dp, err := New(h.s1u.name, h.s5u.name, 8)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { dp.Close() })

	for i := 0; i < 8; i++ {
		key := TcSgwGtpuSgwRuleKey{Teid: uint32(0xA000 + i), Ifindex: dp.S1UIfindex()}
		val := TcSgwGtpuSgwRuleValue{Action: actionDrop, CounterId: uint32(0xA000 + i)}
		if err := dp.InstallRule(key, val); err != nil {
			t.Fatalf("InstallRule #%d: %v", i, err)
		}
	}
	count, err := dp.RuleCount()
	if err != nil {
		t.Fatalf("RuleCount after fill: %v", err)
	}
	if count != 8 {
		t.Fatalf("RuleCount after fill = %d; want 8", count)
	}

	overflowKey := TcSgwGtpuSgwRuleKey{Teid: 0xA999, Ifindex: dp.S1UIfindex()}
	if err := dp.InstallRule(overflowKey, TcSgwGtpuSgwRuleValue{Action: actionDrop}); err == nil {
		t.Fatal("InstallRule succeeded after map reached max entries")
	}

	for i := 0; i < 8; i++ {
		key := TcSgwGtpuSgwRuleKey{Teid: uint32(0xA000 + i), Ifindex: dp.S1UIfindex()}
		if err := dp.RemoveRule(key); err != nil {
			t.Fatalf("RemoveRule #%d: %v", i, err)
		}
	}
	count, err = dp.RuleCount()
	if err != nil {
		t.Fatalf("RuleCount after remove: %v", err)
	}
	if count != 0 {
		t.Fatalf("RuleCount after remove = %d; want 0", count)
	}
}

// TestBPFForwardCounterReconciliation sends a burst through the XDP-BPF fast
// path and reconciles the userspace-observed packet count with the aggregated
// per-CPU BPF rule counter. This is the small deterministic counterpart to
// the longer Phase 15 benchmark script.
func TestBPFForwardCounterReconciliation(t *testing.T) {
	h := newHarness(t)
	dp, err := New(h.s1u.name, h.s5u.name, 1024)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { dp.Close() })

	const (
		localTEID = 0xB000
		newTEID   = 0xB100
		counterID = 0xBEEF
		packets   = 32
	)
	key := TcSgwGtpuSgwRuleKey{Teid: localTEID, Ifindex: dp.S1UIfindex()}
	val := TcSgwGtpuSgwRuleValue{
		Action:        actionForward,
		EgressIfindex: dp.S5UIfindex(),
		NewTeid:       newTEID,
		CounterId:     counterID,
	}
	copy(val.OuterSrcIp[:], h.s5u.ip.To4())
	copy(val.OuterDstIp[:], h.s5uPeer.ip.To4())
	if err := dp.InitStats(counterID); err != nil {
		t.Fatalf("InitStats: %v", err)
	}
	if err := dp.InstallRule(key, val); err != nil {
		t.Fatalf("InstallRule: %v", err)
	}

	payload := []byte("phase15-counter-reconciliation")
	frame := buildGPDUFrame(h.s1uPeer.mac, h.s1u.mac, h.s1uPeer.ip, h.s1u.ip, 33020, localTEID, payload)
	injectFd := openRawSocket(t, h.s1uPeer.ifindex, unix.ETH_P_ALL, 0)
	captureFd := openRawSocket(t, h.s5uPeer.ifindex, unix.ETH_P_ALL, testTimeout)

	for i := 0; i < packets; i++ {
		if err := unix.Send(injectFd, frame, 0); err != nil {
			t.Fatalf("inject #%d: %v", i, err)
		}
		got, ok := captureGPDU(captureFd)
		if !ok {
			t.Fatalf("capture #%d: no G-PDU arrived", i)
		}
		if got.teid != newTEID {
			t.Fatalf("capture #%d TEID = %#x; want %#x", i, got.teid, newTEID)
		}
	}

	gotPackets, gotBytes, ok := dp.ReadStats(counterID)
	if !ok {
		t.Fatalf("ReadStats(%d): no entry found", counterID)
	}
	if gotPackets != packets {
		t.Fatalf("counter packets = %d; want %d", gotPackets, packets)
	}
	if gotBytes == 0 {
		t.Fatalf("counter bytes = 0; want non-zero")
	}
}
