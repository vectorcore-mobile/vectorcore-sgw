//go:build linux

package bpf

// Phase 7 acceptance criterion "Throughput exceeds userspace reference
// path": compares ingest rate of the kernel XDP-BPF fast path against the
// Phase 6 userspace reference forwarder (internal/sgwu/gtpu). Both
// benchmarks measure the same thing — how fast a G-PDU can be handed to the
// path and processed/forwarded onward — using the real compiled BPF object
// and the real Forwarder implementation, not a model of either.

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	"golang.org/x/sys/unix"

	sgwugtpu "vectorcore-sgw/internal/sgwu/gtpu"
	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

// BenchmarkBPFForward measures sustained injection rate through the real
// kernel XDP-BPF fast path (veth harness, real compiled object, real
// redirect). The raw AF_PACKET send for each iteration only returns once
// veth's synchronous xmit path — including BPF program execution and the
// redirect transmit — has run, so b.N iterations include that full cost.
func BenchmarkBPFForward(b *testing.B) {
	h := newHarness(b)
	dp, err := New(h.s1u.name, h.s5u.name, 1024)
	if err != nil {
		b.Fatalf("New: %v", err)
	}
	defer dp.Close()

	const (
		localTEID = 0x6000
		newTEID   = 0x7000
		counterID = 11
	)
	key := XdpSgwGtpuSgwRuleKey{Teid: localTEID, Ifindex: dp.S1UIfindex()}
	val := XdpSgwGtpuSgwRuleValue{
		Action:        actionForward,
		EgressIfindex: dp.S5UIfindex(),
		NewTeid:       newTEID,
		CounterId:     counterID,
	}
	copy(val.OuterSrcIp[:], h.s5u.ip.To4())
	copy(val.OuterDstIp[:], h.s5uPeer.ip.To4())
	if err := dp.InitStats(counterID); err != nil {
		b.Fatalf("InitStats: %v", err)
	}
	if err := dp.InstallRule(key, val); err != nil {
		b.Fatalf("InstallRule: %v", err)
	}

	frame := buildGPDUFrame(h.s1uPeer.mac, h.s1u.mac, h.s1uPeer.ip, h.s1u.ip, 33010, localTEID,
		make([]byte, 64))
	injectFd := openRawSocket(b, h.s1uPeer.ifindex, unix.ETH_P_ALL, 0)
	// No timeout: blocks until the redirected frame lands, matching the
	// synchronous round trip the userspace benchmark below also waits for.
	captureFd := openRawSocket(b, h.s5uPeer.ifindex, unix.ETH_P_ALL, 0)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := unix.Send(injectFd, frame, 0); err != nil {
			b.Fatalf("send: %v", err)
		}
		if _, ok := captureGPDU(captureFd); !ok {
			b.Fatalf("capture: no G-PDU arrived")
		}
	}
	b.StopTimer()
}

// BenchmarkUserspaceForward measures the same thing for the Phase 6
// userspace reference path: a real gtpu.Forwarder receiving real UDP
// packets and relaying them per its FAR, with a real UDP peer absorbing the
// forwarded output (so the comparison isn't skewed by ICMP-port-unreachable
// overhead from an empty destination).
func BenchmarkUserspaceForward(b *testing.B) {
	const (
		localTEID = 0x8000
		farID     = 1
	)
	pgwAddr := netip.MustParseAddr("127.0.0.1")

	// Dummy PGW peer absorbing forwarded G-PDUs; the Forwarder hardcodes the
	// destination port to gtpu.Port (2152) per TS 29.281 §4.4.2.1, so this
	// must bind there. Read synchronously in the benchmark loop (not a
	// background drain goroutine) so each iteration measures the full
	// send -> Forwarder relay -> PGW arrival round trip — the same
	// synchronous-completion shape as BenchmarkBPFForward's send+capture.
	// A background-drain version would only measure the client-side
	// enqueue cost and let the Forwarder's actual relay work happen for
	// free off the clock, which is not a fair comparison.
	pgw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: sgwugtpu.Port})
	if err != nil {
		b.Fatalf("ListenUDP (PGW stand-in): %v", err)
	}
	defer pgw.Close()

	store := sgwusession.NewStore()
	sess := &sgwusession.Session{
		CPSEID: 1,
		UPSEID: store.AllocSEID(),
		PDRs: []sgwusession.PDR{{
			ID:              1,
			SourceInterface: 0, // Access
			LocalTEID:       localTEID,
			FARID:           farID,
		}},
		FARs: []sgwusession.FAR{{
			ID:          farID,
			ApplyAction: 0x02, // FORW per TS 29.244 §8.2.26
			OuterIP:     pgwAddr,
			OuterTEID:   0x9000,
		}},
	}
	if err := store.Create(sess); err != nil {
		b.Fatalf("store.Create: %v", err)
	}

	log := slog.New(slog.DiscardHandler)
	fwd, err := sgwugtpu.New("127.0.0.1:0", netip.MustParseAddr("127.0.0.1"), store, log)
	if err != nil {
		b.Fatalf("gtpu.New: %v", err)
	}
	defer fwd.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go fwd.Serve(ctx)

	client, err := net.DialUDP("udp4", nil, fwd.Conn().LocalAddr().(*net.UDPAddr))
	if err != nil {
		b.Fatalf("DialUDP: %v", err)
	}
	defer client.Close()

	gtpHdr := sgwugtpu.Marshal(sgwugtpu.Header{
		Version: 1,
		PT:      true,
		MsgType: sgwugtpu.MsgTypeGPDU,
		TEID:    localTEID,
	}, 64)
	packet := append(gtpHdr, make([]byte, 64)...)
	buf := make([]byte, 2048)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := client.Write(packet); err != nil {
			b.Fatalf("write: %v", err)
		}
		if _, _, err := pgw.ReadFromUDP(buf); err != nil {
			b.Fatalf("pgw read: %v", err)
		}
	}
	b.StopTimer()
}
