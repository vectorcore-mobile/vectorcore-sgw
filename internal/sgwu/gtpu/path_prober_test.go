package gtpu

// PathProber unit tests and C20 fuzz tests per TS 29.281 V15.7.0.
//
// PathProber state machine is tested via tick(time.Time) directly — no real timers needed.
// C20: FuzzParse and FuzzParseIEs exercise the public network-input parsers with seeds
// drawn from the golden wire vectors defined in header_test.go.

import (
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"
)

// newTestProber creates a PathProber with a loopback UDP socket for testing.
// The prober sends Echo Requests to probePort on 127.0.0.1 (overrides the default 2152).
// Returns the prober, the send socket, and a close function.
func newTestProber(t *testing.T, probePort int, n3 int) (*PathProber, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP: %v", err)
	}
	p := NewPathProber(conn, EchoMinInterval, T3ResponseDefault, n3, discardSlog())
	p.port = probePort
	return p, func() { conn.Close() }
}

// recvEchoRequest reads one packet from peerConn and returns the parsed header.
// Fails the test if the packet is not a valid Echo Request.
func recvEchoRequest(t *testing.T, peerConn *net.UDPConn) Header {
	t.Helper()
	peerConn.SetReadDeadline(time.Now().Add(time.Second)) //nolint:errcheck
	buf := make([]byte, 256)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP (Echo Request): %v", err)
	}
	hdr, _, err := Parse(buf[:n])
	if err != nil {
		t.Fatalf("Parse Echo Request: %v", err)
	}
	if hdr.MsgType != MsgTypeEchoRequest {
		t.Fatalf("got MsgType=%d, want %d (Echo Request)", hdr.MsgType, MsgTypeEchoRequest)
	}
	return hdr
}

// TestPathProberSendsEchoRequest verifies that tick() sends an Echo Request
// to a monitored peer with S=1 and TEID=0 per TS 29.281 §5.1 and §7.2.1.
func TestPathProberSendsEchoRequest(t *testing.T) {
	// Set up a listener simulating the GTP-U peer.
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	prober, closeFn := newTestProber(t, peerPort, N3RequestsDefault)
	defer closeFn()

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	// First tick should start a probe round.
	t0 := time.Now()
	prober.tick(t0)

	hdr := recvEchoRequest(t, peerConn)
	if !hdr.S {
		t.Error("Echo Request S=0, want S=1 per §5.1")
	}
	if hdr.TEID != 0 {
		t.Errorf("Echo Request TEID=%d, want 0 per §5.1", hdr.TEID)
	}
}

// TestPathProberRetransmitSameSeq verifies that within a round, retransmits carry the same
// Sequence Number per TS 29.281 §4.3.1 and §11:
// "This doesn't prevent resending an Echo Request with the same sequence number
// according to the T3-RESPONSE timer."
func TestPathProberRetransmitSameSeq(t *testing.T) {
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	prober, closeFn := newTestProber(t, peerPort, 3)
	defer closeFn()

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	t0 := time.Now()
	t1 := t0.Add(T3ResponseDefault)
	t2 := t1.Add(T3ResponseDefault)

	prober.tick(t0) // round start → send seqNum=X, nextAction=t0+T3
	h0 := recvEchoRequest(t, peerConn)

	prober.tick(t1) // retry → send seqNum=X (same), nextAction=t1+T3
	h1 := recvEchoRequest(t, peerConn)

	prober.tick(t2) // retry → send seqNum=X (same), nextAction=t2+T3
	h2 := recvEchoRequest(t, peerConn)

	if h0.SeqNum != h1.SeqNum || h1.SeqNum != h2.SeqNum {
		t.Errorf("retransmits used different seq numbers: %d, %d, %d — must be same per §4.3.1",
			h0.SeqNum, h1.SeqNum, h2.SeqNum)
	}
}

// TestPathProberNewRoundNewSeq verifies that a new probe round uses a different
// Sequence Number from the previous round per TS 29.281 §4.3.1:
// "a given Sequence Number shall, if used, unambiguously define a GTP-U signalling
// request message sent on the path."
func TestPathProberNewRoundNewSeq(t *testing.T) {
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	prober, closeFn := newTestProber(t, peerPort, 1)
	defer closeFn()

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	t0 := time.Now()
	prober.tick(t0) // round 1 start → sends seqNum=A
	h0 := recvEchoRequest(t, peerConn)

	// Simulate receiving response → round 1 succeeds
	prober.RecordEchoResponse(peerIP, h0.SeqNum)

	// Next tick at t0+T3: round 1 SUCCESS → schedules round 2 at (t0+T3)+probeInterval.
	tSuccess := t0.Add(T3ResponseDefault)
	prober.tick(tSuccess)

	// Advance past nextAction = tSuccess + probeInterval.
	t2 := tSuccess.Add(EchoMinInterval + time.Second)
	prober.tick(t2) // round 2 start → sends seqNum=B
	h1 := recvEchoRequest(t, peerConn)

	if h0.SeqNum == h1.SeqNum {
		t.Errorf("round 2 reused seq %d — new round must use different seq per §4.3.1", h0.SeqNum)
	}
}

// TestPathProberPathFailedCallback verifies that PathFailed is called exactly once
// after N3-REQUESTS retries without a response, per TS 29.281 §12.3.
func TestPathProberPathFailedCallback(t *testing.T) {
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	prober, closeFn := newTestProber(t, peerPort, 3) // N3=3 for speed
	defer closeFn()

	var mu sync.Mutex
	failedPeers := []netip.Addr{}
	prober.PathFailed = func(peer netip.Addr) {
		mu.Lock()
		failedPeers = append(failedPeers, peer)
		mu.Unlock()
	}

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	t0 := time.Now()
	// Exhaust N3=3 retries (tick 0=first send, tick 1=retry1, tick 2=retry2,
	// tick 3=retry3=n3Requests exhausted → FAIL on tick 4)
	for i := 0; i <= 3; i++ {
		peerConn.SetReadDeadline(time.Now().Add(100 * time.Millisecond)) //nolint:errcheck
		prober.tick(t0.Add(time.Duration(i) * T3ResponseDefault))
		// drain sent packet (don't respond)
		buf := make([]byte, 256)
		peerConn.ReadFromUDP(buf) //nolint:errcheck
	}

	// Allow goroutine to run
	time.Sleep(20 * time.Millisecond)

	mu.Lock()
	n := len(failedPeers)
	mu.Unlock()

	if n != 1 {
		t.Errorf("PathFailed called %d times, want 1", n)
	}
}

// TestPathProberPathRecoveredCallback verifies that PathRecovered is called when
// a previously-failed path receives an Echo Response.
func TestPathProberPathRecoveredCallback(t *testing.T) {
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	prober, closeFn := newTestProber(t, peerPort, 2) // N3=2
	defer closeFn()

	recovered := make(chan netip.Addr, 1)
	prober.PathRecovered = func(peer netip.Addr) { recovered <- peer }

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	// Drive to failure: tick 0 (send), tick 1 (retry), tick 2 (FAIL)
	t0 := time.Now()
	for i := 0; i <= 2; i++ {
		peerConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:errcheck
		prober.tick(t0.Add(time.Duration(i) * T3ResponseDefault))
		buf := make([]byte, 256)
		peerConn.ReadFromUDP(buf) //nolint:errcheck
	}
	time.Sleep(10 * time.Millisecond) // allow PathFailed goroutine

	// FAILED tick occurred at t0+2*T3 → nextAction = (t0+2*T3) + probeInterval.
	// Advance past that to trigger the next round.
	tFail := t0.Add(2 * T3ResponseDefault)
	t1 := tFail.Add(EchoMinInterval + time.Second)
	prober.tick(t1) // start recovery round
	hdr := recvEchoRequest(t, peerConn)

	// Simulate peer responding
	prober.RecordEchoResponse(peerIP, hdr.SeqNum)

	select {
	case peer := <-recovered:
		if peer != peerIP {
			t.Errorf("PathRecovered called with %v, want %v", peer, peerIP)
		}
	case <-time.After(200 * time.Millisecond):
		t.Error("PathRecovered not called after response received on failed path")
	}
}

// TestPathProberRemoveCancelsProbing verifies that Remove() stops further Echo Requests.
func TestPathProberRemoveCancelsProbing(t *testing.T) {
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	prober, closeFn := newTestProber(t, peerPort, N3RequestsDefault)
	defer closeFn()

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	t0 := time.Now()
	prober.tick(t0) // sends first Echo Request
	recvEchoRequest(t, peerConn)

	prober.Remove(peerIP)
	prober.tick(t0.Add(T3ResponseDefault)) // should send nothing after Remove

	peerConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:errcheck
	buf := make([]byte, 256)
	n, _, err := peerConn.ReadFromUDP(buf)
	if err == nil && n > 0 {
		t.Error("Echo Request sent after Remove() — should not probe removed peer")
	}
}

// TestPathProberRecordResponseNoMatch verifies that a mismatched sequence number is ignored.
// Per §4.3.1: response seq must match the outstanding request seq.
func TestPathProberRecordResponseNoMatch(t *testing.T) {
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	prober, closeFn := newTestProber(t, peerPort, 2)
	defer closeFn()

	failed := make(chan struct{}, 1)
	prober.PathFailed = func(netip.Addr) { failed <- struct{}{} }

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	t0 := time.Now()
	prober.tick(t0)
	hdr := recvEchoRequest(t, peerConn)

	// Send response with wrong seq — must not satisfy the outstanding probe
	prober.RecordEchoResponse(peerIP, hdr.SeqNum+1)

	// Should still retry and eventually fail
	for i := 1; i <= 2; i++ {
		peerConn.SetReadDeadline(time.Now().Add(50 * time.Millisecond)) //nolint:errcheck
		prober.tick(t0.Add(time.Duration(i) * T3ResponseDefault))
		buf := make([]byte, 256)
		peerConn.ReadFromUDP(buf) //nolint:errcheck
	}
	select {
	case <-failed:
	case <-time.After(200 * time.Millisecond):
		t.Error("PathFailed should fire when mismatched response doesn't satisfy probe")
	}
}

// TestForwarderEchoResponseNotifiesProber verifies that the Forwarder dispatches
// incoming Echo Responses to the registered PathProber.
func TestForwarderEchoResponseNotifiesProber(t *testing.T) {
	// peerConn simulates a GTP-U peer that the PathProber probes.
	peerConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("peerConn ListenUDP: %v", err)
	}
	defer peerConn.Close()
	peerPort := peerConn.LocalAddr().(*net.UDPAddr).Port

	// Create a real Forwarder.
	fwd, err := New("127.0.0.1:0", netip.MustParseAddr("127.0.0.1"), nil, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()

	// Create PathProber using the Forwarder's conn.
	prober := NewPathProber(fwd.Conn(), EchoMinInterval, T3ResponseDefault, N3RequestsDefault, discardSlog())
	prober.port = peerPort
	fwd.SetPathProber(prober)

	peerIP := netip.MustParseAddr("127.0.0.1")
	prober.Add(peerIP)

	// Tick prober → sends Echo Request to peerConn.
	prober.tick(time.Now())
	hdr := recvEchoRequest(t, peerConn)

	// Peer sends Echo Response back to the Forwarder's address.
	fwdAddr := fwd.conn.LocalAddr().(*net.UDPAddr)
	respHdr := Header{
		Version: 1, PT: true, S: true,
		MsgType: MsgTypeEchoResponse,
		TEID:    0,
		SeqNum:  hdr.SeqNum,
	}
	recovery := BuildRecovery()
	respPkt := append(Marshal(respHdr, len(recovery)), recovery...)
	if _, err := peerConn.WriteToUDP(respPkt, fwdAddr); err != nil {
		t.Fatalf("WriteToUDP (Echo Response): %v", err)
	}

	// Read the Echo Response from the Forwarder's socket and dispatch it.
	buf := make([]byte, 256)
	n, srcAddr, err := fwd.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	fwd.handle(buf[:n], srcAddr)

	// Verify the prober recorded the response.
	prober.mu.Lock()
	e, ok := prober.paths[peerIP]
	responded := ok && e.roundResponded
	prober.mu.Unlock()

	if !responded {
		t.Error("PathProber.roundResponded = false after Forwarder dispatched Echo Response")
	}
}

// --- C20 Fuzz Tests ---
// These fuzz targets exercise the public network-input parsers per CLAUDE.md C20.
// Seed corpus entries are taken from the golden wire vectors in header_test.go.

// FuzzParse fuzzes the GTP-U header parser Parse() per C20.
// Seeds: all message-type golden vectors from header_test.go (§5.1 Figure 5.1-1 derived).
func FuzzParse(f *testing.F) {
	// G-PDU no-flags (§5.1: E=0,S=0,PN=0 → octet0=0x30)
	f.Add([]byte{0x30, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01})
	// Echo Request (S=1, TEID=0, SeqNum=0x42) — Table 6.1-1: "1 | Echo Request"
	f.Add([]byte{0x32, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00})
	// Echo Response with Recovery IE — Table 6.1-1: "2 | Echo Response"
	f.Add([]byte{0x32, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x0E, 0x00})
	// Error Indication (S=1, TEID=0) — Table 6.1-1: "26 | Error Indication"
	f.Add([]byte{0x32, 0x1A, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x10, 0x00, 0x00, 0x00, 0x07, // TEID Data I IE (type=16, TEID=7)
		0x85, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01, // Peer Address IE (type=133, IPv4)
	})
	// End Marker (S=0, TEID=5) — Table 6.1-1: "254 | End Marker"
	f.Add([]byte{0x30, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05})
	// E-flag with extension header chain (§5.2 derived)
	f.Add([]byte{
		0x34, 0xFF, 0x00, 0x08, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x00, 0x03,
		0x01, 0xDE, 0xAD, 0x00,
	})
	// All-flags (E=1,S=1,PN=1 → octet0=0x37)
	f.Add([]byte{0x37, 0xFF, 0x00, 0x04, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x00, 0x00})

	f.Fuzz(func(t *testing.T, data []byte) {
		h, consumed, err := Parse(data)
		if err != nil {
			return // errors are acceptable; panics are not
		}
		// Invariant: consumed must be within bounds
		if consumed < MinLen || consumed > len(data) {
			t.Errorf("consumed=%d out of bounds [%d, %d]", consumed, MinLen, len(data))
		}
		// Invariant: version must be 1 on success
		if h.Version != 1 {
			t.Errorf("Parse succeeded with version=%d (want 1)", h.Version)
		}
	})
}

// FuzzParseIEs fuzzes the GTP-U IE parser ParseIEs() per C20.
// Seeds: all IE golden byte vectors from header_test.go (§8 derived).
func FuzzParseIEs(f *testing.F) {
	// Recovery IE (TV format, type=14=0x0E, value=1 byte) — §8.2 / Table 19
	f.Add([]byte{0x0E, 0x00})
	// TEID Data I IE (TV format, type=16=0x10, value=4 bytes) — §8.3 / Table 19
	f.Add([]byte{0x10, 0x12, 0x34, 0x56, 0x78})
	// GTP-U Peer Address IE IPv4 (TLV, type=133=0x85, length=4) — §8.4 / Table 19
	f.Add([]byte{0x85, 0x00, 0x04, 0x0A, 0x01, 0x02, 0x03})
	// Combination: Recovery + TEID Data I
	f.Add([]byte{0x0E, 0x00, 0x10, 0x00, 0x00, 0x00, 0x63})
	// Empty IE list
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// ParseIEs must never panic on arbitrary input.
		_ = ParseIEs(data)
	})
}
