package gtpu

import (
	"encoding/binary"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"testing"

	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

func discardSlog() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// newTestStore builds a session store with one session containing one PDR (TEID=100, FARID=1)
// and two FARs: FAR 1 (FORW to 10.0.0.2:2152 with TEID=200) and FAR 2 (DROP).
func newTestStore() *sgwusession.Store {
	store := sgwusession.NewStore()
	sess := &sgwusession.Session{
		CPSEID: 1,
		UPSEID: 1,
		PDRs: []sgwusession.PDR{
			{ID: 1, LocalTEID: 100, FARID: 1},
		},
		FARs: []sgwusession.FAR{
			{
				ID:          1,
				ApplyAction: 0x02, // FORW per TS 29.244 §8.2.26
				OuterTEID:   200,
				OuterIP:     netip.MustParseAddr("10.0.0.2"),
			},
			{
				ID:          2,
				ApplyAction: 0x01, // DROP per TS 29.244 §8.2.26
			},
		},
	}
	_ = store.Create(sess)
	return store
}

// TestFindByLocalTEID verifies the session store TEID lookup used by the forwarder.
func TestFindByLocalTEID(t *testing.T) {
	store := newTestStore()

	sess, pdr, found := store.FindByLocalTEID(100)
	if !found {
		t.Fatal("FindByLocalTEID(100): not found")
	}
	if pdr.FARID != 1 {
		t.Errorf("FARID = %d, want 1", pdr.FARID)
	}
	if sess.CPSEID != 1 {
		t.Errorf("CPSEID = %d, want 1", sess.CPSEID)
	}

	_, _, found = store.FindByLocalTEID(999)
	if found {
		t.Error("FindByLocalTEID(999): found, want not found")
	}

	_, _, found = store.FindByLocalTEID(0)
	if found {
		t.Error("FindByLocalTEID(0): found, want not found (TEID=0 is reserved)")
	}
}

// TestForwarderEchoRequestReply sends an Echo Request to the forwarder and reads the Echo Response.
// Verifies: S=1 in response header, MsgType=2, TEID=0, SeqNum echoed, Recovery IE present.
// Per §5.1: "For Echo Response, the S flag shall be set to '1'."
// Per §7.2.2: Recovery counter=0.
func TestForwarderEchoRequestReply(t *testing.T) {
	store := sgwusession.NewStore()
	localIP := netip.MustParseAddr("127.0.0.1")

	fwd, err := New("127.0.0.1:0", localIP, store, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()

	listenAddr := fwd.conn.LocalAddr().(*net.UDPAddr)

	// Build Echo Request: S=1, TEID=0, SeqNum=0x55
	reqHdr := Header{Version: 1, PT: true, S: true, MsgType: MsgTypeEchoRequest, TEID: 0, SeqNum: 0x55}
	reqPkt := Marshal(reqHdr, 0)

	// Send the request from a client socket.
	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	defer clientConn.Close()

	if _, err := clientConn.WriteToUDP(reqPkt, listenAddr); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}

	// Process one packet synchronously via handle().
	buf := make([]byte, 65535)
	n, _, err := fwd.conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
	fwd.handle(buf[:n], clientAddr)

	// Read the Echo Response.
	respBuf := make([]byte, 65535)
	m, _, err := clientConn.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("ReadFromUDP (response): %v", err)
	}

	resp, consumed, err := Parse(respBuf[:m])
	if err != nil {
		t.Fatalf("Parse response: %v", err)
	}

	if resp.MsgType != MsgTypeEchoResponse {
		t.Errorf("MsgType = %d, want %d (Echo Response)", resp.MsgType, MsgTypeEchoResponse)
	}
	if !resp.S {
		t.Error("Echo Response S=0, want S=1 (§5.1: S flag shall be set to '1')")
	}
	if resp.TEID != 0 {
		t.Errorf("Echo Response TEID = %d, want 0", resp.TEID)
	}
	if resp.SeqNum != 0x55 {
		t.Errorf("Echo Response SeqNum = %d, want 0x55 (§7.2.2: echo the sequence number)", resp.SeqNum)
	}

	// Verify Recovery IE is present with counter=0.
	ieBytes := respBuf[consumed:m]
	ies := ParseIEs(ieBytes)
	recovVal, ok := ies[IETypeRecovery]
	if !ok {
		t.Error("Echo Response missing Recovery IE (§7.2.2: Table 7.2.2-1: Mandatory)")
	} else if len(recovVal) != 1 || recovVal[0] != 0 {
		t.Errorf("Recovery IE counter = %v, want [0x00] (§7.2.2: shall be set to zero)", recovVal)
	}
}

// TestForwarderGPDUUnknownTEIDSendsErrorIndication verifies that an unknown TEID triggers
// an Error Indication per TS 29.281 §7.3.1.
// Per §7.3.1: "it shall send an Error Indication to the originator of the G-PDU".
// Per §7.3.1: Error Indication must contain TEID Data I and GTP-U Peer Address IEs.
func TestForwarderGPDUUnknownTEIDSendsErrorIndication(t *testing.T) {
	store := sgwusession.NewStore()
	fallbackIP := netip.MustParseAddr("127.0.0.10")
	packetDstIP := netip.MustParseAddr("127.0.0.1")

	fwd, err := New("127.0.0.1:0", fallbackIP, store, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()

	listenAddr := fwd.conn.LocalAddr().(*net.UDPAddr)

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	defer clientConn.Close()

	// G-PDU with unknown TEID=999
	gpduHdr := Header{Version: 1, PT: true, MsgType: MsgTypeGPDU, TEID: 999}
	pkt := Marshal(gpduHdr, 0)
	if _, err := clientConn.WriteToUDP(pkt, listenAddr); err != nil {
		t.Fatalf("WriteToUDP: %v", err)
	}

	buf := make([]byte, 65535)
	oob := make([]byte, 256)
	n, oobn, _, _, err := fwd.conn.ReadMsgUDP(buf, oob)
	if err != nil {
		t.Fatalf("ReadMsgUDP: %v", err)
	}
	gotLocalIP := packetDstAddr(oob[:oobn])
	if gotLocalIP != packetDstIP {
		t.Fatalf("packet destination IP = %v; want %v", gotLocalIP, packetDstIP)
	}
	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
	fwd.handleWithLocalIP(buf[:n], clientAddr, gotLocalIP)

	if fwd.unknownTEID.Load() != 1 {
		t.Errorf("unknownTEID counter = %d, want 1", fwd.unknownTEID.Load())
	}

	// Read Error Indication.
	resp := make([]byte, 65535)
	m, _, err := clientConn.ReadFromUDP(resp)
	if err != nil {
		t.Fatalf("ReadFromUDP (Error Indication): %v", err)
	}

	hdr, consumed, err := Parse(resp[:m])
	if err != nil {
		t.Fatalf("Parse Error Indication: %v", err)
	}
	if hdr.MsgType != MsgTypeErrorIndication {
		t.Errorf("MsgType = %d, want %d (Error Indication)", hdr.MsgType, MsgTypeErrorIndication)
	}
	if !hdr.S {
		t.Error("Error Indication S=0, want S=1 (§5.1: S flag shall be set to '1')")
	}
	if hdr.TEID != 0 {
		t.Errorf("Error Indication TEID = %d, want 0 (§5.1: TEID=0)", hdr.TEID)
	}

	// Verify mandatory IEs per Table 7.3.1-1.
	ies := ParseIEs(resp[consumed:m])
	teidVal, hasTEID := ies[IETypeTEIDDataI]
	if !hasTEID {
		t.Error("Error Indication missing TEID Data I IE (Table 7.3.1-1: Mandatory)")
	} else {
		teid := uint32(teidVal[0])<<24 | uint32(teidVal[1])<<16 | uint32(teidVal[2])<<8 | uint32(teidVal[3])
		if teid != 999 {
			t.Errorf("TEID Data I = %d, want 999 (§7.3.1: TEID from the triggering G-PDU)", teid)
		}
	}
	peerVal, hasPeer := ies[IETypeGTPUPeerAddress]
	if !hasPeer {
		t.Error("Error Indication missing GTP-U Peer Address IE (Table 7.3.1-1: Mandatory)")
	} else if len(peerVal) != 4 {
		t.Errorf("GTP-U Peer Address IE length = %d; want 4 for IPv4", len(peerVal))
	} else {
		gotPeer := addrFrom4Bytes(peerVal)
		if gotPeer != packetDstIP {
			t.Errorf("GTP-U Peer Address IE = %v; want triggering packet destination %v (§7.3.1)", gotPeer, packetDstIP)
		}
	}
}

func TestForwarderGPDUUnknownTEIDFallsBackToConfiguredLocalIP(t *testing.T) {
	store := sgwusession.NewStore()
	fallbackIP := netip.MustParseAddr("127.0.0.10")

	fwd, err := New("127.0.0.1:0", fallbackIP, store, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()

	clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	defer clientConn.Close()

	clientAddr := clientConn.LocalAddr().(*net.UDPAddr)
	gpduHdr := Header{Version: 1, PT: true, MsgType: MsgTypeGPDU, TEID: 12345}
	fwd.handleWithLocalIP(Marshal(gpduHdr, 0), clientAddr, netip.Addr{})

	resp := make([]byte, 65535)
	m, _, err := clientConn.ReadFromUDP(resp)
	if err != nil {
		t.Fatalf("ReadFromUDP (Error Indication): %v", err)
	}
	_, consumed, err := Parse(resp[:m])
	if err != nil {
		t.Fatalf("Parse Error Indication: %v", err)
	}
	ies := ParseIEs(resp[consumed:m])
	peerVal := ies[IETypeGTPUPeerAddress]
	if len(peerVal) != 4 {
		t.Fatalf("GTP-U Peer Address IE length = %d; want 4", len(peerVal))
	}
	gotPeer := addrFrom4Bytes(peerVal)
	if gotPeer != fallbackIP {
		t.Errorf("GTP-U Peer Address fallback = %v; want %v", gotPeer, fallbackIP)
	}
	teidVal := ies[IETypeTEIDDataI]
	if gotTEID := binary.BigEndian.Uint32(teidVal); gotTEID != 12345 {
		t.Errorf("TEID Data I = %d; want 12345", gotTEID)
	}
}

func addrFrom4Bytes(b []byte) netip.Addr {
	return netip.AddrFrom4([4]byte{b[0], b[1], b[2], b[3]})
}

// TestForwarderEndMarkerUnknownTEIDIgnored verifies §7.3.2 behaviour:
// Per §7.3.2: "If an End Marker message is received with a TEID for which there is no
// context, then the receiver shall ignore this message."
func TestForwarderEndMarkerUnknownTEIDIgnored(t *testing.T) {
	store := sgwusession.NewStore()
	localIP := netip.MustParseAddr("127.0.0.1")

	fwd, err := New("127.0.0.1:0", localIP, store, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}

	em := Header{Version: 1, PT: true, MsgType: MsgTypeEndMarker, TEID: 777}
	pkt := Marshal(em, 0)
	fwd.handle(pkt, clientAddr)

	// No response should be sent; counters unchanged.
	if fwd.txPackets.Load() != 0 {
		t.Errorf("txPackets = %d, want 0 (End Marker for unknown TEID must be silently ignored)", fwd.txPackets.Load())
	}
	if fwd.dropped.Load() != 0 {
		t.Errorf("dropped = %d, want 0 (ignored, not dropped)", fwd.dropped.Load())
	}
}

// TestForwarderDropAction verifies that a G-PDU matching a DROP FAR is discarded.
// Per TS 29.244 §8.2.26 "Bit 1 – DROP (Drop)": packet is discarded, no Error Indication sent.
func TestForwarderDropAction(t *testing.T) {
	store := sgwusession.NewStore()
	// Session with PDR TEID=50 → FAR 2 (DROP)
	sess := &sgwusession.Session{
		CPSEID: 2,
		UPSEID: 2,
		PDRs:   []sgwusession.PDR{{ID: 1, LocalTEID: 50, FARID: 2}},
		FARs:   []sgwusession.FAR{{ID: 2, ApplyAction: 0x01}}, // DROP
	}
	_ = store.Create(sess)

	localIP := netip.MustParseAddr("127.0.0.1")
	fwd, err := New("127.0.0.1:0", localIP, store, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12346}
	pkt := Marshal(Header{Version: 1, PT: true, MsgType: MsgTypeGPDU, TEID: 50}, 0)
	fwd.handle(pkt, clientAddr)

	if fwd.dropped.Load() != 1 {
		t.Errorf("dropped = %d, want 1 for DROP FAR", fwd.dropped.Load())
	}
	if fwd.txPackets.Load() != 0 {
		t.Errorf("txPackets = %d, want 0 for DROP FAR", fwd.txPackets.Load())
	}
}

func TestForwarderCountsIdleDownlinkReleaseAccessDrop(t *testing.T) {
	store := sgwusession.NewStore()
	sess := &sgwusession.Session{
		CPSEID: 2,
		UPSEID: 2,
		PDRs: []sgwusession.PDR{{
			ID:              1,
			LocalTEID:       50,
			FARID:           2,
			SourceInterface: 1,
			EBI:             6,
			QCI:             5,
			QoSValid:        true,
		}},
		FARs: []sgwusession.FAR{{
			ID:          2,
			ApplyAction: 0x01,
			DropReason:  sgwusession.DropReasonReleaseAccessBearers,
		}},
	}
	_ = store.Create(sess)

	localIP := netip.MustParseAddr("127.0.0.1")
	fwd, err := New("127.0.0.1:0", localIP, store, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12346}
	pkt := Marshal(Header{Version: 1, PT: true, MsgType: MsgTypeGPDU, TEID: 50}, 0)
	fwd.handle(pkt, clientAddr)

	if fwd.idleDownlink.Load() != 1 {
		t.Fatalf("idleDownlink = %d; want 1", fwd.idleDownlink.Load())
	}
	if fwd.dropped.Load() != 1 {
		t.Fatalf("dropped = %d; want 1", fwd.dropped.Load())
	}
	if fwd.txPackets.Load() != 0 {
		t.Fatalf("txPackets = %d; want 0", fwd.txPackets.Load())
	}
}

type idleDownlinkRecorder struct {
	events []sgwusession.IdleDownlinkEvent
}

func (r *idleDownlinkRecorder) ReportIdleDownlink(event sgwusession.IdleDownlinkEvent) {
	r.events = append(r.events, event)
}

func TestForwarderReportsIdleDownlinkReleaseAccessDrop(t *testing.T) {
	store := sgwusession.NewStore()
	sess := &sgwusession.Session{
		CPSEID: 20,
		UPSEID: 30,
		PDRs: []sgwusession.PDR{{
			ID:              11,
			LocalTEID:       50,
			FARID:           22,
			SourceInterface: 1,
			EBI:             6,
			QCI:             5,
			QoSValid:        true,
		}},
		FARs: []sgwusession.FAR{{
			ID:          22,
			ApplyAction: 0x01,
			DropReason:  sgwusession.DropReasonReleaseAccessBearers,
		}},
	}
	_ = store.Create(sess)

	localIP := netip.MustParseAddr("127.0.0.1")
	fwd, err := New("127.0.0.1:0", localIP, store, discardSlog())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	defer fwd.conn.Close()
	rec := &idleDownlinkRecorder{}
	fwd.SetIdleDownlinkReporter(rec)

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12346}
	pkt := Marshal(Header{Version: 1, PT: true, MsgType: MsgTypeGPDU, TEID: 50}, 0)
	fwd.handle(pkt, clientAddr)

	if len(rec.events) != 1 {
		t.Fatalf("events = %d; want 1", len(rec.events))
	}
	want := sgwusession.IdleDownlinkEvent{
		CPSEID:          20,
		UPSEID:          30,
		PDRID:           11,
		FARID:           22,
		LocalTEID:       50,
		EBI:             6,
		QCI:             5,
		SourceInterface: 1,
		QoSValid:        true,
		DropReason:      sgwusession.DropReasonReleaseAccessBearers,
	}
	if rec.events[0] != want {
		t.Fatalf("event = %+v; want %+v", rec.events[0], want)
	}
}

func TestForwarderGroupCreatesUniqueListeners(t *testing.T) {
	store := sgwusession.NewStore()
	group, err := NewGroup([]Endpoint{
		{Listen: "127.0.0.1:0", LocalIP: netip.MustParseAddr("127.0.0.1")},
		{Listen: "127.0.0.2:0", LocalIP: netip.MustParseAddr("127.0.0.2")},
	}, store, discardSlog())
	if err != nil {
		t.Fatalf("NewGroup: %v", err)
	}
	defer group.Close() //nolint:errcheck

	if got := len(group.Forwarders()); got != 2 {
		t.Fatalf("forwarders = %d; want 2", got)
	}
}

func FuzzForwarderHandleWithLocalIP(f *testing.F) {
	f.Add([]byte{})
	f.Add([]byte{0x30, MsgTypeGPDU, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	f.Add(Marshal(Header{Version: 1, PT: true, MsgType: MsgTypeGPDU, TEID: 100}, 4))
	f.Add(Marshal(Header{Version: 1, PT: true, S: true, MsgType: MsgTypeEchoRequest, TEID: 0, SeqNum: 0x1234}, 0))
	f.Add(Marshal(Header{Version: 1, PT: true, MsgType: MsgTypeEndMarker, TEID: 777}, 0))

	f.Fuzz(func(t *testing.T, data []byte) {
		store := newTestStore()
		fwd, err := New("127.0.0.1:0", netip.MustParseAddr("127.0.0.1"), store, discardSlog())
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		defer fwd.conn.Close()

		clientConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
		if err != nil {
			t.Fatalf("client ListenUDP: %v", err)
		}
		defer clientConn.Close()

		fwd.handleWithLocalIP(data, clientConn.LocalAddr().(*net.UDPAddr), netip.MustParseAddr("127.0.0.1"))
	})
}
