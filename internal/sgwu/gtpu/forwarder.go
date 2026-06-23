package gtpu

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sync/atomic"

	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

// applyActionFORW is bit 2 of the Apply Action IE per TS 29.244 §8.2.26
// (extracted from docs/specs/29244-fa0.docx):
// "Bit 2 – FORW (Forward): the UP function shall forward the packets."
const applyActionFORW uint8 = 0x02

// Forwarder is the userspace GTP-U reference forwarder per TS 29.281 Rel-15 Phase 6.
// It listens on UDP/2152, parses GTP-U headers, looks up local TEIDs in the PDR/FAR
// store, and forwards or drops G-PDUs per the applicable FAR Apply Action.
type Forwarder struct {
	conn    *net.UDPConn
	store   *sgwusession.Store
	localIP netip.Addr // SGW-U GTP-U IP, used as source in Error Indication Peer Address IE
	log     *slog.Logger
	prober  *PathProber // optional; set via SetPathProber

	rxPackets   atomic.Uint64
	txPackets   atomic.Uint64
	rxBytes     atomic.Uint64
	txBytes     atomic.Uint64
	unknownTEID atomic.Uint64
	dropped     atomic.Uint64
}

// New creates a GTP-U Forwarder that listens on listenAddr (e.g., "0.0.0.0:2152").
// localIP is the SGW-U data-plane IP used as the GTP-U Peer Address IE in Error Indications.
func New(listenAddr string, localIP netip.Addr, store *sgwusession.Store, log *slog.Logger) (*Forwarder, error) {
	uaddr, err := net.ResolveUDPAddr("udp4", listenAddr)
	if err != nil {
		return nil, fmt.Errorf("gtpu: resolve %q: %w", listenAddr, err)
	}
	conn, err := net.ListenUDP("udp4", uaddr)
	if err != nil {
		return nil, fmt.Errorf("gtpu: listen %s: %w", listenAddr, err)
	}
	return &Forwarder{
		conn:    conn,
		store:   store,
		localIP: localIP,
		log:     log,
	}, nil
}

// Serve runs the receive loop until ctx is cancelled.
// Must be called in a goroutine; blocks until ctx.Done().
func (f *Forwarder) Serve(ctx context.Context) error {
	f.log.Info("GTP-U forwarder listening", "addr", f.conn.LocalAddr())
	buf := make([]byte, 65535)
	go func() {
		<-ctx.Done()
		f.conn.Close()
	}()
	for {
		n, src, err := f.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("gtpu: read: %w", err)
		}
		f.rxPackets.Add(1)
		f.rxBytes.Add(uint64(n))

		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		f.handle(pkt, src)
	}
}

// Close shuts down the GTP-U listener.
func (f *Forwarder) Close() error {
	return f.conn.Close()
}

// Conn returns the underlying UDP socket.
// Use this to create a PathProber that shares the GTP-U port so Echo Responses
// are received on the same socket that the Forwarder already reads.
func (f *Forwarder) Conn() *net.UDPConn {
	return f.conn
}

// SetPathProber registers a PathProber to receive Echo Response notifications.
// The prober must be created with the same conn (f.Conn()) to share the GTP-U socket.
func (f *Forwarder) SetPathProber(p *PathProber) {
	f.prober = p
}

// Counters holds packet and byte counters for observability.
type Counters struct {
	RxPackets   uint64
	TxPackets   uint64
	RxBytes     uint64
	TxBytes     uint64
	UnknownTEID uint64
	Dropped     uint64
}

// Counters returns a snapshot of current packet/byte counts.
func (f *Forwarder) Counters() Counters {
	return Counters{
		RxPackets:   f.rxPackets.Load(),
		TxPackets:   f.txPackets.Load(),
		RxBytes:     f.rxBytes.Load(),
		TxBytes:     f.txBytes.Load(),
		UnknownTEID: f.unknownTEID.Load(),
		Dropped:     f.dropped.Load(),
	}
}

func (f *Forwarder) handle(pkt []byte, src *net.UDPAddr) {
	hdr, hdrLen, err := Parse(pkt)
	if err != nil {
		f.log.Warn("GTP-U: header parse error", "from", src, "error", err)
		f.dropped.Add(1)
		return
	}

	// R15-REAUDIT-002: bound T-PDU to the declared Length field (§5.1).
	// Parse() has already validated that MinLen+hdr.Length <= len(pkt).
	end := MinLen + int(hdr.Length)

	switch hdr.MsgType {
	case MsgTypeGPDU:
		f.handleGPDU(hdr, pkt[hdrLen:end], src)
	case MsgTypeEchoRequest:
		f.handleEchoRequest(hdr, src)
	case MsgTypeEchoResponse:
		f.handleEchoResponse(hdr, src)
	case MsgTypeEndMarker:
		f.handleEndMarker(hdr, src)
	case MsgTypeErrorIndication:
		f.log.Debug("GTP-U: Error Indication received", "from", src)
	default:
		f.log.Warn("GTP-U: unhandled message type", "from", src, "type", hdr.MsgType)
	}
}

// handleGPDU processes an incoming G-PDU per TS 29.281 §7.1.
// Looks up the local TEID in the PDR/FAR store; sends Error Indication for unknown TEIDs.
// Per §7.3.1: "When a GTP-U node receives a G-PDU for which no EPS Bearer context...
// can be found, it shall send an Error Indication to the originator of the G-PDU."
func (f *Forwarder) handleGPDU(hdr Header, tpdu []byte, src *net.UDPAddr) {
	sess, pdr, found := f.store.FindByLocalTEID(hdr.TEID)
	if !found {
		f.unknownTEID.Add(1)
		// R15-REAUDIT-008: per §7.3.1, Error Indication carries the TEID from the offending G-PDU.
		// TEID=0 is not a valid data TEID — silently discard rather than send EI with TEID=0.
		if hdr.TEID != 0 {
			f.log.Debug("GTP-U: G-PDU for unknown TEID — sending Error Indication",
				"teid", hdr.TEID, "from", src)
			f.sendErrorIndication(hdr.TEID, src)
		} else {
			f.log.Debug("GTP-U: G-PDU with TEID=0 for unknown context — discarded per §7.3.1", "from", src)
		}
		return
	}

	// AUD-07: hold the session read-lock while copying FAR fields so the PFCP
	// SMR handler cannot modify FARs concurrently.
	sess.Mu.RLock()
	var farCopy sgwusession.FAR
	var farFound bool
	for i := range sess.FARs {
		if sess.FARs[i].ID == pdr.FARID {
			farCopy = sess.FARs[i]
			farFound = true
			break
		}
	}
	sess.Mu.RUnlock()

	if !farFound {
		f.log.Warn("GTP-U: PDR references non-existent FAR — dropped",
			"teid", hdr.TEID, "far_id", pdr.FARID)
		f.dropped.Add(1)
		return
	}

	if farCopy.ApplyAction&applyActionFORW != 0 {
		f.forwardGPDU(hdr, &farCopy, tpdu)
	} else {
		// DROP or BUFF: discard. BUFF (DDN) is Phase 7+.
		f.dropped.Add(1)
	}
}

// forwardGPDU re-encapsulates the T-PDU with the FAR outer header creation parameters and sends it.
// R15-REAUDIT-003: relays S/SeqNum, PN/NPDUNum, E/NextExtHdr/ExtHeaders from the inbound header
// per TS 29.281 §4.3.1 and §5.2.
func (f *Forwarder) forwardGPDU(inHdr Header, far *sgwusession.FAR, tpdu []byte) {
	if !far.OuterIP.IsValid() || far.OuterTEID == 0 {
		f.log.Warn("GTP-U: FAR FORW missing outer header parameters",
			"outer_teid", far.OuterTEID, "outer_ip", far.OuterIP)
		f.dropped.Add(1)
		return
	}

	// Relay S/SeqNum, PN/NPDUNum, E/ExtHeaders from inbound header per §4.3.1:
	// "the sending GTP-U entity should set the S bit and the Sequence Number to
	// the same values as received."
	outHdr := Header{
		Version:    1,
		PT:         true,
		MsgType:    MsgTypeGPDU,
		TEID:       far.OuterTEID,
		S:          inHdr.S,
		SeqNum:     inHdr.SeqNum,
		PN:         inHdr.PN,
		NPDUNum:    inHdr.NPDUNum,
		E:          inHdr.E,
		NextExtHdr: inHdr.NextExtHdr,
		ExtHeaders: inHdr.ExtHeaders,
	}
	hdrBytes := Marshal(outHdr, len(tpdu))
	out := make([]byte, 0, len(hdrBytes)+len(tpdu))
	out = append(out, hdrBytes...)
	out = append(out, tpdu...)

	a4 := far.OuterIP.As4()
	dst := &net.UDPAddr{IP: a4[:], Port: Port}
	if _, err := f.conn.WriteToUDP(out, dst); err != nil {
		f.log.Warn("GTP-U: forward send failed", "dst", dst, "error", err)
		return
	}
	f.txPackets.Add(1)
	f.txBytes.Add(uint64(len(out)))
}

// handleEchoRequest responds to an Echo Request per TS 29.281 §7.2.1/§7.2.2.
// Per §5.1: "For the Echo Request, Echo Response, Error Indication...the S flag shall be set to '1'."
// Per §7.2.2: "The Restart Counter value in the Recovery information element shall not be
// used, i.e. it shall be set to zero by the sender."
func (f *Forwarder) handleEchoRequest(req Header, src *net.UDPAddr) {
	respHdr := Header{
		Version: 1,
		PT:      true,
		S:       true,                // §5.1: S=1 required for Echo Response
		MsgType: MsgTypeEchoResponse, // Table 13: "2 | Echo Response"
		TEID:    0,                   // §5.1: TEID=0 for Echo
		SeqNum:  req.SeqNum,          // §7.2.2: echo the sender's sequence number
	}
	recovery := BuildRecovery() // counter=0 per §7.2.2/§8.2
	hdrBytes := Marshal(respHdr, len(recovery))
	pkt := append(hdrBytes, recovery...)

	if _, err := f.conn.WriteToUDP(pkt, src); err != nil {
		f.log.Warn("GTP-U: Echo Response send failed", "to", src, "error", err)
		return
	}
	f.txPackets.Add(1)
	f.txBytes.Add(uint64(len(pkt)))
	f.log.Debug("GTP-U: Echo Response sent", "to", src, "seq", req.SeqNum)
}

// handleEchoResponse processes an Echo Response per TS 29.281 §7.2.2.
// Notifies the PathProber (if set) so it can mark the path as alive.
// Per §5.1: "The Sequence Number in a signalling response message shall be copied
// from the signalling request message that the GTP-U entity is replying to."
func (f *Forwarder) handleEchoResponse(hdr Header, src *net.UDPAddr) {
	f.log.Debug("GTP-U: Echo Response received", "from", src, "seq", hdr.SeqNum)
	if f.prober != nil {
		srcIP, ok := netip.AddrFromSlice(src.IP)
		if ok {
			f.prober.RecordEchoResponse(srcIP.Unmap(), hdr.SeqNum)
		}
	}
}

// handleEndMarker processes an End Marker per TS 29.281 §7.3.2.
// Per §7.3.2: "If an End Marker message is received with a TEID for which there is no
// context, then the receiver shall ignore this message."
// R15-REAUDIT-009: when the TEID is known and the FAR is FORW, forward End Marker to downstream.
func (f *Forwarder) handleEndMarker(hdr Header, src *net.UDPAddr) {
	sess, pdr, found := f.store.FindByLocalTEID(hdr.TEID)
	if !found {
		f.log.Debug("GTP-U: End Marker for unknown TEID — ignored per §7.3.2",
			"teid", hdr.TEID, "from", src)
		return
	}

	// AUD-07: hold the session read-lock while reading FAR fields.
	sess.Mu.RLock()
	var farCopy sgwusession.FAR
	for i := range sess.FARs {
		if sess.FARs[i].ID == pdr.FARID {
			farCopy = sess.FARs[i]
			break
		}
	}
	sess.Mu.RUnlock()

	if farCopy.ApplyAction&applyActionFORW == 0 || !farCopy.OuterIP.IsValid() || farCopy.OuterTEID == 0 {
		f.log.Debug("GTP-U: End Marker received but FAR not forwarding — not relayed",
			"teid", hdr.TEID, "from", src)
		return
	}
	f.sendEndMarker(farCopy.OuterTEID, farCopy.OuterIP)
	f.log.Debug("GTP-U: End Marker relayed downstream", "teid", hdr.TEID,
		"dst_teid", farCopy.OuterTEID, "dst_ip", farCopy.OuterIP)
}

// SendEndMarker sends an End Marker to the given TEID and IP (e.g., triggered by PFCP on
// tunnel switch). Per TS 29.281 §7.3.2, End Marker carries only the GTP-U header (no body).
func (f *Forwarder) SendEndMarker(teid uint32, dstIP netip.Addr) {
	f.sendEndMarker(teid, dstIP)
}

func (f *Forwarder) sendEndMarker(teid uint32, dstIP netip.Addr) {
	outHdr := Header{
		Version: 1,
		PT:      true,
		MsgType: MsgTypeEndMarker,
		TEID:    teid,
	}
	hdrBytes := Marshal(outHdr, 0)

	a4 := dstIP.As4()
	dst := &net.UDPAddr{IP: a4[:], Port: Port}
	if _, err := f.conn.WriteToUDP(hdrBytes, dst); err != nil {
		f.log.Warn("GTP-U: End Marker send failed", "dst", dst, "error", err)
		return
	}
	f.txPackets.Add(1)
	f.txBytes.Add(uint64(len(hdrBytes)))
}

// sendErrorIndication sends an Error Indication per TS 29.281 §7.3.1.
// Per §7.3.1: "The information element Tunnel Endpoint Identifier Data I shall be the TEID
// fetched from the G-PDU that triggered this procedure."
// Per §7.3.1: "The information element GTP-U Peer Address shall be the destination address."
// Per §5.1: "TEID shall be set to all zeros" and "S flag shall be set to '1'" for Error Indication.
func (f *Forwarder) sendErrorIndication(unknownTEID uint32, dst *net.UDPAddr) {
	hdr := Header{
		Version: 1,
		PT:      true,
		S:       true,                   // §5.1: S=1 required for Error Indication
		MsgType: MsgTypeErrorIndication, // Table 13: "26 | Error Indication"
		TEID:    0,                      // §5.1: TEID=0 for Error Indication
	}
	teidIE := BuildTEIDDataI(unknownTEID)
	peerIE, err := BuildGTPUPeerAddressIPv4(f.localIP)
	if err != nil {
		f.log.Warn("GTP-U: cannot build Error Indication peer address IE", "error", err)
		return
	}
	payload := append(teidIE, peerIE...)
	hdrBytes := Marshal(hdr, len(payload))
	pkt := append(hdrBytes, payload...)

	if _, err := f.conn.WriteToUDP(pkt, dst); err != nil {
		f.log.Warn("GTP-U: Error Indication send failed", "to", dst, "error", err)
		return
	}
	f.txPackets.Add(1)
	f.txBytes.Add(uint64(len(pkt)))
}
