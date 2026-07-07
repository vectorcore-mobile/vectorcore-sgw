// Package transport provides GTPv2-C UDP transport with transaction management
// per 3GPP TS 29.274 Sections 6 and 7.6.
package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/qos"
)

const gtpcPort = 2123

// inboundCacheTTL is how long a server-side response is held for retransmit
// detection per TS 29.274 Section 7.6.3. Sized to outlast a typical peer
// T3*N3 window (3s * 5 = 15s default) with margin.
const inboundCacheTTL = 30 * time.Second

// Handler is called when an inbound GTPv2-C request arrives.
// The implementation must send any response via conn before returning.
type Handler func(conn *Conn, addr *net.UDPAddr, hdr message.Header, raw []byte)

// retransmitKey identifies an inbound request for retransmission handling.
type retransmitKey struct {
	addr    string // "ip:port"
	seq     uint32
	msgType uint8
	teid    uint32
}

// cachedResponse holds an encoded response and its expiry time.
type cachedResponse struct {
	raw     []byte
	expires time.Time
}

// transactionKey identifies an outbound pending transaction by peer address and
// sequence number per TS 29.274 §7.6. Seq alone is insufficient when one socket
// serves multiple PGWs — a late or spoofed response could match a wrong transaction.
type transactionKey struct {
	addr         string // "ip:port" of the peer
	seq          uint32
	responseType uint8
}

// Conn is a GTPv2-C UDP endpoint with transaction management.
type Conn struct {
	conn   *net.UDPConn
	log    *slog.Logger
	t3     time.Duration // T3-RESPONSE timer per TS 29.274 §7.6
	n3     int           // N3-REQUESTS retransmit count
	seqMu  sync.Mutex
	seqVal uint32 // 24-bit sequence counter

	// pending tracks outbound requests awaiting responses, keyed by (peer addr, seq).
	pendingMu sync.Mutex
	pending   map[transactionKey]*pendingRequest

	// inboundCache holds encoded responses for inbound retransmit detection
	// per TS 29.274 Section 7.6.3. Keyed by (peer addr, sequence number).
	// inFlight tracks requests currently being processed; together with inboundCache
	// it prevents concurrent duplicates from executing the handler twice.
	// Both are protected by inboundCacheMu so cache lookup and in-flight marking
	// are atomic with respect to each other.
	inboundCacheMu sync.Mutex
	inboundCache   map[retransmitKey]cachedResponse
	inFlight       map[retransmitKey]struct{}

	// handler is called for incoming requests.
	handler atomic.Pointer[Handler]

	// dispatchSem limits the number of goroutines concurrently processing inbound
	// packets (AUD-11). A full semaphore causes excess packets to be dropped rather
	// than spawning unbounded goroutines and exhausting memory.
	dispatchSem chan struct{}
}

type pendingRequest struct {
	addr   *net.UDPAddr
	raw    []byte
	result chan pendingResult
	cancel context.CancelFunc
}

type pendingResult struct {
	raw        []byte
	piggybacks []message.Frame
	err        error
}

// Listen creates a GTPv2-C UDP listener on the given address.
func Listen(addr string, t3Seconds, n3 int, log *slog.Logger) (*Conn, error) {
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("resolve %q: %w", addr, err)
	}
	uc, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, fmt.Errorf("listen UDP %s: %w", addr, err)
	}
	c := &Conn{
		conn:         uc,
		log:          log,
		t3:           time.Duration(t3Seconds) * time.Second,
		n3:           n3,
		pending:      make(map[transactionKey]*pendingRequest),
		inboundCache: make(map[retransmitKey]cachedResponse),
		inFlight:     make(map[retransmitKey]struct{}),
		dispatchSem:  make(chan struct{}, 4096), // AUD-11: cap concurrent dispatches
	}
	return c, nil
}

// SetHandler registers the inbound request handler.
func (c *Conn) SetHandler(h Handler) {
	c.handler.Store(&h)
}

// LocalAddr returns the local UDP address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// SetDSCP applies IPv4 DSCP marking to packets sent by this GTPv2-C socket.
func (c *Conn) SetDSCP(dscp uint8) error {
	return qos.SetUDPConnIPv4DSCP(c.conn, dscp)
}

// Serve reads incoming packets and dispatches them until ctx is cancelled.
func (c *Conn) Serve(ctx context.Context) error {
	go func() {
		<-ctx.Done()
		_ = c.conn.Close()
	}()

	buf := make([]byte, 65535)
	for {
		n, addr, err := c.conn.ReadFromUDP(buf)
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("GTPv2-C read: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		// AUD-11: non-blocking acquire; drop if semaphore is full rather than spawning
		// an unbounded number of goroutines (prevents goroutine-exhaustion DoS).
		select {
		case c.dispatchSem <- struct{}{}:
			go func() {
				defer func() { <-c.dispatchSem }()
				c.dispatch(addr, pkt)
			}()
		default:
			c.log.Warn("GTPv2-C dispatch overload — packet dropped", "from", addr)
		}
	}
}

func (c *Conn) dispatch(addr *net.UDPAddr, raw []byte) {
	frames, err := message.SplitFrames(raw)
	if err != nil {
		// Per TS 29.274 Rel-15 §7.7.2: unsupported version → send Version Not Supported Indication.
		var vnErr *message.ErrVersionNotSupported
		if errors.As(err, &vnErr) {
			// Sequence number cannot be reliably extracted from an unknown-version packet;
			// send with seq=0. This is better than silently dropping per §7.7.2.
			vnsInd := message.MarshalVersionNotSupportedIndication(0)
			if _, writeErr := c.conn.WriteToUDP(vnsInd, addr); writeErr != nil {
				c.log.Warn("GTPv2-C: failed to send Version Not Supported Indication",
					"to", addr, "error", writeErr)
			}
			c.log.Warn("GTPv2-C: unsupported version — sent Version Not Supported Indication",
				"from", addr, "version", vnErr.Version)
			return
		}
		// Per TS 29.274 Rel-15 §7.7.3: when the declared GTP Length field exceeds
		// the received UDP payload, send "Invalid Length" cause response for request
		// message types. The peer TEID is unknown (body truncated), so use 0.
		var lenErr *message.ErrInvalidLength
		if errors.As(err, &lenErr) {
			if resp, marshalErr := message.MarshalInvalidLengthResponse(lenErr.Hdr, 0); marshalErr == nil {
				if _, writeErr := c.conn.WriteToUDP(resp, addr); writeErr != nil {
					c.log.Warn("GTPv2-C: failed to send Invalid Length response",
						"to", addr, "error", writeErr)
				}
			}
		}
		c.log.Warn("GTPv2-C invalid header", "from", addr, "error", err)
		return
	}

	if len(frames) > 1 {
		c.log.Info("GTPv2-C piggybacked messages decoded",
			"from", addr, "frames", len(frames),
			"primary_msg_type", frames[0].Header.MessageType,
			"primary_seq", frames[0].Header.SequenceNumber)
	}

	if c.deliverPendingResponseFrame(addr, frames[0], frames[1:]) {
		return
	}
	c.processFrame(addr, frames[0], false)
	for i := 1; i < len(frames); i++ {
		c.processFrame(addr, frames[i], false)
	}
}

func (c *Conn) deliverPendingResponseFrame(addr *net.UDPAddr, frame message.Frame, piggybacks []message.Frame) bool {
	h := frame.Header
	if err := message.ValidateTFlag(h); err != nil {
		c.log.Warn("GTPv2-C T-flag violation — discarding", "from", addr,
			"msg_type", h.MessageType, "has_teid", h.HasTEID, "error", err)
		return true
	}
	if !isResponseType(h.MessageType) {
		return false
	}
	return c.deliverResponse(addr, h.MessageType, h.SequenceNumber, frame.Raw, piggybacks)
}

// DispatchFrames processes frames that were piggybacked on a response delivered
// to a pending transaction. The transaction owner calls this after committing
// any state derived from the primary response.
func (c *Conn) DispatchFrames(addr *net.UDPAddr, frames []message.Frame) {
	for _, frame := range frames {
		c.processFrame(addr, frame, false)
	}
}

func (c *Conn) processFrame(addr *net.UDPAddr, frame message.Frame, allowPendingResponse bool) {
	h := frame.Header

	// Per TS 29.274 §5: enforce T-flag rule (Echo/VersionNotSupported=T=0; EPC messages=T=1).
	// Check BEFORE response delivery so both inbound requests and responses are validated.
	if err := message.ValidateTFlag(h); err != nil {
		c.log.Warn("GTPv2-C T-flag violation — discarding", "from", addr,
			"msg_type", h.MessageType, "has_teid", h.HasTEID, "error", err)
		return
	}

	// If it matches a pending outbound request (by peer addr + seq), deliver it as a response.
	if allowPendingResponse && isResponseType(h.MessageType) && c.deliverResponse(addr, h.MessageType, h.SequenceNumber, frame.Raw, nil) {
		return
	}

	// Per TS 29.274 Rel-15 §7.6.3: atomically check whether this (peer, seq) is
	// cached (retransmit after response), in-flight (concurrent duplicate), or new.
	// The three checks share inboundCacheMu so no duplicate can slip between them.
	key := retransmitKey{addr: addr.String(), seq: h.SequenceNumber, msgType: h.MessageType, teid: h.TEID}
	cached, inFlight := c.checkAndMarkInFlight(key)
	if cached != nil {
		if cachedFrames, err := message.SplitFrames(cached); err == nil && len(cachedFrames) > 1 {
			c.log.Debug("GTPv2-C retransmit — resending cached piggybacked response",
				"from", addr,
				"seq", h.SequenceNumber,
				"msg_type", h.MessageType,
				"cached_frames", len(cachedFrames),
				"primary_msg_type", cachedFrames[0].Header.MessageType,
				"piggyback_msg_type", cachedFrames[1].Header.MessageType,
				"bytes", len(cached),
			)
		} else {
			c.log.Debug("GTPv2-C retransmit — resending cached response",
				"from", addr, "seq", h.SequenceNumber, "msg_type", h.MessageType)
		}
		if _, err := c.conn.WriteToUDP(cached, addr); err != nil {
			c.log.Warn("GTPv2-C retransmit cache send failed", "to", addr, "error", err)
		}
		return
	}
	if inFlight {
		// A concurrent goroutine is already handling this (peer, seq).
		// Drop the duplicate; the in-progress handler will Reply and cache its response.
		c.log.Debug("GTPv2-C concurrent duplicate dropped — handler in progress",
			"from", addr, "seq", h.SequenceNumber, "msg_type", h.MessageType)
		return
	}
	// We marked the key in-flight; clear it when the handler returns.
	defer c.clearInFlight(key)

	hp := c.handler.Load()
	if hp == nil {
		c.log.Warn("GTPv2-C no handler registered", "from", addr, "msg_type", h.MessageType)
		return
	}
	(*hp)(c, addr, h, frame.Raw)
}

func isResponseType(msgType uint8) bool {
	switch msgType {
	case message.MsgTypeEchoResponse,
		message.MsgTypeVersionNotSupported,
		message.MsgTypeCreateSessionResponse,
		message.MsgTypeModifyBearerResponse,
		message.MsgTypeDeleteSessionResponse,
		message.MsgTypeCreateBearerResponse,
		message.MsgTypeUpdateBearerResponse,
		message.MsgTypeDeleteBearerResponse,
		message.MsgTypeReleaseAccessBearersResponse:
		return true
	default:
		return false
	}
}

func (c *Conn) deliverResponse(addr *net.UDPAddr, msgType uint8, seq uint32, raw []byte, piggybacks []message.Frame) bool {
	key := transactionKey{addr: addr.String(), seq: seq, responseType: msgType}
	c.pendingMu.Lock()
	pr, ok := c.pending[key]
	if ok {
		delete(c.pending, key)
	}
	c.pendingMu.Unlock()
	if !ok {
		return false
	}
	pr.result <- pendingResult{raw: raw, piggybacks: piggybacks}
	pr.cancel()
	return true
}

// checkAndMarkInFlight atomically checks the inbound cache and in-flight set under
// a single lock, preventing a concurrent duplicate from racing past both checks.
// Returns (cachedResp, false) if a cached response exists — caller should resend it.
// Returns (nil, true) if a concurrent goroutine is already handling this key.
// Returns (nil, false) if the key is new; it has been marked in-flight for the caller,
// who must call clearInFlight when done.
func (c *Conn) checkAndMarkInFlight(key retransmitKey) (cached []byte, inFlight bool) {
	c.inboundCacheMu.Lock()
	defer c.inboundCacheMu.Unlock()
	if entry, ok := c.inboundCache[key]; ok {
		if !time.Now().After(entry.expires) {
			return entry.raw, false
		}
		delete(c.inboundCache, key)
	}
	if _, ok := c.inFlight[key]; ok {
		return nil, true
	}
	c.inFlight[key] = struct{}{}
	return nil, false
}

// clearInFlight removes the in-flight mark for key after the handler has returned.
func (c *Conn) clearInFlight(key retransmitKey) {
	c.inboundCacheMu.Lock()
	delete(c.inFlight, key)
	c.inboundCacheMu.Unlock()
}

// storeInboundCache saves resp as the cached response for key and sweeps
// entries that have already expired.
func (c *Conn) storeInboundCache(key retransmitKey, resp []byte) {
	c.inboundCacheMu.Lock()
	defer c.inboundCacheMu.Unlock()
	now := time.Now()
	// Sweep expired entries to keep the map bounded.
	for k, v := range c.inboundCache {
		if now.After(v.expires) {
			delete(c.inboundCache, k)
		}
	}
	dst := make([]byte, len(resp))
	copy(dst, resp)
	c.inboundCache[key] = cachedResponse{raw: dst, expires: now.Add(inboundCacheTTL)}
}

// Send transmits a request to addr and waits for the response with T3/N3 retransmission.
// Returns the raw response bytes on success.
func (c *Conn) Send(ctx context.Context, addr *net.UDPAddr, raw []byte) ([]byte, error) {
	resp, _, err := c.SendWithPiggybacks(ctx, addr, raw)
	return resp, err
}

// SendWithPiggybacks transmits a request and returns the primary response plus
// any piggybacked frames that followed it in the same UDP payload. The caller is
// responsible for dispatching the piggybacked frames after committing state from
// the primary response.
func (c *Conn) SendWithPiggybacks(ctx context.Context, addr *net.UDPAddr, raw []byte) ([]byte, []message.Frame, error) {
	reqHdr, err := c.extractHeader(raw)
	if err != nil {
		return nil, nil, err
	}
	respType, ok := message.ResponseTypeFor(reqHdr.MessageType)
	if !ok {
		return nil, nil, fmt.Errorf("GTPv2-C: no response type for request msg_type=%d", reqHdr.MessageType)
	}

	result := make(chan pendingResult, 1)
	tCtx, cancel := context.WithCancel(ctx)
	key := transactionKey{addr: addr.String(), seq: reqHdr.SequenceNumber, responseType: respType}

	c.pendingMu.Lock()
	if _, exists := c.pending[key]; exists {
		c.pendingMu.Unlock()
		cancel()
		return nil, nil, fmt.Errorf("GTPv2-C: duplicate pending transaction addr=%s seq=%d response_type=%d", key.addr, key.seq, key.responseType)
	}
	c.pending[key] = &pendingRequest{addr: addr, raw: raw, result: result, cancel: cancel}
	c.pendingMu.Unlock()

	defer func() {
		cancel()
		c.pendingMu.Lock()
		delete(c.pending, key)
		c.pendingMu.Unlock()
	}()

	for attempt := 0; attempt < c.n3; attempt++ {
		if _, err := c.conn.WriteToUDP(raw, addr); err != nil {
			return nil, nil, fmt.Errorf("GTPv2-C send: %w", err)
		}
		select {
		case res := <-result:
			return res.raw, res.piggybacks, res.err
		case <-tCtx.Done():
			return nil, nil, ctx.Err()
		case <-time.After(c.t3):
			// retransmit
		}
	}
	return nil, nil, fmt.Errorf("GTPv2-C: no response after %d attempts (seq=%d)", c.n3, reqHdr.SequenceNumber)
}

// Reply sends a response to addr and caches it for inbound retransmit detection
// per TS 29.274 Section 7.6.3.
func (c *Conn) Reply(addr *net.UDPAddr, raw []byte) error {
	_, err := c.conn.WriteToUDP(raw, addr)
	if err != nil {
		return err
	}
	// Cache keyed by (peer addr, sequence number from the response).
	// The response sequence number equals the request sequence number per TS 29.274 §5.1.
	if h, _, parseErr := message.ParseHeader(raw); parseErr == nil {
		key := c.inFlightRetransmitKeyForResponse(addr, h)
		c.storeInboundCache(key, raw)
	}
	return nil
}

// AllocSeq allocates the next 24-bit sequence number.
func (c *Conn) AllocSeq() uint32 {
	c.seqMu.Lock()
	defer c.seqMu.Unlock()
	c.seqVal = (c.seqVal + 1) & 0xFFFFFF
	return c.seqVal
}

func (c *Conn) extractHeader(raw []byte) (message.Header, error) {
	h, _, err := message.ParseHeader(raw)
	if err != nil {
		return message.Header{}, err
	}
	return h, nil
}

func (c *Conn) inFlightRetransmitKeyForResponse(addr *net.UDPAddr, h message.Header) retransmitKey {
	reqType, ok := message.RequestTypeForResponse(h.MessageType)
	if !ok {
		return retransmitKey{addr: addr.String(), seq: h.SequenceNumber, msgType: h.MessageType, teid: h.TEID}
	}
	c.inboundCacheMu.Lock()
	defer c.inboundCacheMu.Unlock()
	for key := range c.inFlight {
		if key.addr == addr.String() && key.seq == h.SequenceNumber && key.msgType == reqType {
			return key
		}
	}
	return retransmitKey{addr: addr.String(), seq: h.SequenceNumber, msgType: reqType}
}

// Close shuts down the connection.
func (c *Conn) Close() error {
	return c.conn.Close()
}
