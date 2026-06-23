// Package transport provides PFCP UDP transport with T1/N1 transaction management
// per 3GPP TS 29.244 Rel-15 §7.6.
//
// Inbound retransmit detection caches responses keyed by (peer addr, seq number)
// per §7.6. Outbound requests are retransmitted up to N1 times with T1 interval.
package transport

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"vectorcore-sgw/internal/pfcp/message"
)

// inboundCacheTTL is how long a server-side response is cached for retransmit
// detection per TS 29.244 §7.6. Sized to outlast a T1*N1 window.
const inboundCacheTTL = 30 * time.Second

// Handler is called when an inbound PFCP request arrives.
// The implementation must call conn.Reply before returning.
type Handler func(conn *Conn, addr *net.UDPAddr, hdr message.Header, raw []byte)

type retransmitKey struct {
	addr string // "ip:port"
	seq  uint32
}

type cachedResponse struct {
	raw     []byte
	expires time.Time
}

// transactionKey identifies a pending PFCP transaction by peer address and sequence
// number. Sequence number alone is insufficient when one socket serves multiple SGW-U
// peers — a late response from one peer could resolve a pending request to another.
type transactionKey struct {
	addr string // "ip:port" of the peer
	seq  uint32
}

// Conn is a PFCP UDP endpoint with T1/N1 transaction management.
type Conn struct {
	conn *net.UDPConn
	log  *slog.Logger
	t1   time.Duration // T1 retransmit timer per TS 29.244 §7.6
	n1   int           // N1 retransmit count

	seqMu  sync.Mutex
	seqVal uint32 // 24-bit sequence counter

	pendingMu sync.Mutex
	pending   map[transactionKey]*pendingRequest

	inboundCacheMu sync.Mutex
	inboundCache   map[retransmitKey]cachedResponse
	inFlight       map[retransmitKey]struct{}

	handler atomic.Pointer[Handler]

	// dispatchSem limits concurrent inbound packet goroutines (AUD-11).
	dispatchSem chan struct{}
}

type pendingRequest struct {
	addr   *net.UDPAddr // peer address this request was sent to
	raw    []byte
	result chan pendingResult
	cancel context.CancelFunc
}

type pendingResult struct {
	raw []byte
	err error
}

// Listen creates a PFCP UDP listener on addr with T1/N1 retransmit parameters.
func Listen(addr string, t1Seconds, n1 int, log *slog.Logger) (*Conn, error) {
	ua, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		return nil, fmt.Errorf("PFCP resolve %q: %w", addr, err)
	}
	uc, err := net.ListenUDP("udp4", ua)
	if err != nil {
		return nil, fmt.Errorf("PFCP listen %s: %w", addr, err)
	}
	return &Conn{
		conn:         uc,
		log:          log,
		t1:           time.Duration(t1Seconds) * time.Second,
		n1:           n1,
		pending:      make(map[transactionKey]*pendingRequest),
		inboundCache: make(map[retransmitKey]cachedResponse),
		inFlight:     make(map[retransmitKey]struct{}),
		dispatchSem:  make(chan struct{}, 4096), // AUD-11: cap concurrent dispatches
	}, nil
}

// SetHandler registers the inbound request handler.
func (c *Conn) SetHandler(h Handler) {
	c.handler.Store(&h)
}

// LocalAddr returns the local UDP address.
func (c *Conn) LocalAddr() net.Addr {
	return c.conn.LocalAddr()
}

// Serve reads incoming packets and dispatches them until ctx is cancelled.
// Per C9: must be running before any Send() calls can receive responses.
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
			return fmt.Errorf("PFCP read: %w", err)
		}
		pkt := make([]byte, n)
		copy(pkt, buf[:n])
		// AUD-11: non-blocking acquire; drop if semaphore is full.
		select {
		case c.dispatchSem <- struct{}{}:
			go func() {
				defer func() { <-c.dispatchSem }()
				c.dispatch(addr, pkt)
			}()
		default:
			c.log.Warn("PFCP dispatch overload — packet dropped", "from", addr)
		}
	}
}

func (c *Conn) dispatch(addr *net.UDPAddr, raw []byte) {
	h, _, err := message.ParseHeader(raw)
	if err != nil {
		c.log.Warn("PFCP invalid header", "from", addr, "error", err)
		return
	}

	// Deliver to pending outbound transaction if (peer addr, seq) matches.
	if c.deliverResponse(addr, h.SequenceNumber, raw) {
		return
	}

	// Inbound request: retransmit detection per TS 29.244 §7.6.
	key := retransmitKey{addr: addr.String(), seq: h.SequenceNumber}
	cached, inFlight := c.checkAndMarkInFlight(key)
	if cached != nil {
		c.log.Debug("PFCP retransmit — resending cached response",
			"from", addr, "seq", h.SequenceNumber, "msg_type", h.MessageType)
		_, _ = c.conn.WriteToUDP(cached, addr)
		return
	}
	if inFlight {
		c.log.Debug("PFCP concurrent duplicate dropped",
			"from", addr, "seq", h.SequenceNumber)
		return
	}
	defer c.clearInFlight(key)

	hp := c.handler.Load()
	if hp == nil {
		c.log.Warn("PFCP no handler registered", "from", addr, "msg_type", h.MessageType)
		return
	}
	(*hp)(c, addr, h, raw)
}

func (c *Conn) deliverResponse(addr *net.UDPAddr, seq uint32, raw []byte) bool {
	key := transactionKey{addr: addr.String(), seq: seq}
	c.pendingMu.Lock()
	pr, ok := c.pending[key]
	if ok {
		delete(c.pending, key)
	}
	c.pendingMu.Unlock()
	if !ok {
		return false
	}
	pr.cancel()
	pr.result <- pendingResult{raw: raw}
	return true
}

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

func (c *Conn) clearInFlight(key retransmitKey) {
	c.inboundCacheMu.Lock()
	delete(c.inFlight, key)
	c.inboundCacheMu.Unlock()
}

func (c *Conn) storeInboundCache(key retransmitKey, resp []byte) {
	c.inboundCacheMu.Lock()
	defer c.inboundCacheMu.Unlock()
	now := time.Now()
	for k, v := range c.inboundCache {
		if now.After(v.expires) {
			delete(c.inboundCache, k)
		}
	}
	dst := make([]byte, len(resp))
	copy(dst, resp)
	c.inboundCache[key] = cachedResponse{raw: dst, expires: now.Add(inboundCacheTTL)}
}

// Send transmits a PFCP request to addr and waits for the response with T1/N1
// retransmission per TS 29.244 §7.6.
// The conn.Serve goroutine must be running before any call to Send (C9).
func (c *Conn) Send(ctx context.Context, addr *net.UDPAddr, raw []byte) ([]byte, error) {
	seq, err := c.extractSeq(raw)
	if err != nil {
		return nil, err
	}
	result := make(chan pendingResult, 1)
	tCtx, cancel := context.WithCancel(ctx)
	key := transactionKey{addr: addr.String(), seq: seq}
	c.pendingMu.Lock()
	c.pending[key] = &pendingRequest{addr: addr, raw: raw, result: result, cancel: cancel}
	c.pendingMu.Unlock()
	defer func() {
		cancel()
		c.pendingMu.Lock()
		delete(c.pending, key)
		c.pendingMu.Unlock()
	}()
	for attempt := 0; attempt < c.n1; attempt++ {
		if _, err := c.conn.WriteToUDP(raw, addr); err != nil {
			return nil, fmt.Errorf("PFCP send: %w", err)
		}
		select {
		case res := <-result:
			return res.raw, res.err
		case <-tCtx.Done():
			return nil, ctx.Err()
		case <-time.After(c.t1):
			// retransmit
		}
	}
	return nil, fmt.Errorf("PFCP: no response after %d attempts (seq=%d)", c.n1, seq)
}

// Reply sends a response and caches it for inbound retransmit detection.
func (c *Conn) Reply(addr *net.UDPAddr, raw []byte) error {
	if _, err := c.conn.WriteToUDP(raw, addr); err != nil {
		return err
	}
	if h, _, parseErr := message.ParseHeader(raw); parseErr == nil {
		key := retransmitKey{addr: addr.String(), seq: h.SequenceNumber}
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

func (c *Conn) extractSeq(raw []byte) (uint32, error) {
	h, _, err := message.ParseHeader(raw)
	if err != nil {
		return 0, err
	}
	return h.SequenceNumber, nil
}

// Close shuts down the PFCP transport.
func (c *Conn) Close() error {
	return c.conn.Close()
}
