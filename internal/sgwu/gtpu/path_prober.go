package gtpu

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"
)

// N3RequestsDefault is the recommended N3-REQUESTS retry limit per TS 29.281 §12.3:
// "The counter N3-REQUESTS holds the maximum number of attempts made by GTP to send a
// request message. The recommended value is 5."
const N3RequestsDefault = 5

// EchoMinInterval is the minimum allowed probe interval per TS 29.281 §7.2.1:
// "an Echo Request shall not be sent more often than every 60 s on each path."
const EchoMinInterval = 60 * time.Second

// T3ResponseDefault is the default per-retry wait (T3-RESPONSE) per TS 29.281 §12.2:
// "The timer T3-RESPONSE holds the maximum wait time for a response of a request message."
// The spec specifies no mandatory value; 5 s is a common implementation choice.
const T3ResponseDefault = 5 * time.Second

// PathProber sends GTP-U Echo Requests to monitored peers and detects path failures.
//
// It implements the T3-RESPONSE/N3-REQUESTS signalling reliability rules per
// TS 29.281 §11 and §12:
//   - A new probe round starts at probeInterval (≥ EchoMinInterval per §7.2.1).
//   - Within a round, up to N3Requests Echo Requests are sent, spaced T3Response apart,
//     all carrying the same Sequence Number per §4.3.1:
//     "This doesn't prevent resending an Echo Request with the same sequence number
//     according to the T3-RESPONSE timer."
//   - If no Echo Response arrives before N3Requests retries are exhausted, PathFailed is called.
//   - When a response subsequently arrives for a failed path, PathRecovered is called.
type PathProber struct {
	conn          *net.UDPConn
	probeInterval time.Duration // interval between rounds; enforced ≥ EchoMinInterval
	t3Response    time.Duration // T3-RESPONSE: wait between retries per §12.2
	n3Requests    int           // N3-REQUESTS: max retries per round per §12.3

	log *slog.Logger

	mu     sync.Mutex
	paths  map[netip.Addr]*pathEntry
	seqGen atomic.Uint32

	// port is the destination UDP port for Echo Requests; defaults to Port (2152).
	// Overridable in tests within the same package.
	port int

	// PathFailed is called once when N3-REQUESTS retries are exhausted without a response.
	// May be nil. Called from a new goroutine.
	PathFailed func(peer netip.Addr)

	// PathRecovered is called when a path that was failed receives a response.
	// May be nil. Called from a new goroutine.
	PathRecovered func(peer netip.Addr)
}

// pathEntry tracks the T3-RESPONSE/N3-REQUESTS probe state for one GTP-U path.
type pathEntry struct {
	roundSeq       uint16    // Sequence Number for the current round per §4.3.1
	roundSent      int       // Echo Requests sent this round (0 = between rounds)
	roundResponded bool      // received matching Echo Response this round
	failed         bool      // path is currently declared failed
	nextAction     time.Time // when to take the next action (zero value → immediately)
}

// NewPathProber creates a PathProber that sends Echo Requests via conn.
// conn should be the same socket as the Forwarder so responses arrive on the same port.
// probeInterval is clamped to ≥ EchoMinInterval per TS 29.281 §7.2.1.
// n3Requests defaults to N3RequestsDefault if ≤ 0.
func NewPathProber(
	conn *net.UDPConn,
	probeInterval, t3Response time.Duration,
	n3Requests int,
	log *slog.Logger,
) *PathProber {
	if probeInterval < EchoMinInterval {
		probeInterval = EchoMinInterval
	}
	if t3Response <= 0 {
		t3Response = T3ResponseDefault
	}
	if n3Requests <= 0 {
		n3Requests = N3RequestsDefault
	}
	return &PathProber{
		conn:          conn,
		probeInterval: probeInterval,
		t3Response:    t3Response,
		n3Requests:    n3Requests,
		log:           log,
		paths:         make(map[netip.Addr]*pathEntry),
		port:          Port,
	}
}

// Add registers a GTP-U peer for periodic path probing. Idempotent.
func (p *PathProber) Add(peer netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.paths[peer]; !ok {
		// zero nextAction → probed immediately on the first tick
		p.paths[peer] = &pathEntry{}
	}
}

// Remove deregisters a GTP-U peer. Idempotent.
func (p *PathProber) Remove(peer netip.Addr) {
	p.mu.Lock()
	defer p.mu.Unlock()
	delete(p.paths, peer)
}

// RecordEchoResponse records an Echo Response received from peer with the given Sequence Number.
// Called by the Forwarder when it receives a MsgTypeEchoResponse.
// Per §4.3.1: "The Sequence Number in a signalling response message shall be copied from
// the signalling request message that the GTP-U entity is replying to."
func (p *PathProber) RecordEchoResponse(peer netip.Addr, seq uint16) {
	p.mu.Lock()
	e, ok := p.paths[peer]
	if !ok || e.roundSent == 0 || e.roundSeq != seq {
		p.mu.Unlock()
		return
	}
	e.roundResponded = true
	wasFailedBefore := e.failed
	if wasFailedBefore {
		// Immediate recovery notification — don't wait for the next tick.
		e.failed = false
		p.mu.Unlock()
		p.log.Info("GTP-U: path recovered", "peer", peer)
		if p.PathRecovered != nil {
			go p.PathRecovered(peer)
		}
		return
	}
	p.mu.Unlock()
}

// Serve runs the path prober until ctx is cancelled.
// Ticks at t3Response granularity; starts new rounds at probeInterval.
func (p *PathProber) Serve(ctx context.Context) error {
	ticker := time.NewTicker(p.t3Response)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case now := <-ticker.C:
			p.tick(now)
		}
	}
}

// tick advances the state machine for every monitored path.
// Called every t3Response. Can be called with an explicit time.Time value for testing.
func (p *PathProber) tick(now time.Time) {
	p.mu.Lock()
	defer p.mu.Unlock()

	for peer, e := range p.paths {
		if now.Before(e.nextAction) {
			continue
		}

		switch {
		case e.roundSent == 0:
			// WAITING → start a new probe round with a fresh Sequence Number.
			e.roundSeq = p.nextSeqLocked()
			e.roundSent = 1
			e.roundResponded = false
			e.nextAction = now.Add(p.t3Response)
			p.sendEchoLocked(peer, e.roundSeq)

		case e.roundResponded:
			// SUCCESS → round complete; schedule next round.
			e.roundSent = 0
			e.nextAction = now.Add(p.probeInterval)

		case e.roundSent < p.n3Requests:
			// PROBING → retransmit with the same Sequence Number per §11 / §4.3.1.
			e.roundSent++
			e.nextAction = now.Add(p.t3Response)
			p.sendEchoLocked(peer, e.roundSeq)

		default:
			// N3-REQUESTS exhausted without response — path failed.
			if !e.failed {
				e.failed = true
				peer := peer
				p.log.Warn("GTP-U: path failure — N3-REQUESTS exhausted",
					"peer", peer,
					"retries", e.roundSent,
				)
				if p.PathFailed != nil {
					go p.PathFailed(peer)
				}
			}
			// Wait probeInterval before trying again; recovery detected via RecordEchoResponse.
			e.roundSent = 0
			e.nextAction = now.Add(p.probeInterval)
		}
	}
}

// nextSeqLocked returns the next GTP-U Sequence Number, wrapping at 65535.
// Must be called with p.mu held.
func (p *PathProber) nextSeqLocked() uint16 {
	return uint16(p.seqGen.Add(1) & 0xFFFF)
}

// sendEchoLocked sends a GTP-U Echo Request to peer:port with the given Sequence Number.
// Must be called with p.mu held.
// Per §5.1: S=1, TEID=0 for Echo Request.
// Per §7.2.1: MsgType=1 (Table 6.1-1: "1 | Echo Request | GTP-U: X").
func (p *PathProber) sendEchoLocked(peer netip.Addr, seq uint16) {
	hdr := Header{
		Version: 1,
		PT:      true,
		S:       true,               // §5.1: "For the Echo Request...S flag shall be set to '1'"
		MsgType: MsgTypeEchoRequest, // Table 6.1-1: "1 | Echo Request | GTP-U: X"
		TEID:    0,                  // §5.1: TEID=0 for Echo Request
		SeqNum:  seq,
	}
	pkt := Marshal(hdr, 0)
	a4 := peer.As4()
	dst := &net.UDPAddr{IP: a4[:], Port: p.port}
	if _, err := p.conn.WriteToUDP(pkt, dst); err != nil {
		p.log.Warn("GTP-U: Echo Request send failed", "peer", peer, "seq", seq, "error", err)
	}
}

// PathProberGroup broadcasts peer tracking to a set of per-socket probers.
type PathProberGroup struct {
	probers []*PathProber
}

func NewPathProberGroup(probers ...*PathProber) *PathProberGroup {
	return &PathProberGroup{probers: append([]*PathProber(nil), probers...)}
}

func (g *PathProberGroup) Add(peer netip.Addr) {
	if !peer.IsValid() || !peer.Is4() {
		return
	}
	for _, p := range g.probers {
		p.Add(peer)
	}
}

func (g *PathProberGroup) Serve(ctx context.Context) error {
	errCh := make(chan error, len(g.probers))
	var wg sync.WaitGroup
	for _, prober := range g.probers {
		wg.Add(1)
		go func(p *PathProber) {
			defer wg.Done()
			errCh <- p.Serve(ctx)
		}(prober)
	}
	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()
	select {
	case <-ctx.Done():
		<-done
		return nil
	case err := <-errCh:
		if err != nil {
			return err
		}
		<-done
		return nil
	}
}
