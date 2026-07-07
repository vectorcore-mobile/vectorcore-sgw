package gtpu

import (
	"context"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

// Endpoint describes one local GTP-U socket.
type Endpoint struct {
	Listen  string
	LocalIP netip.Addr
}

// ForwarderGroup owns one or more GTP-U sockets, typically S1-U and S5/S8-U.
type ForwarderGroup struct {
	forwarders []*Forwarder
}

// NewGroup creates one Forwarder per unique listen address.
func NewGroup(endpoints []Endpoint, store *sgwusession.Store, log *slog.Logger) (*ForwarderGroup, error) {
	seen := make(map[string]bool, len(endpoints))
	var forwarders []*Forwarder
	for _, ep := range endpoints {
		if ep.Listen == "" || seen[ep.Listen] {
			continue
		}
		seen[ep.Listen] = true
		fwd, err := New(ep.Listen, ep.LocalIP, store, log)
		if err != nil {
			for _, existing := range forwarders {
				_ = existing.Close()
			}
			return nil, err
		}
		forwarders = append(forwarders, fwd)
	}
	if len(forwarders) == 0 {
		return nil, fmt.Errorf("gtpu: no listen endpoints configured")
	}
	return &ForwarderGroup{forwarders: forwarders}, nil
}

// Forwarders returns the group's underlying sockets.
func (g *ForwarderGroup) Forwarders() []*Forwarder {
	return append([]*Forwarder(nil), g.forwarders...)
}

// Serve runs every forwarder until ctx is cancelled or a socket returns an error.
func (g *ForwarderGroup) Serve(ctx context.Context) error {
	errCh := make(chan error, len(g.forwarders))
	var wg sync.WaitGroup
	for _, fwd := range g.forwarders {
		wg.Add(1)
		go func(f *Forwarder) {
			defer wg.Done()
			errCh <- f.Serve(ctx)
		}(fwd)
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
			_ = g.Close()
			<-done
			return err
		}
		<-done
		return nil
	}
}

// Close closes every GTP-U socket in the group.
func (g *ForwarderGroup) Close() error {
	var first error
	for _, fwd := range g.forwarders {
		if err := fwd.Close(); err != nil && first == nil {
			first = err
		}
	}
	return first
}

// SendEndMarker sends via the first socket. End Marker destination routing is
// still determined by the kernel route table for dstIP.
func (g *ForwarderGroup) SendEndMarker(teid uint32, dstIP netip.Addr) {
	if len(g.forwarders) == 0 {
		return
	}
	g.forwarders[0].SendEndMarker(teid, dstIP)
}
