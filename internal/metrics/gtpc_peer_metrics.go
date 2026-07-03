package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/peerhealth"
)

type GTPCPeerHealthReader interface {
	Snapshot() []peerhealth.Snapshot
}

type GTPCPeerMetrics struct {
	peers GTPCPeerHealthReader

	state       *prometheus.Desc
	rtt         *prometheus.Desc
	echoSent    *prometheus.Desc
	echoResp    *prometheus.Desc
	echoTimeout *prometheus.Desc
	restarts    *prometheus.Desc
}

func NewGTPCPeerMetrics(reg *prometheus.Registry, peers GTPCPeerHealthReader) *GTPCPeerMetrics {
	m := &GTPCPeerMetrics{
		peers: peers,
		state: prometheus.NewDesc(
			"sgwc_gtpc_peer_state",
			"SGW-C GTPv2-C peer state as a one-hot gauge.",
			[]string{"role", "peer", "state"},
			nil,
		),
		rtt: prometheus.NewDesc(
			"sgwc_gtpc_peer_echo_rtt_seconds",
			"Last SGW-C GTPv2-C Echo Response RTT in seconds.",
			[]string{"role", "peer"},
			nil,
		),
		echoSent: prometheus.NewDesc(
			"sgwc_gtpc_peer_echo_sent_total",
			"Total SGW-C GTPv2-C Echo Requests sent to the peer.",
			[]string{"role", "peer"},
			nil,
		),
		echoResp: prometheus.NewDesc(
			"sgwc_gtpc_peer_echo_responses_total",
			"Total SGW-C GTPv2-C Echo Responses received from the peer.",
			[]string{"role", "peer"},
			nil,
		),
		echoTimeout: prometheus.NewDesc(
			"sgwc_gtpc_peer_echo_timeouts_total",
			"Total SGW-C GTPv2-C Echo timeouts for the peer.",
			[]string{"role", "peer"},
			nil,
		),
		restarts: prometheus.NewDesc(
			"sgwc_gtpc_peer_restarts_total",
			"Total GTPv2-C peer restart counter changes observed by SGW-C.",
			[]string{"role", "peer"},
			nil,
		),
	}
	if reg != nil {
		reg.MustRegister(m)
	}
	return m
}

func (m *GTPCPeerMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.state
	ch <- m.rtt
	ch <- m.echoSent
	ch <- m.echoResp
	ch <- m.echoTimeout
	ch <- m.restarts
}

func (m *GTPCPeerMetrics) Collect(ch chan<- prometheus.Metric) {
	if m == nil || m.peers == nil {
		return
	}
	for _, snap := range m.peers.Snapshot() {
		role := string(snap.Role)
		peer := snap.Addr
		for _, state := range []peerhealth.State{
			peerhealth.StateUnknown,
			peerhealth.StateUp,
			peerhealth.StateDegraded,
			peerhealth.StateSuspect,
			peerhealth.StateDown,
		} {
			value := 0.0
			if snap.State == state {
				value = 1
			}
			ch <- prometheus.MustNewConstMetric(m.state, prometheus.GaugeValue, value, role, peer, string(state))
		}
		ch <- prometheus.MustNewConstMetric(m.rtt, prometheus.GaugeValue, snap.LastRTT.Seconds(), role, peer)
		ch <- prometheus.MustNewConstMetric(m.echoSent, prometheus.CounterValue, float64(snap.EchoSent), role, peer)
		ch <- prometheus.MustNewConstMetric(m.echoResp, prometheus.CounterValue, float64(snap.EchoResponses), role, peer)
		ch <- prometheus.MustNewConstMetric(m.echoTimeout, prometheus.CounterValue, float64(snap.EchoTimeouts), role, peer)
		ch <- prometheus.MustNewConstMetric(m.restarts, prometheus.CounterValue, float64(snap.Restarts), role, peer)
	}
}
