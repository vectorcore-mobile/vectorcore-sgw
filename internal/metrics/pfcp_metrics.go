package metrics

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PFCPMetrics exposes Sxa PFCP association state as Prometheus metrics.
// Metrics are updated by the SGW-C via the peer state callback from pfcpclient.
type PFCPMetrics struct {
	// pfcp_peer_up is 1 when the peer association is Established, 0 when Down.
	peerUp *prometheus.GaugeVec
	// pfcp_peer_restarts_total counts the number of times a peer transitioned Down→Established
	// (i.e., a re-association after failure — approximates peer restart events).
	peerRestarts *prometheus.CounterVec
}

// NewPFCPMetrics creates and registers PFCP peer association metrics.
func NewPFCPMetrics(reg *prometheus.Registry) *PFCPMetrics {
	peerUp := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Name: "pfcp_peer_up",
		Help: "1 if the Sxa PFCP association with the SGW-U peer is Established, 0 if Down.",
	}, []string{"peer_name", "peer_addr"})

	peerRestarts := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "pfcp_peer_restarts_total",
		Help: "Total number of Sxa PFCP peer Down transitions (heartbeat failures or restart detection).",
	}, []string{"peer_name", "peer_addr"})

	reg.MustRegister(peerUp, peerRestarts)
	return &PFCPMetrics{
		peerUp:       peerUp,
		peerRestarts: peerRestarts,
	}
}

// OnPeerStateChange updates the pfcp_peer_up gauge and increments pfcp_peer_restarts_total
// when the state transitions to Down. Intended as the pfcpclient.SetPeerStateCallback target.
//
// peerState must be one of the pfcpclient.PeerState constants; use the string value directly
// to avoid an import cycle.
func (m *PFCPMetrics) OnPeerStateChange(peerName, peerAddr, state string) {
	switch state {
	case "Established":
		m.peerUp.WithLabelValues(peerName, peerAddr).Set(1)
	case "Down":
		m.peerUp.WithLabelValues(peerName, peerAddr).Set(0)
		m.peerRestarts.WithLabelValues(peerName, peerAddr).Inc()
	}
}
