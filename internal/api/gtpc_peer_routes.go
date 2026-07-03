package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/peerhealth"
)

type GTPCPeerHealthReader interface {
	Snapshot() []peerhealth.Snapshot
}

type GTPCPeerView struct {
	Role               string    `json:"role"`
	Addr               string    `json:"addr"`
	State              string    `json:"state"`
	LastStateChange    time.Time `json:"last_state_change,omitempty"`
	LastSeenAt         time.Time `json:"last_seen_at,omitempty"`
	LastMessageType    uint8     `json:"last_message_type,omitempty"`
	LastSequenceNumber uint32    `json:"last_sequence_number,omitempty"`
	LastEchoSentAt     time.Time `json:"last_echo_sent_at,omitempty"`
	LastEchoResponseAt time.Time `json:"last_echo_response_at,omitempty"`
	LastRTTMS          int64     `json:"last_rtt_ms"`
	SmoothedRTTMS      int64     `json:"smoothed_rtt_ms"`
	MaxRTTMS           int64     `json:"max_rtt_ms"`
	ConsecutiveMisses  int       `json:"consecutive_misses"`
	EchoSent           uint64    `json:"echo_sent"`
	EchoResponses      uint64    `json:"echo_responses"`
	EchoTimeouts       uint64    `json:"echo_timeouts"`
	RecoverySeen       bool      `json:"recovery_seen"`
	RecoveryCounter    uint8     `json:"recovery_counter"`
	RestartDetectedAt  time.Time `json:"restart_detected_at,omitempty"`
	Restarts           uint64    `json:"restarts"`
}

type GTPCPeerListOutput struct {
	Body struct {
		Peers []GTPCPeerView `json:"peers"`
		Total int            `json:"total"`
	}
}

func RegisterGTPCPeerRoutes(api huma.API, peers GTPCPeerHealthReader) {
	huma.Register(api, huma.Operation{
		OperationID: "list-gtpc-peers",
		Method:      http.MethodGet,
		Path:        "/gtpc/peers",
		Summary:     "List SGW-C GTPv2-C peer health state",
	}, func(ctx context.Context, _ *struct{}) (*GTPCPeerListOutput, error) {
		out := &GTPCPeerListOutput{}
		if peers == nil {
			return out, nil
		}
		snapshots := peers.Snapshot()
		out.Body.Peers = make([]GTPCPeerView, 0, len(snapshots))
		for _, snap := range snapshots {
			out.Body.Peers = append(out.Body.Peers, gtpcPeerToView(snap))
		}
		out.Body.Total = len(out.Body.Peers)
		return out, nil
	})
}

func gtpcPeerToView(s peerhealth.Snapshot) GTPCPeerView {
	return GTPCPeerView{
		Role:               string(s.Role),
		Addr:               s.Addr,
		State:              string(s.State),
		LastStateChange:    s.LastStateChange,
		LastSeenAt:         s.LastSeenAt,
		LastMessageType:    s.LastMessageType,
		LastSequenceNumber: s.LastSequenceNumber,
		LastEchoSentAt:     s.LastEchoSentAt,
		LastEchoResponseAt: s.LastEchoResponseAt,
		LastRTTMS:          s.LastRTT.Milliseconds(),
		SmoothedRTTMS:      s.SmoothedRTT.Milliseconds(),
		MaxRTTMS:           s.MaxRTT.Milliseconds(),
		ConsecutiveMisses:  s.ConsecutiveMisses,
		EchoSent:           s.EchoSent,
		EchoResponses:      s.EchoResponses,
		EchoTimeouts:       s.EchoTimeouts,
		RecoverySeen:       s.RecoverySeen,
		RecoveryCounter:    s.RecoveryCounter,
		RestartDetectedAt:  s.RestartDetectedAt,
		Restarts:           s.Restarts,
	}
}
