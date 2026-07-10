package api

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"reflect"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/dataplane/bpf"
	"vectorcore-sgw/internal/sgwu/gtpu"
	"vectorcore-sgw/internal/sgwu/pfcpserver"
	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

type sgwuPFCPAssociationReader interface {
	Peers() []pfcpserver.PeerView
}

type bpfRuleReader interface {
	Rules() ([]bpf.RuleEntry, error)
}

type gtpuCounterReader interface {
	Counters() gtpu.Counters
}

// PDRView is the API representation of a PFCP Packet Detection Rule
// per TS 29.244 Rel-15 §5.2.1.
type PDRView struct {
	ID              uint16 `json:"id"`
	Precedence      uint32 `json:"precedence"`
	SourceInterface uint8  `json:"source_interface"`
	LocalTEID       string `json:"local_teid"`
	LocalIP         string `json:"local_ip"`
	FARID           uint32 `json:"far_id"`
}

// FARView is the API representation of a PFCP Forwarding Action Rule
// per TS 29.244 Rel-15 §5.2.1.
type FARView struct {
	ID            uint32 `json:"id"`
	ApplyAction   uint8  `json:"apply_action"`
	DestInterface uint8  `json:"dest_interface"`
	OuterTEID     string `json:"outer_teid"`
	OuterIP       string `json:"outer_ip"`
}

// PFCPSessionView is the API representation of an SGW-U PFCP session.
type PFCPSessionView struct {
	CPSEID    string    `json:"cp_seid"`
	UPSEID    string    `json:"up_seid"`
	CPNodeKey string    `json:"cp_node_key"`
	PDRs      []PDRView `json:"pdrs"`
	FARs      []FARView `json:"fars"`
	QERs      []QERView `json:"qers"`
}

// QERView is reserved for PFCP QoS Enforcement Rule state per TS 29.244
// Rel-15 §5.2.1. The current SGW-U session model does not create QERs yet, so
// Phase 9 returns an explicit empty list instead of omitting the field.
type QERView struct {
	ID uint32 `json:"id"`
}

// PFCPSessionListOutput is the API response for the SGW-U session debug endpoint.
type PFCPSessionListOutput struct {
	Body struct {
		Sessions []PFCPSessionView `json:"sessions"`
		Total    int               `json:"total"`
	}
}

// SGWUPFCPAssociationsOutput is the API response for SGW-U-side PFCP
// association state with SGW-C peers.
type SGWUPFCPAssociationsOutput struct {
	Body struct {
		Peers []pfcpserver.PeerView `json:"peers"`
		Total int                   `json:"total"`
	}
}

// BPFRuleView is the API representation of one BPF forwarding rule from
// sgw_fwd_map, joined with its sgw_rule_stats counters.
type BPFRuleView struct {
	TEID          string `json:"teid"`
	Ifindex       uint32 `json:"ifindex"`
	Ifname        string `json:"ifname,omitempty"`
	Action        string `json:"action"`
	EgressIfindex uint32 `json:"egress_ifindex"`
	EgressIfname  string `json:"egress_ifname,omitempty"`
	OuterSrcIP    string `json:"outer_src_ip"`
	OuterDstIP    string `json:"outer_dst_ip"`
	NewTEID       string `json:"new_teid"`
	CounterID     uint32 `json:"counter_id"`
	Packets       uint64 `json:"packets"`
	Bytes         uint64 `json:"bytes"`
	StatsRecorded bool   `json:"stats_recorded"`
}

// BPFRuleListOutput is the API response for the SGW-U BPF rule-state debug endpoint.
type BPFRuleListOutput struct {
	Body struct {
		Dataplane string        `json:"dataplane" doc:"SGW-U dataplane implementation"`
		Attached  bool          `json:"attached" doc:"true when eBPF maps are attached and readable"`
		Rules     []BPFRuleView `json:"rules"`
		Total     int           `json:"total"`
	}
}

type GTPUCountersOutput struct {
	Body struct {
		RxPackets    uint64 `json:"rx_packets"`
		TxPackets    uint64 `json:"tx_packets"`
		RxBytes      uint64 `json:"rx_bytes"`
		TxBytes      uint64 `json:"tx_bytes"`
		UnknownTEID  uint64 `json:"unknown_teid"`
		Dropped      uint64 `json:"dropped"`
		IdleDownlink uint64 `json:"idle_downlink"`
	}
}

// RegisterSGWURoutes adds SGW-U PFCP session and BPF rule-state debug routes
// to the Huma API. dp is nil when eBPF is not attached yet; the BPF rules
// endpoint then returns an empty list with attached=false.
//
// This closes two previously-unmet acceptance criteria: Phase 5's "Debug API
// showing PDRs/FARs/QERs" (QERs are not yet modeled in internal/sgwu/session
// — Phase 5/9 deliverable scope; nothing to show there yet) and Phase 8's
// "SGW-U API shows PFCP/BPF rule state".
func RegisterSGWURoutes(api huma.API, store *sgwusession.Store, assoc sgwuPFCPAssociationReader, dp bpfRuleReader, gtpu gtpuCounterReader) {
	huma.Register(api, huma.Operation{
		OperationID: "list-sgwu-pfcp-associations",
		Method:      http.MethodGet,
		Path:        "/pfcp/associations",
		Summary:     "List SGW-U PFCP association state with SGW-C peers",
	}, func(ctx context.Context, _ *struct{}) (*SGWUPFCPAssociationsOutput, error) {
		out := &SGWUPFCPAssociationsOutput{}
		if assoc == nil {
			out.Body.Peers = []pfcpserver.PeerView{}
			return out, nil
		}
		out.Body.Peers = assoc.Peers()
		out.Body.Total = len(out.Body.Peers)
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-pfcp-sessions",
		Method:      http.MethodGet,
		Path:        "/sessions",
		Summary:     "List all SGW-U PFCP sessions with PDR/FAR state",
	}, func(ctx context.Context, _ *struct{}) (*PFCPSessionListOutput, error) {
		sessions := store.All()
		out := &PFCPSessionListOutput{}
		out.Body.Total = len(sessions)
		out.Body.Sessions = make([]PFCPSessionView, 0, len(sessions))
		for _, sess := range sessions {
			out.Body.Sessions = append(out.Body.Sessions, pfcpSessionToView(sess))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "list-bpf-rules",
		Method:      http.MethodGet,
		Path:        "/bpf/rules",
		Summary:     "List eBPF forwarding rules and per-rule counters",
	}, func(ctx context.Context, _ *struct{}) (*BPFRuleListOutput, error) {
		out := &BPFRuleListOutput{}
		out.Body.Dataplane = "ebpf"
		if isNilBPFRuleReader(dp) {
			out.Body.Attached = false
			out.Body.Rules = []BPFRuleView{}
			return out, nil
		}
		out.Body.Attached = true
		rules, err := dp.Rules()
		if err != nil {
			return nil, huma.Error500InternalServerError("failed to read BPF rules", err)
		}
		out.Body.Total = len(rules)
		out.Body.Rules = make([]BPFRuleView, 0, len(rules))
		for _, r := range rules {
			out.Body.Rules = append(out.Body.Rules, bpfRuleToView(r))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-gtpu-counters",
		Method:      http.MethodGet,
		Path:        "/gtpu/counters",
		Summary:     "Get SGW-U GTP-U userspace counters",
	}, func(ctx context.Context, _ *struct{}) (*GTPUCountersOutput, error) {
		out := &GTPUCountersOutput{}
		if gtpu == nil {
			return out, nil
		}
		counters := gtpu.Counters()
		out.Body.RxPackets = counters.RxPackets
		out.Body.TxPackets = counters.TxPackets
		out.Body.RxBytes = counters.RxBytes
		out.Body.TxBytes = counters.TxBytes
		out.Body.UnknownTEID = counters.UnknownTEID
		out.Body.Dropped = counters.Dropped
		out.Body.IdleDownlink = counters.IdleDownlink
		return out, nil
	})
}

func isNilBPFRuleReader(dp bpfRuleReader) bool {
	if dp == nil {
		return true
	}
	v := reflect.ValueOf(dp)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

func pfcpSessionToView(sess *sgwusession.Session) PFCPSessionView {
	sess.Mu.RLock()
	defer sess.Mu.RUnlock()

	pdrs := make([]PDRView, 0, len(sess.PDRs))
	for _, p := range sess.PDRs {
		pdrs = append(pdrs, PDRView{
			ID:              p.ID,
			Precedence:      p.Precedence,
			SourceInterface: p.SourceInterface,
			LocalTEID:       fmt.Sprintf("0x%08X", p.LocalTEID),
			LocalIP:         p.LocalIP.String(),
			FARID:           p.FARID,
		})
	}
	fars := make([]FARView, 0, len(sess.FARs))
	for _, f := range sess.FARs {
		fars = append(fars, FARView{
			ID:            f.ID,
			ApplyAction:   f.ApplyAction,
			DestInterface: f.DestInterface,
			OuterTEID:     fmt.Sprintf("0x%08X", f.OuterTEID),
			OuterIP:       f.OuterIP.String(),
		})
	}
	return PFCPSessionView{
		CPSEID:    fmt.Sprintf("0x%016X", sess.CPSEID),
		UPSEID:    fmt.Sprintf("0x%016X", sess.UPSEID),
		CPNodeKey: sess.CPNodeKey,
		PDRs:      pdrs,
		FARs:      fars,
		QERs:      []QERView{},
	}
}

func bpfRuleToView(r bpf.RuleEntry) BPFRuleView {
	v := BPFRuleView{
		TEID:          fmt.Sprintf("0x%08X", r.Key.Teid),
		Ifindex:       r.Key.Ifindex,
		Action:        bpf.ActionName(r.Value.Action),
		EgressIfindex: r.Value.EgressIfindex,
		OuterSrcIP:    net.IP(r.Value.OuterSrcIp[:]).String(),
		OuterDstIP:    net.IP(r.Value.OuterDstIp[:]).String(),
		NewTEID:       fmt.Sprintf("0x%08X", r.Value.NewTeid),
		CounterID:     r.Value.CounterId,
		Packets:       r.Packets,
		Bytes:         r.Bytes,
		StatsRecorded: r.StatsRecorded,
	}
	if iface, err := net.InterfaceByIndex(int(r.Key.Ifindex)); err == nil {
		v.Ifname = iface.Name
	}
	if iface, err := net.InterfaceByIndex(int(r.Value.EgressIfindex)); err == nil {
		v.EgressIfname = iface.Name
	}
	return v
}
