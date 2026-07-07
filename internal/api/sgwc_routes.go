package api

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

// BearerView is the API representation of one EPS bearer per TS 23.401 §4.7.
type BearerView struct {
	EBI                     uint8  `json:"ebi"`
	QCI                     uint8  `json:"qci"`
	ARPPriorityLevel        uint8  `json:"arp_priority_level"`
	ARPPreemptionCapability bool   `json:"arp_preemption_capability"`
	ARPPreemptionVulnerable bool   `json:"arp_preemption_vulnerable"`
	State                   string `json:"state"`
	Type                    string `json:"type"`
	ENBS1UTEID              string `json:"enb_s1u_teid"`
	SGWS1UTEID              string `json:"sgw_s1u_teid"`
	PGWS5UTEID              string `json:"pgw_s5u_teid"`
	SGWS5UTEID              string `json:"sgw_s5u_teid"`
	UplinkPDRID             uint32 `json:"uplink_pdr_id"`
	DownlinkPDRID           uint32 `json:"downlink_pdr_id"`
	UplinkFARID             uint32 `json:"uplink_far_id"`
	DownlinkFARID           uint32 `json:"downlink_far_id"`
	MBRUplink               uint64 `json:"mbr_uplink_kbps"`
	MBRDownlink             uint64 `json:"mbr_downlink_kbps"`
	GBRUplink               uint64 `json:"gbr_uplink_kbps"`
	GBRDownlink             uint64 `json:"gbr_downlink_kbps"`
}

// SecondaryRATUsageReportView is a compact API view of an NSA/DCNR usage report
// received in a GTPv2-C Secondary RAT Usage Data Report IE.
type SecondaryRATUsageReportView struct {
	ReceivedAt      time.Time `json:"received_at"`
	SourceProcedure string    `json:"source_procedure"`
	MMEPeer         string    `json:"mme_peer,omitempty"`
	SGWS11TEID      string    `json:"sgw_s11_teid"`
	SequenceNumber  string    `json:"sequence_number"`
	PayloadLength   int       `json:"payload_length"`
}

type PGWFailureView struct {
	PathState         string    `json:"path_state"`
	PGWAddr           string    `json:"pgw_addr,omitempty"`
	PathDownAt        time.Time `json:"path_down_at,omitempty"`
	RestartDetectedAt time.Time `json:"restart_detected_at,omitempty"`
	RecoverySeen      bool      `json:"recovery_seen"`
	RecoveryCounter   uint8     `json:"recovery_counter"`
}

type MMERestorationView struct {
	State               string    `json:"state"`
	MMEAddr             string    `json:"mme_addr,omitempty"`
	PathDownAt          time.Time `json:"path_down_at,omitempty"`
	RestartDetectedAt   time.Time `json:"restart_detected_at,omitempty"`
	RecoverySeen        bool      `json:"recovery_seen"`
	RecoveryCounter     uint8     `json:"recovery_counter"`
	RestorationPending  bool      `json:"restoration_pending"`
	PolicyAction        string    `json:"policy_action,omitempty"`
	PolicyReason        string    `json:"policy_reason,omitempty"`
	DDNTriggered        bool      `json:"ddn_triggered"`
	DDNTriggeredAt      time.Time `json:"ddn_triggered_at,omitempty"`
	DDNSequence         string    `json:"ddn_sequence,omitempty"`
	DDNAcked            bool      `json:"ddn_acked"`
	DDNAckedAt          time.Time `json:"ddn_acked_at,omitempty"`
	DDNAckCause         uint8     `json:"ddn_ack_cause,omitempty"`
	DDNFailureAt        time.Time `json:"ddn_failure_at,omitempty"`
	DDNFailureCause     uint8     `json:"ddn_failure_cause,omitempty"`
	DDNFailureReason    string    `json:"ddn_failure_reason,omitempty"`
	StopPagingSent      bool      `json:"stop_paging_sent"`
	StopPagingSentAt    time.Time `json:"stop_paging_sent_at,omitempty"`
	StopPagingSequence  string    `json:"stop_paging_sequence,omitempty"`
	UserPlaneRestored   bool      `json:"user_plane_restored"`
	UserPlaneRestoredAt time.Time `json:"user_plane_restored_at,omitempty"`
	RestoredEBI         uint8     `json:"restored_ebi,omitempty"`
}

// SessionView is the API representation of an SGW-C session.
type SessionView struct {
	SessionID                    string                        `json:"session_id"`
	IMSI                         string                        `json:"imsi"`
	APN                          string                        `json:"apn"`
	RATType                      uint8                         `json:"rat_type"`
	ServingNetwork               string                        `json:"serving_network"`
	State                        string                        `json:"state"`
	PFCPState                    string                        `json:"pfcp_state"`
	PFCPLocalSEID                string                        `json:"pfcp_local_seid"`
	PFCPUPSEID                   string                        `json:"pfcp_up_seid"`
	PFCPSGWUName                 string                        `json:"pfcp_sgwu_name,omitempty"`
	PFCPSGWUAddr                 string                        `json:"pfcp_sgwu_addr,omitempty"`
	SGWS11TEID                   string                        `json:"sgw_s11_teid"`
	MMEControlTEID               string                        `json:"mme_control_teid"`
	BearerCount                  int                           `json:"bearer_count"`
	Bearers                      []BearerView                  `json:"bearers"`
	SecondaryRATUsageReportCount int                           `json:"secondary_rat_usage_report_count"`
	SecondaryRATUsageDataReports []SecondaryRATUsageReportView `json:"secondary_rat_usage_data_reports"`
	PGWFailure                   PGWFailureView                `json:"pgw_failure"`
	MMERestoration               MMERestorationView            `json:"mme_restoration"`
	CreatedAt                    time.Time                     `json:"created_at"`
	UpdatedAt                    time.Time                     `json:"updated_at"`
}

type SessionListOutput struct {
	Body struct {
		Sessions []SessionView `json:"sessions"`
		Total    int           `json:"total"`
	}
}

type SessionGetInput struct {
	ID string `path:"id" doc:"Session ID"`
}

type SessionGetOutput struct {
	Body SessionView
}

// RegisterSGWCRoutes adds SGW-C session routes to the Huma API.
func RegisterSGWCRoutes(api huma.API, sessions *session.Manager) {
	huma.Register(api, huma.Operation{
		OperationID: "list-sessions",
		Method:      http.MethodGet,
		Path:        "/sessions",
		Summary:     "List all SGW-C sessions",
	}, func(ctx context.Context, _ *struct{}) (*SessionListOutput, error) {
		list := sessions.List()
		out := &SessionListOutput{}
		out.Body.Total = len(list)
		out.Body.Sessions = make([]SessionView, 0, len(list))
		for _, s := range list {
			out.Body.Sessions = append(out.Body.Sessions, sessionToView(s))
		}
		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "get-session",
		Method:      http.MethodGet,
		Path:        "/sessions/{id}",
		Summary:     "Get a single SGW-C session by ID",
	}, func(ctx context.Context, input *SessionGetInput) (*SessionGetOutput, error) {
		s := sessions.Find(input.ID)
		if s == nil {
			return nil, huma.Error404NotFound("session not found")
		}
		return &SessionGetOutput{Body: sessionToView(s)}, nil
	})
}

func sessionToView(s *session.SGWSession) SessionView {
	bearers := s.BearerList()
	sort.Slice(bearers, func(i, j int) bool {
		return bearers[i].EBI < bearers[j].EBI
	})
	views := make([]BearerView, 0, len(bearers))
	for _, b := range bearers {
		views = append(views, bearerToView(b, s.DefaultBearerID))
	}
	state := s.GetState()
	pfcp := s.PFCPBinding()
	pfcpState := "none"
	if pfcp.Established {
		pfcpState = "established"
	} else if state == session.StateRecovering {
		pfcpState = "stale"
	}
	reports := secondaryRATUsageReportsToView(s.SecondaryRATUsageReports())
	return SessionView{
		SessionID:                    s.SessionID,
		IMSI:                         s.IMSI,
		APN:                          s.APN,
		RATType:                      s.RATType,
		ServingNetwork:               s.ServingNetwork,
		State:                        string(state),
		PFCPState:                    pfcpState,
		PFCPLocalSEID:                fmt.Sprintf("0x%016X", pfcp.LocalFSEID.SEID),
		PFCPUPSEID:                   fmt.Sprintf("0x%016X", pfcp.SGWUFSEID.SEID),
		PFCPSGWUName:                 pfcp.SGWUName,
		PFCPSGWUAddr:                 pfcp.SGWUAddr,
		SGWS11TEID:                   fmt.Sprintf("0x%08X", s.SGWS11FTEID.TEID),
		MMEControlTEID:               fmt.Sprintf("0x%08X", s.MMEControlFTEID.TEID),
		BearerCount:                  s.BearerCount(),
		Bearers:                      views,
		SecondaryRATUsageReportCount: len(reports),
		SecondaryRATUsageDataReports: reports,
		PGWFailure:                   pgwFailureToView(s.PGWFailureSnapshot()),
		MMERestoration:               mmeRestorationToView(s.MMERestorationSnapshot()),
		CreatedAt:                    s.CreatedAt,
		UpdatedAt:                    s.UpdatedAt,
	}
}

func pgwFailureToView(status session.PGWFailureStatus) PGWFailureView {
	return PGWFailureView{
		PathState:         string(status.PathState),
		PGWAddr:           status.PGWAddr,
		PathDownAt:        status.PathDownAt,
		RestartDetectedAt: status.RestartDetectedAt,
		RecoverySeen:      status.RecoverySeen,
		RecoveryCounter:   status.RecoveryCounter,
	}
}

func mmeRestorationToView(status session.MMERestorationStatus) MMERestorationView {
	return MMERestorationView{
		State:               string(status.State),
		MMEAddr:             status.MMEAddr,
		PathDownAt:          status.PathDownAt,
		RestartDetectedAt:   status.RestartDetectedAt,
		RecoverySeen:        status.RecoverySeen,
		RecoveryCounter:     status.RecoveryCounter,
		RestorationPending:  status.RestorationPending,
		PolicyAction:        string(status.PolicyAction),
		PolicyReason:        status.PolicyReason,
		DDNTriggered:        status.DDNTriggered,
		DDNTriggeredAt:      status.DDNTriggeredAt,
		DDNSequence:         fmt.Sprintf("0x%06X", status.DDNSequence),
		DDNAcked:            status.DDNAcked,
		DDNAckedAt:          status.DDNAckedAt,
		DDNAckCause:         status.DDNAckCause,
		DDNFailureAt:        status.DDNFailureAt,
		DDNFailureCause:     status.DDNFailureCause,
		DDNFailureReason:    status.DDNFailureReason,
		StopPagingSent:      status.StopPagingSent,
		StopPagingSentAt:    status.StopPagingSentAt,
		StopPagingSequence:  fmt.Sprintf("0x%06X", status.StopPagingSequence),
		UserPlaneRestored:   status.UserPlaneRestored,
		UserPlaneRestoredAt: status.UserPlaneRestoredAt,
		RestoredEBI:         status.RestoredEBI,
	}
}

func secondaryRATUsageReportsToView(reports []session.SecondaryRATUsageDataReport) []SecondaryRATUsageReportView {
	views := make([]SecondaryRATUsageReportView, 0, len(reports))
	for _, report := range reports {
		views = append(views, SecondaryRATUsageReportView{
			ReceivedAt:      report.ReceivedAt,
			SourceProcedure: report.SourceProcedure,
			MMEPeer:         report.MMEPeer,
			SGWS11TEID:      fmt.Sprintf("0x%08X", report.SGWS11TEID),
			SequenceNumber:  fmt.Sprintf("0x%06X", report.SequenceNumber),
			PayloadLength:   len(report.Payload),
		})
	}
	return views
}

func bearerToView(b *bearer.Bearer, defaultBearerID uint8) BearerView {
	bearerType := "dedicated"
	if b.EBI == defaultBearerID {
		bearerType = "default"
	}
	view := BearerView{
		EBI:                     b.EBI,
		QCI:                     b.QCI,
		ARPPriorityLevel:        b.ARP.PriorityLevel,
		ARPPreemptionCapability: b.ARP.PreemptionCapability,
		ARPPreemptionVulnerable: b.ARP.PreemptionVulnerability,
		State:                   string(b.State),
		Type:                    bearerType,
		ENBS1UTEID:              fmt.Sprintf("0x%08X", b.ENBS1UFTEID.TEID),
		SGWS1UTEID:              fmt.Sprintf("0x%08X", b.SGWS1UFTEID.TEID),
		PGWS5UTEID:              fmt.Sprintf("0x%08X", b.PGWS5UFTEID.TEID),
		SGWS5UTEID:              fmt.Sprintf("0x%08X", b.SGWS5UFTEID.TEID),
		UplinkPDRID:             b.PDRIDs[0],
		DownlinkPDRID:           b.PDRIDs[1],
		UplinkFARID:             b.FARIDs[0],
		DownlinkFARID:           b.FARIDs[1],
		MBRUplink:               b.MBRUplink,
		MBRDownlink:             b.MBRDownlink,
		GBRUplink:               b.GBRUplink,
		GBRDownlink:             b.GBRDownlink,
	}
	return view
}
