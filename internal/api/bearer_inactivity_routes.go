package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/bearerinactivity"
)

type BearerInactivityReader interface {
	Snapshot() bearerinactivity.Snapshot
}

type BearerInactivityRuntimeView struct {
	LastScanAt    time.Time      `json:"last_scan_at,omitempty"`
	LastResult    CleanupResult  `json:"last_result"`
	Scans         uint64         `json:"scans"`
	Planned       uint64         `json:"planned"`
	Skipped       uint64         `json:"skipped"`
	Cleaned       uint64         `json:"cleaned"`
	Failed        uint64         `json:"failed"`
	DeniedDefault uint64         `json:"denied_default"`
	MissingRules  uint64         `json:"missing_rules"`
	LastActions   map[string]int `json:"last_actions"`
}

type CleanupResult struct {
	Planned       int `json:"planned"`
	Skipped       int `json:"skipped"`
	Cleaned       int `json:"cleaned"`
	Failed        int `json:"failed"`
	DeniedDefault int `json:"denied_default"`
	MissingRules  int `json:"missing_rules"`
}

type BearerInactivityDecisionView struct {
	SessionID               string    `json:"session_id"`
	IMSI                    string    `json:"imsi"`
	APN                     string    `json:"apn"`
	EBI                     uint8     `json:"ebi"`
	BearerType              string    `json:"bearer_type"`
	QCI                     uint8     `json:"qci"`
	ARPPriority             uint8     `json:"arp_priority"`
	BearerState             string    `json:"bearer_state"`
	Action                  string    `json:"action"`
	Reason                  string    `json:"reason"`
	IdleThresholdSeconds    int64     `json:"idle_threshold_seconds"`
	IdleForSeconds          int64     `json:"idle_for_seconds"`
	LastControlActivityAt   time.Time `json:"last_control_activity_at,omitempty"`
	LastUserPlaneActivityAt time.Time `json:"last_user_plane_activity_at,omitempty"`
	LastActivityAt          time.Time `json:"last_activity_at,omitempty"`
	LastActivitySource      string    `json:"last_activity_source,omitempty"`
	RequireNoRecentControl  bool      `json:"require_no_recent_control"`
	MatchedPreserveRule     string    `json:"matched_preserve_rule,omitempty"`
	MatchedCleanupRule      string    `json:"matched_cleanup_rule,omitempty"`
}

type BearerInactivityOutput struct {
	Body struct {
		Runtime    BearerInactivityRuntimeView    `json:"runtime"`
		Actions    map[string]int                 `json:"actions"`
		Decisions  []BearerInactivityDecisionView `json:"decisions"`
		Total      int                            `json:"total"`
		Candidates int                            `json:"candidates"`
		Deferred   int                            `json:"deferred"`
		Preserved  int                            `json:"preserved"`
		Denied     int                            `json:"denied"`
	}
}

func RegisterBearerInactivityRoutes(api huma.API, reader BearerInactivityReader) {
	huma.Register(api, huma.Operation{
		OperationID: "get-bearer-inactivity",
		Method:      http.MethodGet,
		Path:        "/gtpc/bearer-inactivity",
		Summary:     "Get SGW-C bearer inactivity cleanup candidates and status",
	}, func(ctx context.Context, _ *struct{}) (*BearerInactivityOutput, error) {
		out := &BearerInactivityOutput{}
		if reader == nil {
			out.Body.Actions = map[string]int{}
			return out, nil
		}
		snap := reader.Snapshot()
		out.Body.Runtime = bearerInactivityRuntimeToView(snap.Runtime)
		out.Body.Actions = actionCountsToView(snap.ActionCounts)
		out.Body.Decisions = make([]BearerInactivityDecisionView, 0, len(snap.Decisions))
		for _, decision := range snap.Decisions {
			out.Body.Decisions = append(out.Body.Decisions, bearerInactivityDecisionToView(decision))
			switch decision.Action {
			case bearerinactivity.DecisionCleanupDedicatedBearer, bearerinactivity.DecisionCleanupDefaultBearer:
				out.Body.Candidates++
			case bearerinactivity.DecisionPreserve:
				out.Body.Preserved++
			case bearerinactivity.DecisionDenyDefaultBearer:
				out.Body.Denied++
			default:
				if isBearerInactivityDefer(decision.Action) {
					out.Body.Deferred++
				}
			}
		}
		out.Body.Total = len(out.Body.Decisions)
		return out, nil
	})
}

func bearerInactivityRuntimeToView(s bearerinactivity.RuntimeSnapshot) BearerInactivityRuntimeView {
	return BearerInactivityRuntimeView{
		LastScanAt: s.LastScanAt,
		LastResult: CleanupResult{
			Planned:       s.LastResult.Planned,
			Skipped:       s.LastResult.Skipped,
			Cleaned:       s.LastResult.Cleaned,
			Failed:        s.LastResult.Failed,
			DeniedDefault: s.LastResult.DeniedDefault,
			MissingRules:  s.LastResult.MissingRules,
		},
		Scans:         s.Scans,
		Planned:       s.Planned,
		Skipped:       s.Skipped,
		Cleaned:       s.Cleaned,
		Failed:        s.Failed,
		DeniedDefault: s.DeniedDefault,
		MissingRules:  s.MissingRules,
		LastActions:   actionCountsToView(s.LastActionCounts),
	}
}

func bearerInactivityDecisionToView(d bearerinactivity.Decision) BearerInactivityDecisionView {
	return BearerInactivityDecisionView{
		SessionID:               d.SessionID,
		IMSI:                    d.IMSI,
		APN:                     d.APN,
		EBI:                     d.EBI,
		BearerType:              d.BearerType,
		QCI:                     d.QCI,
		ARPPriority:             d.ARPPriority,
		BearerState:             d.BearerState,
		Action:                  string(d.Action),
		Reason:                  d.Reason,
		IdleThresholdSeconds:    int64(d.IdleThreshold.Seconds()),
		IdleForSeconds:          int64(d.IdleFor.Seconds()),
		LastControlActivityAt:   d.LastControlActivityAt,
		LastUserPlaneActivityAt: d.LastUserPlaneActivityAt,
		LastActivityAt:          d.LastActivityAt,
		LastActivitySource:      d.LastActivitySource,
		RequireNoRecentControl:  d.RequireNoRecentControl,
		MatchedPreserveRule:     d.MatchedPreserveRule,
		MatchedCleanupRule:      d.MatchedCleanupRule,
	}
}

func actionCountsToView(in map[bearerinactivity.DecisionAction]int) map[string]int {
	out := make(map[string]int, len(in))
	for action, count := range in {
		out[string(action)] = count
	}
	return out
}

func isBearerInactivityDefer(action bearerinactivity.DecisionAction) bool {
	switch action {
	case bearerinactivity.DecisionDeferNoActivityEvidence,
		bearerinactivity.DecisionDeferNotIdle,
		bearerinactivity.DecisionDeferRecentControl,
		bearerinactivity.DecisionDeferNoPolicy,
		bearerinactivity.DecisionDisabled:
		return true
	default:
		return false
	}
}
