package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/pgwfailure"
)

type PGWFailureReader interface {
	Snapshot() []pgwfailure.Snapshot
}

type PGWFailureSummaryView struct {
	PGWAddr           string    `json:"pgw_addr"`
	State             string    `json:"state"`
	LastStateChange   time.Time `json:"last_state_change,omitempty"`
	RecoverySeen      bool      `json:"recovery_seen"`
	RecoveryCounter   uint8     `json:"recovery_counter"`
	RestartDetectedAt time.Time `json:"restart_detected_at,omitempty"`
	AffectedSessions  int       `json:"affected_sessions"`
	Restarts          uint64    `json:"restarts"`
	PathDownEvents    uint64    `json:"path_down_events"`
}

type PGWFailureListOutput struct {
	Body struct {
		PGWFailures []PGWFailureSummaryView `json:"pgw_failures"`
		Total       int                     `json:"total"`
	}
}

func RegisterPGWFailureRoutes(api huma.API, failures PGWFailureReader) {
	huma.Register(api, huma.Operation{
		OperationID: "list-pgw-failures",
		Method:      http.MethodGet,
		Path:        "/gtpc/pgw-failures",
		Summary:     "List SGW-C PGW path and restart failure state",
	}, func(ctx context.Context, _ *struct{}) (*PGWFailureListOutput, error) {
		out := &PGWFailureListOutput{}
		if failures == nil {
			return out, nil
		}
		snapshots := failures.Snapshot()
		out.Body.PGWFailures = make([]PGWFailureSummaryView, 0, len(snapshots))
		for _, snap := range snapshots {
			out.Body.PGWFailures = append(out.Body.PGWFailures, pgwFailureSummaryToView(snap))
		}
		out.Body.Total = len(out.Body.PGWFailures)
		return out, nil
	})
}

func pgwFailureSummaryToView(s pgwfailure.Snapshot) PGWFailureSummaryView {
	return PGWFailureSummaryView{
		PGWAddr:           s.PGWAddr,
		State:             string(s.State),
		LastStateChange:   s.LastStateChange,
		RecoverySeen:      s.RecoverySeen,
		RecoveryCounter:   s.RecoveryCounter,
		RestartDetectedAt: s.RestartDetectedAt,
		AffectedSessions:  s.AffectedSessions,
		Restarts:          s.Restarts,
		PathDownEvents:    s.PathDownEvents,
	}
}
