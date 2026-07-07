package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/mmerestoration"
)

type MMERestorationReader interface {
	Snapshot() []mmerestoration.Snapshot
}

type MMERestorationSummaryView struct {
	MMEAddr           string    `json:"mme_addr"`
	State             string    `json:"state"`
	LastStateChange   time.Time `json:"last_state_change,omitempty"`
	RecoverySeen      bool      `json:"recovery_seen"`
	RecoveryCounter   uint8     `json:"recovery_counter"`
	RestartDetectedAt time.Time `json:"restart_detected_at,omitempty"`
	AffectedSessions  int       `json:"affected_sessions"`
	Restarts          uint64    `json:"restarts"`
	PathDownEvents    uint64    `json:"path_down_events"`
}

type MMERestorationListOutput struct {
	Body struct {
		MMERestorations []MMERestorationSummaryView `json:"mme_restorations"`
		Total           int                         `json:"total"`
	}
}

func RegisterMMERestorationRoutes(api huma.API, restorations MMERestorationReader) {
	huma.Register(api, huma.Operation{
		OperationID: "list-mme-restorations",
		Method:      http.MethodGet,
		Path:        "/gtpc/mme-restorations",
		Summary:     "List SGW-C MME restoration path and restart state",
	}, func(ctx context.Context, _ *struct{}) (*MMERestorationListOutput, error) {
		out := &MMERestorationListOutput{}
		if restorations == nil {
			return out, nil
		}
		snapshots := restorations.Snapshot()
		out.Body.MMERestorations = make([]MMERestorationSummaryView, 0, len(snapshots))
		for _, snap := range snapshots {
			out.Body.MMERestorations = append(out.Body.MMERestorations, mmeRestorationSummaryToView(snap))
		}
		out.Body.Total = len(out.Body.MMERestorations)
		return out, nil
	})
}

func mmeRestorationSummaryToView(s mmerestoration.Snapshot) MMERestorationSummaryView {
	return MMERestorationSummaryView{
		MMEAddr:           s.MMEAddr,
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
