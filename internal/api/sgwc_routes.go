package api

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/session"
)

// SessionView is the API representation of an SGW-C session.
type SessionView struct {
	SessionID      string    `json:"session_id"`
	IMSI           string    `json:"imsi"`
	APN            string    `json:"apn"`
	RATType        uint8     `json:"rat_type"`
	ServingNetwork string    `json:"serving_network"`
	State          string    `json:"state"`
	SGWS11TEID     string    `json:"sgw_s11_teid"`
	MMEControlTEID string    `json:"mme_control_teid"`
	BearerCount    int       `json:"bearer_count"`
	CreatedAt      time.Time `json:"created_at"`
	UpdatedAt      time.Time `json:"updated_at"`
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
	return SessionView{
		SessionID:      s.SessionID,
		IMSI:           s.IMSI,
		APN:            s.APN,
		RATType:        s.RATType,
		ServingNetwork: s.ServingNetwork,
		State:          string(s.GetState()),
		SGWS11TEID:     fmt.Sprintf("0x%08X", s.SGWS11FTEID.TEID),
		MMEControlTEID: fmt.Sprintf("0x%08X", s.MMEControlFTEID.TEID),
		BearerCount:    s.BearerCount(),
		CreatedAt:      s.CreatedAt,
		UpdatedAt:      s.UpdatedAt,
	}
}
