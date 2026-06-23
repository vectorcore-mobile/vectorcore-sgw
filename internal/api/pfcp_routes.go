package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/pfcpclient"
)

// PFCPAssociationsOutput is the API response for Sxa PFCP association status.
type PFCPAssociationsOutput struct {
	Body struct {
		Peers []pfcpclient.PeerView `json:"peers"`
		Total int                   `json:"total"`
	}
}

// RegisterPFCPRoutes adds Sxa PFCP association status routes to the API.
func RegisterPFCPRoutes(api huma.API, client *pfcpclient.Client) {
	huma.Register(api, huma.Operation{
		OperationID: "list-pfcp-associations",
		Method:      http.MethodGet,
		Path:        "/pfcp/associations",
		Summary:     "List Sxa PFCP association states with SGW-U peers",
	}, func(ctx context.Context, _ *struct{}) (*PFCPAssociationsOutput, error) {
		peers := client.Peers()
		out := &PFCPAssociationsOutput{}
		out.Body.Peers = peers
		out.Body.Total = len(peers)
		return out, nil
	})
}
