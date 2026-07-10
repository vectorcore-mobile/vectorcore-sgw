package api

import (
	"context"
	"net/http"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/idledownlink"
)

type IdleDownlinkReader interface {
	Snapshot() idledownlink.Snapshot
}

type IdleDownlinkOutput struct {
	Body idledownlink.Snapshot
}

func RegisterIdleDownlinkRoutes(api huma.API, reader IdleDownlinkReader) {
	huma.Register(api, huma.Operation{
		OperationID: "get-idle-downlink-status",
		Method:      http.MethodGet,
		Path:        "/gtpc/idle-downlink",
		Summary:     "Get SGW-C idle downlink notification status",
	}, func(ctx context.Context, _ *struct{}) (*IdleDownlinkOutput, error) {
		out := &IdleDownlinkOutput{}
		if reader != nil {
			out.Body = reader.Snapshot()
		}
		return out, nil
	})
}
