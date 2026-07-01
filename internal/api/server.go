package api

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humaecho"
	"github.com/labstack/echo/v4"
)

type BuildInfo struct {
	Component string
	Version   string
	BuildDate string
}

type HealthOutput struct {
	Body struct {
		Status    string `json:"status" doc:"Always \"ok\" when the process is running"`
		Component string `json:"component" doc:"API component name, e.g. SGW-C or SGW-U"`
		Version   string `json:"version"`
		BuildDate string `json:"build_date"`
	}
}

type Server struct {
	listen string
	info   BuildInfo
	e      *echo.Echo
	srv    *http.Server
	api    huma.API
	log    *slog.Logger
}

func NewServer(listen string, info BuildInfo, log *slog.Logger) *Server {
	e := echo.New()
	e.HideBanner = true
	e.HidePort = true

	component := info.Component
	if component == "" {
		component = "SGW"
	}
	cfg := huma.DefaultConfig(fmt.Sprintf("VectorCore %s API", component), "0.1.0")
	humaAPI := humaecho.New(e, cfg)

	info.Component = component
	s := &Server{listen: listen, info: info, e: e, api: humaAPI, log: log}
	s.registerRoutes()
	return s
}

func (s *Server) registerRoutes() {
	huma.Register(s.api, huma.Operation{
		OperationID: "get-health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Health check",
	}, func(ctx context.Context, _ *struct{}) (*HealthOutput, error) {
		out := &HealthOutput{}
		out.Body.Status = "ok"
		out.Body.Component = s.info.Component
		out.Body.Version = s.info.Version
		out.Body.BuildDate = s.info.BuildDate
		return out, nil
	})
}

// HumaAPI exposes the huma.API for registering additional routes from other packages.
func (s *Server) HumaAPI() huma.API {
	return s.api
}

func (s *Server) Start(ctx context.Context) error {
	// AUD-12: set read/write timeouts to prevent slow-client resource exhaustion.
	s.srv = &http.Server{
		Addr:              s.listen,
		Handler:           s.e,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		s.log.Info("API listening", "addr", s.listen)
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("API server error", "error", err)
		}
	}()

	go func() {
		<-ctx.Done()
		_ = s.srv.Close()
	}()

	return nil
}

func (s *Server) Stop() error {
	if s.srv == nil {
		return nil
	}
	if err := s.srv.Close(); err != nil {
		return fmt.Errorf("API server close: %w", err)
	}
	return nil
}
