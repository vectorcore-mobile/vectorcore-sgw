package metrics

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

type Server struct {
	listen string
	reg    *prometheus.Registry
	srv    *http.Server
	log    *slog.Logger
}

func NewServer(listen string, log *slog.Logger) *Server {
	reg := prometheus.NewRegistry()
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)
	return &Server{listen: listen, reg: reg, log: log}
}

// Registry returns the Prometheus registry for registering custom metrics.
func (s *Server) Registry() *prometheus.Registry {
	return s.reg
}

func (s *Server) Start(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(s.reg, promhttp.HandlerOpts{}))
	// AUD-12: set read/write timeouts to prevent slow-client resource exhaustion.
	s.srv = &http.Server{
		Addr:              s.listen,
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      60 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	go func() {
		s.log.Info("metrics listening", "addr", s.listen)
		if err := s.srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			s.log.Error("metrics server error", "error", err)
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
		return fmt.Errorf("metrics server close: %w", err)
	}
	return nil
}
