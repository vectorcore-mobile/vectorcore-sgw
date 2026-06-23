package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"net"
	"net/netip"

	"vectorcore-sgw/internal/api"
	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/log"
	"vectorcore-sgw/internal/metrics"
	"vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/recovery"
	"vectorcore-sgw/internal/sgwc/s11"
	"vectorcore-sgw/internal/sgwc/s5c"
	"vectorcore-sgw/internal/sgwc/session"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

func main() {
	var cfgPath string
	var debug bool
	var validateOnly bool
	var showVersion bool

	flag.StringVar(&cfgPath, "c", sgwcconfig.DefaultPath, "path to SGW-C YAML config")
	flag.BoolVar(&debug, "d", false, "enable debug console logging")
	flag.BoolVar(&validateOnly, "validate", false, "load and validate config, then exit")
	flag.BoolVar(&showVersion, "v", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("VectorCore SGW-C %s\nbuild_date: %s\ngo: %s\n", version, buildDate, runtime.Version())
		return
	}

	fmt.Fprintf(os.Stdout, "Starting VectorCore SGW-C %s\n", version)

	cfg, err := sgwcconfig.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore SGW-C: %v\n", err)
		os.Exit(1)
	}
	if validateOnly {
		fmt.Printf("config valid: %s\n", cfgPath)
		return
	}

	logger, err := log.New(log.Config{Level: cfg.Logging.Level, File: cfg.Logging.File}, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore SGW-C: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close() //nolint:errcheck

	logger.Info("VectorCore SGW-C starting",
		"node_id", cfg.SGWC.NodeID,
		"mcc", cfg.SGWC.PLMN.MCC,
		"mnc", cfg.SGWC.PLMN.MNC,
		"version", version,
		"build_date", buildDate,
	)

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		sig := <-sigCh
		logger.Info("VectorCore SGW-C shutdown requested", "signal", sig.String())
		cancel()
	}()

	// Recovery counter persistence per TS 29.274 Rel-15 §7.1.1/§7.1.2.
	// The counter must increment on each restart so peers detect context loss.
	stateDir := cfg.SGWC.StateDir
	if stateDir == "" {
		stateDir = "/var/lib/vectorcore-sgw"
	}
	counterPath := filepath.Join(stateDir, "recovery.counter")
	rc, err := recovery.LoadOrInit(counterPath)
	if err != nil {
		logger.Warn("SGW-C: recovery counter not persisted; restarts may be invisible to peers",
			"error", err, "path", counterPath)
		rc = recovery.New(0)
	}
	// Resolve SGW-C control-plane IP for Sender F-TEID IEs on S11 and S5/S8-C.
	// Prefer explicit control_plane_ip; fall back to parsing from the S5/S8-C listen addr.
	controlIP := resolveControlIP(cfg)
	if !controlIP.IsValid() {
		logger.Warn("SGW-C: control_plane_ip not configured and could not be derived from listen addresses; F-TEID IEs will carry 0.0.0.0")
	}

	sessions := session.NewManager()

	pfcpClient, err := pfcpclient.New(cfg, time.Now(), logger.Logger)
	if err != nil {
		logger.Error("PFCP client failed to start", "error", err)
		os.Exit(1)
	}
	// C9: Serve loop must be running before any outbound Send() calls.
	go func() {
		if err := pfcpClient.Serve(ctx); err != nil {
			logger.Error("PFCP client serve error", "error", err)
		}
	}()

	s5cClient, err := s5c.New(cfg, controlIP, rc, logger.Logger)
	if err != nil {
		logger.Error("S5/S8-C listener failed to start", "error", err)
		os.Exit(1)
	}
	// C9: start the S5/S8-C receive loop so Send() calls can receive PGW responses.
	go func() {
		if err := s5cClient.Serve(ctx); err != nil {
			logger.Error("S5/S8-C serve error", "error", err)
		}
	}()

	metricsSrv := metrics.NewServer(cfg.Metrics.Listen, logger.Logger)
	if err := metricsSrv.Start(ctx); err != nil {
		logger.Error("metrics server failed to start", "error", err)
		os.Exit(1)
	}

	// Wire PFCP peer state changes to Prometheus metrics (Phase 11).
	pfcpMetrics := metrics.NewPFCPMetrics(metricsSrv.Registry())
	pfcpClient.SetPeerStateCallback(func(peerName, peerAddr string, state pfcpclient.PeerState) {
		pfcpMetrics.OnPeerStateChange(peerName, peerAddr, string(state))
	})

	apiSrv := api.NewServer(cfg.API.Listen, api.BuildInfo{Version: version, BuildDate: buildDate}, logger.Logger)
	api.RegisterSGWCRoutes(apiSrv.HumaAPI(), sessions)
	api.RegisterPFCPRoutes(apiSrv.HumaAPI(), pfcpClient)
	if err := apiSrv.Start(ctx); err != nil {
		logger.Error("API server failed to start", "error", err)
		os.Exit(1)
	}

	s11Handler, err := s11.New(cfg, sessions, rc, s5cClient, pfcpClient, controlIP, logger.Logger)
	if err != nil {
		logger.Error("S11 listener failed to start", "error", err)
		os.Exit(1)
	}
	// Register handler for PGW-initiated bearer procedures (CBReq, UBReq, DBReq).
	// Must be set before any session can be established so requests are never dropped.
	// Per TS 29.274 §7.2.3/§7.2.9.2/§7.2.15: PGW initiates these after session creation.
	s5cClient.SetRequestHandler(s11Handler.HandleS5CInbound)
	go func() {
		if err := s11Handler.Serve(ctx); err != nil {
			logger.Error("S11 serve error", "error", err)
		}
	}()

	logger.Info("VectorCore SGW-C ready",
		"s11", cfg.S11.Listen,
		"s5c", cfg.S5C.LocalAddr,
		"control_ip", controlIP,
		"pfcp", cfg.PFCP.LocalAddr,
		"api", cfg.API.Listen,
		"metrics", cfg.Metrics.Listen,
	)

	<-ctx.Done()

	shutdownTimeout := time.Duration(cfg.Shutdown.TimeoutSeconds) * time.Second
	logger.Info("VectorCore SGW-C shutting down", "timeout", shutdownTimeout)

	waitComponent(logger, "s11", shutdownTimeout, s11Handler.Close)
	waitComponent(logger, "s5c", shutdownTimeout, s5cClient.Close)
	waitComponent(logger, "pfcp", shutdownTimeout, pfcpClient.Close)
	waitComponent(logger, "api", shutdownTimeout, apiSrv.Stop)
	waitComponent(logger, "metrics", shutdownTimeout, metricsSrv.Stop)

	logger.Info("VectorCore SGW-C stopped")
}

func waitComponent(logger *log.Logger, component string, timeout time.Duration, stop func() error) {
	done := make(chan error, 1)
	go func() { done <- stop() }()
	select {
	case err := <-done:
		if err != nil {
			logger.Warn("shutdown component failed", "component", component, "error", err)
		}
	case <-time.After(timeout):
		logger.Error("shutdown timeout", "component", component, "waited", timeout)
	}
}

// resolveControlIP determines the SGW-C control-plane IP to use in F-TEID IEs.
// Per TS 29.274 §8.22, F-TEID IEs carry the actual IP; 0.0.0.0 binds are invalid.
// Priority: (1) cfg.SGWC.ControlPlaneIP, (2) IP from cfg.S5C.LocalAddr if not 0.0.0.0.
func resolveControlIP(cfg *sgwcconfig.Config) netip.Addr {
	if cfg.SGWC.ControlPlaneIP != "" {
		if addr, err := netip.ParseAddr(cfg.SGWC.ControlPlaneIP); err == nil {
			return addr.Unmap()
		}
	}
	// Fall back to S5C local addr if it has a specific IP.
	if ua, err := net.ResolveUDPAddr("udp4", cfg.S5C.LocalAddr); err == nil {
		if ip4 := ua.IP.To4(); ip4 != nil {
			addr := netip.AddrFrom4([4]byte(ip4))
			if !addr.IsUnspecified() {
				return addr
			}
		}
	}
	return netip.Addr{}
}
