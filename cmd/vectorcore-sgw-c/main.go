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
	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/gtpv2/transport"
	"vectorcore-sgw/internal/log"
	"vectorcore-sgw/internal/metrics"
	"vectorcore-sgw/internal/sgwc/peerhealth"
	"vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/pgwfailure"
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
		"config", cfgPath,
		"s11", cfg.S11Listen(),
		"s5c", cfg.S5CListen(),
		"pfcp", cfg.PFCP.LocalAddr,
		"sgwu_peers", len(cfg.PFCP.SGWU),
		"api", cfg.API.Listen,
		"metrics", cfg.Metrics.Listen,
	)
	logger.Info("SGW-C QoS outer marking configured",
		"enabled", cfg.QoS.OuterMarking.Enabled,
		"gtpc_enabled", cfg.QoS.OuterMarking.GTPC.Enabled,
		"gtpc_dscp", cfg.QoS.OuterMarking.GTPC.DSCP,
		"pfcp_enabled", cfg.QoS.OuterMarking.PFCP.Enabled,
		"pfcp_dscp", cfg.QoS.OuterMarking.PFCP.DSCP,
	)
	logger.Info("SGW-C GTPv2-C transaction collision policy configured",
		"mode", cfg.GTPC.TransactionCollision.Mode,
		"active_procedure_timeout_seconds", cfg.GTPC.TransactionCollision.ActiveProcedureTimeoutSeconds,
	)
	logger.Info("SGW-C NSA/DCNR awareness configured",
		"enabled", cfg.GTPC.NSADCNR.Enabled,
		"forward_secondary_rat_usage_reports", cfg.GTPC.NSADCNR.ForwardSecondaryRATUsageReports,
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
	gtpcPeers := peerhealth.NewTable(logger.Logger)
	pgwFailureHandler := pgwfailure.NewHandler(sessions, pgwfailure.Config{
		Enabled:                cfg.GTPC.PGWFailure.Enabled,
		MarkSessionsOnPathDown: cfg.GTPC.PGWFailure.MarkSessionsOnPathDown,
		MarkSessionsOnRestart:  cfg.GTPC.PGWFailure.MarkSessionsOnRestart,
	}, logger.Logger)
	gtpcPeers.SetEventHandler(pgwFailureHandler)

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

	sharedControl := cfg.GTPC.S11.Bind == cfg.GTPC.S5C.Bind
	var sharedGTPC *transport.Conn
	var s5cClient *s5c.Client
	if sharedControl {
		sharedGTPC, err = transport.Listen(
			cfg.S11Listen(),
			cfg.S11.T3ResponseSeconds,
			cfg.S11.N3Requests,
			logger.Logger,
		)
		if err != nil {
			logger.Error("shared S11/S5/S8-C listener failed to start", "error", err)
			os.Exit(1)
		}
		if cfg.QoS.OuterMarking.Enabled && cfg.QoS.OuterMarking.GTPC.Enabled {
			if err := sharedGTPC.SetDSCP(uint8(cfg.QoS.OuterMarking.GTPC.DSCP)); err != nil {
				logger.Error("shared S11/S5/S8-C QoS outer marking failed", "error", err)
				os.Exit(1)
			}
		}
		s5cClient = s5c.NewWithConn(sharedGTPC, controlIP, rc, logger.Logger)
	} else {
		s5cClient, err = s5c.New(cfg, controlIP, rc, logger.Logger)
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
	}
	s5cClient.SetPeerHealth(gtpcPeers)

	metricsSrv := metrics.NewServer(cfg.Metrics.Listen, logger.Logger)
	if err := metricsSrv.Start(ctx); err != nil {
		logger.Error("metrics server failed to start", "error", err)
		os.Exit(1)
	}

	// Wire PFCP peer state changes to Prometheus metrics (Phase 11).
	pfcpMetrics := metrics.NewPFCPMetrics(metricsSrv.Registry())
	collisionMetrics := metrics.NewCollisionMetrics(metricsSrv.Registry())
	nsaMetrics := metrics.NewNSAMetrics(metricsSrv.Registry())
	metrics.NewGTPCPeerMetrics(metricsSrv.Registry(), gtpcPeers)
	metrics.NewPGWFailureMetrics(metricsSrv.Registry(), pgwFailureHandler)
	pfcpClient.SetPeerStateCallback(func(peerName, peerAddr string, state pfcpclient.PeerState) {
		pfcpMetrics.OnPeerStateChange(peerName, peerAddr, string(state))
		if state == pfcpclient.PeerStateDown {
			invalidated := sessions.InvalidatePFCPBindingsForPeer(peerName, peerAddr)
			logger.Warn("PFCP peer down; invalidated stale SGW-U session bindings",
				"peer", peerName,
				"addr", peerAddr,
				"sessions", invalidated)
		}
	})
	pfcpClient.SetPeerRestartCallback(func(peerName, peerAddr string, oldTS, newTS uint32) {
		invalidated := sessions.InvalidatePFCPBindingsForPeer(peerName, peerAddr)
		logger.Warn("PFCP peer restart detected; invalidated stale SGW-U session bindings",
			"peer", peerName,
			"addr", peerAddr,
			"old_recovery_ts", oldTS,
			"new_recovery_ts", newTS,
			"sessions", invalidated)
	})

	apiSrv := api.NewServer(cfg.API.Listen, api.BuildInfo{Component: "SGW-C", Version: version, BuildDate: buildDate}, logger.Logger)
	api.RegisterSGWCRoutes(apiSrv.HumaAPI(), sessions)
	api.RegisterPFCPRoutes(apiSrv.HumaAPI(), pfcpClient)
	api.RegisterGTPCPeerRoutes(apiSrv.HumaAPI(), gtpcPeers)
	api.RegisterPGWFailureRoutes(apiSrv.HumaAPI(), pgwFailureHandler)
	if err := apiSrv.Start(ctx); err != nil {
		logger.Error("API server failed to start", "error", err)
		os.Exit(1)
	}

	var s11Handler *s11.Handler
	if sharedControl {
		s11Handler = s11.NewWithConn(cfg, sharedGTPC, sessions, rc, s5cClient, pfcpClient, controlIP, logger.Logger)
	} else {
		s11Handler, err = s11.New(cfg, sessions, rc, s5cClient, pfcpClient, controlIP, logger.Logger)
		if err != nil {
			logger.Error("S11 listener failed to start", "error", err)
			os.Exit(1)
		}
	}
	s11Handler.SetPeerHealth(gtpcPeers)
	s11Handler.SetCollisionMetrics(collisionMetrics)
	s11Handler.SetNSAMetrics(nsaMetrics)
	gtpcPeerProber := peerhealth.NewProber(gtpcPeers, peerhealth.ProberConfig{
		Enabled:            cfg.GTPC.PeerHealth.Enabled,
		EchoInterval:       time.Duration(cfg.GTPC.PeerHealth.EchoIntervalSeconds) * time.Second,
		EchoTimeout:        time.Duration(cfg.GTPC.PeerHealth.EchoTimeoutSeconds) * time.Second,
		SuspectAfterMissed: cfg.GTPC.PeerHealth.SuspectAfterMissed,
		DownAfterMissed:    cfg.GTPC.PeerHealth.DownAfterMissed,
		DegradedRTT:        time.Duration(cfg.GTPC.PeerHealth.DegradedRTTMS) * time.Millisecond,
		ProbeMMEPeers:      cfg.GTPC.PeerHealth.ProbeMMEPeers,
		ProbePGWPeers:      cfg.GTPC.PeerHealth.ProbePGWPeers,
	}, func(probeCtx context.Context, target peerhealth.Target, seq uint32) (*peerhealth.EchoResult, error) {
		switch target.Role {
		case peerhealth.RoleMME:
			return s11Handler.SendEcho(probeCtx, target.Addr, seq)
		case peerhealth.RolePGW:
			return s5cClient.SendEcho(probeCtx, target.Addr, seq)
		default:
			return nil, fmt.Errorf("unsupported GTP-C peer role %q", target.Role)
		}
	}, logger.Logger, func(target peerhealth.Target) uint32 {
		if target.Role == peerhealth.RolePGW {
			return s5cClient.AllocSeq()
		}
		return s11Handler.AllocSeq()
	})
	go gtpcPeerProber.Run(ctx)
	// Register handler for PGW-initiated bearer procedures (CBReq, UBReq, DBReq).
	// Must be set before any session can be established so requests are never dropped.
	// Per TS 29.274 §7.2.3/§7.2.9.2/§7.2.15: PGW initiates these after session creation.
	if sharedControl {
		sharedGTPC.SetHandler(sharedGTPCHandler(s11Handler))
		go func() {
			logger.Info("shared S11/S5/S8-C listening", "addr", sharedGTPC.LocalAddr())
			if err := sharedGTPC.Serve(ctx); err != nil {
				logger.Error("shared S11/S5/S8-C serve error", "error", err)
			}
		}()
	} else {
		s5cClient.SetRequestHandler(s11Handler.HandleS5CInbound)
		go func() {
			if err := s11Handler.Serve(ctx); err != nil {
				logger.Error("S11 serve error", "error", err)
			}
		}()
	}

	logger.Info("VectorCore SGW-C ready",
		"s11", cfg.S11Listen(),
		"s5c", cfg.S5CListen(),
		"shared_control", sharedControl,
		"control_ip", controlIP,
		"pfcp", cfg.PFCP.LocalAddr,
		"api", cfg.API.Listen,
		"metrics", cfg.Metrics.Listen,
	)

	<-ctx.Done()

	shutdownTimeout := time.Duration(cfg.Shutdown.TimeoutSeconds) * time.Second
	logger.Info("VectorCore SGW-C shutting down", "timeout", shutdownTimeout)

	if sharedControl {
		waitComponent(logger, "gtpc", shutdownTimeout, sharedGTPC.Close)
	} else {
		waitComponent(logger, "s11", shutdownTimeout, s11Handler.Close)
		waitComponent(logger, "s5c", shutdownTimeout, s5cClient.Close)
	}
	waitComponent(logger, "pfcp", shutdownTimeout, pfcpClient.Close)
	waitComponent(logger, "api", shutdownTimeout, apiSrv.Stop)
	waitComponent(logger, "metrics", shutdownTimeout, metricsSrv.Stop)

	logger.Info("VectorCore SGW-C stopped")
}

func sharedGTPCHandler(h *s11.Handler) transport.Handler {
	return func(conn *transport.Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
		if isPGWInitiatedBearerRequest(hdr.MessageType) {
			h.HandleS5CInbound(conn, addr, hdr, raw)
			return
		}
		h.Handle(conn, addr, hdr, raw)
	}
}

func isPGWInitiatedBearerRequest(msgType uint8) bool {
	switch msgType {
	case message.MsgTypeCreateBearerRequest,
		message.MsgTypeUpdateBearerRequest,
		message.MsgTypeDeleteBearerRequest:
		return true
	default:
		return false
	}
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
// Priority: (1) cfg.SGWC.ControlPlaneIP, (2) IP from the S5/S8-C control binding if not 0.0.0.0.
func resolveControlIP(cfg *sgwcconfig.Config) netip.Addr {
	if cfg.SGWC.ControlPlaneIP != "" {
		if addr, err := netip.ParseAddr(cfg.SGWC.ControlPlaneIP); err == nil {
			return addr.Unmap()
		}
	}
	// Fall back to S5C local addr if it has a specific IP.
	if ua, err := net.ResolveUDPAddr("udp4", cfg.S5CListen()); err == nil {
		if ip4 := ua.IP.To4(); ip4 != nil {
			addr := netip.AddrFrom4([4]byte(ip4))
			if !addr.IsUnspecified() {
				return addr
			}
		}
	}
	return netip.Addr{}
}
