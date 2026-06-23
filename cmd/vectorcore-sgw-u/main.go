package main

import (
	"context"
	"flag"
	"fmt"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"syscall"
	"time"

	"vectorcore-sgw/internal/api"
	sgwuconfig "vectorcore-sgw/internal/config/sgwu"
	"vectorcore-sgw/internal/dataplane/bpf"
	"vectorcore-sgw/internal/log"
	"vectorcore-sgw/internal/metrics"
	"vectorcore-sgw/internal/sgwu/gtpu"
	"vectorcore-sgw/internal/sgwu/pfcpserver"
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

	flag.StringVar(&cfgPath, "c", sgwuconfig.DefaultPath, "path to SGW-U YAML config")
	flag.BoolVar(&debug, "d", false, "enable debug console logging")
	flag.BoolVar(&validateOnly, "validate", false, "load and validate config, then exit")
	flag.BoolVar(&showVersion, "v", false, "print version and exit")
	flag.Parse()

	if showVersion {
		fmt.Printf("VectorCore SGW-U %s\nbuild_date: %s\ngo: %s\n", version, buildDate, runtime.Version())
		return
	}

	fmt.Fprintf(os.Stdout, "Starting VectorCore SGW-U %s\n", version)

	cfg, err := sgwuconfig.Load(cfgPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore SGW-U: %v\n", err)
		os.Exit(1)
	}
	if validateOnly {
		fmt.Printf("config valid: %s\n", cfgPath)
		return
	}

	logger, err := log.New(log.Config{Level: cfg.Logging.Level, File: cfg.Logging.File}, debug)
	if err != nil {
		fmt.Fprintf(os.Stderr, "VectorCore SGW-U: %v\n", err)
		os.Exit(1)
	}
	defer logger.Close() //nolint:errcheck

	logger.Info("VectorCore SGW-U starting",
		"node_id", cfg.SGWU.NodeID,
		"version", version,
		"build_date", buildDate,
	)

	ctx, cancel := context.WithCancel(context.Background())
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigCh)
	go func() {
		sig := <-sigCh
		logger.Info("VectorCore SGW-U shutdown requested", "signal", sig.String())
		cancel()
	}()

	pfcpSrv, err := pfcpserver.New(cfg, time.Now(), logger.Logger)
	if err != nil {
		logger.Error("PFCP server failed to start", "error", err)
		os.Exit(1)
	}
	go func() {
		if err := pfcpSrv.Serve(ctx); err != nil {
			logger.Error("PFCP server serve error", "error", err)
		}
	}()

	// GTP-U dataplane setup: tc-bpf (default) or userspace fallback.
	// Port 2152 per TS 29.281 §4.4.2.1: "The port number for GTP-U request messages is 2152."
	var gtpuFwd *gtpu.Forwarder
	switch cfg.Dataplane.Mode {
	case "tc-bpf":
		// Phase 7: TC-BPF GTP-U fast path.
		// Attach BPF program to S1-U and S5/S8-U interfaces.
		s1uLocalIP, parseErr := netip.ParseAddr(cfg.GTPU.Access.LocalAddr)
		if parseErr != nil {
			logger.Error("GTP-U: invalid access local_addr", "addr", cfg.GTPU.Access.LocalAddr, "error", parseErr)
			os.Exit(1)
		}
		s5uLocalIP, parseErr := netip.ParseAddr(cfg.GTPU.Core.LocalAddr)
		if parseErr != nil {
			logger.Error("GTP-U: invalid core local_addr", "addr", cfg.GTPU.Core.LocalAddr, "error", parseErr)
			os.Exit(1)
		}
		maxEntries := cfg.Dataplane.BPFMapMaxEntries
		if !cfg.Dataplane.AttachOnStart {
			logger.Info("TC-BPF: attach_on_start=false — BPF hooks skipped")
			break
		}
		tcDp, bpfErr := bpf.New(cfg.GTPU.Access.Ifname, cfg.GTPU.Core.Ifname, maxEntries)
		if bpfErr != nil {
			logger.Error("TC-BPF dataplane failed to start", "error", bpfErr)
			os.Exit(1)
		}
		compiler := bpf.NewCompiler(tcDp, s1uLocalIP, s5uLocalIP, logger.Logger)
		pfcpSrv.SetBPFInstaller(compiler)
		logger.Info("TC-BPF GTP-U fast path active",
			"s1u_iface", cfg.GTPU.Access.Ifname,
			"s5u_iface", cfg.GTPU.Core.Ifname,
			"map_entries", maxEntries,
		)
		if cfg.Dataplane.CleanupOnExit {
			defer func() { _ = tcDp.Close() }()
		}

		// AUD-03: start GTP-U signalling listener in tc-bpf mode too.
		// BPF redirects matched G-PDUs before they reach the socket; the userspace
		// listener handles Echo Request/Response, Error Indication, End Marker, and
		// G-PDUs for unknown TEIDs (Error Indication per TS 29.281 §7.3.1).
		gtpuFwd, err = gtpu.New(cfg.GTPU.Listen, s1uLocalIP, pfcpSrv.SessionStore(), logger.Logger)
		if err != nil {
			logger.Error("GTP-U signalling listener failed to start", "error", err)
			os.Exit(1)
		}
		pfcpSrv.SetEndMarkerSender(gtpuFwd)
		go func() {
			if err := gtpuFwd.Serve(ctx); err != nil {
				logger.Error("GTP-U signalling listener serve error", "error", err)
			}
		}()

	case "userspace":
		// Phase 6: userspace GTP-U forwarder (reference / fallback path).
		localGTPUIP, parseErr := netip.ParseAddr(cfg.GTPU.Access.LocalAddr)
		if parseErr != nil {
			logger.Error("GTP-U: invalid access local_addr", "addr", cfg.GTPU.Access.LocalAddr, "error", parseErr)
			os.Exit(1)
		}
		gtpuFwd, err = gtpu.New(cfg.GTPU.Listen, localGTPUIP, pfcpSrv.SessionStore(), logger.Logger)
		if err != nil {
			logger.Error("GTP-U forwarder failed to start", "error", err)
			os.Exit(1)
		}
		// R15-REAUDIT-009: wire GTP-U forwarder as End Marker sender so PFCP session
		// modifications (tunnel switch) trigger End Markers to the old downstream peer.
		pfcpSrv.SetEndMarkerSender(gtpuFwd)
		go func() {
			if err := gtpuFwd.Serve(ctx); err != nil {
				logger.Error("GTP-U forwarder serve error", "error", err)
			}
		}()

	default:
		logger.Error("unknown dataplane.mode in config", "mode", cfg.Dataplane.Mode)
		os.Exit(1)
	}

	// Phase 11: wire PathProber to report GTP-U path failures to SGW-C via PFCP Node Report.
	// PathProber uses the same GTP-U socket as the forwarder per TS 29.281 §11/§12.
	if gtpuFwd != nil {
		prober := gtpu.NewPathProber(
			gtpuFwd.Conn(),
			30*time.Second, // probeInterval: probe each peer every 30s
			3*time.Second,  // T3-RESPONSE: wait 3s between retries
			3,              // N3-REQUESTS: 3 attempts before declaring failure
			logger.Logger,
		)
		prober.PathFailed = func(peer netip.Addr) {
			go pfcpSrv.HandlePathFailure(ctx, peer)
		}
		gtpuFwd.SetPathProber(prober)
		go func() {
			if err := prober.Serve(ctx); err != nil {
				logger.Error("GTP-U path prober error", "error", err)
			}
		}()
	}

	metricsSrv := metrics.NewServer(cfg.Metrics.Listen, logger.Logger)
	if err := metricsSrv.Start(ctx); err != nil {
		logger.Error("metrics server failed to start", "error", err)
		os.Exit(1)
	}

	apiSrv := api.NewServer(cfg.API.Listen, api.BuildInfo{Version: version, BuildDate: buildDate}, logger.Logger)
	if err := apiSrv.Start(ctx); err != nil {
		logger.Error("API server failed to start", "error", err)
		os.Exit(1)
	}

	logger.Info("VectorCore SGW-U ready",
		"pfcp", cfg.PFCP.Listen,
		"s1u_iface", cfg.GTPU.Access.Ifname,
		"s5u_iface", cfg.GTPU.Core.Ifname,
		"dataplane", cfg.Dataplane.Mode,
		"gtpu_listen", cfg.GTPU.Listen,
		"api", cfg.API.Listen,
		"metrics", cfg.Metrics.Listen,
	)

	<-ctx.Done()

	shutdownTimeout := time.Duration(cfg.Shutdown.TimeoutSeconds) * time.Second
	logger.Info("VectorCore SGW-U shutting down", "timeout", shutdownTimeout)

	waitComponent(logger, "pfcp", shutdownTimeout, pfcpSrv.Close)
	if gtpuFwd != nil {
		waitComponent(logger, "gtpu", shutdownTimeout, gtpuFwd.Close)
	}
	waitComponent(logger, "api", shutdownTimeout, apiSrv.Stop)
	waitComponent(logger, "metrics", shutdownTimeout, metricsSrv.Stop)

	logger.Info("VectorCore SGW-U stopped")
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
