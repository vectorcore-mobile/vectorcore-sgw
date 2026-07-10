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
		"config", cfgPath,
		"pfcp", cfg.PFCP.Listen,
		"s1u_bind", cfg.GTPU.S1U.Bind,
		"s5u_bind", cfg.GTPU.S5U.Bind,
		"dataplane", "ebpf",
		"driver_mode", cfg.Dataplane.DriverMode,
		"attach_on_start", cfg.Dataplane.AttachOnStart,
		"cleanup_on_exit", cfg.Dataplane.CleanupOnExit,
		"api", cfg.API.Listen,
		"metrics", cfg.Metrics.Listen,
	)
	logger.Info("SGW-U QoS outer marking configured",
		"enabled", cfg.QoS.OuterMarking.Enabled,
		"gtpu_enabled", cfg.QoS.OuterMarking.GTPU.Enabled,
		"gtpu_dscp", cfg.QoS.OuterMarking.GTPU.DSCP,
		"pfcp_enabled", cfg.QoS.OuterMarking.PFCP.Enabled,
		"pfcp_dscp", cfg.QoS.OuterMarking.PFCP.DSCP,
	)
	logger.Info("SGW-U QCI marking configured",
		"enabled", cfg.QoS.QCIMarking.Enabled,
		"override_default_gtpu", cfg.QoS.QCIMarking.OverrideDefaultGTPU,
		"default_gtpu_dscp", cfg.QoS.QCIMarking.DefaultGTPUDSCP,
		"qci_mappings", len(cfg.QoS.QCIMarking.QCIToDSCP),
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

	// GTP-U dataplane setup: eBPF fast path with a userspace signalling socket.
	// Port 2152 per TS 29.281 §4.4.2.1: "The port number for GTP-U request messages is 2152."
	var gtpuFwd *gtpu.ForwarderGroup
	// xdpDp stays nil if attach_on_start=false; the API layer reports an empty
	// BPF rule list in that case.
	var xdpDp *bpf.XDPDataplane
	s1u := cfg.S1UInterface()
	s5u := cfg.S5UInterface()
	s1uLocalIP, parseErr := cfg.S1ULocalAddr()
	if parseErr != nil {
		logger.Error("GTP-U: invalid s1u listen address", "listen", s1u.Listen, "error", parseErr)
		os.Exit(1)
	}
	s5uLocalIP, parseErr := cfg.S5ULocalAddr()
	if parseErr != nil {
		logger.Error("GTP-U: invalid s5u listen address", "listen", s5u.Listen, "error", parseErr)
		os.Exit(1)
	}
	maxEntries := cfg.Dataplane.MapMaxEntries
	if !cfg.Dataplane.AttachOnStart {
		logger.Info("XDP-BPF: attach_on_start=false — BPF hooks skipped")
	} else {
		var bpfErr error
		xdpDp, bpfErr = bpf.NewWithMode(s1u.Ifname, s5u.Ifname, maxEntries, cfg.Dataplane.DriverMode)
		if bpfErr != nil {
			logger.Error("XDP-BPF dataplane failed to start", "error", bpfErr)
			os.Exit(1)
		}
		if err := xdpDp.ConfigureQoSOuterMarking(bpf.QoSOuterMarkingConfig{
			Enabled:        cfg.QoS.OuterMarking.Enabled,
			GTPUEnabled:    cfg.QoS.OuterMarking.GTPU.Enabled,
			GTPUDSCP:       uint8(cfg.QoS.OuterMarking.GTPU.DSCP),
			QCIEnabled:     cfg.QoS.QCIMarking.Enabled && cfg.QoS.QCIMarking.OverrideDefaultGTPU,
			QCIDefaultDSCP: uint8(cfg.QoS.QCIMarking.DefaultGTPUDSCP),
		}); err != nil {
			logger.Error("XDP-BPF QoS outer marking map load failed", "error", err)
			os.Exit(1)
		}
		logger.Info("SGW-U eBPF QoS outer marking map loaded",
			"gtpu_enabled", cfg.QoS.OuterMarking.Enabled && cfg.QoS.OuterMarking.GTPU.Enabled,
			"gtpu_dscp", cfg.QoS.OuterMarking.GTPU.DSCP,
			"qci_enabled", cfg.QoS.QCIMarking.Enabled && cfg.QoS.QCIMarking.OverrideDefaultGTPU,
			"qci_default_dscp", cfg.QoS.QCIMarking.DefaultGTPUDSCP,
		)
		compiler := bpf.NewCompiler(xdpDp, s1uLocalIP, s5uLocalIP, logger.Logger, bpf.QCIMarkingConfig{
			Enabled:             cfg.QoS.QCIMarking.Enabled,
			OverrideDefaultGTPU: cfg.QoS.QCIMarking.OverrideDefaultGTPU,
			DefaultGTPUDSCP:     uint8(cfg.QoS.QCIMarking.DefaultGTPUDSCP),
			QCIToDSCP:           qciToDSCPMap(cfg.QoS.QCIMarking.QCIToDSCP),
		})
		pfcpSrv.SetBPFInstaller(compiler)
		logger.Info("XDP-BPF GTP-U fast path active",
			"s1u_iface", s1u.Ifname,
			"s5u_iface", s5u.Ifname,
			"driver_mode", cfg.Dataplane.DriverMode,
			"single_interface_gtpu", xdpDp.SharedInterface(),
			"map_entries", maxEntries,
		)
		if cfg.Dataplane.CleanupOnExit {
			defer func() { _ = xdpDp.Close() }()
		}
	}

	// BPF redirects matched G-PDUs before they reach the socket; the userspace
	// listener handles Echo Request/Response, Error Indication, End Marker, and
	// G-PDUs for unknown TEIDs (Error Indication per TS 29.281 §7.3.1).
	gtpuFwd, err = gtpu.NewGroup([]gtpu.Endpoint{
		{Listen: s1u.Listen, LocalIP: s1uLocalIP},
		{Listen: s5u.Listen, LocalIP: s5uLocalIP},
	}, pfcpSrv.SessionStore(), logger.Logger)
	if err != nil {
		logger.Error("GTP-U signalling listener failed to start", "error", err)
		os.Exit(1)
	}
	pfcpSrv.SetEndMarkerSender(gtpuFwd)
	gtpuFwd.SetIdleDownlinkReporter(pfcpSrv)
	go func() {
		if err := gtpuFwd.Serve(ctx); err != nil {
			logger.Error("GTP-U signalling listener serve error", "error", err)
		}
	}()

	// Phase 11: wire PathProber to report GTP-U path failures to SGW-C via PFCP Node Report.
	// PathProber uses the same GTP-U socket as the forwarder per TS 29.281 §11/§12.
	if gtpuFwd != nil {
		var probers []*gtpu.PathProber
		for _, fwd := range gtpuFwd.Forwarders() {
			prober := gtpu.NewPathProber(
				fwd.Conn(),
				gtpu.EchoMinInterval,
				3*time.Second, // T3-RESPONSE: wait 3s between retries
				3,             // N3-REQUESTS: 3 attempts before declaring failure
				logger.Logger,
			)
			prober.PathFailed = func(peer netip.Addr) {
				go pfcpSrv.HandlePathFailure(ctx, peer)
			}
			fwd.SetPathProber(prober)
			probers = append(probers, prober)
		}
		proberGroup := gtpu.NewPathProberGroup(probers...)
		pfcpSrv.SetPathPeerTracker(proberGroup)
		go func() {
			if err := proberGroup.Serve(ctx); err != nil {
				logger.Error("GTP-U path prober error", "error", err)
			}
		}()
	}

	metricsSrv := metrics.NewServer(cfg.Metrics.Listen, logger.Logger)
	if err := metricsSrv.Start(ctx); err != nil {
		logger.Error("metrics server failed to start", "error", err)
		os.Exit(1)
	}

	apiSrv := api.NewServer(cfg.API.Listen, api.BuildInfo{Component: "SGW-U", Version: version, BuildDate: buildDate}, logger.Logger)
	api.RegisterSGWURoutes(apiSrv.HumaAPI(), pfcpSrv.SessionStore(), pfcpSrv, xdpDp, gtpuFwd)
	if err := apiSrv.Start(ctx); err != nil {
		logger.Error("API server failed to start", "error", err)
		os.Exit(1)
	}

	logger.Info("VectorCore SGW-U ready",
		"pfcp", cfg.PFCP.Listen,
		"s1u_iface", s1u.Ifname,
		"s5u_iface", s5u.Ifname,
		"dataplane", "ebpf",
		"s1u_gtpu_listen", s1u.Listen,
		"s5u_gtpu_listen", s5u.Listen,
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

func qciToDSCPMap(in map[int]int) map[uint8]uint8 {
	out := make(map[uint8]uint8, len(in))
	for qci, dscp := range in {
		out[uint8(qci)] = uint8(dscp)
	}
	return out
}
