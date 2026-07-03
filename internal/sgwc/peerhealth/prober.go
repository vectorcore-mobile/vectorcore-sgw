package peerhealth

import (
	"context"
	"log/slog"
	"time"
)

type EchoResult struct {
	RTT      time.Duration
	Recovery *uint8
}

type EchoSender func(ctx context.Context, target Target, seq uint32) (*EchoResult, error)

type ProberConfig struct {
	Enabled            bool
	EchoInterval       time.Duration
	EchoTimeout        time.Duration
	SuspectAfterMissed int
	DownAfterMissed    int
	DegradedRTT        time.Duration
	ProbeMMEPeers      bool
	ProbePGWPeers      bool
}

type Prober struct {
	table   *Table
	cfg     ProberConfig
	send    EchoSender
	log     *slog.Logger
	nextSeq func(Target) uint32
}

func NewProber(table *Table, cfg ProberConfig, send EchoSender, log *slog.Logger, nextSeq func(Target) uint32) *Prober {
	if log == nil {
		log = slog.Default()
	}
	return &Prober{
		table:   table,
		cfg:     cfg,
		send:    send,
		log:     log,
		nextSeq: nextSeq,
	}
}

func (p *Prober) Run(ctx context.Context) {
	if p == nil || !p.cfg.Enabled || p.table == nil || p.send == nil || p.nextSeq == nil {
		return
	}
	if p.cfg.EchoInterval <= 0 {
		p.cfg.EchoInterval = 30 * time.Second
	}
	if p.cfg.EchoTimeout <= 0 {
		p.cfg.EchoTimeout = 3 * time.Second
	}
	ticker := time.NewTicker(p.cfg.EchoInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			p.probeOnce(ctx)
		}
	}
}

func (p *Prober) probeOnce(ctx context.Context) {
	targets := p.table.ProbeTargets(p.cfg.ProbeMMEPeers, p.cfg.ProbePGWPeers)
	for _, target := range targets {
		seq := p.nextSeq(target)
		p.table.MarkEchoSent(target.Role, target.Addr, seq)
		probeCtx, cancel := context.WithTimeout(ctx, p.cfg.EchoTimeout)
		res, err := p.send(probeCtx, target, seq)
		cancel()
		if err != nil {
			p.table.MarkEchoTimeout(target.Role, target.Addr, seq, ProbeConfig{
				SuspectAfterMissed: p.cfg.SuspectAfterMissed,
				DownAfterMissed:    p.cfg.DownAfterMissed,
				DegradedRTT:        p.cfg.DegradedRTT,
			})
			p.log.Debug("GTP-C peer Echo failed", "role", target.Role, "peer", target.Addr, "seq", seq, "error", err)
			continue
		}
		p.table.MarkEchoResponse(target.Role, target.Addr, seq, res.RTT, res.Recovery, ProbeConfig{
			SuspectAfterMissed: p.cfg.SuspectAfterMissed,
			DownAfterMissed:    p.cfg.DownAfterMissed,
			DegradedRTT:        p.cfg.DegradedRTT,
		})
	}
}
