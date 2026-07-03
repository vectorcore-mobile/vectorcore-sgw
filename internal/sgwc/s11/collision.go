package s11

import (
	"fmt"
	"net"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/sgwc/collision"
	"vectorcore-sgw/internal/sgwc/session"
)

type collisionMetrics interface {
	OnDecision(active collision.ActiveProcedure, req collision.Request, decision collision.Decision)
	OnStaleExpired(req collision.Request, expired int)
}

type nsaMetrics interface {
	OnSecondaryRATUsageReportsCaptured(apn, sourceProcedure string, count int)
	OnSecondaryRATUsageReportsForwarded(apn string, cause uint8, count int)
}

// SetCollisionMetrics wires optional GTPv2-C transaction collision KPI reporting.
func (h *Handler) SetCollisionMetrics(metrics collisionMetrics) {
	h.collisionMetrics = metrics
}

// SetNSAMetrics wires optional Rel-15 NSA/DCNR KPI reporting.
func (h *Handler) SetNSAMetrics(metrics nsaMetrics) {
	h.nsaMetrics = metrics
}

func (h *Handler) beginProcedure(sess *session.SGWSession, req collision.Request) (collision.ActiveProcedure, bool) {
	if sess == nil {
		return collision.ActiveProcedure{}, true
	}
	track := sess.ProcedureTracker()
	track.Configure(h.collisionMode, h.collisionTimeout)
	if expired := track.SweepExpired(); expired > 0 {
		if h.collisionMetrics != nil {
			h.collisionMetrics.OnStaleExpired(req, expired)
		}
		h.log.Warn("GTPv2-C stale transaction collision state expired",
			"session_id", sess.SessionID,
			"imsi", sess.IMSI,
			"apn", sess.APN,
			"expired", expired,
			"new_procedure", req.Procedure,
			"new_peer", req.Peer,
			"new_seq", req.Seq,
		)
	}
	proc, decision := track.Begin(req)
	if decision.Action == collision.ActionAllow {
		return proc, true
	}
	if h.collisionMetrics != nil {
		h.collisionMetrics.OnDecision(decision.Current, req, decision)
	}
	h.log.Warn("GTPv2-C transaction collision",
		"session_id", sess.SessionID,
		"imsi", sess.IMSI,
		"apn", sess.APN,
		"new_procedure", req.Procedure,
		"new_owner", req.Owner,
		"new_peer", req.Peer,
		"new_teid", fmt.Sprintf("0x%08X", req.TEID),
		"new_seq", req.Seq,
		"new_ebis", req.EBIs,
		"active_procedure", decision.Current.Procedure,
		"active_owner", decision.Current.Owner,
		"active_peer", decision.Current.Peer,
		"active_teid", fmt.Sprintf("0x%08X", decision.Current.TEID),
		"active_seq", decision.Current.Seq,
		"active_ebis", decision.Current.EBIs,
		"action", decision.Action,
		"policy", decision.Policy,
		"reason", decision.Reason,
	)
	return collision.ActiveProcedure{}, false
}

func collisionModeFromConfig(cfg *sgwcconfig.Config) collision.Mode {
	if cfg == nil || cfg.GTPC.TransactionCollision.Mode == "" {
		return collision.ModeStrict
	}
	return collision.Mode(cfg.GTPC.TransactionCollision.Mode)
}

func collisionTimeoutFromConfig(cfg *sgwcconfig.Config) time.Duration {
	if cfg == nil || cfg.GTPC.TransactionCollision.ActiveProcedureTimeoutSeconds <= 0 {
		return collision.DefaultActiveProcedureTimeout
	}
	return time.Duration(cfg.GTPC.TransactionCollision.ActiveProcedureTimeoutSeconds) * time.Second
}

func finishProcedure(sess *session.SGWSession, proc collision.ActiveProcedure) {
	if sess == nil || proc.ID == 0 {
		return
	}
	sess.ProcedureTracker().Finish(proc)
}

func mmeProcedureRequest(proc collision.Procedure, addr *net.UDPAddr, teid, seq uint32, ebis []uint8) collision.Request {
	return collision.Request{
		Procedure: proc,
		Owner:     collision.OwnerMME,
		Peer:      addr.String(),
		TEID:      teid,
		Seq:       seq,
		EBIs:      ebis,
	}
}

func pgwProcedureRequest(proc collision.Procedure, addr *net.UDPAddr, teid, seq uint32, ebis []uint8) collision.Request {
	return collision.Request{
		Procedure: proc,
		Owner:     collision.OwnerPGW,
		Peer:      addr.String(),
		TEID:      teid,
		Seq:       seq,
		EBIs:      ebis,
	}
}

func bearerContextEBIs(bcs []*ie.IE) []uint8 {
	var ebis []uint8
	seen := make(map[uint8]bool)
	for _, bc := range bcs {
		children, err := bc.ChildIEs()
		if err != nil {
			continue
		}
		ebiIE := ie.FindFirst(children, ie.TypeEBI)
		if ebiIE == nil {
			continue
		}
		ebi, err := ebiIE.EBIValue()
		if err != nil || seen[ebi] {
			continue
		}
		seen[ebi] = true
		ebis = append(ebis, ebi)
	}
	return ebis
}

func ebiIEsToValues(ies []*ie.IE) []uint8 {
	var ebis []uint8
	seen := make(map[uint8]bool)
	for _, ebiIE := range ies {
		ebi, err := ebiIE.EBIValue()
		if err != nil || seen[ebi] {
			continue
		}
		seen[ebi] = true
		ebis = append(ebis, ebi)
	}
	return ebis
}
