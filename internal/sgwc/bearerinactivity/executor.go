package bearerinactivity

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"vectorcore-sgw/internal/sgwc/session"
)

type PFCPRuleRemover interface {
	RemoveBearerRulesOnPeer(ctx context.Context, peerAddr string, cpSEID, upSEID uint64, pdrIDs, farIDs []uint32) error
}

type CleanupResult struct {
	Planned       int
	Skipped       int
	Cleaned       int
	Failed        int
	DeniedDefault int
	MissingRules  int
}

type Executor struct {
	Sessions  *session.Manager
	PFCP      PFCPRuleRemover
	Evaluator Evaluator
	Status    *Status
	Log       *slog.Logger
}

func (e Executor) Apply(ctx context.Context, now time.Time) CleanupResult {
	result := CleanupResult{}
	if e.Sessions == nil {
		return result
	}
	if now.IsZero() {
		now = time.Now()
	}
	decisions := e.Evaluator.EvaluateManager(e.Sessions, now)
	defer func() {
		e.Status.RecordScan(now, result, decisions)
	}()
	for _, decision := range decisions {
		result.Planned++
		switch decision.Action {
		case DecisionCleanupDedicatedBearer:
			if err := e.cleanupDedicatedBearer(ctx, decision); err != nil {
				result.Failed++
				if isMissingRuleError(err) {
					result.MissingRules++
				}
				e.log().Warn("SGW-C bearer inactivity cleanup failed",
					"session_id", decision.SessionID,
					"imsi", decision.IMSI,
					"apn", decision.APN,
					"ebi", decision.EBI,
					"reason", decision.Reason,
					"error", err)
				continue
			}
			result.Cleaned++
		case DecisionCleanupDefaultBearer:
			result.DeniedDefault++
			e.log().Warn("SGW-C bearer inactivity denied default bearer cleanup",
				"session_id", decision.SessionID,
				"imsi", decision.IMSI,
				"apn", decision.APN,
				"ebi", decision.EBI,
				"reason", "default-bearer-cleanup-not-executed-by-phase4")
		case DecisionDenyDefaultBearer:
			result.DeniedDefault++
		default:
			result.Skipped++
		}
	}
	return result
}

func (e Executor) cleanupDedicatedBearer(ctx context.Context, decision Decision) error {
	if decision.BearerType == "default" {
		return fmt.Errorf("refusing inactivity cleanup for default bearer ebi=%d", decision.EBI)
	}
	if e.PFCP == nil {
		return fmt.Errorf("pfcp rule remover unavailable")
	}
	sess := e.Sessions.Find(decision.SessionID)
	if sess == nil {
		return fmt.Errorf("session not found")
	}
	if decision.EBI == sess.DefaultBearerID {
		return fmt.Errorf("refusing inactivity cleanup for default bearer ebi=%d", decision.EBI)
	}
	b := sess.GetBearer(decision.EBI)
	if b == nil {
		return fmt.Errorf("bearer ebi=%d not found", decision.EBI)
	}
	binding := sess.PFCPBinding()
	if !binding.Established || binding.LocalFSEID.SEID == 0 || binding.SGWUFSEID.SEID == 0 || binding.SGWUAddr == "" {
		return fmt.Errorf("established pfcp binding required for bearer cleanup")
	}
	pdrIDs := []uint32{b.PDRIDs[0], b.PDRIDs[1]}
	farIDs := []uint32{b.FARIDs[0], b.FARIDs[1]}
	if !completeRuleIDs(pdrIDs, farIDs) {
		return missingRuleIDsError{ebi: decision.EBI, pdrIDs: pdrIDs, farIDs: farIDs}
	}
	if err := e.PFCP.RemoveBearerRulesOnPeer(ctx, binding.SGWUAddr, binding.LocalFSEID.SEID, binding.SGWUFSEID.SEID, pdrIDs, farIDs); err != nil {
		return err
	}
	sess.DeleteBearer(decision.EBI)
	e.log().Info("SGW-C bearer inactivity cleanup completed",
		"session_id", decision.SessionID,
		"imsi", decision.IMSI,
		"apn", decision.APN,
		"ebi", decision.EBI,
		"pdr_ids", pdrIDs,
		"far_ids", farIDs,
		"reason", decision.Reason)
	return nil
}

func completeRuleIDs(pdrIDs, farIDs []uint32) bool {
	if len(pdrIDs) != 2 || len(farIDs) != 2 {
		return false
	}
	for _, id := range pdrIDs {
		if id == 0 {
			return false
		}
	}
	for _, id := range farIDs {
		if id == 0 {
			return false
		}
	}
	return true
}

type missingRuleIDsError struct {
	ebi    uint8
	pdrIDs []uint32
	farIDs []uint32
}

func (e missingRuleIDsError) Error() string {
	return fmt.Sprintf("missing dedicated bearer rule IDs ebi=%d pdr_ids=%v far_ids=%v", e.ebi, e.pdrIDs, e.farIDs)
}

func isMissingRuleError(err error) bool {
	_, ok := err.(missingRuleIDsError)
	return ok
}

func (e Executor) log() *slog.Logger {
	if e.Log != nil {
		return e.Log
	}
	return slog.Default()
}
