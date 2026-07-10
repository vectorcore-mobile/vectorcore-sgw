package bearerinactivity

import (
	"context"
	"time"
)

type Runner struct {
	Executor Executor
	Interval time.Duration
	Now      func() time.Time
}

func (r Runner) Run(ctx context.Context) {
	interval := r.Interval
	if interval <= 0 {
		interval = 30 * time.Second
	}
	now := r.Now
	if now == nil {
		now = time.Now
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			result := r.Executor.Apply(ctx, now())
			if result.Cleaned > 0 || result.Failed > 0 || result.DeniedDefault > 0 {
				r.Executor.log().Info("SGW-C bearer inactivity scan complete",
					"planned", result.Planned,
					"skipped", result.Skipped,
					"cleaned", result.Cleaned,
					"failed", result.Failed,
					"denied_default", result.DeniedDefault,
					"missing_rules", result.MissingRules)
			}
		}
	}
}
