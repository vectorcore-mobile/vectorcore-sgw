package api

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"

	"vectorcore-sgw/internal/sgwc/ddncontrol"
)

type DDNControlReader interface {
	Snapshot() ddncontrol.Snapshot
}

type DDNControlMMEView struct {
	MMEAddr                     string    `json:"mme_addr"`
	Tokens                      int       `json:"tokens"`
	Burst                       int       `json:"burst"`
	RateLimitPerSecond          int       `json:"rate_limit_per_second"`
	LastRefillAt                time.Time `json:"last_refill_at,omitempty"`
	LowPriorityThrottledUntil   time.Time `json:"low_priority_throttled_until,omitempty"`
	LowPriorityThrottleReceived time.Time `json:"low_priority_throttle_received,omitempty"`
	LowPriorityThrottleReason   string    `json:"low_priority_throttle_reason,omitempty"`
	Sent                        uint64    `json:"sent"`
	Delayed                     uint64    `json:"delayed"`
	Suppressed                  uint64    `json:"suppressed"`
	HighPriorityBypassed        uint64    `json:"high_priority_bypassed"`
}

type DDNControlUEView struct {
	IMSI         string    `json:"imsi"`
	LastDDNAt    time.Time `json:"last_ddn_at,omitempty"`
	LastMMEAddr  string    `json:"last_mme_addr,omitempty"`
	LastAPN      string    `json:"last_apn,omitempty"`
	LastEBI      uint8     `json:"last_ebi,omitempty"`
	LastPriority string    `json:"last_priority,omitempty"`
	Sent         uint64    `json:"sent"`
	Delayed      uint64    `json:"delayed"`
	Suppressed   uint64    `json:"suppressed"`
}

type DDNControlOutput struct {
	Body struct {
		MMEs     []DDNControlMMEView `json:"mmes"`
		UEs      []DDNControlUEView  `json:"ues"`
		MMETotal int                 `json:"mme_total"`
		UETotal  int                 `json:"ue_total"`
	}
}

func RegisterDDNControlRoutes(api huma.API, control DDNControlReader) {
	huma.Register(api, huma.Operation{
		OperationID: "get-ddn-control",
		Method:      http.MethodGet,
		Path:        "/gtpc/ddn-control",
		Summary:     "Get SGW-C DDN throttling and priority paging state",
	}, func(ctx context.Context, _ *struct{}) (*DDNControlOutput, error) {
		out := &DDNControlOutput{}
		if control == nil {
			return out, nil
		}
		snap := control.Snapshot()
		out.Body.MMEs = make([]DDNControlMMEView, 0, len(snap.MMEs))
		for _, mme := range snap.MMEs {
			out.Body.MMEs = append(out.Body.MMEs, ddnControlMMEToView(mme))
		}
		out.Body.UEs = make([]DDNControlUEView, 0, len(snap.UEs))
		for _, ue := range snap.UEs {
			out.Body.UEs = append(out.Body.UEs, ddnControlUEToView(ue))
		}
		out.Body.MMETotal = len(out.Body.MMEs)
		out.Body.UETotal = len(out.Body.UEs)
		return out, nil
	})
}

func ddnControlMMEToView(m ddncontrol.MMEState) DDNControlMMEView {
	return DDNControlMMEView{
		MMEAddr:                     m.MMEAddr,
		Tokens:                      m.Tokens,
		Burst:                       m.Burst,
		RateLimitPerSecond:          m.RateLimitPerSecond,
		LastRefillAt:                m.LastRefillAt,
		LowPriorityThrottledUntil:   m.LowPriorityThrottledUntil,
		LowPriorityThrottleReceived: m.LowPriorityThrottleReceived,
		LowPriorityThrottleReason:   m.LowPriorityThrottleReason,
		Sent:                        m.Sent,
		Delayed:                     m.Delayed,
		Suppressed:                  m.Suppressed,
		HighPriorityBypassed:        m.HighPriorityBypassed,
	}
}

func ddnControlUEToView(u ddncontrol.UEState) DDNControlUEView {
	return DDNControlUEView{
		IMSI:         u.IMSI,
		LastDDNAt:    u.LastDDNAt,
		LastMMEAddr:  u.LastMMEAddr,
		LastAPN:      u.LastAPN,
		LastEBI:      u.LastEBI,
		LastPriority: string(u.LastPriority),
		Sent:         u.Sent,
		Delayed:      u.Delayed,
		Suppressed:   u.Suppressed,
	}
}
