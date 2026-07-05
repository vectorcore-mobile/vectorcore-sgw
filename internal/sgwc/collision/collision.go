package collision

import (
	"fmt"
	"sync"
	"time"
)

const DefaultActiveProcedureTimeout = 2 * time.Minute

type Mode string

const (
	ModeStrict     Mode = "strict"
	ModePermissive Mode = "permissive"
)

type Procedure string

const (
	ProcedureCreateSession        Procedure = "CREATE_SESSION"
	ProcedureModifyBearer         Procedure = "MODIFY_BEARER"
	ProcedureDeleteSession        Procedure = "DELETE_SESSION"
	ProcedureReleaseAccessBearers Procedure = "RELEASE_ACCESS_BEARERS"
	ProcedureCreateBearer         Procedure = "CREATE_BEARER"
	ProcedureCreateBearerResponse Procedure = "CREATE_BEARER_RESPONSE"
	ProcedureUpdateBearer         Procedure = "UPDATE_BEARER"
	ProcedureDeleteBearer         Procedure = "DELETE_BEARER"
)

type Owner string

const (
	OwnerMME Owner = "mme"
	OwnerPGW Owner = "pgw"
	OwnerSGW Owner = "sgw"
)

type Action string

const (
	ActionAllow     Action = "allow"
	ActionRejectNew Action = "reject_new"
)

type Request struct {
	Procedure Procedure
	Owner     Owner
	Peer      string
	TEID      uint32
	Seq       uint32
	EBIs      []uint8
	Reason    string
}

type Decision struct {
	Action  Action
	Current ActiveProcedure
	Reason  string
	Policy  Policy
}

type Policy string

const (
	PolicyNone           Policy = ""
	PolicyAllowResponse  Policy = "allow_response"
	PolicySessionOverlap Policy = "session_overlap"
	PolicyBearerOverlap  Policy = "bearer_overlap"
	PolicyBearerDisjoint Policy = "bearer_disjoint"
	PolicyBearerUnknown  Policy = "bearer_unknown_scope"
)

type ActiveProcedure struct {
	ID        uint64
	Procedure Procedure
	Owner     Owner
	Peer      string
	TEID      uint32
	Seq       uint32
	EBIs      []uint8
	StartedAt time.Time
	UpdatedAt time.Time
}

type Tracker struct {
	mu      sync.Mutex
	nextID  uint64
	timeout time.Duration
	mode    Mode
	active  map[uint64]ActiveProcedure
}

func NewTracker() *Tracker {
	return NewTrackerWithTimeout(DefaultActiveProcedureTimeout)
}

func NewTrackerWithTimeout(timeout time.Duration) *Tracker {
	if timeout <= 0 {
		timeout = DefaultActiveProcedureTimeout
	}
	return &Tracker{timeout: timeout, mode: ModeStrict, active: make(map[uint64]ActiveProcedure)}
}

func (t *Tracker) Configure(mode Mode, timeout time.Duration) {
	if t == nil {
		return
	}
	if mode == "" {
		mode = ModeStrict
	}
	if timeout <= 0 {
		timeout = DefaultActiveProcedureTimeout
	}
	t.mu.Lock()
	t.mode = mode
	t.timeout = timeout
	t.mu.Unlock()
}

func (t *Tracker) Begin(req Request) (ActiveProcedure, Decision) {
	if t == nil {
		return ActiveProcedure{}, Decision{Action: ActionAllow}
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.active == nil {
		t.active = make(map[uint64]ActiveProcedure)
	}
	if t.timeout <= 0 {
		t.timeout = DefaultActiveProcedureTimeout
	}
	if t.mode == "" {
		t.mode = ModeStrict
	}
	now := time.Now()
	t.sweepExpiredLocked(now)
	for _, cur := range t.active {
		decision := decide(t.mode, cur, req)
		if decision.Action != ActionAllow {
			decision.Current = cur
			return ActiveProcedure{}, Decision{
				Action:  decision.Action,
				Current: cur,
				Reason:  decision.Reason,
				Policy:  decision.Policy,
			}
		}
	}
	t.nextID++
	proc := ActiveProcedure{
		ID:        t.nextID,
		Procedure: req.Procedure,
		Owner:     req.Owner,
		Peer:      req.Peer,
		TEID:      req.TEID,
		Seq:       req.Seq,
		EBIs:      append([]uint8(nil), req.EBIs...),
		StartedAt: now,
		UpdatedAt: now,
	}
	t.active[proc.ID] = proc
	return proc, Decision{Action: ActionAllow}
}

func (t *Tracker) SweepExpired() int {
	if t == nil {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.timeout <= 0 {
		t.timeout = DefaultActiveProcedureTimeout
	}
	return t.sweepExpiredLocked(time.Now())
}

func (t *Tracker) sweepExpiredLocked(now time.Time) int {
	expired := 0
	for id, proc := range t.active {
		if now.Sub(proc.UpdatedAt) > t.timeout {
			delete(t.active, id)
			expired++
		}
	}
	return expired
}

func (t *Tracker) Finish(proc ActiveProcedure) {
	if t == nil || proc.ID == 0 {
		return
	}
	t.mu.Lock()
	delete(t.active, proc.ID)
	t.mu.Unlock()
}

func (t *Tracker) Active() []ActiveProcedure {
	if t == nil {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out := make([]ActiveProcedure, 0, len(t.active))
	for _, proc := range t.active {
		out = append(out, proc)
	}
	return out
}

type pairKey struct {
	active Procedure
	next   Procedure
}

type pairRule struct {
	policy Policy
}

var procedurePairRules = map[pairKey]pairRule{
	{ProcedureCreateBearer, ProcedureCreateBearerResponse}: {policy: PolicyAllowResponse},
	{ProcedureCreateBearerResponse, ProcedureCreateBearer}: {policy: PolicyAllowResponse},
	// Delete Session is terminal for a PDN connection. If the MME starts PDN
	// teardown while a bearer-scoped procedure is still active, the SGW must not
	// reject the teardown and leave stale SGW/PGW state behind. The reverse
	// direction is intentionally not allowed: once Delete Session is active, new
	// bearer procedures remain blocked by the session-wide overlap rule.
	{ProcedureModifyBearer, ProcedureDeleteSession}:         {policy: PolicyNone},
	{ProcedureCreateBearer, ProcedureDeleteSession}:         {policy: PolicyNone},
	{ProcedureCreateBearerResponse, ProcedureDeleteSession}: {policy: PolicyNone},
	{ProcedureUpdateBearer, ProcedureDeleteSession}:         {policy: PolicyNone},
	{ProcedureDeleteBearer, ProcedureDeleteSession}:         {policy: PolicyNone},
	// Release Access Bearers is an access-side idle transition. It must not be
	// rejected solely because the PGW is concurrently updating or deleting
	// bearer state for the same PDN; the RAB handler only drops access FARs and
	// preserves the core session/bearer ownership.
	{ProcedureDeleteBearer, ProcedureReleaseAccessBearers}: {policy: PolicyNone},
	{ProcedureReleaseAccessBearers, ProcedureDeleteBearer}: {policy: PolicyNone},
	{ProcedureUpdateBearer, ProcedureReleaseAccessBearers}: {policy: PolicyNone},
	{ProcedureReleaseAccessBearers, ProcedureUpdateBearer}: {policy: PolicyNone},
}

func decide(mode Mode, cur ActiveProcedure, req Request) Decision {
	if mode == "" {
		mode = ModeStrict
	}
	policy := pairPolicy(cur.Procedure, req.Procedure)
	switch policy {
	case PolicyAllowResponse:
		return Decision{Action: ActionAllow, Policy: policy, Reason: "matching bearer response is allowed while request is active"}
	case PolicySessionOverlap:
		return Decision{
			Action: ActionRejectNew,
			Policy: policy,
			Reason: fmt.Sprintf("session-wide procedure overlap: active=%s new=%s", cur.Procedure, req.Procedure),
		}
	case PolicyBearerOverlap:
		if len(cur.EBIs) == 0 || len(req.EBIs) == 0 {
			if mode == ModePermissive {
				return Decision{Action: ActionAllow, Policy: PolicyBearerUnknown, Reason: "bearer procedure unknown EBI scope allowed by permissive mode"}
			}
			return Decision{
				Action: ActionRejectNew,
				Policy: policy,
				Reason: fmt.Sprintf("bearer procedure overlap with unknown EBI scope: active=%s new=%s", cur.Procedure, req.Procedure),
			}
		}
		if overlapsEBI(cur.EBIs, req.EBIs) {
			return Decision{
				Action: ActionRejectNew,
				Policy: policy,
				Reason: fmt.Sprintf("bearer procedure overlap: active=%s new=%s", cur.Procedure, req.Procedure),
			}
		}
		return Decision{Action: ActionAllow, Policy: PolicyBearerDisjoint, Reason: "bearer procedure EBIs are disjoint"}
	default:
		return Decision{Action: ActionAllow, Policy: PolicyNone}
	}
}

func pairPolicy(active, next Procedure) Policy {
	if rule, ok := procedurePairRules[pairKey{active: active, next: next}]; ok {
		return rule.policy
	}
	if isSessionWide(active) || isSessionWide(next) {
		return PolicySessionOverlap
	}
	if isBearerScoped(active) && isBearerScoped(next) {
		return PolicyBearerOverlap
	}
	return PolicySessionOverlap
}

func overlapsEBI(a, b []uint8) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

func isBearerScoped(proc Procedure) bool {
	switch proc {
	case ProcedureModifyBearer, ProcedureCreateBearer, ProcedureCreateBearerResponse, ProcedureUpdateBearer, ProcedureDeleteBearer:
		return true
	default:
		return false
	}
}

func isSessionWide(proc Procedure) bool {
	switch proc {
	case ProcedureCreateSession, ProcedureDeleteSession, ProcedureReleaseAccessBearers:
		return true
	default:
		return false
	}
}
