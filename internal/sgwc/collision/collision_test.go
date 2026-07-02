package collision

import (
	"testing"
	"time"
)

func TestTrackerRejectsDeleteSessionDuringCreateBearer(t *testing.T) {
	tr := NewTracker()
	cb, dec := tr.Begin(Request{Procedure: ProcedureCreateBearer, Owner: OwnerPGW, EBIs: []uint8{6}})
	if dec.Action != ActionAllow {
		t.Fatalf("Create Bearer decision = %s, want allow", dec.Action)
	}
	_, dec = tr.Begin(Request{Procedure: ProcedureDeleteSession, Owner: OwnerMME})
	if dec.Action != ActionRejectNew {
		t.Fatalf("Delete Session decision = %s, want reject_new", dec.Action)
	}
	if dec.Current.ID != cb.ID {
		t.Fatalf("current collision ID = %d, want %d", dec.Current.ID, cb.ID)
	}
}

func TestTrackerAllowsDifferentBearerProcedures(t *testing.T) {
	tr := NewTracker()
	_, dec := tr.Begin(Request{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Update Bearer decision = %s, want allow", dec.Action)
	}
	_, dec = tr.Begin(Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{8}})
	if dec.Action != ActionAllow {
		t.Fatalf("Modify Bearer different EBI decision = %s, want allow", dec.Action)
	}
}

func TestTrackerRejectsSameBearerProcedures(t *testing.T) {
	tr := NewTracker()
	_, dec := tr.Begin(Request{Procedure: ProcedureCreateBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Create Bearer decision = %s, want allow", dec.Action)
	}
	_, dec = tr.Begin(Request{Procedure: ProcedureDeleteBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionRejectNew {
		t.Fatalf("Delete Bearer same EBI decision = %s, want reject_new", dec.Action)
	}
}

func TestTrackerAllowsCreateBearerResponseDuringCreateBearer(t *testing.T) {
	tr := NewTracker()
	cb, dec := tr.Begin(Request{Procedure: ProcedureCreateBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Create Bearer decision = %s, want allow", dec.Action)
	}
	_, dec = tr.Begin(Request{Procedure: ProcedureCreateBearerResponse, Owner: OwnerMME, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Create Bearer Response decision = %s, want allow", dec.Action)
	}
	tr.Finish(cb)
	if got := tr.Active(); len(got) != 1 {
		t.Fatalf("active procedures after finishing CB = %d, want 1 CBResp", len(got))
	}
}

func TestTrackerFinishAllowsNextProcedure(t *testing.T) {
	tr := NewTracker()
	proc, dec := tr.Begin(Request{Procedure: ProcedureDeleteBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Delete Bearer decision = %s, want allow", dec.Action)
	}
	tr.Finish(proc)
	_, dec = tr.Begin(Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Modify Bearer after finish decision = %s, want allow", dec.Action)
	}
}

func TestTrackerExpiresStaleProcedureBeforeDecision(t *testing.T) {
	tr := NewTrackerWithTimeout(5 * time.Millisecond)
	_, dec := tr.Begin(Request{Procedure: ProcedureCreateBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Create Bearer decision = %s, want allow", dec.Action)
	}
	time.Sleep(20 * time.Millisecond)
	_, dec = tr.Begin(Request{Procedure: ProcedureDeleteBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Delete Bearer after stale expiry decision = %s, want allow", dec.Action)
	}
	if got := tr.Active(); len(got) != 1 || got[0].Procedure != ProcedureDeleteBearer {
		t.Fatalf("active procedures = %+v, want only Delete Bearer", got)
	}
}

func TestTrackerSweepExpired(t *testing.T) {
	tr := NewTrackerWithTimeout(5 * time.Millisecond)
	_, dec := tr.Begin(Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{5}})
	if dec.Action != ActionAllow {
		t.Fatalf("Modify Bearer decision = %s, want allow", dec.Action)
	}
	time.Sleep(20 * time.Millisecond)
	if expired := tr.SweepExpired(); expired != 1 {
		t.Fatalf("SweepExpired = %d, want 1", expired)
	}
	if got := tr.Active(); len(got) != 0 {
		t.Fatalf("active procedures after sweep = %+v, want none", got)
	}
}

func TestProcedurePairDecisionMatrix(t *testing.T) {
	tests := []struct {
		name      string
		active    ActiveProcedure
		next      Request
		want      Action
		wantPol   Policy
		wantCause string
	}{
		{
			name:      "session wide procedure rejects bearer procedure",
			active:    ActiveProcedure{Procedure: ProcedureDeleteSession, Owner: OwnerMME, EBIs: []uint8{5}},
			next:      Request{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW, EBIs: []uint8{5}},
			want:      ActionRejectNew,
			wantPol:   PolicySessionOverlap,
			wantCause: "session-wide procedure overlap",
		},
		{
			name:      "bearer procedure same EBI rejects",
			active:    ActiveProcedure{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW, EBIs: []uint8{7}},
			next:      Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{7}},
			want:      ActionRejectNew,
			wantPol:   PolicyBearerOverlap,
			wantCause: "bearer procedure overlap",
		},
		{
			name:    "bearer procedure unknown EBI scope rejects",
			active:  ActiveProcedure{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW},
			next:    Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{7}},
			want:    ActionRejectNew,
			wantPol: PolicyBearerOverlap,
		},
		{
			name:    "bearer procedure different EBI allows",
			active:  ActiveProcedure{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW, EBIs: []uint8{7}},
			next:    Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{8}},
			want:    ActionAllow,
			wantPol: PolicyBearerDisjoint,
		},
		{
			name:    "create bearer response allowed during create bearer",
			active:  ActiveProcedure{Procedure: ProcedureCreateBearer, Owner: OwnerPGW, EBIs: []uint8{7}},
			next:    Request{Procedure: ProcedureCreateBearerResponse, Owner: OwnerMME, EBIs: []uint8{7}},
			want:    ActionAllow,
			wantPol: PolicyAllowResponse,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := decide(ModeStrict, tt.active, tt.next)
			if got.Action != tt.want {
				t.Fatalf("action = %s, want %s; decision=%+v", got.Action, tt.want, got)
			}
			if got.Policy != tt.wantPol {
				t.Fatalf("policy = %s, want %s; decision=%+v", got.Policy, tt.wantPol, got)
			}
			if tt.wantCause != "" && !contains(got.Reason, tt.wantCause) {
				t.Fatalf("reason = %q, want containing %q", got.Reason, tt.wantCause)
			}
		})
	}
}

func TestPermissiveModeAllowsUnknownBearerScope(t *testing.T) {
	tr := NewTracker()
	tr.Configure(ModePermissive, DefaultActiveProcedureTimeout)
	_, dec := tr.Begin(Request{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW})
	if dec.Action != ActionAllow {
		t.Fatalf("Update Bearer unknown EBI decision = %s, want allow", dec.Action)
	}
	_, dec = tr.Begin(Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Modify Bearer unknown-scope collision decision = %s, want allow", dec.Action)
	}
	if dec.Policy != PolicyNone {
		t.Fatalf("allowed tracker decision policy = %s, want empty policy", dec.Policy)
	}
}

func TestPermissiveModeStillRejectsSessionWideOverlap(t *testing.T) {
	tr := NewTracker()
	tr.Configure(ModePermissive, DefaultActiveProcedureTimeout)
	_, dec := tr.Begin(Request{Procedure: ProcedureDeleteSession, Owner: OwnerMME})
	if dec.Action != ActionAllow {
		t.Fatalf("Delete Session decision = %s, want allow", dec.Action)
	}
	_, dec = tr.Begin(Request{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW})
	if dec.Action != ActionRejectNew {
		t.Fatalf("Update Bearer during Delete Session decision = %s, want reject_new", dec.Action)
	}
	if dec.Policy != PolicySessionOverlap {
		t.Fatalf("reject policy = %s, want %s", dec.Policy, PolicySessionOverlap)
	}
}

func TestTrackerRejectDecisionIncludesMatrixPolicy(t *testing.T) {
	tr := NewTracker()
	_, dec := tr.Begin(Request{Procedure: ProcedureUpdateBearer, Owner: OwnerPGW, EBIs: []uint8{7}})
	if dec.Action != ActionAllow {
		t.Fatalf("Update Bearer decision = %s, want allow", dec.Action)
	}
	_, dec = tr.Begin(Request{Procedure: ProcedureModifyBearer, Owner: OwnerMME, EBIs: []uint8{7}})
	if dec.Action != ActionRejectNew {
		t.Fatalf("Modify Bearer same EBI decision = %s, want reject_new", dec.Action)
	}
	if dec.Policy != PolicyBearerOverlap {
		t.Fatalf("reject policy = %s, want %s", dec.Policy, PolicyBearerOverlap)
	}
}

func contains(s, sub string) bool {
	if sub == "" {
		return true
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
