package session_test

import (
	"testing"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

func TestCheckpointSinkReceivesSessionMutations(t *testing.T) {
	m := session.NewManager()
	sink := &recordingSink{}
	m.SetCheckpointSink(sink)

	sess, _, err := m.Create(defaultParams())
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if sink.saveCount == 0 {
		t.Fatal("Create did not emit checkpoint save")
	}
	sink.reset()

	sess.SetBearer(&bearer.Bearer{EBI: 7, QCI: 1, State: bearer.BearerStateActive})
	if sink.saveCount != 1 || sink.lastSave.SessionID != sess.SessionID {
		t.Fatalf("SetBearer checkpoint = count:%d snapshot:%+v", sink.saveCount, sink.lastSave)
	}
	if len(sink.lastSave.Bearers) != 2 {
		t.Fatalf("checkpoint bearers = %d; want default + dedicated", len(sink.lastSave.Bearers))
	}
	sink.reset()

	sess.MarkPGWRestart("10.90.250.92:2123", 7, time.Unix(10, 0).UTC())
	if sink.saveCount != 1 || sink.lastSave.PGWFailure.RecoveryCounter != 7 {
		t.Fatalf("MarkPGWRestart checkpoint = count:%d snapshot:%+v", sink.saveCount, sink.lastSave.PGWFailure)
	}
	sink.reset()

	sess.MarkMMERestorationDDNTriggered(0x1234, time.Unix(11, 0).UTC())
	if sink.saveCount != 1 || sink.lastSave.MMERestoration.DDNSequence != 0x1234 {
		t.Fatalf("MarkMMERestorationDDNTriggered checkpoint = count:%d snapshot:%+v", sink.saveCount, sink.lastSave.MMERestoration)
	}
	sink.reset()

	m.Delete(sess.SessionID)
	if sink.deleteCount != 1 || sink.lastDelete != sess.SessionID {
		t.Fatalf("Delete checkpoint = count:%d session:%q", sink.deleteCount, sink.lastDelete)
	}
}

type recordingSink struct {
	saveCount   int
	deleteCount int
	lastSave    sessioncheckpoint.SessionSnapshot
	lastDelete  string
}

func (r *recordingSink) SaveSessionSnapshot(snapshot sessioncheckpoint.SessionSnapshot) {
	r.saveCount++
	r.lastSave = snapshot
}

func (r *recordingSink) DeleteSessionSnapshot(sessionID string) {
	r.deleteCount++
	r.lastDelete = sessionID
}

func (r *recordingSink) reset() {
	r.saveCount = 0
	r.deleteCount = 0
	r.lastSave = sessioncheckpoint.SessionSnapshot{}
	r.lastDelete = ""
}
