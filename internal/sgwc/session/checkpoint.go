package session

import "vectorcore-sgw/internal/sgwc/sessioncheckpoint"

// CheckpointSink accepts durable session snapshots emitted by the session model.
// Implementations should return quickly; slow I/O belongs in an async writer.
type CheckpointSink interface {
	SaveSessionSnapshot(snapshot sessioncheckpoint.SessionSnapshot)
	DeleteSessionSnapshot(sessionID string)
}

func (s *SGWSession) setCheckpointSink(sink CheckpointSink) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.checkpointSink = sink
}

func (s *SGWSession) checkpoint() {
	s.mu.RLock()
	sink := s.checkpointSink
	s.mu.RUnlock()
	if sink == nil {
		return
	}
	sink.SaveSessionSnapshot(s.Snapshot())
}
