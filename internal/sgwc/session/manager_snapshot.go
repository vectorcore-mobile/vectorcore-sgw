package session

import "vectorcore-sgw/internal/sgwc/sessioncheckpoint"

// Snapshots returns durable snapshots of all sessions currently in the manager.
func (m *Manager) Snapshots() []sessioncheckpoint.SessionSnapshot {
	sessions := m.List()
	out := make([]sessioncheckpoint.SessionSnapshot, 0, len(sessions))
	for _, sess := range sessions {
		out = append(out, sess.Snapshot())
	}
	return out
}
