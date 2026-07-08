package sessioncheckpoint

import (
	"context"
	"errors"
	"testing"
	"time"
)

func TestWriterFlushCoalescesLatestSnapshot(t *testing.T) {
	store := &memoryStore{sessions: make(map[string]SessionSnapshot)}
	writer := NewWriter(store, time.Hour, nil)
	ctx := context.Background()

	first := testSnapshot("sess-1", "00101", "ims", 1, 6)
	second := first
	second.APN = "internet"
	writer.SaveSessionSnapshot(first)
	writer.SaveSessionSnapshot(second)

	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if store.saveCount != 1 {
		t.Fatalf("saveCount = %d; want 1 coalesced save", store.saveCount)
	}
	if got := store.sessions["sess-1"].APN; got != "internet" {
		t.Fatalf("saved APN = %q; want latest internet", got)
	}
}

func TestWriterDeleteRemovesPendingSave(t *testing.T) {
	store := &memoryStore{sessions: make(map[string]SessionSnapshot)}
	writer := NewWriter(store, time.Hour, nil)
	ctx := context.Background()

	writer.SaveSessionSnapshot(testSnapshot("sess-1", "00101", "ims", 1, 6))
	writer.DeleteSessionSnapshot("sess-1")

	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if store.saveCount != 0 {
		t.Fatalf("saveCount = %d; want no save after delete", store.saveCount)
	}
	if store.deleteCount != 1 {
		t.Fatalf("deleteCount = %d; want 1", store.deleteCount)
	}
}

func TestWriterRequeuesFailedSave(t *testing.T) {
	store := &memoryStore{
		sessions: make(map[string]SessionSnapshot),
		saveErr:  errors.New("disk full"),
	}
	writer := NewWriter(store, time.Hour, nil)
	ctx := context.Background()

	writer.SaveSessionSnapshot(testSnapshot("sess-1", "00101", "ims", 1, 6))
	if err := writer.Flush(ctx); err == nil {
		t.Fatal("Flush succeeded with failing store")
	}
	store.saveErr = nil
	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("second Flush: %v", err)
	}
	if store.saveCount != 2 {
		t.Fatalf("saveCount = %d; want failed attempt + retry", store.saveCount)
	}
	if _, ok := store.sessions["sess-1"]; !ok {
		t.Fatal("snapshot was not saved after retry")
	}
}

func TestWriterFlushCoalescesPeerSnapshot(t *testing.T) {
	store := &memoryStore{sessions: make(map[string]SessionSnapshot), peers: make(map[string]PeerSnapshot)}
	writer := NewWriter(store, time.Hour, nil)
	ctx := context.Background()

	first := PeerSnapshot{Role: "mme", Addr: "10.0.0.1:2123", RecoverySeen: true, RecoveryCounter: 1}
	second := first
	second.RecoveryCounter = 2
	writer.SavePeerSnapshot(first)
	writer.SavePeerSnapshot(second)

	if err := writer.Flush(ctx); err != nil {
		t.Fatalf("Flush: %v", err)
	}
	if store.peerSaveCount != 1 {
		t.Fatalf("peerSaveCount = %d; want 1 coalesced save", store.peerSaveCount)
	}
	if got := store.peers[peerKey("mme", "10.0.0.1:2123")].RecoveryCounter; got != 2 {
		t.Fatalf("saved peer recovery = %d; want latest 2", got)
	}
}

type memoryStore struct {
	sessions      map[string]SessionSnapshot
	peers         map[string]PeerSnapshot
	saveErr       error
	deleteErr     error
	saveCount     int
	deleteCount   int
	peerSaveCount int
}

func (m *memoryStore) SaveSession(_ context.Context, snapshot SessionSnapshot) error {
	m.saveCount++
	if m.saveErr != nil {
		return m.saveErr
	}
	m.sessions[snapshot.SessionID] = snapshot
	return nil
}

func (m *memoryStore) DeleteSession(_ context.Context, sessionID string) error {
	m.deleteCount++
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.sessions, sessionID)
	return nil
}

func (m *memoryStore) LoadSession(_ context.Context, sessionID string) (SessionSnapshot, error) {
	snapshot, ok := m.sessions[sessionID]
	if !ok {
		return SessionSnapshot{}, ErrNotFound
	}
	return snapshot, nil
}

func (m *memoryStore) LoadSessions(context.Context) ([]SessionSnapshot, error) {
	out := make([]SessionSnapshot, 0, len(m.sessions))
	for _, snapshot := range m.sessions {
		out = append(out, snapshot)
	}
	return out, nil
}

func (m *memoryStore) SavePeer(_ context.Context, snapshot PeerSnapshot) error {
	m.peerSaveCount++
	if m.saveErr != nil {
		return m.saveErr
	}
	if m.peers == nil {
		m.peers = make(map[string]PeerSnapshot)
	}
	m.peers[peerKey(snapshot.Role, snapshot.Addr)] = snapshot
	return nil
}

func (m *memoryStore) DeletePeer(_ context.Context, role, addr string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.peers, peerKey(role, addr))
	return nil
}

func (m *memoryStore) LoadPeers(context.Context) ([]PeerSnapshot, error) {
	out := make([]PeerSnapshot, 0, len(m.peers))
	for _, snapshot := range m.peers {
		out = append(out, snapshot)
	}
	return out, nil
}

func (m *memoryStore) Close() error {
	return nil
}
