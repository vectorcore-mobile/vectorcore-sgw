package sessioncheckpoint

import (
	"context"
	"log/slog"
	"sync"
	"time"
)

type Writer struct {
	store    Store
	interval time.Duration
	log      *slog.Logger
	status   *StatusTracker

	mu      sync.Mutex
	dirty   map[string]SessionSnapshot
	deleted map[string]struct{}
	peers   map[string]PeerSnapshot
	done    chan struct{}
	once    sync.Once
}

func NewWriter(store Store, interval time.Duration, log *slog.Logger) *Writer {
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if log == nil {
		log = slog.Default()
	}
	return &Writer{
		store:    store,
		interval: interval,
		log:      log,
		dirty:    make(map[string]SessionSnapshot),
		deleted:  make(map[string]struct{}),
		peers:    make(map[string]PeerSnapshot),
		done:     make(chan struct{}),
	}
}

func (w *Writer) SetStatusTracker(status *StatusTracker) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.status = status
}

func (w *Writer) Start(ctx context.Context) {
	go w.loop(ctx)
}

func (w *Writer) SaveSessionSnapshot(snapshot SessionSnapshot) {
	if w == nil || w.store == nil || snapshot.SessionID == "" {
		return
	}
	w.mu.Lock()
	delete(w.deleted, snapshot.SessionID)
	w.dirty[snapshot.SessionID] = snapshot
	w.mu.Unlock()
}

func (w *Writer) SavePeerSnapshot(snapshot PeerSnapshot) {
	if w == nil || w.store == nil || snapshot.Role == "" || snapshot.Addr == "" {
		return
	}
	w.mu.Lock()
	w.peers[peerKey(snapshot.Role, snapshot.Addr)] = snapshot
	w.mu.Unlock()
}

func (w *Writer) DeleteSessionSnapshot(sessionID string) {
	if w == nil || w.store == nil || sessionID == "" {
		return
	}
	w.mu.Lock()
	delete(w.dirty, sessionID)
	w.deleted[sessionID] = struct{}{}
	w.mu.Unlock()
}

func (w *Writer) Flush(ctx context.Context) error {
	if w == nil || w.store == nil {
		return nil
	}
	var flushErr error
	defer func() {
		w.statusTracker().RecordFlush(flushErr, time.Now())
	}()
	dirty, deleted, peers := w.drain()
	for sessionID := range deleted {
		if err := w.store.DeleteSession(ctx, sessionID); err != nil {
			w.requeueDelete(sessionID)
			flushErr = err
			return err
		}
		w.statusTracker().RecordSessionDelete()
	}
	for _, snapshot := range dirty {
		if err := w.store.SaveSession(ctx, snapshot); err != nil {
			w.requeueSave(snapshot)
			flushErr = err
			return err
		}
		w.statusTracker().RecordSessionSave()
	}
	for _, snapshot := range peers {
		if err := w.store.SavePeer(ctx, snapshot); err != nil {
			w.requeuePeer(snapshot)
			flushErr = err
			return err
		}
		w.statusTracker().RecordPeerSave()
	}
	return nil
}

func (w *Writer) Close(ctx context.Context) error {
	if w == nil {
		return nil
	}
	w.once.Do(func() {
		close(w.done)
	})
	return w.Flush(ctx)
}

func (w *Writer) loop(ctx context.Context) {
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			if err := w.Flush(context.Background()); err != nil {
				w.log.Warn("SGW-C session checkpoint flush on shutdown failed", "error", err)
			}
			return
		case <-w.done:
			return
		case <-ticker.C:
			if err := w.Flush(ctx); err != nil {
				w.log.Warn("SGW-C session checkpoint flush failed", "error", err)
			}
		}
	}
}

func (w *Writer) drain() (map[string]SessionSnapshot, map[string]struct{}, map[string]PeerSnapshot) {
	w.mu.Lock()
	defer w.mu.Unlock()
	dirty := w.dirty
	deleted := w.deleted
	peers := w.peers
	w.dirty = make(map[string]SessionSnapshot)
	w.deleted = make(map[string]struct{})
	w.peers = make(map[string]PeerSnapshot)
	return dirty, deleted, peers
}

func (w *Writer) requeueSave(snapshot SessionSnapshot) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if _, deleted := w.deleted[snapshot.SessionID]; deleted {
		return
	}
	w.dirty[snapshot.SessionID] = snapshot
}

func (w *Writer) requeueDelete(sessionID string) {
	w.mu.Lock()
	defer w.mu.Unlock()
	delete(w.dirty, sessionID)
	w.deleted[sessionID] = struct{}{}
}

func (w *Writer) requeuePeer(snapshot PeerSnapshot) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.peers[peerKey(snapshot.Role, snapshot.Addr)] = snapshot
}

func (w *Writer) statusTracker() *StatusTracker {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.status
}

func peerKey(role, addr string) string {
	return role + "\x00" + addr
}
