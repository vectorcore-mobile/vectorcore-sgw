package sessioncheckpoint

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

const sqliteSchemaVersion = 1

const DefaultSQLiteFileName = "sgwc-state.db"

type SQLiteOptions struct {
	Path        string
	BusyTimeout time.Duration
	Now         func() time.Time
}

type SQLiteStore struct {
	db  *sql.DB
	now func() time.Time
}

func DefaultSQLitePath(stateDir string) string {
	if stateDir == "" {
		stateDir = "/var/lib/vectorcore-sgw"
	}
	return filepath.Join(stateDir, DefaultSQLiteFileName)
}

func OpenSQLite(ctx context.Context, opts SQLiteOptions) (*SQLiteStore, error) {
	if opts.Path == "" {
		return nil, fmt.Errorf("sqlite checkpoint path is required")
	}
	if opts.Path != ":memory:" {
		if err := os.MkdirAll(filepath.Dir(opts.Path), 0o755); err != nil {
			return nil, fmt.Errorf("create sqlite checkpoint dir: %w", err)
		}
	}
	db, err := sql.Open("sqlite", opts.Path)
	if err != nil {
		return nil, fmt.Errorf("open sqlite checkpoint db: %w", err)
	}
	store := &SQLiteStore{
		db:  db,
		now: opts.Now,
	}
	if store.now == nil {
		store.now = time.Now
	}
	if opts.BusyTimeout <= 0 {
		opts.BusyTimeout = 5 * time.Second
	}
	if err := store.configure(ctx, opts.BusyTimeout); err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

func (s *SQLiteStore) configure(ctx context.Context, busyTimeout time.Duration) error {
	pragmas := []string{
		"PRAGMA journal_mode=WAL",
		fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeout.Milliseconds()),
		"PRAGMA foreign_keys=ON",
	}
	for _, stmt := range pragmas {
		if _, err := s.db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("configure sqlite checkpoint db %q: %w", stmt, err)
		}
	}
	if _, err := s.db.ExecContext(ctx, `
CREATE TABLE IF NOT EXISTS schema_meta (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
	session_id TEXT PRIMARY KEY,
	imsi TEXT NOT NULL,
	apn TEXT NOT NULL,
	sgw_s11_teid INTEGER NOT NULL,
	default_ebi INTEGER NOT NULL,
	updated_at TEXT NOT NULL,
	snapshot_json TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS sessions_imsi_idx ON sessions(imsi);
CREATE INDEX IF NOT EXISTS sessions_sgw_s11_teid_idx ON sessions(sgw_s11_teid);
CREATE TABLE IF NOT EXISTS peers (
	role TEXT NOT NULL,
	addr TEXT NOT NULL,
	updated_at TEXT NOT NULL,
	snapshot_json TEXT NOT NULL,
	PRIMARY KEY(role, addr)
);
`); err != nil {
		return fmt.Errorf("create sqlite checkpoint schema: %w", err)
	}
	now := s.now().UTC().Format(time.RFC3339Nano)
	if _, err := s.db.ExecContext(ctx, `
INSERT INTO schema_meta(key, value, updated_at)
VALUES('schema_version', ?, ?)
ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
`, sqliteSchemaVersion, now); err != nil {
		return fmt.Errorf("write sqlite checkpoint schema version: %w", err)
	}
	return nil
}

func (s *SQLiteStore) SaveSession(ctx context.Context, snapshot SessionSnapshot) error {
	if snapshot.SessionID == "" {
		return fmt.Errorf("session checkpoint snapshot missing session_id")
	}
	raw, err := Marshal(snapshot)
	if err != nil {
		return fmt.Errorf("marshal session checkpoint snapshot: %w", err)
	}
	updatedAt := snapshot.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = s.now()
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO sessions(session_id, imsi, apn, sgw_s11_teid, default_ebi, updated_at, snapshot_json)
VALUES(?, ?, ?, ?, ?, ?, ?)
ON CONFLICT(session_id) DO UPDATE SET
	imsi = excluded.imsi,
	apn = excluded.apn,
	sgw_s11_teid = excluded.sgw_s11_teid,
	default_ebi = excluded.default_ebi,
	updated_at = excluded.updated_at,
	snapshot_json = excluded.snapshot_json
`, snapshot.SessionID, snapshot.IMSI, snapshot.APN, snapshot.SGWS11FTEID.TEID, snapshot.DefaultBearerID, updatedAt.UTC().Format(time.RFC3339Nano), string(raw))
	if err != nil {
		return fmt.Errorf("save session checkpoint %q: %w", snapshot.SessionID, err)
	}
	return nil
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, sessionID string) error {
	if sessionID == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE session_id = ?`, sessionID)
	if err != nil {
		return fmt.Errorf("delete session checkpoint %q: %w", sessionID, err)
	}
	return nil
}

func (s *SQLiteStore) LoadSession(ctx context.Context, sessionID string) (SessionSnapshot, error) {
	var raw string
	err := s.db.QueryRowContext(ctx, `SELECT snapshot_json FROM sessions WHERE session_id = ?`, sessionID).Scan(&raw)
	if errors.Is(err, sql.ErrNoRows) {
		return SessionSnapshot{}, ErrNotFound
	}
	if err != nil {
		return SessionSnapshot{}, fmt.Errorf("load session checkpoint %q: %w", sessionID, err)
	}
	snapshot, err := Unmarshal([]byte(raw))
	if err != nil {
		return SessionSnapshot{}, fmt.Errorf("decode session checkpoint %q: %w", sessionID, err)
	}
	return snapshot, nil
}

func (s *SQLiteStore) LoadSessions(ctx context.Context) ([]SessionSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT session_id, snapshot_json FROM sessions ORDER BY session_id`)
	if err != nil {
		return nil, fmt.Errorf("list session checkpoints: %w", err)
	}
	defer rows.Close()

	var snapshots []SessionSnapshot
	for rows.Next() {
		var sessionID, raw string
		if err := rows.Scan(&sessionID, &raw); err != nil {
			return nil, fmt.Errorf("scan session checkpoint row: %w", err)
		}
		snapshot, err := Unmarshal([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("decode session checkpoint %q: %w", sessionID, err)
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate session checkpoints: %w", err)
	}
	return snapshots, nil
}

func (s *SQLiteStore) SavePeer(ctx context.Context, snapshot PeerSnapshot) error {
	if snapshot.Role == "" || snapshot.Addr == "" {
		return fmt.Errorf("peer checkpoint snapshot missing role or addr")
	}
	raw, err := MarshalPeer(snapshot)
	if err != nil {
		return fmt.Errorf("marshal peer checkpoint snapshot: %w", err)
	}
	updatedAt := snapshot.UpdatedAt
	if updatedAt.IsZero() {
		updatedAt = s.now()
	}
	_, err = s.db.ExecContext(ctx, `
INSERT INTO peers(role, addr, updated_at, snapshot_json)
VALUES(?, ?, ?, ?)
ON CONFLICT(role, addr) DO UPDATE SET
	updated_at = excluded.updated_at,
	snapshot_json = excluded.snapshot_json
`, snapshot.Role, snapshot.Addr, updatedAt.UTC().Format(time.RFC3339Nano), string(raw))
	if err != nil {
		return fmt.Errorf("save peer checkpoint %s/%s: %w", snapshot.Role, snapshot.Addr, err)
	}
	return nil
}

func (s *SQLiteStore) DeletePeer(ctx context.Context, role, addr string) error {
	if role == "" || addr == "" {
		return nil
	}
	_, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE role = ? AND addr = ?`, role, addr)
	if err != nil {
		return fmt.Errorf("delete peer checkpoint %s/%s: %w", role, addr, err)
	}
	return nil
}

func (s *SQLiteStore) LoadPeers(ctx context.Context) ([]PeerSnapshot, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT role, addr, snapshot_json FROM peers ORDER BY role, addr`)
	if err != nil {
		return nil, fmt.Errorf("list peer checkpoints: %w", err)
	}
	defer rows.Close()

	var snapshots []PeerSnapshot
	for rows.Next() {
		var role, addr, raw string
		if err := rows.Scan(&role, &addr, &raw); err != nil {
			return nil, fmt.Errorf("scan peer checkpoint row: %w", err)
		}
		snapshot, err := UnmarshalPeer([]byte(raw))
		if err != nil {
			return nil, fmt.Errorf("decode peer checkpoint %s/%s: %w", role, addr, err)
		}
		snapshots = append(snapshots, snapshot)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate peer checkpoints: %w", err)
	}
	return snapshots, nil
}

func (s *SQLiteStore) Close() error {
	if s == nil || s.db == nil {
		return nil
	}
	return s.db.Close()
}
