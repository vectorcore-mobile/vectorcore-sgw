package sessioncheckpoint

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestSQLiteStoreSaveLoadListDelete(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgwc-state.db")
	store, err := OpenSQLite(ctx, SQLiteOptions{
		Path: path,
		Now:  func() time.Time { return time.Unix(1000, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer store.Close()

	first := testSnapshot("sess-1", "311435300070599", "ims.mnc435.mcc311.gprs", 0xabc1, 6)
	if err := store.SaveSession(ctx, first); err != nil {
		t.Fatalf("SaveSession first: %v", err)
	}

	loaded, err := store.LoadSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("LoadSession first: %v", err)
	}
	if loaded.IMSI != first.IMSI || loaded.SGWS11FTEID.TEID != first.SGWS11FTEID.TEID || loaded.DefaultBearerID != 6 {
		t.Fatalf("loaded first = %+v; want %+v", loaded, first)
	}

	first.APN = "internet.mnc435.mcc311.gprs"
	first.DefaultBearerID = 5
	first.UpdatedAt = first.UpdatedAt.Add(time.Second)
	if err := store.SaveSession(ctx, first); err != nil {
		t.Fatalf("SaveSession update: %v", err)
	}

	second := testSnapshot("sess-2", "311435300070599", "ims.mnc435.mcc311.gprs", 0xabc1, 6)
	second.SGWS5CFTEID.TEID = 0x5002
	if err := store.SaveSession(ctx, second); err != nil {
		t.Fatalf("SaveSession second: %v", err)
	}

	all, err := store.LoadSessions(ctx)
	if err != nil {
		t.Fatalf("LoadSessions: %v", err)
	}
	if len(all) != 2 {
		t.Fatalf("LoadSessions count = %d; want 2", len(all))
	}

	if err := store.DeleteSession(ctx, "sess-1"); err != nil {
		t.Fatalf("DeleteSession: %v", err)
	}
	_, err = store.LoadSession(ctx, "sess-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("LoadSession deleted error = %v; want ErrNotFound", err)
	}
}

func TestSQLiteStorePersistsAcrossReopen(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgwc-state.db")
	store, err := OpenSQLite(ctx, SQLiteOptions{Path: path})
	if err != nil {
		t.Fatalf("OpenSQLite first: %v", err)
	}
	if err := store.SaveSession(ctx, testSnapshot("sess-1", "00101", "ims", 10, 6)); err != nil {
		t.Fatalf("SaveSession: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close first store: %v", err)
	}

	reopened, err := OpenSQLite(ctx, SQLiteOptions{Path: path})
	if err != nil {
		t.Fatalf("OpenSQLite reopen: %v", err)
	}
	defer reopened.Close()
	loaded, err := reopened.LoadSession(ctx, "sess-1")
	if err != nil {
		t.Fatalf("LoadSession after reopen: %v", err)
	}
	if loaded.SessionID != "sess-1" || loaded.IMSI != "00101" {
		t.Fatalf("loaded after reopen = %+v", loaded)
	}
}

func TestSQLiteStoreSaveLoadPeerSnapshots(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgwc-state.db")
	store, err := OpenSQLite(ctx, SQLiteOptions{Path: path})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer store.Close()

	mme := PeerSnapshot{
		Role:            "mme",
		Addr:            "10.90.250.77:2123",
		State:           "up",
		RecoverySeen:    true,
		RecoveryCounter: 7,
		UpdatedAt:       time.Unix(100, 0).UTC(),
	}
	sgwu := PeerSnapshot{
		Role:              "sgwu",
		Name:              "sgwu-a",
		Addr:              "192.0.2.10:8805",
		State:             "Established",
		RecoverySeen:      true,
		RecoveryTimestamp: 0x65000001,
		UpdatedAt:         time.Unix(101, 0).UTC(),
	}
	if err := store.SavePeer(ctx, mme); err != nil {
		t.Fatalf("SavePeer mme: %v", err)
	}
	if err := store.SavePeer(ctx, sgwu); err != nil {
		t.Fatalf("SavePeer sgwu: %v", err)
	}

	peers, err := store.LoadPeers(ctx)
	if err != nil {
		t.Fatalf("LoadPeers: %v", err)
	}
	if len(peers) != 2 {
		t.Fatalf("LoadPeers count = %d; want 2", len(peers))
	}
	if peers[0].Role != "mme" || peers[0].RecoveryCounter != 7 {
		t.Fatalf("first peer = %+v; want mme recovery counter 7", peers[0])
	}
	if peers[1].Role != "sgwu" || peers[1].RecoveryTimestamp != 0x65000001 {
		t.Fatalf("second peer = %+v; want sgwu recovery timestamp", peers[1])
	}

	mme.RecoveryCounter = 8
	if err := store.SavePeer(ctx, mme); err != nil {
		t.Fatalf("SavePeer update: %v", err)
	}
	peers, err = store.LoadPeers(ctx)
	if err != nil {
		t.Fatalf("LoadPeers after update: %v", err)
	}
	if peers[0].RecoveryCounter != 8 {
		t.Fatalf("updated MME recovery = %d; want 8", peers[0].RecoveryCounter)
	}

	if err := store.DeletePeer(ctx, "mme", "10.90.250.77:2123"); err != nil {
		t.Fatalf("DeletePeer: %v", err)
	}
	peers, err = store.LoadPeers(ctx)
	if err != nil {
		t.Fatalf("LoadPeers after delete: %v", err)
	}
	if len(peers) != 1 || peers[0].Role != "sgwu" {
		t.Fatalf("peers after delete = %+v; want only sgwu", peers)
	}
}

func TestSQLiteStoreRejectsCorruptSnapshotRows(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "sgwc-state.db")
	store, err := OpenSQLite(ctx, SQLiteOptions{Path: path})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	defer store.Close()
	if _, err := store.db.ExecContext(ctx, `
INSERT INTO sessions(session_id, imsi, apn, sgw_s11_teid, default_ebi, updated_at, snapshot_json)
VALUES('bad', '00101', 'ims', 10, 6, 'now', '{"schema_version":999}')
`); err != nil {
		t.Fatalf("insert corrupt row: %v", err)
	}
	_, err = store.LoadSession(ctx, "bad")
	if err == nil {
		t.Fatal("LoadSession succeeded with corrupt snapshot row")
	}
}

func TestSQLiteStoreCreatesParentDirectoryAndSchema(t *testing.T) {
	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nested", "state", "sgwc-state.db")
	store, err := OpenSQLite(ctx, SQLiteOptions{Path: path})
	if err != nil {
		t.Fatalf("OpenSQLite nested path: %v", err)
	}
	defer store.Close()

	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("open raw sqlite: %v", err)
	}
	defer db.Close()
	var version string
	if err := db.QueryRowContext(ctx, `SELECT value FROM schema_meta WHERE key = 'schema_version'`).Scan(&version); err != nil {
		t.Fatalf("query schema version: %v", err)
	}
	if version != "1" {
		t.Fatalf("schema version = %q; want 1", version)
	}
}

func TestDefaultSQLitePath(t *testing.T) {
	if got := DefaultSQLitePath("/tmp/vectorcore"); got != filepath.Join("/tmp/vectorcore", "sgwc-state.db") {
		t.Fatalf("DefaultSQLitePath custom = %q", got)
	}
	if got := DefaultSQLitePath(""); got != filepath.Join("/var/lib/vectorcore-sgw", "sgwc-state.db") {
		t.Fatalf("DefaultSQLitePath empty = %q", got)
	}
}

func testSnapshot(sessionID, imsi, apn string, sgwS11TEID uint32, defaultEBI uint8) SessionSnapshot {
	now := time.Unix(100, 0).UTC()
	return SessionSnapshot{
		SessionID:       sessionID,
		IMSI:            imsi,
		APN:             apn,
		SGWS11FTEID:     FTEIDSnapshot{TEID: sgwS11TEID, IPv4: "10.90.250.10"},
		SGWS5CFTEID:     FTEIDSnapshot{TEID: 0x5001, IPv4: "10.90.250.10"},
		DefaultBearerID: defaultEBI,
		State:           "active",
		CreatedAt:       now,
		UpdatedAt:       now,
		Bearers: []BearerSnapshot{
			{EBI: defaultEBI, QCI: 5, State: "active", PDRIDs: [2]uint32{1, 2}, FARIDs: [2]uint32{1, 2}},
		},
	}
}
