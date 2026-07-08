package e2e

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"vectorcore-sgw/internal/api"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

func TestSessionRecoveryCheckpointRestartGate(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	stateDB := filepath.Join(t.TempDir(), "sgwc-state.db")
	store, err := sessioncheckpoint.OpenSQLite(ctx, sessioncheckpoint.SQLiteOptions{Path: stateDB})
	if err != nil {
		t.Fatalf("OpenSQLite: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	before := session.NewManager()
	sess, _, err := before.Create(session.CreateParams{
		IMSI:            "311435300070599",
		APN:             "ims.mnc435.mcc311.gprs",
		RATType:         6,
		ServingNetwork:  "311-435",
		MMEControlFTEID: session.FTEID{TEID: 0xAABBCCDD, IPv4: netip.MustParseAddr("10.90.250.77")},
		DefaultEBI:      6,
		QCI:             5,
		ARP:             bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create source session: %v", err)
	}
	sess.PFCP = session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 0x1111, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 0x2222, IPv4: netip.MustParseAddr("10.90.250.59")},
		SGWUName:    "sgwu-a",
		SGWUAddr:    "10.90.250.59:8805",
		Established: true,
	}
	if !sess.Transition(session.StateActive) {
		t.Fatalf("Transition source session to active failed")
	}
	if err := store.SaveSession(ctx, sess.Snapshot()); err != nil {
		t.Fatalf("SaveSession checkpoint: %v", err)
	}
	if err := store.SavePeer(ctx, sessioncheckpoint.PeerSnapshot{
		Role:            "mme",
		Addr:            "10.90.250.77:2123",
		State:           "up",
		RecoverySeen:    true,
		RecoveryCounter: 9,
		UpdatedAt:       time.Unix(100, 0).UTC(),
	}); err != nil {
		t.Fatalf("SavePeer checkpoint: %v", err)
	}

	after := session.NewManager()
	snapshots, err := store.LoadSessions(ctx)
	if err != nil {
		t.Fatalf("LoadSessions: %v", err)
	}
	restoreResult, err := after.RestoreSnapshots(snapshots)
	if err != nil {
		t.Fatalf("RestoreSnapshots: %v", err)
	}
	reconcile := after.ReconcilePFCPBindings(nil, time.Unix(200, 0).UTC())
	peers, err := store.LoadPeers(ctx)
	if err != nil {
		t.Fatalf("LoadPeers: %v", err)
	}

	status := sessioncheckpoint.NewStatusTracker(sessioncheckpoint.RuntimeConfig{
		Enabled:                   true,
		Backend:                   sessioncheckpoint.BackendSQLite,
		SQLitePath:                stateDB,
		RestoreOnStartup:          true,
		ReconcileOnStartup:        true,
		CheckpointIntervalSeconds: 5,
	})
	status.RecordSessionRestore(restoreResult.Loaded, restoreResult.Restored, restoreResult.SkippedDeleted, restoreResult.SkippedInvalid, restoreResult.ReservedS11TEID)
	status.RecordPeerSnapshotsLoaded(len(peers))

	if restoreResult.Restored != 1 || reconcile.Unverifiable != 1 {
		t.Fatalf("restore/reconcile = %+v/%+v; want one restored and unverifiable without live inventory", restoreResult, reconcile)
	}

	apiAddr := freeTCPAddr(t)
	srv := api.NewServer(apiAddr, api.BuildInfo{Component: "SGW-C", Version: "test", BuildDate: "phase9"}, slog.New(slog.DiscardHandler))
	api.RegisterSGWCRoutes(srv.HumaAPI(), after)
	api.RegisterRecoveryRoutes(srv.HumaAPI(), status, after)
	if err := srv.Start(ctx); err != nil {
		t.Fatalf("API Start: %v", err)
	}
	t.Cleanup(func() { _ = srv.Stop() })

	var out struct {
		Checkpoint sessioncheckpoint.RuntimeStatus `json:"checkpoint"`
		Summary    api.RecoverySummaryView         `json:"summary"`
	}
	getE2EJSON(t, "http://"+apiAddr+"/recovery/status", &out)
	if out.Checkpoint.SessionsRestored != 1 || out.Checkpoint.PeerSnapshotsLoaded != 1 {
		t.Fatalf("recovery checkpoint status = %+v; want restored session and peer snapshot", out.Checkpoint)
	}
	if out.Summary.TotalSessions != 1 ||
		out.Summary.SessionsByState[string(session.StateRecovering)] != 1 ||
		out.Summary.PFCPReconciliation[string(session.PFCPReconciliationUnverifiable)] != 1 {
		t.Fatalf("recovery summary = %+v; want one recovering unverifiable session", out.Summary)
	}
}

func getE2EJSON(t *testing.T, url string, dst any) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("GET %s status = %s", url, resp.Status)
	}
	if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
}
