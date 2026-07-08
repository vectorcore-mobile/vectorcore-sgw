package pfcpclient

import (
	"net"
	"testing"
	"time"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

func TestIsRecoveryRestart(t *testing.T) {
	tests := []struct {
		name  string
		oldTS uint32
		newTS uint32
		want  bool
	}{
		{name: "initial timestamp is not restart", oldTS: 0, newTS: 100, want: false},
		{name: "same timestamp is not restart", oldTS: 100, newTS: 100, want: false},
		{name: "changed timestamp is restart", oldTS: 100, newTS: 200, want: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isRecoveryRestart(tc.oldTS, tc.newTS); got != tc.want {
				t.Fatalf("isRecoveryRestart(%d, %d) = %v; want %v", tc.oldTS, tc.newTS, got, tc.want)
			}
		})
	}
}

func TestNotifyPeerRestartCallback(t *testing.T) {
	c := &Client{}
	p := &peer{cfg: sgwcconfig.SGWUPeer{Name: "sgwu-a", Addr: "192.0.2.10:8805"}}

	var gotName, gotAddr string
	var gotOld, gotNew uint32
	c.SetPeerRestartCallback(func(peerName, peerAddr string, oldTS, newTS uint32) {
		gotName = peerName
		gotAddr = peerAddr
		gotOld = oldTS
		gotNew = newTS
	})

	c.notifyPeerRestart(p, 100, 200)
	if gotName != "sgwu-a" || gotAddr != "192.0.2.10:8805" || gotOld != 100 || gotNew != 200 {
		t.Fatalf("restart callback got (%q, %q, %d, %d)", gotName, gotAddr, gotOld, gotNew)
	}
}

func TestSelectPeerRoundRobinEstablishedPeers(t *testing.T) {
	c := &Client{peers: []*peer{
		testPeer("sgwu-a", "192.0.2.10:8805", PeerStateEstablished),
		testPeer("sgwu-b", "192.0.2.11:8805", PeerStateEstablished),
	}}

	p1, err := c.SelectPeer()
	if err != nil {
		t.Fatalf("SelectPeer #1: %v", err)
	}
	p2, err := c.SelectPeer()
	if err != nil {
		t.Fatalf("SelectPeer #2: %v", err)
	}
	p3, err := c.SelectPeer()
	if err != nil {
		t.Fatalf("SelectPeer #3: %v", err)
	}

	if p1.cfg.Name != "sgwu-a" || p2.cfg.Name != "sgwu-b" || p3.cfg.Name != "sgwu-a" {
		t.Fatalf("round-robin peers = %s, %s, %s; want sgwu-a, sgwu-b, sgwu-a",
			p1.cfg.Name, p2.cfg.Name, p3.cfg.Name)
	}
}

func TestSelectPeerSkipsDownPeers(t *testing.T) {
	c := &Client{peers: []*peer{
		testPeer("sgwu-a", "192.0.2.10:8805", PeerStateDown),
		testPeer("sgwu-b", "192.0.2.11:8805", PeerStateEstablished),
	}}

	for i := 0; i < 3; i++ {
		p, err := c.SelectPeer()
		if err != nil {
			t.Fatalf("SelectPeer #%d: %v", i+1, err)
		}
		if p.cfg.Name != "sgwu-b" {
			t.Fatalf("SelectPeer #%d = %s; want sgwu-b", i+1, p.cfg.Name)
		}
	}
}

func TestSelectPeerByAddrRequiresConfiguredEstablishedPeer(t *testing.T) {
	c := &Client{peers: []*peer{
		testPeer("sgwu-a", "192.0.2.10:8805", PeerStateEstablished),
		testPeer("sgwu-b", "192.0.2.11:8805", PeerStateDown),
	}}

	p, err := c.selectPeerByAddr("192.0.2.10:8805")
	if err != nil {
		t.Fatalf("selectPeerByAddr established: %v", err)
	}
	if p.cfg.Name != "sgwu-a" {
		t.Fatalf("selectPeerByAddr returned %s; want sgwu-a", p.cfg.Name)
	}

	if _, err := c.selectPeerByAddr("192.0.2.11:8805"); err == nil {
		t.Fatal("selectPeerByAddr succeeded for Down peer")
	}
	if _, err := c.selectPeerByAddr("192.0.2.12:8805"); err == nil {
		t.Fatal("selectPeerByAddr succeeded for unconfigured peer")
	}
}

func TestRestoreCheckpointSnapshotsSeedsPFCPPeerRecovery(t *testing.T) {
	c := &Client{peers: []*peer{
		testPeer("sgwu-a", "192.0.2.10:8805", PeerStatePending),
		testPeer("sgwu-b", "192.0.2.11:8805", PeerStatePending),
	}}
	updatedAt := time.Unix(100, 0).UTC()

	restored := c.RestoreCheckpointSnapshots([]sessioncheckpoint.PeerSnapshot{
		{Role: "sgwu", Name: "sgwu-a", Addr: "192.0.2.10:8805", State: string(PeerStateEstablished), RecoveryTimestamp: 1234, UpdatedAt: updatedAt},
		{Role: "mme", Addr: "10.0.0.1:2123", RecoveryCounter: 7},
	})
	if restored != 1 {
		t.Fatalf("restored = %d; want 1", restored)
	}

	views := c.Peers()
	if views[0].PeerRecoveryTimestamp != 1234 || views[0].State != string(PeerStateEstablished) || !views[0].LastSeen.Equal(updatedAt) {
		t.Fatalf("restored peer view = %+v; want timestamp/state/last_seen from checkpoint", views[0])
	}
	if views[1].PeerRecoveryTimestamp != 0 {
		t.Fatalf("unmatched peer timestamp = %d; want 0", views[1].PeerRecoveryTimestamp)
	}
}

func TestCheckpointSnapshotsExportPFCPPeerRecovery(t *testing.T) {
	c := &Client{peers: []*peer{
		testPeer("sgwu-a", "192.0.2.10:8805", PeerStateEstablished),
	}}
	c.peers[0].peerRecoveryTS = 5678
	c.peers[0].lastSeen = time.Unix(200, 0).UTC()

	snapshots := c.CheckpointSnapshots()
	if len(snapshots) != 1 {
		t.Fatalf("snapshots = %d; want 1", len(snapshots))
	}
	got := snapshots[0]
	if got.Role != "sgwu" || got.Name != "sgwu-a" || got.Addr != "192.0.2.10:8805" ||
		!got.RecoverySeen || got.RecoveryTimestamp != 5678 {
		t.Fatalf("checkpoint snapshot = %+v; want SGW-U recovery timestamp", got)
	}
}

func testPeer(name, addr string, state PeerState) *peer {
	udpAddr, err := net.ResolveUDPAddr("udp4", addr)
	if err != nil {
		panic(err)
	}
	return &peer{
		cfg:   sgwcconfig.SGWUPeer{Name: name, Addr: addr},
		addr:  udpAddr,
		state: state,
	}
}
