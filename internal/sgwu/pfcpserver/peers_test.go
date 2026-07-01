package pfcpserver

import (
	"net"
	"net/netip"
	"testing"
	"time"

	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

func TestPeersReturnsAssociationSnapshotWithSessionCount(t *testing.T) {
	store := sgwusession.NewStore()
	if err := store.Create(&sgwusession.Session{
		CPSEID:    1,
		UPSEID:    11,
		CPNodeKey: "ipv4:192.0.2.10",
	}); err != nil {
		t.Fatalf("Create session 1: %v", err)
	}
	if err := store.Create(&sgwusession.Session{
		CPSEID:    2,
		UPSEID:    22,
		CPNodeKey: "ipv4:192.0.2.10",
	}); err != nil {
		t.Fatalf("Create session 2: %v", err)
	}
	if err := store.Create(&sgwusession.Session{
		CPSEID:    3,
		UPSEID:    33,
		CPNodeKey: "ipv4:192.0.2.20",
	}); err != nil {
		t.Fatalf("Create unrelated session: %v", err)
	}

	lastSeen := time.Unix(1710000000, 0).UTC()
	s := &Server{sessions: store}
	s.peers.Store("ipv4:192.0.2.10", &PeerRecord{
		nodeIDKey:  "ipv4:192.0.2.10",
		recoveryTS: 0x01020304,
		lastSeen:   lastSeen,
		lastAddr:   &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8805},
	})

	peers := s.Peers()
	if len(peers) != 1 {
		t.Fatalf("Peers len = %d; want 1", len(peers))
	}
	got := peers[0]
	if got.NodeIDKey != "ipv4:192.0.2.10" || got.State != "Established" ||
		got.RecoveryTimestamp != 0x01020304 || !got.LastSeen.Equal(lastSeen) ||
		got.LastAddr != "192.0.2.10:8805" || got.SessionCount != 2 {
		t.Fatalf("Peer view = %+v; want association snapshot with two sessions", got)
	}
}

func TestCountByCPNodeKey(t *testing.T) {
	store := sgwusession.NewStore()
	for _, sess := range []*sgwusession.Session{
		{CPSEID: 1, UPSEID: 11, CPNodeKey: "ipv4:192.0.2.10"},
		{CPSEID: 2, UPSEID: 22, CPNodeKey: "ipv4:192.0.2.10"},
		{CPSEID: 3, UPSEID: 33, CPNodeKey: "ipv4:192.0.2.20", PDRs: []sgwusession.PDR{{LocalIP: netip.MustParseAddr("10.0.0.1")}}},
	} {
		if err := store.Create(sess); err != nil {
			t.Fatalf("Create %+v: %v", sess, err)
		}
	}
	if got := store.CountByCPNodeKey("ipv4:192.0.2.10"); got != 2 {
		t.Fatalf("CountByCPNodeKey = %d; want 2", got)
	}
	if got := store.CountByCPNodeKey("ipv4:198.51.100.1"); got != 0 {
		t.Fatalf("CountByCPNodeKey missing = %d; want 0", got)
	}
}
