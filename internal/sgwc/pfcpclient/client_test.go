package pfcpclient

import (
	"net"
	"testing"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
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
