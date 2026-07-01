package pfcpserver

import (
	"errors"
	"net"
	"net/netip"
	"testing"

	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

type fakeBPFInstaller struct {
	updateErr error
	updated   *sgwusession.Session
	removed   []*sgwusession.Session
}

func (f *fakeBPFInstaller) InstallSession(*sgwusession.Session) error {
	return nil
}

func (f *fakeBPFInstaller) UpdateSession(sess *sgwusession.Session) error {
	f.updated = sess
	return f.updateErr
}

func (f *fakeBPFInstaller) RemoveSession(sess *sgwusession.Session) error {
	f.removed = append(f.removed, sess)
	return nil
}

func TestCreatedPDRFTEIDUsesGTPUInterfaceIP(t *testing.T) {
	s := &Server{
		accessIP: netip.MustParseAddr("10.90.251.11"),
		coreIP:   netip.MustParseAddr("10.90.252.11"),
	}

	tests := []struct {
		name            string
		sourceInterface uint8
		wantIP          netip.Addr
	}{
		{
			name:            "access PDR returns S1-U address",
			sourceInterface: pfcpie.SourceInterfaceAccess,
			wantIP:          netip.MustParseAddr("10.90.251.11"),
		},
		{
			name:            "core PDR returns S5/S8-U address",
			sourceInterface: pfcpie.SourceInterfaceCore,
			wantIP:          netip.MustParseAddr("10.90.252.11"),
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			gotIP, createdPDR, err := s.newCreatedPDRForSource(7, 0x11223344, tc.sourceInterface)
			if err != nil {
				t.Fatalf("newCreatedPDRForSource: %v", err)
			}
			if gotIP != tc.wantIP {
				t.Fatalf("local F-TEID IP = %v; want %v", gotIP, tc.wantIP)
			}

			children, err := createdPDR.Children()
			if err != nil {
				t.Fatalf("CreatedPDR.Children: %v", err)
			}
			fteidIE := pfcpie.Find(children, pfcpie.TypeFTEID)
			if fteidIE == nil {
				t.Fatal("Created PDR missing F-TEID IE")
			}
			fteid, choose, err := fteidIE.FTEIDPFCPValue()
			if err != nil {
				t.Fatalf("FTEIDPFCPValue: %v", err)
			}
			if choose {
				t.Fatal("Created PDR F-TEID still has CHOOSE set; want allocated TEID/IP")
			}
			if fteid.TEID != 0x11223344 {
				t.Errorf("F-TEID TEID = 0x%08X; want 0x11223344", fteid.TEID)
			}
			if fteid.IPv4 != tc.wantIP {
				t.Errorf("F-TEID IPv4 = %v; want %v", fteid.IPv4, tc.wantIP)
			}
		})
	}
}

func TestCreatedPDRUnsupportedSourceInterfaceRejected(t *testing.T) {
	s := &Server{
		accessIP: netip.MustParseAddr("10.90.251.11"),
		coreIP:   netip.MustParseAddr("10.90.252.11"),
	}

	if _, _, err := s.newCreatedPDRForSource(7, 0x11223344, 99); err == nil {
		t.Fatal("newCreatedPDRForSource unsupported Source Interface: got nil error")
	}
}

func TestAssociationReleaseUsesCPNodeKeyForSessionCleanup(t *testing.T) {
	addr := &net.UDPAddr{IP: net.ParseIP("192.0.2.10"), Port: 8805}
	if got, want := cpNodeKey(nil, addr), "ipv4:192.0.2.10"; got != want {
		t.Fatalf("cpNodeKey fallback = %q; want %q", got, want)
	}

	nodeID := pfcpie.NewNodeIDIPv4(net.ParseIP("192.0.2.20"))
	if got, want := cpNodeKey(nodeID, addr), "ipv4:192.0.2.20"; got != want {
		t.Fatalf("cpNodeKey Node ID = %q; want %q", got, want)
	}

	store := sgwusession.NewStore()
	if err := store.Create(&sgwusession.Session{CPSEID: 1, UPSEID: 11, CPNodeKey: "ipv4:192.0.2.10"}); err != nil {
		t.Fatalf("Create session 1: %v", err)
	}
	if err := store.Create(&sgwusession.Session{CPSEID: 2, UPSEID: 22, CPNodeKey: "ipv4:192.0.2.30"}); err != nil {
		t.Fatalf("Create session 2: %v", err)
	}

	deleted := store.DeleteByCPNodeKey(cpNodeKey(nil, addr))
	if len(deleted) != 1 || deleted[0].CPSEID != 1 {
		t.Fatalf("DeleteByCPNodeKey deleted %+v; want only CP-SEID 1", deleted)
	}
	if store.FindByCPSEID(1) != nil {
		t.Fatal("released peer session still present")
	}
	if store.FindByCPSEID(2) == nil {
		t.Fatal("unrelated peer session was deleted")
	}
}

func TestDeletePeerSessionsRemovesBPFStateForMatchingPeerOnly(t *testing.T) {
	store := sgwusession.NewStore()
	matching := &sgwusession.Session{CPSEID: 1, UPSEID: 11, CPNodeKey: "ipv4:192.0.2.10"}
	unrelated := &sgwusession.Session{CPSEID: 2, UPSEID: 22, CPNodeKey: "ipv4:192.0.2.30"}
	if err := store.Create(matching); err != nil {
		t.Fatalf("Create matching session: %v", err)
	}
	if err := store.Create(unrelated); err != nil {
		t.Fatalf("Create unrelated session: %v", err)
	}
	installer := &fakeBPFInstaller{}
	s := &Server{sessions: store, bpfInstall: installer}

	if got := s.deletePeerSessions("ipv4:192.0.2.10", "test"); got != 1 {
		t.Fatalf("deletePeerSessions = %d; want 1", got)
	}
	if store.FindByCPSEID(matching.CPSEID) != nil {
		t.Fatal("matching peer session still present")
	}
	if store.FindByCPSEID(unrelated.CPSEID) == nil {
		t.Fatal("unrelated peer session was deleted")
	}
	if len(installer.removed) != 1 {
		t.Fatalf("BPF RemoveSession calls = %d; want 1", len(installer.removed))
	}
	if installer.removed[0] != matching {
		t.Fatalf("BPF removed session %+v; want matching peer session", installer.removed[0])
	}
}

func TestApplyFARUpdatesBPFErrorLeavesSessionUnchanged(t *testing.T) {
	bpfErr := errors.New("bpf update failed")
	s := &Server{bpfInstall: &fakeBPFInstaller{updateErr: bpfErr}}
	sess := &sgwusession.Session{
		CPSEID: 1,
		UPSEID: 2,
		FARs: []sgwusession.FAR{{
			ID:            7,
			ApplyAction:   pfcpie.ApplyActionDROP,
			DestInterface: pfcpie.DestInterfaceCore,
			OuterTEID:     0x11111111,
			OuterIP:       netip.MustParseAddr("10.0.0.1"),
		}},
	}
	update := parsedFARUpdate{
		farID:       7,
		applyAction: pfcpie.NewApplyAction(pfcpie.ApplyActionFORW),
		ufpIE: pfcpie.NewUpdateForwardingParameters(
			pfcpie.NewDestinationInterface(pfcpie.DestInterfaceAccess),
			pfcpie.NewOuterHeaderCreation(pfcpie.OHCDescGTPUUDPIPv4, 0x22222222, netip.MustParseAddr("10.0.0.2")),
		),
	}

	endMarkers, err := s.applyFARUpdates(sess, []parsedFARUpdate{update})
	if !errors.Is(err, bpfErr) {
		t.Fatalf("applyFARUpdates error = %v; want %v", err, bpfErr)
	}
	if len(endMarkers) != 0 {
		t.Fatalf("end markers returned on failed update: %+v", endMarkers)
	}
	got := sess.FARs[0]
	if got.ApplyAction != pfcpie.ApplyActionDROP ||
		got.DestInterface != pfcpie.DestInterfaceCore ||
		got.OuterTEID != 0x11111111 ||
		got.OuterIP != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("session FAR mutated after BPF failure: %+v", got)
	}
}

func TestApplyFARUpdatesCommitsAfterBPFSuccessAndReturnsEndMarker(t *testing.T) {
	bpf := &fakeBPFInstaller{}
	s := &Server{bpfInstall: bpf}
	sess := &sgwusession.Session{
		CPSEID: 1,
		UPSEID: 2,
		FARs: []sgwusession.FAR{{
			ID:            7,
			ApplyAction:   pfcpie.ApplyActionDROP,
			DestInterface: pfcpie.DestInterfaceCore,
			OuterTEID:     0x11111111,
			OuterIP:       netip.MustParseAddr("10.0.0.1"),
		}},
	}
	update := parsedFARUpdate{
		farID:       7,
		applyAction: pfcpie.NewApplyAction(pfcpie.ApplyActionFORW),
		ufpIE: pfcpie.NewUpdateForwardingParameters(
			pfcpie.NewDestinationInterface(pfcpie.DestInterfaceAccess),
			pfcpie.NewOuterHeaderCreation(pfcpie.OHCDescGTPUUDPIPv4, 0x22222222, netip.MustParseAddr("10.0.0.2")),
		),
	}

	endMarkers, err := s.applyFARUpdates(sess, []parsedFARUpdate{update})
	if err != nil {
		t.Fatalf("applyFARUpdates: %v", err)
	}
	if bpf.updated == nil {
		t.Fatal("BPF UpdateSession was not called")
	}
	if bpf.updated.FARs[0].OuterTEID != 0x22222222 {
		t.Fatalf("BPF candidate FAR = %+v; want updated TEID", bpf.updated.FARs[0])
	}
	if sess.FARs[0].ApplyAction != pfcpie.ApplyActionFORW ||
		sess.FARs[0].DestInterface != pfcpie.DestInterfaceAccess ||
		sess.FARs[0].OuterTEID != 0x22222222 ||
		sess.FARs[0].OuterIP != netip.MustParseAddr("10.0.0.2") {
		t.Fatalf("session FAR not committed after BPF success: %+v", sess.FARs[0])
	}
	if len(endMarkers) != 1 {
		t.Fatalf("end markers = %+v; want 1", endMarkers)
	}
	if endMarkers[0].teid != 0x11111111 || endMarkers[0].dstIP != netip.MustParseAddr("10.0.0.1") {
		t.Fatalf("end marker = %+v; want old OHC", endMarkers[0])
	}
}
