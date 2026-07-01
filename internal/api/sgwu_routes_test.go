package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"vectorcore-sgw/internal/dataplane/bpf"
	"vectorcore-sgw/internal/sgwu/pfcpserver"
	sgwusession "vectorcore-sgw/internal/sgwu/session"
)

type fakeAssocReader struct {
	peers []pfcpserver.PeerView
}

func (f fakeAssocReader) Peers() []pfcpserver.PeerView {
	return f.peers
}

type fakeBPFReader struct {
	rules []bpf.RuleEntry
	err   error
}

func (f fakeBPFReader) Rules() ([]bpf.RuleEntry, error) {
	return f.rules, f.err
}

func newTestSGWUAPI(store *sgwusession.Store, assoc sgwuPFCPAssociationReader, dp bpfRuleReader) *Server {
	srv := NewServer("127.0.0.1:0", BuildInfo{Version: "test", BuildDate: "now"}, slog.New(slog.DiscardHandler))
	RegisterSGWURoutes(srv.HumaAPI(), store, assoc, dp)
	return srv
}

func getJSON(t *testing.T, srv *Server, path string, dst any) {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	rec := httptest.NewRecorder()
	srv.e.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("GET %s status = %d body=%s; want 200", path, rec.Code, rec.Body.String())
	}
	if err := json.Unmarshal(rec.Body.Bytes(), dst); err != nil {
		t.Fatalf("GET %s decode: %v body=%s", path, err, rec.Body.String())
	}
}

func TestSGWURoutesListSessionsIncludesRulesAndExplicitEmptyQERs(t *testing.T) {
	store := sgwusession.NewStore()
	if err := store.Create(&sgwusession.Session{
		CPSEID:    0x1111,
		UPSEID:    0x2222,
		CPNodeKey: "ipv4:192.0.2.10",
		PDRs: []sgwusession.PDR{{
			ID:              7,
			Precedence:      100,
			SourceInterface: 0,
			LocalTEID:       0xABCDEF01,
			LocalIP:         netip.MustParseAddr("10.0.0.1"),
			FARID:           9,
		}},
		FARs: []sgwusession.FAR{{
			ID:            9,
			ApplyAction:   2,
			DestInterface: 1,
			OuterTEID:     0x12345678,
			OuterIP:       netip.MustParseAddr("10.0.0.2"),
		}},
	}); err != nil {
		t.Fatalf("Create session: %v", err)
	}

	srv := newTestSGWUAPI(store, nil, nil)

	var out PFCPSessionListOutput
	getJSON(t, srv, "/sessions", &out.Body)

	if out.Body.Total != 1 {
		t.Fatalf("total = %d; want 1", out.Body.Total)
	}
	sess := out.Body.Sessions[0]
	if sess.CPSEID != "0x0000000000001111" || sess.UPSEID != "0x0000000000002222" {
		t.Fatalf("session IDs = %s/%s; want formatted CP/UP SEIDs", sess.CPSEID, sess.UPSEID)
	}
	if len(sess.PDRs) != 1 || sess.PDRs[0].LocalTEID != "0xABCDEF01" || sess.PDRs[0].FARID != 9 {
		t.Fatalf("PDR view = %+v; want local TEID and FAR ID", sess.PDRs)
	}
	if len(sess.FARs) != 1 || sess.FARs[0].OuterTEID != "0x12345678" || sess.FARs[0].OuterIP != "10.0.0.2" {
		t.Fatalf("FAR view = %+v; want outer TEID/IP", sess.FARs)
	}
	if sess.QERs == nil || len(sess.QERs) != 0 {
		t.Fatalf("QERs = %#v; want explicit empty list", sess.QERs)
	}
}

func TestSGWURoutesListPFCPAssociations(t *testing.T) {
	now := time.Unix(1710000000, 0).UTC()
	assoc := fakeAssocReader{peers: []pfcpserver.PeerView{{
		NodeIDKey:         "ipv4:192.0.2.10",
		State:             "Established",
		RecoveryTimestamp: 0x01020304,
		LastSeen:          now,
		LastAddr:          "192.0.2.10:8805",
		SessionCount:      2,
	}}}
	srv := newTestSGWUAPI(sgwusession.NewStore(), assoc, nil)

	var out SGWUPFCPAssociationsOutput
	getJSON(t, srv, "/pfcp/associations", &out.Body)

	if out.Body.Total != 1 {
		t.Fatalf("total = %d; want 1", out.Body.Total)
	}
	got := out.Body.Peers[0]
	if got.NodeIDKey != "ipv4:192.0.2.10" || got.State != "Established" ||
		got.RecoveryTimestamp != 0x01020304 || got.LastAddr != "192.0.2.10:8805" ||
		got.SessionCount != 2 {
		t.Fatalf("peer view = %+v; want association details", got)
	}
}

func TestSGWURoutesListBPFRulesAndUnattachedDataplane(t *testing.T) {
	store := sgwusession.NewStore()
	rule := bpf.RuleEntry{
		Key: bpf.XdpSgwGtpuSgwRuleKey{Teid: 0x1000, Ifindex: 1},
		Value: bpf.XdpSgwGtpuSgwRuleValue{
			Action:        1,
			EgressIfindex: 2,
			NewTeid:       0x2000,
			CounterId:     0x1000,
		},
		Packets:       3,
		Bytes:         192,
		StatsRecorded: true,
	}
	copy(rule.Value.OuterSrcIp[:], []byte{10, 0, 0, 1})
	copy(rule.Value.OuterDstIp[:], []byte{10, 0, 0, 2})

	srv := newTestSGWUAPI(store, nil, fakeBPFReader{rules: []bpf.RuleEntry{rule}})
	var bpfOut BPFRuleListOutput
	getJSON(t, srv, "/bpf/rules", &bpfOut.Body)

	if bpfOut.Body.Dataplane != "ebpf" || !bpfOut.Body.Attached || bpfOut.Body.Total != 1 {
		t.Fatalf("bpf response dataplane/attached/total = %s/%v/%d; want ebpf/true/1",
			bpfOut.Body.Dataplane, bpfOut.Body.Attached, bpfOut.Body.Total)
	}
	got := bpfOut.Body.Rules[0]
	if got.TEID != "0x00001000" || got.NewTEID != "0x00002000" ||
		got.Action != "FORWARD" || got.OuterSrcIP != "10.0.0.1" ||
		got.OuterDstIP != "10.0.0.2" || got.Packets != 3 ||
		got.Bytes != 192 || !got.StatsRecorded {
		t.Fatalf("BPF rule view = %+v; want formatted rule and counters", got)
	}

	unattachedSrv := newTestSGWUAPI(store, nil, nil)
	var unattachedOut BPFRuleListOutput
	getJSON(t, unattachedSrv, "/bpf/rules", &unattachedOut.Body)
	if unattachedOut.Body.Dataplane != "ebpf" || unattachedOut.Body.Attached ||
		unattachedOut.Body.Total != 0 || len(unattachedOut.Body.Rules) != 0 {
		t.Fatalf("unattached BPF response = %+v; want empty unattached eBPF dataplane", unattachedOut.Body)
	}
}
