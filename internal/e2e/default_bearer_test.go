package e2e

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"vectorcore-sgw/internal/api"
	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	sgwuconfig "vectorcore-sgw/internal/config/sgwu"
	gtpv2ie "vectorcore-sgw/internal/gtpv2/ie"
	gtpv2msg "vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/recovery"
	"vectorcore-sgw/internal/sgwc/s11"
	"vectorcore-sgw/internal/sgwc/s5c"
	sgwcsession "vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwu/gtpu"
	"vectorcore-sgw/internal/sgwu/pfcpserver"
)

const (
	ctrlIP = "127.0.0.1"
	sgwuIP = "127.10.0.2"
	pgwIP  = "127.10.0.4"
	enbIP  = "127.10.0.5"
	mmeIP  = "127.10.0.6"
)

type capturePacket struct {
	name    string
	srcIP   net.IP
	dstIP   net.IP
	srcPort uint16
	dstPort uint16
	payload []byte
}

type fakePGW struct {
	conn       *net.UDPConn
	gotCSReq   chan []byte
	sentCSResp chan []byte
	sgwuS5U    chan gtpv2ie.FTEID
}

func TestDefaultBearerAttachProgramsControlPlaneAndUserspaceGTPU(t *testing.T) {
	// Phase 10 E2E scope:
	// - TS 29.274 Rel-15 Table 7.2.1-1/7.2.2-1: S11 and S5/S8-C Create Session.
	// - TS 29.244 Rel-15 Table 7.5.2.2-1/7.5.3.1-1: PFCP Session Establishment.
	// - TS 29.274 Rel-15 Table 7.2.7-1/7.2.8-1: Modify Bearer installs eNB S1-U F-TEID.
	// - TS 29.281 Rel-15 §5.1/Table 6.1-1: G-PDU forwarding on UDP/2152.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sgwuPFCPPort := freeUDPPortOn(t, ctrlIP)
	sgwcPFCPPort := freeUDPPortOn(t, ctrlIP)
	sgwcS11Port := freeUDPPortOn(t, ctrlIP)
	sgwcS5CPort := freeUDPPortOn(t, ctrlIP)
	sgwcAPIAddr := freeTCPAddr(t)
	sgwuAPIAddr := freeTCPAddr(t)

	pgw := startFakePGW(t, log)
	defer pgw.conn.Close()

	sgwuCfg := sgwuconfig.Default()
	sgwuCfg.PFCP.Listen = fmt.Sprintf("%s:%d", ctrlIP, sgwuPFCPPort)
	sgwuCfg.PFCP.AllowedSGWC = []string{"127.0.0.0/8"}
	sgwuCfg.Interfaces.User = map[string]sgwuconfig.UserInterfaceConfig{
		"up0": {Ifname: "lo", Listen: sgwuIP + ":2152"},
	}
	sgwuCfg.GTPU.S1U = sgwuconfig.GTPULogical{Bind: "up0"}
	sgwuCfg.GTPU.S5U = sgwuconfig.GTPULogical{Bind: "up0"}

	sgwuPFCP, err := pfcpserver.New(sgwuCfg, time.Now(), log)
	if err != nil {
		t.Fatalf("SGW-U PFCP New: %v", err)
	}
	t.Cleanup(func() { _ = sgwuPFCP.Close() })
	go func() {
		if err := sgwuPFCP.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("SGW-U PFCP Serve: %v", err)
		}
	}()

	sgwuGTPU, err := gtpu.New(sgwuCfg.GTPUListen(), mustAddr(t, sgwuIP), sgwuPFCP.SessionStore(), log)
	if err != nil {
		t.Fatalf("SGW-U GTP-U New: %v", err)
	}
	sgwuPFCP.SetEndMarkerSender(sgwuGTPU)
	t.Cleanup(func() { _ = sgwuGTPU.Close() })
	go func() {
		if err := sgwuGTPU.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("SGW-U GTP-U Serve: %v", err)
		}
	}()

	sgwuAPI := api.NewServer(sgwuAPIAddr, api.BuildInfo{Version: "test", BuildDate: "phase10"}, log)
	api.RegisterSGWURoutes(sgwuAPI.HumaAPI(), sgwuPFCP.SessionStore(), sgwuPFCP, nil, nil)
	if err := sgwuAPI.Start(ctx); err != nil {
		t.Fatalf("SGW-U API Start: %v", err)
	}
	t.Cleanup(func() { _ = sgwuAPI.Stop() })

	sgwcCfg := sgwcconfig.Default()
	sgwcCfg.Interfaces.Control = map[string]sgwcconfig.ControlInterfaceConfig{
		"mme_path": {Listen: fmt.Sprintf("%s:%d", ctrlIP, sgwcS11Port)},
		"pgw_path": {Listen: fmt.Sprintf("%s:%d", ctrlIP, sgwcS5CPort)},
	}
	sgwcCfg.GTPC.S11 = sgwcconfig.S11Logical{Bind: "mme_path", Timers: sgwcCfg.S11}
	sgwcCfg.GTPC.S5C = sgwcconfig.GTPCLogical{Bind: "pgw_path"}
	sgwcCfg.S11.T3ResponseSeconds = 1
	sgwcCfg.S11.N3Requests = 2
	sgwcCfg.S11.T3ResponseSeconds = 1
	sgwcCfg.S11.N3Requests = 2
	sgwcCfg.PFCP.LocalAddr = fmt.Sprintf("%s:%d", ctrlIP, sgwcPFCPPort)
	sgwcCfg.PFCP.SGWU = []sgwcconfig.SGWUPeer{{Name: "sgwu-e2e", Addr: sgwuCfg.PFCP.Listen}}
	sgwcCfg.PFCP.Heartbeat.HeartbeatIntervalSeconds = 60
	sgwcCfg.PFCP.Heartbeat.HeartbeatTimeoutSeconds = 3
	sgwcCfg.SGWC.ControlPlaneIP = ctrlIP

	sessions := sgwcsession.NewManager()
	rc := recovery.New(0)
	pfcpClient, err := pfcpclient.New(sgwcCfg, time.Now(), log)
	if err != nil {
		t.Fatalf("SGW-C PFCP New: %v", err)
	}
	t.Cleanup(func() { _ = pfcpClient.Close() })
	go func() {
		if err := pfcpClient.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("SGW-C PFCP Serve: %v", err)
		}
	}()
	waitForPFCPPeer(t, pfcpClient)

	s5cClient, err := s5c.New(sgwcCfg, mustAddr(t, ctrlIP), rc, log)
	if err != nil {
		t.Fatalf("S5C New: %v", err)
	}
	t.Cleanup(func() { _ = s5cClient.Close() })
	go func() {
		if err := s5cClient.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("S5C Serve: %v", err)
		}
	}()

	s11Handler, err := s11.New(sgwcCfg, sessions, rc, s5cClient, pfcpClient, mustAddr(t, ctrlIP), log)
	if err != nil {
		t.Fatalf("S11 New: %v", err)
	}
	t.Cleanup(func() { _ = s11Handler.Close() })
	s5cClient.SetRequestHandler(s11Handler.HandleS5CInbound)
	go func() {
		if err := s11Handler.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("S11 Serve: %v", err)
		}
	}()

	sgwcAPI := api.NewServer(sgwcAPIAddr, api.BuildInfo{Version: "test", BuildDate: "phase10"}, log)
	api.RegisterSGWCRoutes(sgwcAPI.HumaAPI(), sessions)
	api.RegisterPFCPRoutes(sgwcAPI.HumaAPI(), pfcpClient)
	if err := sgwcAPI.Start(ctx); err != nil {
		t.Fatalf("SGW-C API Start: %v", err)
	}
	t.Cleanup(func() { _ = sgwcAPI.Stop() })

	mmeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ctrlIP), Port: 0})
	if err != nil {
		t.Fatalf("MME ListenUDP: %v", err)
	}
	defer mmeConn.Close()
	s11Dst := &net.UDPAddr{IP: net.ParseIP(ctrlIP), Port: sgwcS11Port}
	s11CSReq := buildS11CreateSessionRequest(t)
	if _, err := mmeConn.WriteToUDP(s11CSReq, s11Dst); err != nil {
		t.Fatalf("send S11 CSReq: %v", err)
	}
	s11CSResp := readUDP(t, mmeConn, 3*time.Second)

	s11Resp, sgwS11TEID, sgwUS1UTEID := parseS11CreateSessionResponse(t, s11CSResp)
	if s11Resp.Header.TEID != 0xAABBCCDD {
		t.Fatalf("S11 CSResp TEID = 0x%08X; want MME TEID 0xAABBCCDD", s11Resp.Header.TEID)
	}
	if sgwS11TEID == 0 || sgwUS1UTEID == 0 {
		t.Fatalf("S11 CSResp missing SGW-C S11 TEID or SGW-U S1-U TEID: sgwS11=0x%08X sgwUS1U=0x%08X", sgwS11TEID, sgwUS1UTEID)
	}
	s5CSReq := mustReceive(t, pgw.gotCSReq, "S5/S8-C CSReq")
	s5CSResp := mustReceive(t, pgw.sentCSResp, "S5/S8-C CSResp")
	sgwuS5U := mustReceive(t, pgw.sgwuS5U, "SGW-U S5/S8-U F-TEID")
	if sgwuS5U.TEID == 0 || sgwuS5U.IPv4.String() != sgwuIP {
		t.Fatalf("S5/S8-C CSReq SGW-U S5-U F-TEID = %+v; want non-zero TEID at %s", sgwuS5U, sgwuIP)
	}

	mbReq := buildModifyBearerRequest(t, sgwS11TEID)
	if _, err := mmeConn.WriteToUDP(mbReq, s11Dst); err != nil {
		t.Fatalf("send S11 MBReq: %v", err)
	}
	mbRespRaw := readUDP(t, mmeConn, 3*time.Second)
	assertModifyBearerResponse(t, mbRespRaw)

	pgwUConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(pgwIP), Port: 2152})
	if err != nil {
		t.Fatalf("PGW-U ListenUDP: %v", err)
	}
	defer pgwUConn.Close()
	enbUConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(enbIP), Port: 2152})
	if err != nil {
		t.Fatalf("eNB-U ListenUDP: %v", err)
	}
	defer enbUConn.Close()

	uplinkPayload := []byte("phase10-uplink-tpdu")
	uplinkIn := buildGPDU(sgwUS1UTEID, uplinkPayload)
	if _, err := enbUConn.WriteToUDP(uplinkIn, &net.UDPAddr{IP: net.ParseIP(sgwuIP), Port: 2152}); err != nil {
		t.Fatalf("send uplink G-PDU: %v", err)
	}
	uplinkOut := readUDP(t, pgwUConn, 3*time.Second)
	assertGPDU(t, "uplink", uplinkOut, 0x51525354, uplinkPayload)

	downlinkPayload := []byte("phase10-downlink-tpdu")
	downlinkIn := buildGPDU(sgwuS5U.TEID, downlinkPayload)
	if _, err := pgwUConn.WriteToUDP(downlinkIn, &net.UDPAddr{IP: net.ParseIP(sgwuIP), Port: 2152}); err != nil {
		t.Fatalf("send downlink G-PDU: %v", err)
	}
	downlinkOut := readUDP(t, enbUConn, 3*time.Second)
	assertGPDU(t, "downlink", downlinkOut, 0x0E0B0001, downlinkPayload)

	assertAPIState(t, sgwcAPIAddr, sgwuAPIAddr)
	maybeWritePCAPs(t, []capturePacket{
		{srcIP: net.ParseIP(ctrlIP), dstIP: net.ParseIP(ctrlIP), srcPort: uint16(mmeConn.LocalAddr().(*net.UDPAddr).Port), dstPort: uint16(sgwcS11Port), payload: s11CSReq},
		{srcIP: net.ParseIP(ctrlIP), dstIP: net.ParseIP(ctrlIP), srcPort: uint16(sgwcS11Port), dstPort: uint16(mmeConn.LocalAddr().(*net.UDPAddr).Port), payload: s11CSResp},
		{srcIP: net.ParseIP(ctrlIP), dstIP: net.ParseIP(ctrlIP), srcPort: uint16(sgwcS5CPort), dstPort: 2123, payload: s5CSReq},
		{srcIP: net.ParseIP(ctrlIP), dstIP: net.ParseIP(ctrlIP), srcPort: 2123, dstPort: uint16(sgwcS5CPort), payload: s5CSResp},
		{srcIP: net.ParseIP(enbIP), dstIP: net.ParseIP(sgwuIP), srcPort: 2152, dstPort: 2152, payload: uplinkIn},
		{srcIP: net.ParseIP(sgwuIP), dstIP: net.ParseIP(pgwIP), srcPort: 2152, dstPort: 2152, payload: uplinkOut},
		{srcIP: net.ParseIP(pgwIP), dstIP: net.ParseIP(sgwuIP), srcPort: 2152, dstPort: 2152, payload: downlinkIn},
		{srcIP: net.ParseIP(sgwuIP), dstIP: net.ParseIP(enbIP), srcPort: 2152, dstPort: 2152, payload: downlinkOut},
	})
}

func TestDedicatedBearerCreateUpdateDeleteProgramsPFCPAndAPI(t *testing.T) {
	// Phase 12 E2E scope:
	// - TS 29.274 Rel-15 §7.2.3/§7.2.4: PGW-initiated Create Bearer relayed S5/S8-C↔S11.
	// - TS 29.274 Rel-15 §7.2.15/§7.2.16: Update Bearer relays TFT/QoS changes.
	// - TS 29.274 Rel-15 §7.2.9.2/§7.2.10.2: Delete Bearer removes only the dedicated bearer.
	// - TS 29.244 Rel-15 §7.5.4: PFCP Session Modification adds/removes dedicated bearer PDR/FARs.
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	sgwuPFCPPort := freeUDPPortOn(t, ctrlIP)
	sgwcPFCPPort := freeUDPPortOn(t, ctrlIP)
	sgwcS11Port := freeUDPPortOn(t, ctrlIP)
	sgwcS5CPort := freeUDPPortOn(t, ctrlIP)
	sgwcAPIAddr := freeTCPAddr(t)
	sgwuAPIAddr := freeTCPAddr(t)

	pgw := startFakePGW(t, log)
	defer pgw.conn.Close()

	sgwuCfg := sgwuconfig.Default()
	sgwuCfg.PFCP.Listen = fmt.Sprintf("%s:%d", ctrlIP, sgwuPFCPPort)
	sgwuCfg.PFCP.AllowedSGWC = []string{"127.0.0.0/8"}
	sgwuCfg.Interfaces.User = map[string]sgwuconfig.UserInterfaceConfig{
		"up0": {Ifname: "lo", Listen: sgwuIP + ":2152"},
	}
	sgwuCfg.GTPU.S1U = sgwuconfig.GTPULogical{Bind: "up0"}
	sgwuCfg.GTPU.S5U = sgwuconfig.GTPULogical{Bind: "up0"}

	sgwuPFCP, err := pfcpserver.New(sgwuCfg, time.Now(), log)
	if err != nil {
		t.Fatalf("SGW-U PFCP New: %v", err)
	}
	t.Cleanup(func() { _ = sgwuPFCP.Close() })
	go func() {
		if err := sgwuPFCP.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("SGW-U PFCP Serve: %v", err)
		}
	}()
	sgwuAPI := api.NewServer(sgwuAPIAddr, api.BuildInfo{Version: "test", BuildDate: "phase12"}, log)
	api.RegisterSGWURoutes(sgwuAPI.HumaAPI(), sgwuPFCP.SessionStore(), sgwuPFCP, nil, nil)
	if err := sgwuAPI.Start(ctx); err != nil {
		t.Fatalf("SGW-U API Start: %v", err)
	}
	t.Cleanup(func() { _ = sgwuAPI.Stop() })

	sgwcCfg := sgwcconfig.Default()
	sgwcCfg.Interfaces.Control = map[string]sgwcconfig.ControlInterfaceConfig{
		"mme_path": {Listen: fmt.Sprintf("%s:%d", ctrlIP, sgwcS11Port)},
		"pgw_path": {Listen: fmt.Sprintf("%s:%d", ctrlIP, sgwcS5CPort)},
	}
	sgwcCfg.GTPC.S11 = sgwcconfig.S11Logical{Bind: "mme_path", Timers: sgwcCfg.S11}
	sgwcCfg.GTPC.S5C = sgwcconfig.GTPCLogical{Bind: "pgw_path"}
	sgwcCfg.S11.T3ResponseSeconds = 1
	sgwcCfg.S11.N3Requests = 2
	sgwcCfg.S11.T3ResponseSeconds = 1
	sgwcCfg.S11.N3Requests = 2
	sgwcCfg.PFCP.LocalAddr = fmt.Sprintf("%s:%d", ctrlIP, sgwcPFCPPort)
	sgwcCfg.PFCP.SGWU = []sgwcconfig.SGWUPeer{{Name: "sgwu-e2e", Addr: sgwuCfg.PFCP.Listen}}
	sgwcCfg.PFCP.Heartbeat.HeartbeatIntervalSeconds = 60
	sgwcCfg.PFCP.Heartbeat.HeartbeatTimeoutSeconds = 3
	sgwcCfg.SGWC.ControlPlaneIP = ctrlIP

	sessions := sgwcsession.NewManager()
	rc := recovery.New(0)
	pfcpClient, err := pfcpclient.New(sgwcCfg, time.Now(), log)
	if err != nil {
		t.Fatalf("SGW-C PFCP New: %v", err)
	}
	t.Cleanup(func() { _ = pfcpClient.Close() })
	go func() {
		if err := pfcpClient.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("SGW-C PFCP Serve: %v", err)
		}
	}()
	waitForPFCPPeer(t, pfcpClient)

	s5cClient, err := s5c.New(sgwcCfg, mustAddr(t, ctrlIP), rc, log)
	if err != nil {
		t.Fatalf("S5C New: %v", err)
	}
	t.Cleanup(func() { _ = s5cClient.Close() })
	go func() {
		if err := s5cClient.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("S5C Serve: %v", err)
		}
	}()

	s11Handler, err := s11.New(sgwcCfg, sessions, rc, s5cClient, pfcpClient, mustAddr(t, ctrlIP), log)
	if err != nil {
		t.Fatalf("S11 New: %v", err)
	}
	t.Cleanup(func() { _ = s11Handler.Close() })
	s5cClient.SetRequestHandler(s11Handler.HandleS5CInbound)
	go func() {
		if err := s11Handler.Serve(ctx); err != nil && ctx.Err() == nil && !isClosedNetErr(err) {
			t.Errorf("S11 Serve: %v", err)
		}
	}()

	sgwcAPI := api.NewServer(sgwcAPIAddr, api.BuildInfo{Version: "test", BuildDate: "phase12"}, log)
	api.RegisterSGWCRoutes(sgwcAPI.HumaAPI(), sessions)
	if err := sgwcAPI.Start(ctx); err != nil {
		t.Fatalf("SGW-C API Start: %v", err)
	}
	t.Cleanup(func() { _ = sgwcAPI.Stop() })

	mmeConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(mmeIP), Port: 2123})
	if err != nil {
		t.Fatalf("MME ListenUDP %s:2123: %v", mmeIP, err)
	}
	defer mmeConn.Close()

	mmeInitialConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(mmeIP), Port: 0})
	if err != nil {
		t.Fatalf("MME initial ListenUDP: %v", err)
	}
	defer mmeInitialConn.Close()
	s11Dst := &net.UDPAddr{IP: net.ParseIP(ctrlIP), Port: sgwcS11Port}
	if _, err := mmeInitialConn.WriteToUDP(buildS11CreateSessionRequestFromMME(t, mmeIP), s11Dst); err != nil {
		t.Fatalf("send S11 CSReq: %v", err)
	}
	s11CSResp := readUDP(t, mmeInitialConn, 3*time.Second)
	_, sgwS11TEID, _ := parseS11CreateSessionResponse(t, s11CSResp)
	s5CSReq := mustReceive(t, pgw.gotCSReq, "S5/S8-C CSReq")
	_ = mustReceive(t, pgw.sentCSResp, "S5/S8-C CSResp")
	sgwS5CTEID := parseSGWS5CTEIDFromCSReq(t, s5CSReq)

	mbReq := buildModifyBearerRequest(t, sgwS11TEID)
	if _, err := mmeInitialConn.WriteToUDP(mbReq, s11Dst); err != nil {
		t.Fatalf("send S11 MBReq: %v", err)
	}
	assertModifyBearerResponse(t, readUDP(t, mmeInitialConn, 3*time.Second))

	cbReq := buildCreateBearerRequest(t, sgwS5CTEID)
	if _, err := pgw.conn.WriteToUDP(cbReq, &net.UDPAddr{IP: net.ParseIP(ctrlIP), Port: sgwcS5CPort}); err != nil {
		t.Fatalf("send S5/S8-C CBReq: %v", err)
	}
	s11CBReq, s11CBReqSrc := readUDPFrom(t, mmeConn, 3*time.Second)
	sgwDedicatedS1U := assertS11CreateBearerRequest(t, s11CBReq)
	if _, err := mmeConn.WriteToUDP(buildCreateBearerResponse(t, s11CBReq, sgwDedicatedS1U), s11CBReqSrc); err != nil {
		t.Fatalf("send S11 CBResp: %v", err)
	}
	s5CBResp := readUDP(t, pgw.conn, 3*time.Second)
	sgwDedicatedS5U := assertS5CreateBearerResponse(t, s5CBResp)
	assertDedicatedAPIState(t, sgwcAPIAddr, sgwuAPIAddr, 2, 4, 5, sgwDedicatedS5U)

	ubReq := buildUpdateBearerRequest(t, sgwS5CTEID)
	if _, err := pgw.conn.WriteToUDP(ubReq, &net.UDPAddr{IP: net.ParseIP(ctrlIP), Port: sgwcS5CPort}); err != nil {
		t.Fatalf("send S5/S8-C UBReq: %v", err)
	}
	s11UBReq, s11UBReqSrc := readUDPFrom(t, mmeConn, 3*time.Second)
	assertS11UpdateBearerRequest(t, s11UBReq)
	if _, err := mmeConn.WriteToUDP(buildUpdateBearerResponse(t, s11UBReq), s11UBReqSrc); err != nil {
		t.Fatalf("send S11 UBResp: %v", err)
	}
	assertUpdateBearerResponse(t, readUDP(t, pgw.conn, 3*time.Second))
	assertDedicatedAPIState(t, sgwcAPIAddr, sgwuAPIAddr, 2, 4, 7, sgwDedicatedS5U)

	dbReq := buildDeleteBearerRequest(t, sgwS5CTEID)
	if _, err := pgw.conn.WriteToUDP(dbReq, &net.UDPAddr{IP: net.ParseIP(ctrlIP), Port: sgwcS5CPort}); err != nil {
		t.Fatalf("send S5/S8-C DBReq: %v", err)
	}
	s11DBReq, s11DBReqSrc := readUDPFrom(t, mmeConn, 3*time.Second)
	assertS11DeleteBearerRequest(t, s11DBReq)
	if _, err := mmeConn.WriteToUDP(buildDeleteBearerResponse(t, s11DBReq), s11DBReqSrc); err != nil {
		t.Fatalf("send S11 DBResp: %v", err)
	}
	assertDeleteBearerResponse(t, readUDP(t, pgw.conn, 3*time.Second))
	assertDedicatedAPIState(t, sgwcAPIAddr, sgwuAPIAddr, 1, 2, 0, 0)
}

func startFakePGW(t *testing.T, log *slog.Logger) *fakePGW {
	t.Helper()
	addr := &net.UDPAddr{IP: net.ParseIP(ctrlIP), Port: 2123}
	conn, err := net.ListenUDP("udp4", addr)
	if err != nil {
		t.Fatalf("PGW-C ListenUDP %s: %v", addr, err)
	}
	p := &fakePGW{
		conn:       conn,
		gotCSReq:   make(chan []byte, 1),
		sentCSResp: make(chan []byte, 1),
		sgwuS5U:    make(chan gtpv2ie.FTEID, 1),
	}
	go func() {
		buf := make([]byte, 65535)
		n, src, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		raw := append([]byte{}, buf[:n]...)
		p.gotCSReq <- raw
		h, ies, err := gtpv2msg.Parse(raw)
		if err != nil {
			log.Error("fake PGW parse CSReq failed", "error", err)
			return
		}
		req, err := gtpv2msg.ParseCreateSessionRequest(h, ies)
		if err != nil {
			log.Error("fake PGW decode CSReq failed", "error", err)
			return
		}
		sgwS5C, err := req.FTEID.FTEIDValue()
		if err != nil {
			log.Error("fake PGW SGW-C FTEID failed", "error", err)
			return
		}
		children, err := req.BearerContexts[0].ChildIEs()
		if err != nil {
			log.Error("fake PGW bearer children failed", "error", err)
			return
		}
		sgwuS5UIE := gtpv2ie.FindInstance(children, gtpv2ie.TypeFTEID, 2)
		if sgwuS5UIE == nil {
			log.Error("fake PGW CSReq missing SGW-U S5/S8-U F-TEID instance 2")
			return
		}
		sgwuS5U, err := sgwuS5UIE.FTEIDValue()
		if err != nil {
			log.Error("fake PGW SGW-U S5-U FTEID failed", "error", err)
			return
		}
		p.sgwuS5U <- sgwuS5U

		respHdr := gtpv2msg.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    gtpv2msg.MsgTypeCreateSessionResponse,
			TEID:           sgwS5C.TEID,
			SequenceNumber: h.SequenceNumber,
		}
		resp, err := gtpv2msg.Marshal(respHdr, []*gtpv2ie.IE{
			gtpv2ie.NewCause(gtpv2ie.CauseRequestAccepted, 0, 0, 0, nil),
			gtpv2ie.NewFTEID(1, gtpv2ie.IFTypeS5S8CPGW, 0x41424344, mustAddrNoT(ctrlIP)),
			gtpv2ie.NewPAA(gtpv2ie.PDNTypeIPv4, mustAddrNoT("10.45.0.9")),
			gtpv2ie.NewAMBR(256000, 256000),
			&gtpv2ie.IE{Type: gtpv2ie.TypeAPNRestriction, Value: []byte{0x00}},
			&gtpv2ie.IE{Type: gtpv2ie.TypePCO, Value: []byte{0x80, 0x80, 0x21}},
			gtpv2ie.NewBearerContext(0,
				gtpv2ie.NewEBI(5),
				gtpv2ie.NewCause(gtpv2ie.CauseRequestAccepted, 0, 0, 0, nil),
				gtpv2ie.NewFTEID(2, gtpv2ie.IFTypeS5S8UPGW, 0x51525354, mustAddrNoT(pgwIP)),
				&gtpv2ie.IE{Type: gtpv2ie.TypeChargingID, Value: []byte{0x01, 0x02, 0x03, 0x04}},
			),
		})
		if err != nil {
			log.Error("fake PGW marshal CSResp failed", "error", err)
			return
		}
		p.sentCSResp <- append([]byte{}, resp...)
		_, _ = conn.WriteToUDP(resp, src)
	}()
	return p
}

func buildS11CreateSessionRequest(t *testing.T) []byte {
	t.Helper()
	return buildS11CreateSessionRequestFromMME(t, ctrlIP)
}

func buildS11CreateSessionRequestFromMME(t *testing.T, mmeAddr string) []byte {
	t.Helper()
	h := gtpv2msg.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    gtpv2msg.MsgTypeCreateSessionRequest,
		TEID:           0,
		SequenceNumber: 0x101,
	}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{
		gtpv2ie.NewIMSI("311430000000001"),
		gtpv2ie.NewRATType(gtpv2ie.RATTypeEUTRAN),
		gtpv2ie.NewServingNetwork("311", "430"),
		gtpv2ie.NewSelectionMode(0),
		gtpv2ie.NewFTEID(0, gtpv2ie.IFTypeS11MMEC, 0xAABBCCDD, mustAddr(t, mmeAddr)),
		gtpv2ie.NewFTEID(1, gtpv2ie.IFTypeS5S8CPGW, 0, mustAddr(t, ctrlIP)),
		gtpv2ie.NewAPN("internet"),
		gtpv2ie.NewPDNType(gtpv2ie.PDNTypeIPv4),
		gtpv2ie.NewPAA(gtpv2ie.PDNTypeIPv4, mustAddr(t, "0.0.0.0")),
		gtpv2ie.NewAMBR(256000, 256000),
		gtpv2ie.NewBearerContext(0,
			gtpv2ie.NewEBI(5),
			gtpv2ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0),
		),
	})
	if err != nil {
		t.Fatalf("marshal S11 CSReq: %v", err)
	}
	return raw
}

func parseSGWS5CTEIDFromCSReq(t *testing.T, raw []byte) uint32 {
	t.Helper()
	h, ies, err := gtpv2msg.Parse(raw)
	if err != nil {
		t.Fatalf("parse S5/S8-C CSReq: %v", err)
	}
	req, err := gtpv2msg.ParseCreateSessionRequest(h, ies)
	if err != nil {
		t.Fatalf("decode S5/S8-C CSReq: %v", err)
	}
	f, err := req.FTEID.FTEIDValue()
	if err != nil {
		t.Fatalf("S5/S8-C CSReq SGW-C FTEID: %v", err)
	}
	return f.TEID
}

func parseS11CreateSessionResponse(t *testing.T, raw []byte) (*gtpv2msg.CreateSessionResponse, uint32, uint32) {
	t.Helper()
	h, ies, err := gtpv2msg.Parse(raw)
	if err != nil {
		t.Fatalf("parse S11 CSResp: %v", err)
	}
	resp, err := gtpv2msg.ParseCreateSessionResponse(h, ies)
	if err != nil {
		t.Fatalf("decode S11 CSResp: %v", err)
	}
	cause, _ := resp.Cause.CauseValue()
	if cause != gtpv2ie.CauseRequestAccepted {
		t.Fatalf("S11 CSResp cause = %d; want %d", cause, gtpv2ie.CauseRequestAccepted)
	}
	if resp.Header.SequenceNumber != 0x101 {
		t.Fatalf("S11 CSResp sequence = %d; want 0x101", resp.Header.SequenceNumber)
	}
	sgwS11, err := resp.FTEID.FTEIDValue()
	if err != nil {
		t.Fatalf("S11 CSResp SGW FTEID: %v", err)
	}
	if resp.FTEID.Value[0]&0x3F != gtpv2ie.IFTypeS11S4SGW {
		t.Fatalf("S11 CSResp SGW-C F-TEID interface = %d; want S11/S4 SGW %d",
			resp.FTEID.Value[0]&0x3F, gtpv2ie.IFTypeS11S4SGW)
	}
	if resp.PGWFTEID == nil {
		t.Fatal("S11 CSResp missing PGW S5/S8-C F-TEID instance 1")
	}
	if resp.PGWFTEID.Value[0]&0x3F != gtpv2ie.IFTypeS5S8CPGW {
		t.Fatalf("S11 CSResp PGW F-TEID interface = %d; want S5/S8-C PGW %d",
			resp.PGWFTEID.Value[0]&0x3F, gtpv2ie.IFTypeS5S8CPGW)
	}
	if resp.APNRestriction == nil || !bytes.Equal(resp.APNRestriction.Value, []byte{0x00}) {
		t.Fatalf("S11 CSResp APN Restriction = %#v; want 00", resp.APNRestriction)
	}
	if resp.PCO == nil || !bytes.Equal(resp.PCO.Value, []byte{0x80, 0x80, 0x21}) {
		t.Fatalf("S11 CSResp PCO = %#v; want 80 80 21", resp.PCO)
	}
	children, err := resp.BearerContexts[0].ChildIEs()
	if err != nil {
		t.Fatalf("S11 CSResp bearer children: %v", err)
	}
	sgwuS1UIE := gtpv2ie.FindInstance(children, gtpv2ie.TypeFTEID, 0)
	if sgwuS1UIE == nil {
		t.Fatal("S11 CSResp missing SGW-U S1-U F-TEID instance 0")
	}
	sgwuS1U, err := sgwuS1UIE.FTEIDValue()
	if err != nil {
		t.Fatalf("S11 CSResp SGW-U S1-U FTEID: %v", err)
	}
	if sgwuS1UIE.Value[0]&0x3F != gtpv2ie.IFTypeS1USGW {
		t.Fatalf("S11 CSResp SGW-U S1-U F-TEID interface = %d; want %d",
			sgwuS1UIE.Value[0]&0x3F, gtpv2ie.IFTypeS1USGW)
	}
	pgwS5UIE := gtpv2ie.FindInstance(children, gtpv2ie.TypeFTEID, 2)
	if pgwS5UIE == nil {
		t.Fatal("S11 CSResp missing PGW S5/S8-U F-TEID instance 2")
	}
	if pgwS5UIE.Value[0]&0x3F != gtpv2ie.IFTypeS5S8UPGW {
		t.Fatalf("S11 CSResp PGW S5/S8-U F-TEID interface = %d; want %d",
			pgwS5UIE.Value[0]&0x3F, gtpv2ie.IFTypeS5S8UPGW)
	}
	chargingID := gtpv2ie.FindFirst(children, gtpv2ie.TypeChargingID)
	if chargingID != nil {
		t.Fatalf("S11 CSResp Bearer Context Charging ID = %#v; want omitted for Cisco-compatible S11 primary shape", chargingID)
	}
	return resp, sgwS11.TEID, sgwuS1U.TEID
}

func buildModifyBearerRequest(t *testing.T, sgwS11TEID uint32) []byte {
	t.Helper()
	h := gtpv2msg.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    gtpv2msg.MsgTypeModifyBearerRequest,
		TEID:           sgwS11TEID,
		SequenceNumber: 0x102,
	}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{
		gtpv2ie.NewBearerContext(0,
			gtpv2ie.NewEBI(5),
			gtpv2ie.NewFTEID(0, gtpv2ie.IFTypeS1UENB, 0x0E0B0001, mustAddr(t, enbIP)),
		),
	})
	if err != nil {
		t.Fatalf("marshal S11 MBReq: %v", err)
	}
	return raw
}

func assertModifyBearerResponse(t *testing.T, raw []byte) {
	t.Helper()
	h, ies, err := gtpv2msg.Parse(raw)
	if err != nil {
		t.Fatalf("parse S11 MBResp: %v", err)
	}
	resp, err := gtpv2msg.ParseModifyBearerResponse(h, ies)
	if err != nil {
		t.Fatalf("decode S11 MBResp: %v", err)
	}
	cause, _ := resp.Cause.CauseValue()
	if cause != gtpv2ie.CauseRequestAccepted {
		t.Fatalf("S11 MBResp cause = %d; want %d", cause, gtpv2ie.CauseRequestAccepted)
	}
}

func buildCreateBearerRequest(t *testing.T, sgwS5CTEID uint32) []byte {
	t.Helper()
	h := gtpv2msg.Header{Version: 2, HasTEID: true, MessageType: gtpv2msg.MsgTypeCreateBearerRequest, TEID: sgwS5CTEID, SequenceNumber: 0x201}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{
		gtpv2ie.NewEBI(5),
		gtpv2ie.NewBearerContext(0,
			gtpv2ie.NewEBI(0),
			gtpv2ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			gtpv2ie.NewFTEID(1, gtpv2ie.IFTypeS5S8UPGW, 0x61626364, mustAddr(t, pgwIP)),
			gtpv2ie.NewBearerQoS(1, 2, 0, 5, 128000, 128000, 64000, 64000),
		),
	})
	if err != nil {
		t.Fatalf("marshal S5/S8-C CBReq: %v", err)
	}
	return raw
}

func assertS11CreateBearerRequest(t *testing.T, raw []byte) gtpv2ie.FTEID {
	t.Helper()
	h, _, err := gtpv2msg.Parse(raw)
	if err != nil {
		t.Fatalf("parse S11 CBReq: %v", err)
	}
	req, err := gtpv2msg.ParseCreateBearerRequest(raw)
	if err != nil {
		t.Fatalf("decode S11 CBReq: %v", err)
	}
	if h.MessageType != gtpv2msg.MsgTypeCreateBearerRequest || len(req.BearerContexts) != 1 {
		t.Fatalf("S11 CBReq header/bearers = %d/%d; want CBReq with one bearer", h.MessageType, len(req.BearerContexts))
	}
	children, err := req.BearerContexts[0].ChildIEs()
	if err != nil {
		t.Fatalf("S11 CBReq bearer children: %v", err)
	}
	lbi, err := req.LBI.EBIValue()
	if err != nil || lbi != 5 {
		t.Fatalf("S11 CBReq LBI = %d err=%v; want linked default EBI 5", lbi, err)
	}
	ebiIE := gtpv2ie.FindFirst(children, gtpv2ie.TypeEBI)
	if ebiIE == nil {
		t.Fatal("S11 CBReq Bearer Context missing mandatory EBI IE")
	}
	bcEBI, err := ebiIE.EBIValue()
	if err != nil || bcEBI != 0 {
		t.Fatalf("S11 CBReq Bearer Context EBI = %d err=%v; want 0 per TS 29.274 Table 7.2.3-2", bcEBI, err)
	}
	tft, err := gtpv2ie.FindFirst(children, gtpv2ie.TypeBearerTFT).BearerTFTValue()
	if err != nil || !bytes.Equal(tft, []byte{0x21, 0x01, 0x02}) {
		t.Fatalf("S11 CBReq TFT = % X err=%v; want raw TFT", tft, err)
	}
	qos := gtpv2ie.FindFirst(children, gtpv2ie.TypeBearerQoS)
	if qos == nil || len(qos.Value) < 2 || qos.Value[1] != 5 {
		t.Fatalf("S11 CBReq QoS = %+v; want QCI 5", qos)
	}
	sgwS1UIE := gtpv2ie.FindInstance(children, gtpv2ie.TypeFTEID, 0)
	if sgwS1UIE == nil {
		t.Fatal("S11 CBReq missing SGW S1-U F-TEID instance 0")
	}
	sgwS1U, err := sgwS1UIE.FTEIDValue()
	if err != nil || sgwS1U.TEID == 0 || sgwS1U.IPv4.String() != sgwuIP {
		t.Fatalf("S11 CBReq SGW S1-U FTEID = %+v err=%v; want SGW-U TEID at %s", sgwS1U, err, sgwuIP)
	}
	if sgwS1UIE.Value[0]&0x3F != gtpv2ie.IFTypeS1USGW {
		t.Fatalf("S11 CBReq SGW S1-U F-TEID interface = %d; want %d",
			sgwS1UIE.Value[0]&0x3F, gtpv2ie.IFTypeS1USGW)
	}
	pgwS5UIE := gtpv2ie.FindInstance(children, gtpv2ie.TypeFTEID, 1)
	if pgwS5UIE == nil {
		t.Fatal("S11 CBReq missing PGW S5/S8-U F-TEID instance 1")
	}
	pgwS5U, err := pgwS5UIE.FTEIDValue()
	if err != nil || pgwS5U.TEID != 0x61626364 || pgwS5U.IPv4.String() != pgwIP {
		t.Fatalf("S11 CBReq PGW S5/S8-U FTEID = %+v err=%v; want PGW-U TEID at %s", pgwS5U, err, pgwIP)
	}
	if pgwS5UIE.Value[0]&0x3F != gtpv2ie.IFTypeS5S8UPGW {
		t.Fatalf("S11 CBReq PGW S5/S8-U F-TEID interface = %d; want %d",
			pgwS5UIE.Value[0]&0x3F, gtpv2ie.IFTypeS5S8UPGW)
	}
	return sgwS1U
}

func buildCreateBearerResponse(t *testing.T, reqRaw []byte, sgwS1U gtpv2ie.FTEID) []byte {
	t.Helper()
	reqHdr, _, err := gtpv2msg.Parse(reqRaw)
	if err != nil {
		t.Fatalf("parse S11 CBReq for response: %v", err)
	}
	h := gtpv2msg.Header{Version: 2, HasTEID: true, MessageType: gtpv2msg.MsgTypeCreateBearerResponse, TEID: reqHdr.TEID, SequenceNumber: reqHdr.SequenceNumber}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{
		gtpv2ie.NewCause(gtpv2ie.CauseRequestAccepted, 0, 0, 0, nil),
		gtpv2ie.NewBearerContext(0,
			gtpv2ie.NewEBI(6),
			gtpv2ie.NewCause(gtpv2ie.CauseRequestAccepted, 0, 0, 0, nil),
			gtpv2ie.NewFTEID(0, gtpv2ie.IFTypeS1UENB, 0x0E0B0006, mustAddr(t, enbIP)),
			gtpv2ie.NewFTEID(1, gtpv2ie.IFTypeS1USGW, sgwS1U.TEID, sgwS1U.IPv4),
		),
	})
	if err != nil {
		t.Fatalf("marshal S11 CBResp: %v", err)
	}
	return raw
}

func assertS5CreateBearerResponse(t *testing.T, raw []byte) uint32 {
	t.Helper()
	resp, err := gtpv2msg.ParseCreateBearerResponse(raw)
	if err != nil {
		t.Fatalf("decode S5/S8-C CBResp: %v", err)
	}
	cause, _ := resp.Cause.CauseValue()
	if cause != gtpv2ie.CauseRequestAccepted {
		t.Fatalf("S5/S8-C CBResp cause = %d; want accepted", cause)
	}
	children, err := resp.BearerContexts[0].ChildIEs()
	if err != nil {
		t.Fatalf("S5/S8-C CBResp bearer children: %v", err)
	}
	sgwS5UIE := gtpv2ie.FindInstance(children, gtpv2ie.TypeFTEID, 2)
	if sgwS5UIE == nil {
		t.Fatal("S5/S8-C CBResp missing SGW S5/S8-U F-TEID instance 2")
	}
	sgwS5U, err := sgwS5UIE.FTEIDValue()
	if err != nil || sgwS5U.TEID == 0 || sgwS5U.IPv4.String() != sgwuIP {
		t.Fatalf("S5/S8-C CBResp SGW S5-U FTEID = %+v err=%v; want SGW-U TEID at %s", sgwS5U, err, sgwuIP)
	}
	return sgwS5U.TEID
}

func buildUpdateBearerRequest(t *testing.T, sgwS5CTEID uint32) []byte {
	t.Helper()
	h := gtpv2msg.Header{Version: 2, HasTEID: true, MessageType: gtpv2msg.MsgTypeUpdateBearerRequest, TEID: sgwS5CTEID, SequenceNumber: 0x202}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{
		gtpv2ie.NewBearerContext(0,
			gtpv2ie.NewEBI(6),
			gtpv2ie.NewBearerTFT([]byte{0x22, 0x03, 0x04}),
			gtpv2ie.NewBearerQoS(1, 3, 0, 7, 256000, 256000, 128000, 128000),
		),
		gtpv2ie.NewAMBR(512000, 512000),
	})
	if err != nil {
		t.Fatalf("marshal S5/S8-C UBReq: %v", err)
	}
	return raw
}

func assertS11UpdateBearerRequest(t *testing.T, raw []byte) {
	t.Helper()
	req, err := gtpv2msg.ParseUpdateBearerRequest(raw)
	if err != nil {
		t.Fatalf("decode S11 UBReq: %v", err)
	}
	children, err := req.BearerContexts[0].ChildIEs()
	if err != nil {
		t.Fatalf("S11 UBReq bearer children: %v", err)
	}
	tft, err := gtpv2ie.FindFirst(children, gtpv2ie.TypeBearerTFT).BearerTFTValue()
	if err != nil || !bytes.Equal(tft, []byte{0x22, 0x03, 0x04}) {
		t.Fatalf("S11 UBReq TFT = % X err=%v; want updated raw TFT", tft, err)
	}
	qos := gtpv2ie.FindFirst(children, gtpv2ie.TypeBearerQoS)
	if qos == nil || len(qos.Value) < 2 || qos.Value[1] != 7 {
		t.Fatalf("S11 UBReq QoS = %+v; want QCI 7", qos)
	}
}

func buildUpdateBearerResponse(t *testing.T, reqRaw []byte) []byte {
	t.Helper()
	reqHdr, _, err := gtpv2msg.Parse(reqRaw)
	if err != nil {
		t.Fatalf("parse S11 UBReq for response: %v", err)
	}
	h := gtpv2msg.Header{Version: 2, HasTEID: true, MessageType: gtpv2msg.MsgTypeUpdateBearerResponse, TEID: reqHdr.TEID, SequenceNumber: reqHdr.SequenceNumber}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{
		gtpv2ie.NewCause(gtpv2ie.CauseRequestAccepted, 0, 0, 0, nil),
		gtpv2ie.NewBearerContext(0,
			gtpv2ie.NewEBI(6),
			gtpv2ie.NewCause(gtpv2ie.CauseRequestAccepted, 0, 0, 0, nil),
		),
	})
	if err != nil {
		t.Fatalf("marshal S11 UBResp: %v", err)
	}
	return raw
}

func assertUpdateBearerResponse(t *testing.T, raw []byte) {
	t.Helper()
	resp, err := gtpv2msg.ParseUpdateBearerResponse(raw)
	if err != nil {
		t.Fatalf("decode S5/S8-C UBResp: %v", err)
	}
	cause, _ := resp.Cause.CauseValue()
	if cause != gtpv2ie.CauseRequestAccepted {
		t.Fatalf("S5/S8-C UBResp cause = %d; want accepted", cause)
	}
}

func buildDeleteBearerRequest(t *testing.T, sgwS5CTEID uint32) []byte {
	t.Helper()
	h := gtpv2msg.Header{Version: 2, HasTEID: true, MessageType: gtpv2msg.MsgTypeDeleteBearerRequest, TEID: sgwS5CTEID, SequenceNumber: 0x203}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{gtpv2ie.NewEBIInstance(1, 6)})
	if err != nil {
		t.Fatalf("marshal S5/S8-C DBReq: %v", err)
	}
	return raw
}

func assertS11DeleteBearerRequest(t *testing.T, raw []byte) {
	t.Helper()
	req, err := gtpv2msg.ParseDeleteBearerRequest(raw)
	if err != nil {
		t.Fatalf("decode S11 DBReq: %v", err)
	}
	if len(req.EBIs) != 1 {
		t.Fatalf("S11 DBReq EBIs = %d; want one dedicated bearer EBI", len(req.EBIs))
	}
	ebi, _ := req.EBIs[0].EBIValue()
	if ebi != 6 {
		t.Fatalf("S11 DBReq EBI = %d; want 6", ebi)
	}
}

func buildDeleteBearerResponse(t *testing.T, reqRaw []byte) []byte {
	t.Helper()
	reqHdr, _, err := gtpv2msg.Parse(reqRaw)
	if err != nil {
		t.Fatalf("parse S11 DBReq for response: %v", err)
	}
	h := gtpv2msg.Header{Version: 2, HasTEID: true, MessageType: gtpv2msg.MsgTypeDeleteBearerResponse, TEID: reqHdr.TEID, SequenceNumber: reqHdr.SequenceNumber}
	raw, err := gtpv2msg.Marshal(h, []*gtpv2ie.IE{
		gtpv2ie.NewCause(gtpv2ie.CauseRequestAcceptedPartially, 0, 0, 0, nil),
		gtpv2ie.NewBearerContext(0,
			gtpv2ie.NewEBI(6),
			gtpv2ie.NewCause(gtpv2ie.CauseRequestAccepted, 0, 0, 0, nil),
		),
	})
	if err != nil {
		t.Fatalf("marshal S11 DBResp: %v", err)
	}
	return raw
}

func assertDeleteBearerResponse(t *testing.T, raw []byte) {
	t.Helper()
	resp, err := gtpv2msg.ParseDeleteBearerResponse(raw)
	if err != nil {
		t.Fatalf("decode S5/S8-C DBResp: %v", err)
	}
	cause, _ := resp.Cause.CauseValue()
	if cause != gtpv2ie.CauseRequestAcceptedPartially {
		t.Fatalf("S5/S8-C DBResp cause = %d; want partial accepted", cause)
	}
}

func assertDedicatedAPIState(t *testing.T, sgwcAPIAddr, sgwuAPIAddr string, wantBearers, wantRules int, wantQCI uint8, wantDedicatedS5UTEID uint32) {
	t.Helper()
	var sgwcSessions struct {
		Sessions []struct {
			BearerCount int `json:"bearer_count"`
			Bearers     []struct {
				EBI           uint8  `json:"ebi"`
				Type          string `json:"type"`
				QCI           uint8  `json:"qci"`
				SGWS1UTEID    string `json:"sgw_s1u_teid"`
				SGWS5UTEID    string `json:"sgw_s5u_teid"`
				PGWS5UTEID    string `json:"pgw_s5u_teid"`
				ENBS1UTEID    string `json:"enb_s1u_teid"`
				UplinkPDRID   uint32 `json:"uplink_pdr_id"`
				DownlinkPDRID uint32 `json:"downlink_pdr_id"`
				UplinkFARID   uint32 `json:"uplink_far_id"`
				DownlinkFARID uint32 `json:"downlink_far_id"`
			} `json:"bearers"`
		} `json:"sessions"`
		Total int `json:"total"`
	}
	getJSON(t, "http://"+sgwcAPIAddr+"/sessions", &sgwcSessions)
	if sgwcSessions.Total != 1 || sgwcSessions.Sessions[0].BearerCount != wantBearers || len(sgwcSessions.Sessions[0].Bearers) != wantBearers {
		t.Fatalf("SGW-C /sessions = %+v; want %d bearers", sgwcSessions, wantBearers)
	}
	if sgwcSessions.Sessions[0].Bearers[0].Type != "default" {
		t.Fatalf("first bearer = %+v; want default bearer first", sgwcSessions.Sessions[0].Bearers[0])
	}
	if wantBearers == 2 {
		dedicated := sgwcSessions.Sessions[0].Bearers[1]
		if dedicated.EBI != 6 || dedicated.Type != "dedicated" || dedicated.QCI != wantQCI ||
			dedicated.SGWS1UTEID == "0x00000000" || dedicated.SGWS5UTEID == "0x00000000" ||
			dedicated.PGWS5UTEID == "0x00000000" || dedicated.ENBS1UTEID == "0x00000000" ||
			dedicated.UplinkPDRID == 0 || dedicated.DownlinkPDRID == 0 ||
			dedicated.UplinkFARID == 0 || dedicated.DownlinkFARID == 0 {
			t.Fatalf("dedicated bearer API = %+v; want complete active dedicated bearer", dedicated)
		}
	}

	var sgwuSessions struct {
		Sessions []struct {
			PDRs []struct {
				LocalTEID string `json:"local_teid"`
			} `json:"pdrs"`
			FARs []struct {
				ID        uint32 `json:"id"`
				OuterTEID string `json:"outer_teid"`
			} `json:"fars"`
		} `json:"sessions"`
		Total int `json:"total"`
	}
	getJSON(t, "http://"+sgwuAPIAddr+"/sessions", &sgwuSessions)
	if sgwuSessions.Total != 1 || len(sgwuSessions.Sessions[0].PDRs) != wantRules || len(sgwuSessions.Sessions[0].FARs) != wantRules {
		t.Fatalf("SGW-U /sessions = %+v; want %d PDRs/FARs", sgwuSessions, wantRules)
	}
	if wantDedicatedS5UTEID != 0 {
		wantTEID := fmt.Sprintf("0x%08X", wantDedicatedS5UTEID)
		found := false
		for _, pdr := range sgwuSessions.Sessions[0].PDRs {
			if pdr.LocalTEID == wantTEID {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("SGW-U PDRs = %+v; want dedicated S5/S8-U TEID %s", sgwuSessions.Sessions[0].PDRs, wantTEID)
		}
	}
}

func assertAPIState(t *testing.T, sgwcAPIAddr, sgwuAPIAddr string) {
	t.Helper()
	var sgwcSessions struct {
		Sessions []struct {
			BearerCount int `json:"bearer_count"`
			Bearers     []struct {
				SGWS1UTEID string `json:"sgw_s1u_teid"`
				SGWS5UTEID string `json:"sgw_s5u_teid"`
				PGWS5UTEID string `json:"pgw_s5u_teid"`
				ENBS1UTEID string `json:"enb_s1u_teid"`
			} `json:"bearers"`
		} `json:"sessions"`
		Total int `json:"total"`
	}
	getJSON(t, "http://"+sgwcAPIAddr+"/sessions", &sgwcSessions)
	if sgwcSessions.Total != 1 || sgwcSessions.Sessions[0].BearerCount != 1 || len(sgwcSessions.Sessions[0].Bearers) != 1 {
		t.Fatalf("SGW-C /sessions = %+v; want one session with one bearer", sgwcSessions)
	}
	b := sgwcSessions.Sessions[0].Bearers[0]
	if b.SGWS1UTEID == "0x00000000" || b.SGWS5UTEID == "0x00000000" ||
		b.PGWS5UTEID == "0x00000000" || b.ENBS1UTEID == "0x00000000" {
		t.Fatalf("SGW-C bearer TEIDs not fully populated: %+v", b)
	}

	var sgwuSessions struct {
		Sessions []struct {
			PDRs []struct {
				LocalTEID string `json:"local_teid"`
				FARID     uint32 `json:"far_id"`
			} `json:"pdrs"`
			FARs []struct {
				ID          uint32 `json:"id"`
				ApplyAction uint8  `json:"apply_action"`
				OuterTEID   string `json:"outer_teid"`
				OuterIP     string `json:"outer_ip"`
			} `json:"fars"`
		} `json:"sessions"`
		Total int `json:"total"`
	}
	getJSON(t, "http://"+sgwuAPIAddr+"/sessions", &sgwuSessions)
	if sgwuSessions.Total != 1 || len(sgwuSessions.Sessions[0].PDRs) != 2 || len(sgwuSessions.Sessions[0].FARs) != 2 {
		t.Fatalf("SGW-U /sessions = %+v; want one session with two PDRs and two FARs", sgwuSessions)
	}
	for _, far := range sgwuSessions.Sessions[0].FARs {
		if far.ApplyAction != 0x02 || far.OuterTEID == "0x00000000" || far.OuterIP == "invalid IP" {
			t.Fatalf("SGW-U FAR not forwarding after attach+modify: %+v", far)
		}
	}

	var peers struct {
		Peers []struct {
			State        string `json:"state"`
			SessionCount int    `json:"session_count"`
		} `json:"peers"`
		Total int `json:"total"`
	}
	getJSON(t, "http://"+sgwuAPIAddr+"/pfcp/associations", &peers)
	if peers.Total != 1 || peers.Peers[0].State != "Established" || peers.Peers[0].SessionCount != 1 {
		t.Fatalf("SGW-U /pfcp/associations = %+v; want established peer with one session", peers)
	}
}

func buildGPDU(teid uint32, payload []byte) []byte {
	hdr := gtpu.Marshal(gtpu.Header{Version: 1, PT: true, MsgType: gtpu.MsgTypeGPDU, TEID: teid}, len(payload))
	return append(hdr, payload...)
}

func assertGPDU(t *testing.T, name string, raw []byte, wantTEID uint32, wantPayload []byte) {
	t.Helper()
	h, hdrLen, err := gtpu.Parse(raw)
	if err != nil {
		t.Fatalf("%s G-PDU parse: %v", name, err)
	}
	if h.MsgType != gtpu.MsgTypeGPDU || h.TEID != wantTEID {
		t.Fatalf("%s G-PDU msg/TEID = %d/0x%08X; want G-PDU/0x%08X", name, h.MsgType, h.TEID, wantTEID)
	}
	if got := raw[hdrLen:]; !bytes.Equal(got, wantPayload) {
		t.Fatalf("%s G-PDU payload = %q; want %q", name, got, wantPayload)
	}
}

func getJSON(t *testing.T, url string, dst any) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := http.Get(url) //nolint:gosec // test-only local HTTP endpoint
		if err != nil {
			lastErr = err
			time.Sleep(25 * time.Millisecond)
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			lastErr = fmt.Errorf("status %d", resp.StatusCode)
			time.Sleep(25 * time.Millisecond)
			continue
		}
		if err := json.NewDecoder(resp.Body).Decode(dst); err != nil {
			t.Fatalf("decode %s: %v", url, err)
		}
		return
	}
	t.Fatalf("GET %s failed: %v", url, lastErr)
}

func waitForPFCPPeer(t *testing.T, client *pfcpclient.Client) {
	t.Helper()
	deadline := time.Now().Add(12 * time.Second)
	for time.Now().Before(deadline) {
		for _, p := range client.Peers() {
			if p.State == string(pfcpclient.PeerStateEstablished) {
				return
			}
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("PFCP peer did not reach Established: %+v", client.Peers())
}

func isClosedNetErr(err error) bool {
	return err != nil && (bytes.Contains([]byte(err.Error()), []byte("use of closed network connection")) ||
		bytes.Contains([]byte(err.Error()), []byte("closed network connection")))
}

func readUDP(t *testing.T, conn *net.UDPConn, timeout time.Duration) []byte {
	t.Helper()
	raw, _ := readUDPFrom(t, conn, timeout)
	return raw
}

func readUDPFrom(t *testing.T, conn *net.UDPConn, timeout time.Duration) ([]byte, *net.UDPAddr) {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	buf := make([]byte, 65535)
	n, src, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP on %s: %v", conn.LocalAddr(), err)
	}
	return append([]byte{}, buf[:n]...), src
}

func mustReceive[T any](t *testing.T, ch <-chan T, name string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(3 * time.Second):
		var zero T
		t.Fatalf("timeout waiting for %s", name)
		return zero
	}
}

func freeUDPPortOn(t *testing.T, ip string) int {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(ip), Port: 0})
	if err != nil {
		t.Fatalf("ListenUDP free port on %s: %v", ip, err)
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).Port
}

func freeTCPAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen TCP free addr: %v", err)
	}
	defer ln.Close()
	return ln.Addr().String()
}

func mustAddr(t *testing.T, s string) netip.Addr {
	t.Helper()
	addr, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr %q: %v", s, err)
	}
	return addr
}

func mustAddrNoT(s string) netip.Addr {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		panic(err)
	}
	return addr
}

func maybeWritePCAPs(t *testing.T, packets []capturePacket) {
	t.Helper()
	dir := os.Getenv("E2E_PCAP_DIR")
	if dir == "" {
		return
	}
	if err := os.MkdirAll(dir, 0755); err != nil {
		t.Fatalf("pcap mkdir %s: %v", dir, err)
	}
	writeRawIPPCAP(t, filepath.Join(dir, "phase10-control-plane.pcap"), packets[:4])
	writeRawIPPCAP(t, filepath.Join(dir, "phase10-gtpu.pcap"), packets[4:])
}

func writeRawIPPCAP(t *testing.T, path string, packets []capturePacket) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("pcap create %s: %v", path, err)
	}
	defer f.Close()

	global := make([]byte, 24)
	binary.LittleEndian.PutUint32(global[0:4], 0xa1b2c3d4)
	binary.LittleEndian.PutUint16(global[4:6], 2)
	binary.LittleEndian.PutUint16(global[6:8], 4)
	binary.LittleEndian.PutUint32(global[16:20], 65535)
	binary.LittleEndian.PutUint32(global[20:24], 101) // LINKTYPE_RAW
	if _, err := f.Write(global); err != nil {
		t.Fatalf("pcap write global %s: %v", path, err)
	}
	for _, p := range packets {
		ip := ipv4UDPPacket(p.srcIP.To4(), p.dstIP.To4(), p.srcPort, p.dstPort, p.payload)
		now := time.Now()
		rec := make([]byte, 16)
		binary.LittleEndian.PutUint32(rec[0:4], uint32(now.Unix()))
		binary.LittleEndian.PutUint32(rec[4:8], uint32(now.Nanosecond()/1000))
		binary.LittleEndian.PutUint32(rec[8:12], uint32(len(ip)))
		binary.LittleEndian.PutUint32(rec[12:16], uint32(len(ip)))
		if _, err := f.Write(rec); err != nil {
			t.Fatalf("pcap write record %s: %v", path, err)
		}
		if _, err := f.Write(ip); err != nil {
			t.Fatalf("pcap write packet %s: %v", path, err)
		}
	}
}

func ipv4UDPPacket(src, dst net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	ipLen := 20
	udpLen := 8 + len(payload)
	total := ipLen + udpLen
	pkt := make([]byte, total)
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(total))
	pkt[8] = 64
	pkt[9] = 17
	copy(pkt[12:16], src)
	copy(pkt[16:20], dst)
	binary.BigEndian.PutUint16(pkt[10:12], ipv4Checksum(pkt[:20]))
	udp := pkt[20:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpLen))
	copy(udp[8:], payload)
	return pkt
}

func ipv4Checksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	return ^uint16(sum)
}
