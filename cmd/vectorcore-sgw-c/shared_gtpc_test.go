package main

import (
	"log/slog"
	"net/netip"
	"testing"

	sgwcconfig "vectorcore-sgw/internal/config/sgwc"
	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/gtpv2/transport"
	"vectorcore-sgw/internal/sgwc/pfcpclient"
	"vectorcore-sgw/internal/sgwc/recovery"
	"vectorcore-sgw/internal/sgwc/s11"
	"vectorcore-sgw/internal/sgwc/s5c"
	"vectorcore-sgw/internal/sgwc/session"
)

func TestIsPGWInitiatedBearerRequest(t *testing.T) {
	for _, msgType := range []uint8{
		message.MsgTypeCreateBearerRequest,
		message.MsgTypeUpdateBearerRequest,
		message.MsgTypeDeleteBearerRequest,
	} {
		if !isPGWInitiatedBearerRequest(msgType) {
			t.Fatalf("isPGWInitiatedBearerRequest(%d) = false, want true", msgType)
		}
	}

	for _, msgType := range []uint8{
		message.MsgTypeEchoRequest,
		message.MsgTypeCreateSessionRequest,
		message.MsgTypeModifyBearerRequest,
		message.MsgTypeDeleteSessionRequest,
		message.MsgTypeReleaseAccessBearersRequest,
	} {
		if isPGWInitiatedBearerRequest(msgType) {
			t.Fatalf("isPGWInitiatedBearerRequest(%d) = true, want false", msgType)
		}
	}
}

func TestSharedGTPCConstructorsUseOneTransport(t *testing.T) {
	cfg := sgwcconfig.Default()
	cfg.SGWC.NodeID = "sgw-c-1"
	cfg.SGWC.PLMN.MCC = "311"
	cfg.SGWC.PLMN.MNC = "435"
	cfg.Interfaces.Control = map[string]sgwcconfig.ControlInterfaceConfig{
		"shared": {Listen: "127.0.0.1:0"},
	}
	cfg.GTPC.S11 = sgwcconfig.S11Logical{Bind: "shared", Timers: cfg.S11}
	cfg.GTPC.S5C = sgwcconfig.GTPCLogical{Bind: "shared"}
	cfg.PFCP.LocalAddr = "127.0.0.1:0"
	cfg.PFCP.SGWU = []sgwcconfig.SGWUPeer{{Name: "sgw-u-1", Addr: "127.0.0.2:8805"}}

	conn, err := transport.Listen(cfg.S11Listen(), cfg.S11.T3ResponseSeconds, cfg.S11.N3Requests, slog.Default())
	if err != nil {
		t.Fatalf("shared transport listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	localIP := netip.MustParseAddr("127.0.0.1")
	rc := recovery.New(0)
	s5cClient := s5c.NewWithConn(conn, localIP, rc, slog.Default())
	h := s11.NewWithConn(cfg, conn, session.NewManager(), rc, s5cClient, &pfcpclient.Client{}, localIP, slog.Default())
	conn.SetHandler(sharedGTPCHandler(h))
}
