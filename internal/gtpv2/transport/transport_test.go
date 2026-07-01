package transport

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
)

func TestInboundRetransmitResendsCachedResponseBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn, err := Listen("127.0.0.1:0", 1, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	handlerCalls := 0
	conn.SetHandler(func(c *Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
		handlerCalls++
		respHdr := message.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    message.MsgTypeCreateSessionResponse,
			TEID:           0xAABBCCDD,
			SequenceNumber: hdr.SequenceNumber,
		}
		resp, err := message.Marshal(respHdr, []*ie.IE{
			ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
			ie.NewRecovery(uint8(handlerCalls)),
		})
		if err != nil {
			t.Errorf("Marshal response: %v", err)
			return
		}
		if err := c.Reply(addr, resp); err != nil {
			t.Errorf("Reply: %v", err)
		}
	})
	go func() {
		if err := conn.Serve(ctx); err != nil && ctx.Err() == nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("Serve: %v", err)
			}
		}
	}()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	reqHdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           0,
		SequenceNumber: 0x010203,
	}
	req, err := message.Marshal(reqHdr, nil)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	serverAddr := conn.LocalAddr().(*net.UDPAddr)

	if _, err := client.WriteToUDP(req, serverAddr); err != nil {
		t.Fatalf("first send: %v", err)
	}
	first := readUDPTest(t, client)

	if _, err := client.WriteToUDP(req, serverAddr); err != nil {
		t.Fatalf("duplicate send: %v", err)
	}
	second := readUDPTest(t, client)

	if !bytes.Equal(first, second) {
		t.Fatalf("cached retransmit bytes differ\nfirst:  % X\nsecond: % X", first, second)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler calls = %d; want 1 (duplicate must use cached response)", handlerCalls)
	}
}

func TestInboundRetransmitResendsCachedPiggybackedResponseBytes(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn, err := Listen("127.0.0.1:0", 1, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	handlerCalls := 0
	conn.SetHandler(func(c *Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
		handlerCalls++
		primary, err := message.Marshal(message.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    message.MsgTypeCreateSessionResponse,
			TEID:           0xAABBCCDD,
			SequenceNumber: hdr.SequenceNumber,
		}, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil)})
		if err != nil {
			t.Errorf("Marshal primary response: %v", err)
			return
		}
		piggy, err := message.MarshalCreateBearerRequest(0xAABBCCDD, 0x010204,
			ie.NewEBI(6),
			ie.NewBearerContext(0,
				ie.NewEBI(0),
				ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
				ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x55667788, netip.MustParseAddr("10.90.252.92")),
				ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
			),
		)
		if err != nil {
			t.Errorf("Marshal piggyback request: %v", err)
			return
		}
		resp, err := message.MarshalPiggybacked(primary, piggy)
		if err != nil {
			t.Errorf("MarshalPiggybacked: %v", err)
			return
		}
		if err := c.Reply(addr, resp); err != nil {
			t.Errorf("Reply: %v", err)
		}
	})
	go func() {
		if err := conn.Serve(ctx); err != nil && ctx.Err() == nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("Serve: %v", err)
			}
		}
	}()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}

	req, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           0,
		SequenceNumber: 0x010203,
	}, nil)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	serverAddr := conn.LocalAddr().(*net.UDPAddr)
	if _, err := client.WriteToUDP(req, serverAddr); err != nil {
		t.Fatalf("first send: %v", err)
	}
	first := readUDPTest(t, client)
	if _, err := client.WriteToUDP(req, serverAddr); err != nil {
		t.Fatalf("duplicate send: %v", err)
	}
	second := readUDPTest(t, client)

	if !bytes.Equal(first, second) {
		t.Fatalf("cached piggyback retransmit bytes differ\nfirst:  % X\nsecond: % X", first, second)
	}
	frames, err := message.SplitFrames(second)
	if err != nil {
		t.Fatalf("SplitFrames cached piggyback response: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("cached frames = %d; want CSRsp + CBR", len(frames))
	}
	if frames[0].Header.MessageType != message.MsgTypeCreateSessionResponse || frames[1].Header.MessageType != message.MsgTypeCreateBearerRequest {
		t.Fatalf("cached frame types = %d/%d; want 33/95", frames[0].Header.MessageType, frames[1].Header.MessageType)
	}
	if handlerCalls != 1 {
		t.Fatalf("handler calls = %d; want 1", handlerCalls)
	}
}

func TestInboundRetransmitCacheDoesNotMatchDifferentMessageTypeSameSequence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn, err := Listen("127.0.0.1:0", 1, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	var handled []uint8
	conn.SetHandler(func(c *Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
		handled = append(handled, hdr.MessageType)
		respType, ok := message.ResponseTypeFor(hdr.MessageType)
		if !ok {
			t.Errorf("ResponseTypeFor(%d): !ok", hdr.MessageType)
			return
		}
		resp, err := message.Marshal(message.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    respType,
			TEID:           0xAABBCCDD,
			SequenceNumber: hdr.SequenceNumber,
		}, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil)})
		if err != nil {
			t.Errorf("Marshal response: %v", err)
			return
		}
		if err := c.Reply(addr, resp); err != nil {
			t.Errorf("Reply: %v", err)
		}
	})
	go func() {
		if err := conn.Serve(ctx); err != nil && ctx.Err() == nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("Serve: %v", err)
			}
		}
	}()

	client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("client ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	serverAddr := conn.LocalAddr().(*net.UDPAddr)

	csr, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           0,
		SequenceNumber: 0x010203,
	}, nil)
	if err != nil {
		t.Fatalf("Marshal CSR: %v", err)
	}
	mbr, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeModifyBearerRequest,
		TEID:           0x01010101,
		SequenceNumber: 0x010203,
	}, nil)
	if err != nil {
		t.Fatalf("Marshal MBR: %v", err)
	}

	if _, err := client.WriteToUDP(csr, serverAddr); err != nil {
		t.Fatalf("send CSR: %v", err)
	}
	first := readUDPTest(t, client)
	firstHdr, _, err := message.Parse(first)
	if err != nil {
		t.Fatalf("Parse first response: %v", err)
	}
	if firstHdr.MessageType != message.MsgTypeCreateSessionResponse {
		t.Fatalf("first response type = %d; want CSResp", firstHdr.MessageType)
	}

	if _, err := client.WriteToUDP(mbr, serverAddr); err != nil {
		t.Fatalf("send MBR: %v", err)
	}
	second := readUDPTest(t, client)
	secondHdr, _, err := message.Parse(second)
	if err != nil {
		t.Fatalf("Parse second response: %v", err)
	}
	if secondHdr.MessageType != message.MsgTypeModifyBearerResponse {
		t.Fatalf("second response type = %d; want MBResp, not cached CSResp", secondHdr.MessageType)
	}
	if len(handled) != 2 || handled[0] != message.MsgTypeCreateSessionRequest || handled[1] != message.MsgTypeModifyBearerRequest {
		t.Fatalf("handled message types = %v; want CSR then MBR", handled)
	}
}

func TestPiggybackedResponseDeliversPrimaryAndDefersPiggybackDispatch(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn, err := Listen("127.0.0.1:0", 1, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	handlerCh := make(chan message.Header, 1)
	conn.SetHandler(func(c *Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
		handlerCh <- hdr
	})
	go func() {
		if err := conn.Serve(ctx); err != nil && ctx.Err() == nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("Serve: %v", err)
			}
		}
	}()

	pgw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("PGW ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = pgw.Close() })

	req, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           0,
		SequenceNumber: 0x010203,
	}, nil)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}

	primary, err := message.Marshal(message.Header{
		Version:        2,
		PiggyBacked:    true,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionResponse,
		TEID:           0x11111111,
		SequenceNumber: 0x010203,
	}, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil)})
	if err != nil {
		t.Fatalf("Marshal primary response: %v", err)
	}
	piggy, err := message.MarshalCreateBearerRequest(0x22222222, 0x010204,
		ie.NewEBI(5),
		ie.NewBearerContext(0,
			ie.NewEBI(6),
			ie.NewBearerQoS(0, 9, 0, 5, 0, 0, 0, 0),
		),
	)
	if err != nil {
		t.Fatalf("Marshal piggyback request: %v", err)
	}

	go func() {
		if err := pgw.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Errorf("PGW SetReadDeadline: %v", err)
			return
		}
		buf := make([]byte, 65535)
		_, sgwAddr, err := pgw.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("PGW ReadFromUDP: %v", err)
			return
		}
		payload := append(append([]byte{}, primary...), piggy...)
		if _, err := pgw.WriteToUDP(payload, sgwAddr); err != nil {
			t.Errorf("PGW WriteToUDP: %v", err)
		}
	}()

	resp, piggybacks, err := conn.SendWithPiggybacks(ctx, pgw.LocalAddr().(*net.UDPAddr), req)
	if err != nil {
		t.Fatalf("Send: %v", err)
	}
	if !bytes.Equal(resp, primary) {
		t.Fatalf("Send returned non-primary bytes\nwant: % X\ngot:  % X", primary, resp)
	}
	if len(piggybacks) != 1 {
		t.Fatalf("piggybacks = %d; want 1", len(piggybacks))
	}
	if piggybacks[0].Header.MessageType != message.MsgTypeCreateBearerRequest {
		t.Fatalf("piggyback type = %d; want Create Bearer Request", piggybacks[0].Header.MessageType)
	}

	select {
	case hdr := <-handlerCh:
		t.Fatalf("piggyback dispatched before transaction owner commit: %+v", hdr)
	case <-time.After(50 * time.Millisecond):
	}

	conn.DispatchFrames(pgw.LocalAddr().(*net.UDPAddr), piggybacks)

	select {
	case hdr := <-handlerCh:
		if hdr.MessageType != message.MsgTypeCreateBearerRequest {
			t.Fatalf("handler message type = %d; want Create Bearer Request", hdr.MessageType)
		}
		if hdr.SequenceNumber != 0x010204 {
			t.Fatalf("handler seq = 0x%06x; want 0x010204", hdr.SequenceNumber)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for piggybacked Create Bearer Request dispatch")
	}
}

func TestPendingTransactionDoesNotConsumeInboundRequestWithSameSequence(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conn, err := Listen("127.0.0.1:0", 1, 1, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatalf("Listen: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	handlerCh := make(chan message.Header, 1)
	conn.SetHandler(func(c *Conn, addr *net.UDPAddr, hdr message.Header, raw []byte) {
		handlerCh <- hdr
	})
	go func() {
		if err := conn.Serve(ctx); err != nil && ctx.Err() == nil {
			if !strings.Contains(err.Error(), "use of closed network connection") {
				t.Errorf("Serve: %v", err)
			}
		}
	}()

	pgw, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 0})
	if err != nil {
		t.Fatalf("PGW ListenUDP: %v", err)
	}
	t.Cleanup(func() { _ = pgw.Close() })

	req, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           0,
		SequenceNumber: 0x010203,
	}, nil)
	if err != nil {
		t.Fatalf("Marshal request: %v", err)
	}
	collidingReq, err := message.MarshalCreateBearerRequest(0x22222222, 0x010203,
		ie.NewEBI(5),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x55667788, netip.MustParseAddr("10.90.252.92")),
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
	)
	if err != nil {
		t.Fatalf("Marshal colliding request: %v", err)
	}
	resp, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionResponse,
		TEID:           0x11111111,
		SequenceNumber: 0x010203,
	}, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil)})
	if err != nil {
		t.Fatalf("Marshal response: %v", err)
	}

	go func() {
		if err := pgw.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Errorf("PGW SetReadDeadline: %v", err)
			return
		}
		buf := make([]byte, 65535)
		_, sgwAddr, err := pgw.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("PGW ReadFromUDP: %v", err)
			return
		}
		if _, err := pgw.WriteToUDP(collidingReq, sgwAddr); err != nil {
			t.Errorf("PGW colliding request WriteToUDP: %v", err)
			return
		}
		time.Sleep(50 * time.Millisecond)
		if _, err := pgw.WriteToUDP(resp, sgwAddr); err != nil {
			t.Errorf("PGW response WriteToUDP: %v", err)
		}
	}()

	gotResp, _, err := conn.SendWithPiggybacks(ctx, pgw.LocalAddr().(*net.UDPAddr), req)
	if err != nil {
		t.Fatalf("SendWithPiggybacks: %v", err)
	}
	gotHdr, _, err := message.Parse(gotResp)
	if err != nil {
		t.Fatalf("Parse response: %v", err)
	}
	if gotHdr.MessageType != message.MsgTypeCreateSessionResponse {
		t.Fatalf("Send returned message type = %d; want CSResp", gotHdr.MessageType)
	}

	select {
	case hdr := <-handlerCh:
		if hdr.MessageType != message.MsgTypeCreateBearerRequest {
			t.Fatalf("handler message type = %d; want CBR", hdr.MessageType)
		}
		if hdr.SequenceNumber != 0x010203 {
			t.Fatalf("handler seq = 0x%06x; want 0x010203", hdr.SequenceNumber)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for colliding inbound request dispatch")
	}
}

func readUDPTest(t *testing.T, conn *net.UDPConn) []byte {
	t.Helper()
	buf := make([]byte, 65535)
	n, _, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("ReadFromUDP: %v", err)
	}
	return append([]byte{}, buf[:n]...)
}
