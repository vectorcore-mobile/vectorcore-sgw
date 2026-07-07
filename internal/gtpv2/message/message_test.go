package message_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
)

func TestMarshalRejectsOversizedIE(t *testing.T) {
	_, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		SequenceNumber: 1,
	}, []*ie.IE{{
		Type:  ie.TypePCO,
		Value: make([]byte, 1<<16),
	}})
	if err == nil || !strings.Contains(err.Error(), "exceeds uint16") {
		t.Fatalf("Marshal oversized IE error = %v; want uint16 length error", err)
	}
}

func TestMarshalInvalidLengthEchoResponseUsesNoTEIDHeader(t *testing.T) {
	raw, err := message.MarshalInvalidLengthResponse(message.Header{
		Version:        2,
		HasTEID:        false,
		MessageType:    message.MsgTypeEchoRequest,
		SequenceNumber: 0x010203,
	}, 0)
	if err != nil {
		t.Fatalf("MarshalInvalidLengthResponse: %v", err)
	}
	hdr, _, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse invalid-length Echo response: %v", err)
	}
	if hdr.MessageType != message.MsgTypeEchoResponse {
		t.Fatalf("message type = %d; want Echo Response", hdr.MessageType)
	}
	if hdr.HasTEID {
		t.Fatal("Echo invalid-length response has TEID; want T=0")
	}
}

func TestHeaderRoundtripWithTEID(t *testing.T) {
	h := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           0xDEADBEEF,
		SequenceNumber: 0x000042,
	}
	buf := message.MarshalHeader(h, 0)

	got, _, err := message.ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got.TEID != h.TEID {
		t.Errorf("TEID: got 0x%08X, want 0x%08X", got.TEID, h.TEID)
	}
	if got.SequenceNumber != h.SequenceNumber {
		t.Errorf("Seq: got %d, want %d", got.SequenceNumber, h.SequenceNumber)
	}
	if got.MessageType != h.MessageType {
		t.Errorf("MsgType: got %d, want %d", got.MessageType, h.MessageType)
	}
}

func TestHeaderRoundtripWithoutTEID(t *testing.T) {
	h := message.Header{
		Version:        2,
		HasTEID:        false,
		MessageType:    message.MsgTypeEchoRequest,
		SequenceNumber: 0x000001,
	}
	buf := message.MarshalHeader(h, 0)
	got, _, err := message.ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got.HasTEID {
		t.Error("expected HasTEID=false")
	}
	if got.SequenceNumber != 1 {
		t.Errorf("Seq: got %d, want 1", got.SequenceNumber)
	}
}

func TestWrongVersion(t *testing.T) {
	buf := []byte{0x20, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01} // version=1
	_, _, err := message.ParseHeader(buf)
	if err == nil {
		t.Error("expected error for version=1")
	}
}

// TestMessageLengthValidation verifies that ParseHeader enforces the declared Length
// field per TS 29.274 Rel-15 §5.1: truncated messages return ErrInvalidLength with
// the partial header populated (for §7.7.3 error responses), and the body is bounded
// to the declared length when trailing padding is present.
func TestMessageLengthValidation(t *testing.T) {
	// Build a valid Echo Request, then truncate one byte.
	req := message.EchoRequest{Header: message.Header{
		Version: 2, HasTEID: false, MessageType: message.MsgTypeEchoRequest, SequenceNumber: 7,
	}}
	wire, err := message.MarshalEchoResponse(&req, 1)
	if err != nil {
		t.Fatal(err)
	}
	// Truncate: shorten buf so declared length > received length.
	truncated := wire[:len(wire)-1]
	_, _, parseErr := message.ParseHeader(truncated)
	if parseErr == nil {
		t.Fatal("expected ErrInvalidLength for truncated message, got nil")
	}
	var lenErr *message.ErrInvalidLength
	if !errors.As(parseErr, &lenErr) {
		t.Fatalf("expected *ErrInvalidLength, got %T: %v", parseErr, parseErr)
	}
	// Partial header must carry the sequence number for §7.7.3 error response.
	if lenErr.Hdr.SequenceNumber != 7 {
		t.Errorf("ErrInvalidLength.Hdr.SequenceNumber = %d; want 7", lenErr.Hdr.SequenceNumber)
	}

	// Trailing garbage beyond declared length must be ignored (body bounded).
	padded := append(wire, 0xFF, 0xFF, 0xFF)
	h, body, err := message.ParseHeader(padded)
	if err != nil {
		t.Fatalf("ParseHeader on padded message: %v", err)
	}
	// Body must be bounded to declared length, not extend into padding.
	wantBodyLen := int(h.Length) - (8 - 4) // without-TEID header = 8; Length = total - 4
	if len(body) != wantBodyLen {
		t.Errorf("body length: got %d, want %d (trailing padding must be excluded)", len(body), wantBodyLen)
	}
}

func TestSplitFramesPiggybackedCreateBearerRequest(t *testing.T) {
	primaryHdr := message.Header{
		Version:        2,
		PiggyBacked:    true,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionResponse,
		TEID:           0x01020304,
		SequenceNumber: 0x010203,
	}
	primary, err := message.Marshal(primaryHdr, []*ie.IE{
		ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
	})
	if err != nil {
		t.Fatalf("Marshal primary response: %v", err)
	}

	piggyHdr := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x11223344,
		SequenceNumber: 0x010204,
	}
	piggy, err := message.Marshal(piggyHdr, []*ie.IE{
		ie.NewEBI(5),
		ie.NewBearerContext(0,
			ie.NewEBI(6),
			ie.NewBearerQoS(0, 9, 0, 5, 0, 0, 0, 0),
		),
	})
	if err != nil {
		t.Fatalf("Marshal piggybacked request: %v", err)
	}

	frames, err := message.SplitFrames(append(primary, piggy...))
	if err != nil {
		t.Fatalf("SplitFrames: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d; want 2", len(frames))
	}
	if frames[0].Header.MessageType != message.MsgTypeCreateSessionResponse {
		t.Fatalf("frame[0] type = %d; want Create Session Response", frames[0].Header.MessageType)
	}
	if frames[1].Header.MessageType != message.MsgTypeCreateBearerRequest {
		t.Fatalf("frame[1] type = %d; want Create Bearer Request", frames[1].Header.MessageType)
	}
	if !bytes.Equal(frames[0].Raw, primary) {
		t.Fatalf("primary raw was not bounded to first message")
	}
	if !bytes.Equal(frames[1].Raw, piggy) {
		t.Fatalf("piggy raw mismatch")
	}
	if frames[0].End != len(primary) || frames[1].Start != len(primary) {
		t.Fatalf("frame boundaries = [%d,%d] [%d,%d]; primary len=%d",
			frames[0].Start, frames[0].End, frames[1].Start, frames[1].End, len(primary))
	}
}

func TestMarshalPiggybackedCreateSessionResponseWithCreateBearerRequest(t *testing.T) {
	primary, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionResponse,
		TEID:           0x01020304,
		SequenceNumber: 0x010203,
	}, []*ie.IE{
		ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
	})
	if err != nil {
		t.Fatalf("Marshal primary response: %v", err)
	}
	piggy, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateBearerRequest,
		TEID:           0x11223344,
		SequenceNumber: 0x010204,
	}, []*ie.IE{
		ie.NewEBI(6),
		ie.NewBearerContext(0,
			ie.NewEBI(0),
			ie.NewBearerTFT([]byte{0x21, 0x01, 0x02}),
			ie.NewFTEID(1, ie.IFTypeS5S8UPGW, 0x55667788, netip.MustParseAddr("10.90.252.92")),
			ie.NewBearerQoS(1, 5, 0, 5, 128000, 128000, 64000, 64000),
		),
	})
	if err != nil {
		t.Fatalf("Marshal piggyback request: %v", err)
	}

	out, err := message.MarshalPiggybacked(primary, piggy)
	if err != nil {
		t.Fatalf("MarshalPiggybacked: %v", err)
	}
	frames, err := message.SplitFrames(out)
	if err != nil {
		t.Fatalf("SplitFrames: %v", err)
	}
	if len(frames) != 2 {
		t.Fatalf("frames = %d; want 2", len(frames))
	}
	if !frames[0].Header.PiggyBacked {
		t.Fatal("primary P flag is clear; want set when another message follows")
	}
	if frames[1].Header.PiggyBacked {
		t.Fatal("final piggybacked message P flag is set; want clear")
	}
	if frames[0].Header.MessageType != message.MsgTypeCreateSessionResponse {
		t.Fatalf("frame[0] type = %d; want Create Session Response", frames[0].Header.MessageType)
	}
	if frames[1].Header.MessageType != message.MsgTypeCreateBearerRequest {
		t.Fatalf("frame[1] type = %d; want Create Bearer Request", frames[1].Header.MessageType)
	}
	if frames[0].Header.SequenceNumber != 0x010203 || frames[1].Header.SequenceNumber != 0x010204 {
		t.Fatalf("sequences = 0x%06X/0x%06X; want 0x010203/0x010204",
			frames[0].Header.SequenceNumber, frames[1].Header.SequenceNumber)
	}
	if frames[0].End != len(primary) || frames[1].Start != len(primary) || frames[1].End != len(out) {
		t.Fatalf("frame boundaries = [%d,%d] [%d,%d]; primary len=%d total=%d",
			frames[0].Start, frames[0].End, frames[1].Start, frames[1].End, len(primary), len(out))
	}
	if int(frames[0].Header.Length)+4 != len(primary) {
		t.Fatalf("primary length field covers %d bytes; want %d", int(frames[0].Header.Length)+4, len(primary))
	}
	if int(frames[1].Header.Length)+4 != len(piggy) {
		t.Fatalf("piggyback length field covers %d bytes; want %d", int(frames[1].Header.Length)+4, len(piggy))
	}
}

func TestSplitFramesRejectsMissingPiggybackedMessage(t *testing.T) {
	primary, err := message.Marshal(message.Header{
		Version:        2,
		PiggyBacked:    true,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionResponse,
		TEID:           0x01020304,
		SequenceNumber: 0x010203,
	}, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil)})
	if err != nil {
		t.Fatalf("Marshal primary response: %v", err)
	}

	_, err = message.SplitFrames(primary)
	if err == nil {
		t.Fatal("SplitFrames succeeded for P flag without following message")
	}
}

// TestHeaderMPFlagWire verifies MP flag and Message Priority encoding in the GTPv2-C
// header per TS 29.274 §5.4 Figure 5.4-1 (TEID-bearing variant). Per C14: raw wire tests
// required. Per C17: TestHeaderNoTEIDIgnoresMP below covers the other flag-bit state —
// the §5.3 (no-TEID) variant, where bit 3 is plain spare and there is no MP subfield at all.
func TestHeaderMPFlagWire(t *testing.T) {
	// With TEID: octet 1 bit 2 = MP; octet 12 bits 7-4 = priority.
	h := message.Header{
		Version: 2, HasTEID: true, MP: true, MessagePriority: 5,
		MessageType: message.MsgTypeCreateSessionRequest, TEID: 0x11223344, SequenceNumber: 1,
	}
	buf := message.MarshalHeader(h, 0)
	// Octet 1: version(0x40) | T(0x08) | MP(0x04) = 0x4C
	if buf[0] != 0x4C {
		t.Errorf("octet 1 with MP: got 0x%02X; want 0x4C (version=2, T=1, MP=1)", buf[0])
	}
	// Octet 12: priority=5 → bits 7-4 = 0x50
	if buf[11] != 0x50 {
		t.Errorf("octet 12 priority byte: got 0x%02X; want 0x50 (priority=5)", buf[11])
	}

	// Parse back and verify fields.
	got, _, err := message.ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if !got.MP {
		t.Error("MP flag not parsed")
	}
	if got.MessagePriority != 5 {
		t.Errorf("MessagePriority: got %d; want 5", got.MessagePriority)
	}

	// Without MP: octet 12 must be spare (0x00).
	h2 := message.Header{Version: 2, HasTEID: true, MP: false, MessageType: 1, SequenceNumber: 1}
	buf2 := message.MarshalHeader(h2, 0)
	if buf2[0]&0x04 != 0 {
		t.Errorf("MP bit set in octet 1 when MP=false: 0x%02X", buf2[0])
	}
	if buf2[11] != 0x00 {
		t.Errorf("octet 12 spare not zero when MP=false: 0x%02X", buf2[11])
	}
}

// TestHeaderNoTEIDIgnoresMP verifies that the no-TEID header variant (§5.3 Figure 5.3-1:
// Echo Request/Response, Version Not Supported Indication) never sets or interprets the
// MP bit or a Message-Priority subfield — bit 3 of octet 1 and the trailing octet are
// plain spare in that figure (no MP CR applied to it), unlike the TEID-bearing §5.4
// variant covered by TestHeaderMPFlagWire above. Found and fixed 2026-06-23: ParseHeader/
// MarshalHeader previously read/wrote MP unconditionally regardless of HasTEID.
func TestHeaderNoTEIDIgnoresMP(t *testing.T) {
	h := message.Header{
		Version: 2, HasTEID: false, MP: true, MessagePriority: 9,
		MessageType: message.MsgTypeEchoRequest, SequenceNumber: 1,
	}
	buf := message.MarshalHeader(h, 0)
	if buf[0]&0x04 != 0 {
		t.Errorf("octet 1 bit 3 (spare per §5.3) set despite no MP subfield in this variant: 0x%02X", buf[0])
	}
	if buf[7] != 0x00 {
		t.Errorf("trailing octet (plain Spare per §5.3) not zero: 0x%02X", buf[7])
	}

	got, _, err := message.ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader: %v", err)
	}
	if got.MP {
		t.Error("MP parsed as true for no-TEID header; §5.3 defines no MP bit for this variant")
	}
	if got.MessagePriority != 0 {
		t.Errorf("MessagePriority: got %d; want 0 (no subfield in §5.3 variant)", got.MessagePriority)
	}
}

func TestEchoRoundtrip(t *testing.T) {
	req := message.EchoRequest{
		Header: message.Header{
			Version:        2,
			HasTEID:        false,
			MessageType:    message.MsgTypeEchoRequest,
			SequenceNumber: 77,
		},
	}
	wire, err := message.MarshalEchoResponse(&req, 5)
	if err != nil {
		t.Fatalf("MarshalEchoResponse: %v", err)
	}

	h, ies, err := message.Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.MessageType != message.MsgTypeEchoResponse {
		t.Errorf("MsgType: got %d, want %d", h.MessageType, message.MsgTypeEchoResponse)
	}
	if h.SequenceNumber != 77 {
		t.Errorf("Seq: got %d, want 77", h.SequenceNumber)
	}
	recovery := ie.FindFirst(ies, ie.TypeRecovery)
	if recovery == nil {
		t.Fatal("Recovery IE missing from Echo Response")
	}
	val, err := recovery.RecoveryValue()
	if err != nil {
		t.Fatal(err)
	}
	if val != 5 {
		t.Errorf("RestartCounter: got %d, want 5", val)
	}
}

func TestMarshalEchoRequest(t *testing.T) {
	recovery := uint8(9)
	wire, err := message.MarshalEchoRequest(0x010203, &recovery)
	if err != nil {
		t.Fatalf("MarshalEchoRequest: %v", err)
	}

	h, ies, err := message.Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.HasTEID {
		t.Fatal("Echo Request has TEID flag set; want no-TEID header")
	}
	if h.MessageType != message.MsgTypeEchoRequest {
		t.Fatalf("Echo Request message type = %d; want %d", h.MessageType, message.MsgTypeEchoRequest)
	}
	if h.SequenceNumber != 0x010203 {
		t.Fatalf("Echo Request seq = 0x%06X; want 0x010203", h.SequenceNumber)
	}
	recIE := ie.FindFirst(ies, ie.TypeRecovery)
	if recIE == nil {
		t.Fatal("Recovery IE missing from Echo Request")
	}
	got, err := recIE.RecoveryValue()
	if err != nil {
		t.Fatalf("RecoveryValue: %v", err)
	}
	if got != recovery {
		t.Fatalf("Recovery IE value = %d; want %d", got, recovery)
	}
}

func buildCSR(t *testing.T, teid uint32, seq uint32) []byte {
	t.Helper()
	h := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionRequest,
		TEID:           teid,
		SequenceNumber: seq,
	}
	addr := netip.MustParseAddr("10.1.1.1")
	ies := []*ie.IE{
		ie.NewIMSI("311430000000001"),
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewSelectionMode(0), // R15-REAUDIT-007: C per Table 7.2.1-1, required for E-UTRAN initial attach
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 0xAABBCCDD, addr),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(256000, 256000),
		ie.NewBearerContext(0,
			ie.NewEBI(5),
			ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0),
		),
	}
	wire, err := message.Marshal(h, ies)
	if err != nil {
		t.Fatalf("Marshal CSR: %v", err)
	}
	return wire
}

func TestCreateSessionRequestParse(t *testing.T) {
	wire := buildCSR(t, 0xAABBCCDD, 1)

	h, ies, err := message.Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.MessageType != message.MsgTypeCreateSessionRequest {
		t.Fatalf("wrong message type: %d", h.MessageType)
	}

	req, err := message.ParseCreateSessionRequest(h, ies)
	if err != nil {
		t.Fatalf("ParseCreateSessionRequest: %v", err)
	}

	imsi, err := req.IMSI.IMSI()
	if err != nil {
		t.Fatal(err)
	}
	if imsi != "311430000000001" {
		t.Errorf("IMSI: got %q, want %q", imsi, "311430000000001")
	}
	apn, err := req.APN.APNValue()
	if err != nil {
		t.Fatal(err)
	}
	if apn != "internet" {
		t.Errorf("APN: got %q, want %q", apn, "internet")
	}
	if len(req.BearerContexts) != 1 {
		t.Errorf("expected 1 bearer context, got %d", len(req.BearerContexts))
	}
}

// TestCreateSessionRequestMissingUEIdentity verifies that a CSReq with neither IMSI
// nor MEI is rejected. Per TS 29.274 Rel-15 Table 7.2.1-1, IMSI is Conditional (C);
// MEI serves as the identifier for emergency (unauthenticated) UEs. At least one must
// be present.
func TestCreateSessionRequestMissingUEIdentity(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest, SequenceNumber: 1}
	ies := []*ie.IE{
		// IMSI and MEI both omitted — no UE identity
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(256000, 256000),
		ie.NewBearerContext(0, ie.NewEBI(5), ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)),
	}
	_, err := message.ParseCreateSessionRequest(h, ies)
	if err == nil {
		t.Error("expected error when neither IMSI nor MEI is present")
	}
	me, ok := err.(*message.MissingIEError)
	if !ok {
		t.Fatalf("expected MissingIEError, got %T: %v", err, err)
	}
	if me.IEType != ie.TypeIMSI {
		t.Errorf("wrong IE type in error: %d", me.IEType)
	}
}

// TestCreateSessionRequestMEIOnlyAccepted verifies that a CSReq with MEI but no IMSI
// is accepted. Per TS 29.274 Rel-15 Table 7.2.1-1, IMSI is Conditional (C) — absent
// for unauthenticated UEs where MEI is the identifying IE.
func TestCreateSessionRequestMEIOnlyAccepted(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest, SequenceNumber: 1}
	ies := []*ie.IE{
		ie.NewMEI("490154203237518"), // IMSI absent; MEI present for emergency UE
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"), // C per Table 7.2.1-1, required for E-UTRAN initial attach
		ie.NewSelectionMode(0),             // C per Table 7.2.1-1, required for E-UTRAN initial attach
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("sos"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(256000, 256000),
		ie.NewBearerContext(0, ie.NewEBI(5), ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)),
	}
	_, err := message.ParseCreateSessionRequest(h, ies)
	if err != nil {
		t.Errorf("CSReq with MEI but no IMSI must be accepted (IMSI is C per Rel-15 Table 7.2.1-1): %v", err)
	}
}

// TestCreateSessionRequestMissingIMSI is preserved for compatibility; it tests
// the same path as TestCreateSessionRequestMissingUEIdentity (no IMSI, no MEI).
func TestCreateSessionRequestMissingIMSI(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest, SequenceNumber: 1}
	ies := []*ie.IE{
		// IMSI deliberately omitted, MEI also absent
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(256000, 256000),
		ie.NewBearerContext(0, ie.NewEBI(5), ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)),
	}
	_, err := message.ParseCreateSessionRequest(h, ies)
	if err == nil {
		t.Error("expected error for missing IMSI")
	}
	me, ok := err.(*message.MissingIEError)
	if !ok {
		t.Fatalf("expected MissingIEError, got %T: %v", err, err)
	}
	if me.IEType != ie.TypeIMSI {
		t.Errorf("wrong IE type in error: %d", me.IEType)
	}
}

func TestCreateSessionRequestMissingBearerContext(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest}
	ies := []*ie.IE{
		ie.NewIMSI("311430000000001"),
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewSelectionMode(0),
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(256000, 256000),
		// BearerContext omitted
	}
	_, err := message.ParseCreateSessionRequest(h, ies)
	if err == nil {
		t.Error("expected error for missing BearerContext")
	}
}

func TestCreateSessionResponseRoundtrip(t *testing.T) {
	wire := buildCSR(t, 0x11223344, 42)
	h, ies, _ := message.Parse(wire)
	req, _ := message.ParseCreateSessionRequest(h, ies)

	sgwFTEID := ie.NewFTEID(0, ie.IFTypeS11S4SGW, 0xCAFEBABE, netip.MustParseAddr("10.90.250.10"))
	resp, err := message.MarshalCreateSessionResponse(req, ie.CauseRequestAccepted, sgwFTEID)
	if err != nil {
		t.Fatalf("MarshalCreateSessionResponse: %v", err)
	}

	rh, ries, err := message.Parse(resp)
	if err != nil {
		t.Fatalf("Parse response: %v", err)
	}
	if rh.MessageType != message.MsgTypeCreateSessionResponse {
		t.Errorf("wrong msg type: %d", rh.MessageType)
	}
	if rh.SequenceNumber != 42 {
		t.Errorf("seq: got %d, want 42", rh.SequenceNumber)
	}
	causeIE := ie.FindFirst(ries, ie.TypeCause)
	if causeIE == nil {
		t.Fatal("Cause IE missing from response")
	}
	cause, _ := causeIE.CauseValue()
	if cause != ie.CauseRequestAccepted {
		t.Errorf("cause: got %d, want %d", cause, ie.CauseRequestAccepted)
	}
}

func TestCreateSessionResponsePreservesPolicyContextIEs(t *testing.T) {
	h := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeCreateSessionResponse,
		TEID:           0x11223344,
		SequenceNumber: 1,
	}
	pco := &ie.IE{Type: ie.TypePCO, Value: []byte{0x80, 0x80, 0x21}}
	apnRestriction := &ie.IE{Type: ie.TypeAPNRestriction, Value: []byte{0x00}}
	chargingID := &ie.IE{Type: ie.TypeChargingID, Value: []byte{0x01, 0x02, 0x03, 0x04}}
	raw, err := message.Marshal(h, []*ie.IE{
		ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
		ie.NewFTEID(1, ie.IFTypeS5S8CPGW, 0x01020304, netip.MustParseAddr("10.0.0.1")),
		ie.NewPAA(ie.PDNTypeIPv4, netip.MustParseAddr("100.64.0.1")),
		ie.NewAMBR(256000, 256000),
		pco,
		apnRestriction,
		chargingID,
		ie.NewBearerContext(0,
			ie.NewEBI(5),
			ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
			ie.NewFTEID(2, ie.IFTypeS5S8UPGW, 0x11121314, netip.MustParseAddr("10.0.0.2")),
		),
	})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	parsedH, parsedIEs, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	resp, err := message.ParseCreateSessionResponse(parsedH, parsedIEs)
	if err != nil {
		t.Fatalf("ParseCreateSessionResponse: %v", err)
	}
	if resp.PCO == nil || string(resp.PCO.Value) != string(pco.Value) {
		t.Fatalf("PCO not preserved: %#v", resp.PCO)
	}
	if resp.APNRestriction == nil || string(resp.APNRestriction.Value) != string(apnRestriction.Value) {
		t.Fatalf("APNRestriction not preserved: %#v", resp.APNRestriction)
	}
	if resp.ChargingID == nil || string(resp.ChargingID.Value) != string(chargingID.Value) {
		t.Fatalf("ChargingID not preserved: %#v", resp.ChargingID)
	}
}

// TestCreateSessionRequestMissingPAAAccepted verifies that CSReq without PAA is
// accepted. PAA is conditional on S11/S5/S8, and Open5GS does not reject the
// S11 Create Session Request solely because it is absent.
func TestCreateSessionRequestMissingPAAAccepted(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest}
	ies := []*ie.IE{
		ie.NewIMSI("311430000000001"),
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewSelectionMode(0),
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		// PAA omitted
		ie.NewAMBR(256000, 256000),
		ie.NewBearerContext(0, ie.NewEBI(5), ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)),
	}
	req, err := message.ParseCreateSessionRequest(h, ies)
	if err != nil {
		t.Fatalf("ParseCreateSessionRequest: %v", err)
	}
	if req.PAA != nil {
		t.Fatalf("PAA = %#v; want nil", req.PAA)
	}
}

// TestCreateSessionRequestMissingAMBRAccepted verifies that CSReq without AMBR
// is accepted. AMBR is conditional on S11/S5/S8, and Open5GS tolerates it being
// absent on the inbound S11 Create Session Request.
func TestCreateSessionRequestMissingAMBRAccepted(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest}
	ies := []*ie.IE{
		ie.NewIMSI("311430000000001"),
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewSelectionMode(0),
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		// AMBR omitted
		ie.NewBearerContext(0, ie.NewEBI(5), ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)),
	}
	req, err := message.ParseCreateSessionRequest(h, ies)
	if err != nil {
		t.Fatalf("ParseCreateSessionRequest: %v", err)
	}
	if req.AMBR != nil {
		t.Fatalf("AMBR = %#v; want nil", req.AMBR)
	}
}

// TestCreateSessionRequestBearerContextMissingEBI verifies that a Bearer Context
// without EBI is rejected. Per TS 29.274 Rel-15 Table 7.2.1-2, EBI is M within
// the default Bearer Context.
func TestCreateSessionRequestBearerContextMissingEBI(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest}
	ies := []*ie.IE{
		ie.NewIMSI("311430000000001"),
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewSelectionMode(0),
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(256000, 256000),
		ie.NewBearerContext(0, ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0)), // EBI omitted
	}
	_, err := message.ParseCreateSessionRequest(h, ies)
	if err == nil {
		t.Error("expected error for Bearer Context missing EBI (M per Rel-15 Table 7.2.1-2)")
	}
}

// TestCreateSessionRequestBearerContextMissingQoS verifies that a Bearer Context
// without Bearer QoS is rejected. Per TS 29.274 Rel-15 Table 7.2.1-2, Bearer
// Level QoS is M within the default Bearer Context.
func TestCreateSessionRequestBearerContextMissingQoS(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeCreateSessionRequest}
	ies := []*ie.IE{
		ie.NewIMSI("311430000000001"),
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("311", "435"),
		ie.NewSelectionMode(0),
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 1, netip.MustParseAddr("1.2.3.4")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(256000, 256000),
		ie.NewBearerContext(0, ie.NewEBI(5)), // Bearer QoS omitted
	}
	_, err := message.ParseCreateSessionRequest(h, ies)
	if err == nil {
		t.Error("expected error for Bearer Context missing Bearer QoS (M per Rel-15 Table 7.2.1-2)")
	}
}

// TestDeleteSessionRequestMissingEBI verifies that a DSReq without EBI is accepted.
// Per TS 29.274 Table 7.2.9.1-1, EBI is Conditional (C) — absence is not an error.
func TestDeleteSessionRequestMissingEBI(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeDeleteSessionRequest}
	req, err := message.ParseDeleteSessionRequest(h, nil)
	if err != nil {
		t.Errorf("DSReq without EBI must be accepted (EBI is Conditional per Table 7.2.9.1-1): %v", err)
	}
	if req.EBI != nil {
		t.Error("EBI should be nil when not present")
	}
}

// TestModifyBearerResponseWire verifies raw byte encoding of Modify Bearer Response per
// TS 29.274 Rel-15 §7.2.8 / Table 7.2.8-1 and Table 7.2.8-2.
//
// Compliance checks exercised:
//
//	C4:  Response header TEID = peerTEID (MME's S11 TEID), not the request TEID.
//	     Per TS 29.274 §5.5.1: TEID in response must be the one received from the peer.
//	C5:  MessageType = 35 (MsgTypeModifyBearerResponse per Table 6.1-1), not request type 34.
//	C10: Bearer Context Modified IE at instance=0 per Table 7.2.8-1:
//	     "Bearer Contexts modified | C | ... | Bearer Context | 0".
//	C10: S1-U SGW F-TEID at instance=0 within Bearer Context per Table 7.2.8-2:
//	     "S1-U SGW F-TEID | C | ... | F-TEID | 0".
func TestModifyBearerResponseWire(t *testing.T) {
	// Request TEID 0x12345678 is SGW's own S11 TEID used to route the MBReq inbound.
	// Response header must use peerTEID 0xAABBCCDD (the MME's S11 TEID), not 0x12345678.
	req := &message.ModifyBearerRequest{
		Header: message.Header{
			Version:        2,
			HasTEID:        true,
			MessageType:    message.MsgTypeModifyBearerRequest,
			TEID:           0x12345678, // SGW's inbound TEID — must NOT appear in response
			SequenceNumber: 77,
		},
	}

	// Bearer Context Modified (instance=0 per Table 7.2.8-1).
	// S1-U SGW F-TEID at instance=0 per Table 7.2.8-2 row: "S1-U SGW F-TEID | C | ... | F-TEID | 0".
	// IFTypeS1USGW=1 per TS 29.274 Table 8.22-1: "S1-U SGW GTP-U F-TEID | 1".
	bcModified := ie.NewBearerContext(0,
		ie.NewEBI(5),
		ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil),
		ie.NewFTEID(0, ie.IFTypeS1USGW, 0x11223344, netip.MustParseAddr("10.0.0.1")),
	)

	wire, err := message.MarshalModifyBearerResponse(req, 0xAABBCCDD, ie.CauseRequestAccepted, bcModified)
	if err != nil {
		t.Fatalf("MarshalModifyBearerResponse: %v", err)
	}

	// Expected 46-byte wire (header=12, body=34):
	// [0x48, 0x23, 0x00, 0x2A, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x4D, 0x00,  // GTPv2-C header
	//  0x02, 0x00, 0x02, 0x00, 0x10, 0x00,                                        // Cause(16)
	//  0x5D, 0x00, 0x18, 0x00,                                                    // BC(type=93,len=24,inst=0)
	//    0x49, 0x00, 0x01, 0x00, 0x05,                                            // EBI=5
	//    0x02, 0x00, 0x02, 0x00, 0x10, 0x00,                                      // bearer Cause=16
	//    0x57, 0x00, 0x09, 0x00, 0x81, 0x11, 0x22, 0x33, 0x44, 0x0A, 0x00, 0x00, 0x01]  // F-TEID
	want := []byte{
		// GTPv2-C header (12 bytes): version=2 T=1 → 0x48; MsgType=35; Len=42; TEID; Seq=77
		0x48, 0x23, 0x00, 0x2A, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x4D, 0x00,
		// Message-level Cause IE: type=2, len=2, inst=0, cause=16, flags=0
		0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
		// Bearer Context IE: type=93(0x5D), len=24(0x18), inst=0
		0x5D, 0x00, 0x18, 0x00,
		// EBI: type=73(0x49), len=1, inst=0, val=5
		0x49, 0x00, 0x01, 0x00, 0x05,
		// Bearer Cause: type=2, len=2, inst=0, cause=16, flags=0
		0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
		// S1-U SGW F-TEID: type=87(0x57), len=9, inst=0
		// flags=0x81: V4(bit7)=1 | IFTypeS1USGW(1)=0x01; TEID=0x11223344; IP=10.0.0.1
		0x57, 0x00, 0x09, 0x00, 0x81, 0x11, 0x22, 0x33, 0x44, 0x0A, 0x00, 0x00, 0x01,
	}
	if len(wire) != len(want) {
		t.Fatalf("wire length = %d; want %d", len(wire), len(want))
	}
	for i, b := range want {
		if wire[i] != b {
			t.Errorf("byte[%d] = 0x%02X; want 0x%02X", i, wire[i], b)
		}
	}

	// Named compliance assertions for readability in CI output.
	// C5: response message type
	if wire[1] != 35 {
		t.Errorf("C5: MessageType = %d; want 35 (MsgTypeModifyBearerResponse per Table 6.1-1)", wire[1])
	}
	// C4: response TEID must be peerTEID, not the request TEID (0x12345678)
	teid := binary.BigEndian.Uint32(wire[4:8])
	if teid != 0xAABBCCDD {
		t.Errorf("C4: header TEID = 0x%08X; want 0xAABBCCDD (peerTEID, not request TEID 0x12345678)", teid)
	}
	// C10: Bearer Context IE type=93 at instance=0
	if wire[18] != ie.TypeBearerContext {
		t.Errorf("C10: BC IE type byte[18] = 0x%02X; want 0x%02X (TypeBearerContext=93)", wire[18], ie.TypeBearerContext)
	}
	if wire[21] != 0x00 {
		t.Errorf("C10: BC instance byte[21] = 0x%02X; want 0x00 (Table 7.2.8-1 instance=0)", wire[21])
	}
	// C10: S1-U SGW F-TEID at instance=0 within BC
	if wire[33] != ie.TypeFTEID {
		t.Errorf("C10: F-TEID type byte[33] = 0x%02X; want 0x%02X (TypeFTEID=87)", wire[33], ie.TypeFTEID)
	}
	if wire[36] != 0x00 {
		t.Errorf("C10: F-TEID instance byte[36] = 0x%02X; want 0x00 (Table 7.2.8-2 S1-U SGW F-TEID at instance 0)", wire[36])
	}
	if wire[37] != 0x81 {
		t.Errorf("F-TEID flags byte[37] = 0x%02X; want 0x81 (V4=1, IFTypeS1USGW=1 per Table 8.22-1)", wire[37])
	}
}

// TestModifyBearerRequestENBFTEIDInstance verifies that the eNodeB S1-U F-TEID in a
// Modify Bearer Request Bearer Context is encoded at instance=0 and can be decoded correctly.
// Per TS 29.274 Rel-15 Table 7.2.7-2 row R5:
//
//	"S1 eNodeB F-TEID | C | This IE shall be sent on the S11 interface if S1-U is being used: ... | F-TEID | 0"
//
// The handler uses ie.FindFirst(children, ie.TypeFTEID) which looks up instance=0.
// If the F-TEID were at a non-zero instance, the handler would silently skip it.
func TestModifyBearerRequestENBFTEIDInstance(t *testing.T) {
	enbIP := netip.MustParseAddr("192.168.1.1")
	// IFTypeS1UENB=0 per TS 29.274 Table 8.22-1: "S1-U eNodeB GTP-U F-TEID | 0".
	// instance=0 per Table 7.2.7-2 column "Ins." = 0.
	enbFTEID := ie.NewFTEID(0, ie.IFTypeS1UENB, 0xDEADBEEF, enbIP)
	bc := ie.NewBearerContext(0, ie.NewEBI(5), enbFTEID)

	h := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeModifyBearerRequest,
		TEID:           0x00000001,
		SequenceNumber: 1,
	}
	wire, err := message.Marshal(h, []*ie.IE{bc})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	// Wire layout (header=12, BC_IE_header=4, EBI=5, F-TEID=13; total=34):
	// [12]=BC type=93, [13:15]=len=18, [15]=BC inst=0
	// [16]=EBI type=73, [19]=EBI inst=0, [20]=EBI val=5
	// [21]=FTEID type=87, [22:24]=len=9, [24]=FTEID inst, [25]=flags
	//
	// C10: F-TEID instance byte at wire[24] must be 0x00.
	// Wire = header(12) + BC_IE_header(4) + EBI(5) + F-TEID(13) = 34 bytes.
	// Need at least 26 bytes to check wire[25] (F-TEID flags).
	if len(wire) < 26 {
		t.Fatalf("wire too short: %d bytes (want at least 26)", len(wire))
	}
	if wire[24] != 0x00 {
		t.Errorf("C10: eNB F-TEID instance byte wire[24] = 0x%02X; want 0x00 (Table 7.2.7-2 instance=0)", wire[24])
	}
	// flags = V4(0x80) | IFTypeS1UENB(0x00) = 0x80
	if wire[25] != 0x80 {
		t.Errorf("eNB F-TEID flags byte wire[25] = 0x%02X; want 0x80 (V4=1, IFTypeS1UENB=0 per Table 8.22-1)", wire[25])
	}

	// Parse and verify functional correctness.
	parsedH, ies, err := message.Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	req, err := message.ParseModifyBearerRequest(parsedH, ies)
	if err != nil {
		t.Fatalf("ParseModifyBearerRequest: %v", err)
	}
	if len(req.BearerContexts) != 1 {
		t.Fatalf("BearerContexts count = %d; want 1", len(req.BearerContexts))
	}
	children, err := req.BearerContexts[0].ChildIEs()
	if err != nil {
		t.Fatalf("ChildIEs: %v", err)
	}
	// FindFirst looks up instance=0 — must find the F-TEID.
	fteidIE := ie.FindFirst(children, ie.TypeFTEID)
	if fteidIE == nil {
		t.Fatal("eNB F-TEID not found in Bearer Context (ie.FindFirst at instance=0)")
	}
	if fteidIE.Instance != 0 {
		t.Errorf("eNB F-TEID instance = %d; want 0 (Table 7.2.7-2 S1 eNodeB F-TEID at instance 0)", fteidIE.Instance)
	}
	fteid, err := fteidIE.FTEIDValue()
	if err != nil {
		t.Fatalf("FTEIDValue: %v", err)
	}
	if fteid.TEID != 0xDEADBEEF {
		t.Errorf("eNB TEID = 0x%08X; want 0xDEADBEEF", fteid.TEID)
	}
	if fteid.IPv4.String() != "192.168.1.1" {
		t.Errorf("eNB IP = %v; want 192.168.1.1", fteid.IPv4)
	}
}

// TestModifyBearerRequestMissingBearerContext verifies that an MBReq without BearerContext is accepted.
// Per TS 29.274 Table 7.2.7-1, BearerContext is Conditional (C) — absence is not an error.
func TestModifyBearerRequestMissingBearerContext(t *testing.T) {
	h := message.Header{Version: 2, HasTEID: true, MessageType: message.MsgTypeModifyBearerRequest}
	req, err := message.ParseModifyBearerRequest(h, nil)
	if err != nil {
		t.Errorf("MBReq without BearerContext must be accepted (BearerContext is Conditional per Table 7.2.7-1): %v", err)
	}
	if len(req.BearerContexts) != 0 {
		t.Error("BearerContexts should be empty when not present")
	}
}

func TestModifyBearerRequestPreservesSecondaryRATUsageDataReport(t *testing.T) {
	rawReport := []byte{0x01, 0x06, 0x00, 0xaa, 0xbb, 0xcc}
	report := ie.NewSecondaryRATUsageDataReport(rawReport)
	bc := ie.NewBearerContext(0, ie.NewEBI(5))
	h := message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeModifyBearerRequest,
		TEID:           0x01020304,
		SequenceNumber: 0x123456,
	}
	wire, err := message.Marshal(h, []*ie.IE{bc, report})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	parsedH, ies, err := message.Parse(wire)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	req, err := message.ParseModifyBearerRequest(parsedH, ies)
	if err != nil {
		t.Fatalf("ParseModifyBearerRequest: %v", err)
	}
	if len(req.SecondaryRATUsageDataReports) != 1 {
		t.Fatalf("SecondaryRATUsageDataReports count = %d; want 1", len(req.SecondaryRATUsageDataReports))
	}
	got, err := req.SecondaryRATUsageDataReports[0].SecondaryRATUsageDataReportValue()
	if err != nil {
		t.Fatalf("SecondaryRATUsageDataReportValue: %v", err)
	}
	if !bytes.Equal(got, rawReport) {
		t.Fatalf("secondary RAT report payload = %x, want %x", got, rawReport)
	}
	if len(req.BearerContexts) != 1 {
		t.Fatalf("BearerContexts count = %d; want 1", len(req.BearerContexts))
	}
}

func TestResponseTypeForRel15RequestPairs(t *testing.T) {
	tests := []struct {
		name string
		req  uint8
		resp uint8
	}{
		{"Echo", message.MsgTypeEchoRequest, message.MsgTypeEchoResponse},
		{"CreateSession", message.MsgTypeCreateSessionRequest, message.MsgTypeCreateSessionResponse},
		{"ModifyBearer", message.MsgTypeModifyBearerRequest, message.MsgTypeModifyBearerResponse},
		{"DeleteSession", message.MsgTypeDeleteSessionRequest, message.MsgTypeDeleteSessionResponse},
		{"CreateBearer", message.MsgTypeCreateBearerRequest, message.MsgTypeCreateBearerResponse},
		{"UpdateBearer", message.MsgTypeUpdateBearerRequest, message.MsgTypeUpdateBearerResponse},
		{"DeleteBearer", message.MsgTypeDeleteBearerRequest, message.MsgTypeDeleteBearerResponse},
		{"ReleaseAccessBearers", message.MsgTypeReleaseAccessBearersRequest, message.MsgTypeReleaseAccessBearersResponse},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := message.ResponseTypeFor(tc.req)
			if !ok || got != tc.resp {
				t.Fatalf("ResponseTypeFor(%d) = (%d, %v), want (%d, true)", tc.req, got, ok, tc.resp)
			}
		})
	}
	if got, ok := message.ResponseTypeFor(255); ok {
		t.Fatalf("ResponseTypeFor(255) = (%d, true), want unknown", got)
	}
}

// FuzzParseHeader fuzzes GTPv2-C header parsing per C20.
// Seeds are golden wire vectors from prior phase wire tests.
func FuzzParseHeader(f *testing.F) {
	// GTPv2-C header with TEID (T=1, version=2): flags=0x48, MsgType=35 (MBResp)
	// 12-byte header from TestModifyBearerResponseWire
	f.Add([]byte{0x48, 0x23, 0x00, 0x2A, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x4D, 0x00})

	// GTPv2-C header without TEID (T=0): flags=0x40, 8-byte form
	f.Add([]byte{0x40, 0x20, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00})

	// Truncated — 4 bytes (too short for any valid header)
	f.Add([]byte{0x48, 0x20, 0x00, 0x10})
	// Empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = message.ParseHeader(b)
	})
}

// FuzzParse fuzzes full GTPv2-C message parsing (header + IEs) per C20.
// Seeds are complete message wire vectors from prior phase golden wire tests.
func FuzzParse(f *testing.F) {
	// Full 46-byte Modify Bearer Response from TestModifyBearerResponseWire
	f.Add([]byte{
		0x48, 0x23, 0x00, 0x2A, 0xAA, 0xBB, 0xCC, 0xDD, 0x00, 0x00, 0x4D, 0x00,
		0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
		0x5D, 0x00, 0x18, 0x00,
		0x49, 0x00, 0x01, 0x00, 0x05,
		0x02, 0x00, 0x02, 0x00, 0x10, 0x00,
		0x57, 0x00, 0x09, 0x00, 0x81, 0x11, 0x22, 0x33, 0x44, 0x0A, 0x00, 0x00, 0x01,
	})

	// 34-byte Modify Bearer Request (header + BC with EBI + eNB F-TEID)
	// from TestModifyBearerRequestENBFTEIDInstance
	f.Add([]byte{
		0x48, 0x22, 0x00, 0x16, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
		0x5D, 0x00, 0x12, 0x00,
		0x49, 0x00, 0x01, 0x00, 0x05,
		0x57, 0x00, 0x09, 0x00, 0x80, 0x00, 0xDE, 0xAD, 0xBE, 0xEF,
		0xC0, 0xA8, 0x01, 0x01,
	})

	// Header-only (no IEs), valid flags
	f.Add([]byte{0x48, 0x20, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
	// Empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = message.Parse(b)
	})
}
