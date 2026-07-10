package message_test

import (
	"net"
	"net/netip"
	"testing"

	"vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/pfcp/message"
)

// TestPFCPHeaderWire verifies the PFCP node-level header wire encoding
// per TS 29.244 Rel-15 §7.1.
//
// Expected encoding for AssociationSetupRequest with seq=1 and no IEs:
//
//	Octet 1: Version(3)=1 in bits 7-5 | FO=0 | MP=0 | S=0 | Spare=0 = 0x20
//	Octet 2: MessageType = 5 (AssociationSetupRequest)
//	Octets 3-4: Length = 4 (total 8 - mandatory 4)
//	Octets 5-7: Sequence = 1 = [0x00, 0x00, 0x01]
//	Octet 8: Spare = 0x00
func TestPFCPHeaderWire(t *testing.T) {
	h := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeAssociationSetupRequest,
		SequenceNumber: 1,
	}
	buf := message.MarshalHeader(h, 0)

	want := []byte{0x20, 0x05, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00}
	if len(buf) != len(want) {
		t.Fatalf("header length = %d; want %d", len(buf), len(want))
	}
	for i, b := range want {
		if buf[i] != b {
			t.Errorf("header byte[%d] = 0x%02X; want 0x%02X", i, buf[i], b)
		}
	}

	// Round-trip parse.
	got, body, err := message.ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader() error: %v", err)
	}
	if got.Version != 1 {
		t.Errorf("Version = %d; want 1", got.Version)
	}
	if got.MessageType != message.MsgTypeAssociationSetupRequest {
		t.Errorf("MessageType = %d; want %d", got.MessageType, message.MsgTypeAssociationSetupRequest)
	}
	if got.SequenceNumber != 1 {
		t.Errorf("SequenceNumber = %d; want 1", got.SequenceNumber)
	}
	if got.HasSEID {
		t.Error("HasSEID should be false for node-level message")
	}
	if len(body) != 0 {
		t.Errorf("body length = %d; want 0", len(body))
	}
}

// TestAssociationSetupRequestRoundTrip verifies AssocSetupRequest marshal+parse per §7.4.1.
func TestAssociationSetupRequestRoundTrip(t *testing.T) {
	const ntpTS uint32 = 2208988800
	nodeIP := net.IP{10, 90, 250, 10}

	h := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeAssociationSetupRequest,
		SequenceNumber: 42,
	}
	ies := []*ie.IE{
		ie.NewNodeIDIPv4(nodeIP),
		ie.NewRecoveryTimeStamp(ntpTS),
	}
	raw, err := message.Marshal(h, ies)
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	req, err := message.ParseAssociationSetupRequest(raw)
	if err != nil {
		t.Fatalf("ParseAssociationSetupRequest() error: %v", err)
	}
	if req.SequenceNumber != 42 {
		t.Errorf("SequenceNumber = %d; want 42", req.SequenceNumber)
	}
	if req.NodeID == nil {
		t.Fatal("NodeID IE missing")
	}
	if req.RecoveryTimeStamp == nil {
		t.Fatal("RecoveryTimeStamp IE missing")
	}
	ts, _ := req.RecoveryTimeStamp.RecoveryTimeStampValue()
	if ts != ntpTS {
		t.Errorf("RecoveryTimeStamp = %d; want %d", ts, ntpTS)
	}
}

// TestAssociationSetupResponseValidation verifies M-IE validation per Table 7.4.2-1.
func TestAssociationSetupResponseValidation(t *testing.T) {
	// Missing Recovery Time Stamp should be rejected.
	h := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeAssociationSetupResponse,
		SequenceNumber: 1,
	}
	raw, _ := message.Marshal(h, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
		ie.NewCause(ie.CauseRequestAccepted),
		// Recovery Time Stamp intentionally omitted
	})
	_, err := message.ParseAssociationSetupResponse(raw)
	if err == nil {
		t.Error("expected error for missing Recovery Time Stamp M-IE; got nil")
	}
}

// TestPFCPSessionHeaderWire verifies the PFCP session-level header wire encoding (S=1)
// per TS 29.244 Rel-15 §7.2.2.1 Figure 7.2.2.1-1.
//
// Expected encoding for a session-level message with SEID=0x0102030405060708, seq=3, no IEs:
//
//	Octet 1:      0x21 — Version=1 (bits 8-6=0b001=0x20) | S=1 (bit 1=0x01)
//	Octet 2:      MessageType (using AssocSetupReq=5 as placeholder)
//	Octets 3-4:   Length = 12 (total 16 - 4)
//	Octets 5-12:  SEID = 0x0102030405060708
//	Octets 13-15: Seq = 3 = [0x00, 0x00, 0x03]
//	Octet 16:     Spare = 0x00
func TestPFCPSessionHeaderWire(t *testing.T) {
	h := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0x0102030405060708,
		MessageType:    message.MsgTypeAssociationSetupRequest,
		SequenceNumber: 3,
	}
	buf := message.MarshalSessionHeader(h, 0)

	want := []byte{
		0x21,       // Version=1 (0x20) | S=1 (0x01)
		0x05,       // MsgType AssociationSetupRequest
		0x00, 0x0C, // Length = 12
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, // SEID
		0x00, 0x00, 0x03, // Seq = 3
		0x00, // Spare
	}
	if len(buf) != len(want) {
		t.Fatalf("session header length = %d; want %d", len(buf), len(want))
	}
	for i, b := range want {
		if buf[i] != b {
			t.Errorf("session header byte[%d] = 0x%02X; want 0x%02X", i, buf[i], b)
		}
	}

	// Round-trip parse — ParseHeader must set HasSEID=true and decode SEID.
	got, body, err := message.ParseHeader(buf)
	if err != nil {
		t.Fatalf("ParseHeader(session) error: %v", err)
	}
	if !got.HasSEID {
		t.Error("ParseHeader: HasSEID should be true for S=1 header")
	}
	if got.SEID != 0x0102030405060708 {
		t.Errorf("SEID = 0x%016X; want 0x0102030405060708", got.SEID)
	}
	if got.SequenceNumber != 3 {
		t.Errorf("SequenceNumber = %d; want 3", got.SequenceNumber)
	}
	if len(body) != 0 {
		t.Errorf("body length = %d; want 0", len(body))
	}
}

// TestCPFunctionFeaturesType verifies the CP Function Features IE type is 89
// per TS 29.244 Rel-15 Table 8.1.2-1 (not 54 which is Overload Control Information).
func TestCPFunctionFeaturesType(t *testing.T) {
	if ie.TypeCPFunctionFeatures != 89 {
		t.Errorf("TypeCPFunctionFeatures = %d; want 89 (Table 8.1.2-1)", ie.TypeCPFunctionFeatures)
	}
	if ie.TypeUPFunctionFeatures != 43 {
		t.Errorf("TypeUPFunctionFeatures = %d; want 43 (Table 8.1.2-1)", ie.TypeUPFunctionFeatures)
	}
}

// TestHeartbeatRoundTrip verifies HeartbeatRequest/Response per §7.2.2/§7.2.3.
func TestHeartbeatRoundTrip(t *testing.T) {
	const ntpTS uint32 = 2209000000
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeHeartbeatRequest,
		SequenceNumber: 7,
	}
	raw, err := message.Marshal(hdr, []*ie.IE{
		ie.NewRecoveryTimeStamp(ntpTS),
	})
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	req, err := message.ParseHeartbeatRequest(raw)
	if err != nil {
		t.Fatalf("ParseHeartbeatRequest() error: %v", err)
	}
	if req.SequenceNumber != 7 {
		t.Errorf("SequenceNumber = %d; want 7", req.SequenceNumber)
	}
	if req.RecoveryTimeStamp == nil {
		t.Fatal("RecoveryTimeStamp IE missing")
	}
	ts, _ := req.RecoveryTimeStamp.RecoveryTimeStampValue()
	if ts != ntpTS {
		t.Errorf("RecoveryTimeStamp = %d; want %d", ts, ntpTS)
	}
}

// TestHeartbeatRequestRejectsMissingTS verifies that Heartbeat Request without
// Recovery Time Stamp is rejected, as Recovery TS is M per TS 29.244 §7.4.2.
func TestHeartbeatRequestRejectsMissingTS(t *testing.T) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeHeartbeatRequest,
		SequenceNumber: 1,
	}
	raw, _ := message.Marshal(hdr, nil) // no IEs — Recovery TS absent
	_, err := message.ParseHeartbeatRequest(raw)
	if err == nil {
		t.Error("expected error for missing mandatory Recovery Time Stamp; got nil")
	}
}

// TestHeartbeatResponseRejectsMissingTS verifies that Heartbeat Response without
// Recovery Time Stamp is rejected, as Recovery TS is M per TS 29.244 §7.4.2.
func TestHeartbeatResponseRejectsMissingTS(t *testing.T) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeHeartbeatResponse,
		SequenceNumber: 1,
	}
	raw, _ := message.Marshal(hdr, nil) // no IEs — Recovery TS absent
	_, err := message.ParseHeartbeatResponse(raw)
	if err == nil {
		t.Error("expected error for missing mandatory Recovery Time Stamp; got nil")
	}
}

// ── Session-level message tests (Phase 5) ────────────────────────────────────

// TestSessionEstablishmentRequestRoundTrip verifies SER marshal+parse per §7.5.2/Table 7.5.2.2-1.
// Message type 50 per docs/specs/29244-fa0.docx Table 7.3-1: "50 | PFCP Session Establishment Request | X".
// Session-level (S=1), SEID=0 on initial per §7.5.2.
func TestSessionEstablishmentRequestRoundTrip(t *testing.T) {
	nodeIDIE := ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1})
	cpSEID := ie.NewFSEID(1, netip.MustParseAddr("10.0.0.1"))
	pdi := ie.NewPDI(ie.NewSourceInterface(ie.SourceInterfaceAccess), ie.NewFTEIDChoose())
	createPDR := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), pdi, ie.NewFARID(1))
	fwdParams := ie.NewForwardingParameters(
		ie.NewDestinationInterface(ie.DestInterfaceCore),
	)
	createFAR := ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(ie.ApplyActionFORW), fwdParams)

	hdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0, // initial SER per §7.5.2: CP-SEID in F-SEID IE, header SEID=0
		MessageType:    message.MsgTypeSessionEstablishmentRequest,
		SequenceNumber: 10,
	}
	raw, err := message.Marshal(hdr, []*ie.IE{nodeIDIE, cpSEID, createPDR, createFAR})
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	req, err := message.ParseSessionEstablishmentRequest(raw)
	if err != nil {
		t.Fatalf("ParseSessionEstablishmentRequest() error: %v", err)
	}
	if req.SequenceNumber != 10 {
		t.Errorf("SequenceNumber = %d; want 10", req.SequenceNumber)
	}
	if !req.HasSEID {
		t.Error("HasSEID should be true for session-level message")
	}
	if req.NodeID == nil {
		t.Error("NodeID IE missing")
	}
	if req.CPSEID == nil {
		t.Error("CP F-SEID IE missing")
	}
	if len(req.CreatePDRs) != 1 {
		t.Errorf("CreatePDRs count = %d; want 1", len(req.CreatePDRs))
	}
	if len(req.CreateFARs) != 1 {
		t.Errorf("CreateFARs count = %d; want 1", len(req.CreateFARs))
	}
}

// TestSessionEstablishmentRequestMissingMandatory verifies M-IE validation per Table 7.5.2.2-1.
func TestSessionEstablishmentRequestMissingMandatory(t *testing.T) {
	tests := []struct {
		name string
		ies  []*ie.IE
	}{
		{"missing NodeID", []*ie.IE{
			ie.NewFSEID(1, netip.MustParseAddr("10.0.0.1")),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0)), ie.NewFARID(1)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(ie.ApplyActionDROP)),
		}},
		{"missing CPSEID", []*ie.IE{
			ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0)), ie.NewFARID(1)),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(ie.ApplyActionDROP)),
		}},
		{"missing CreatePDR", []*ie.IE{
			ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
			ie.NewFSEID(1, netip.MustParseAddr("10.0.0.1")),
			ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(ie.ApplyActionDROP)),
		}},
		{"missing CreateFAR", []*ie.IE{
			ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
			ie.NewFSEID(1, netip.MustParseAddr("10.0.0.1")),
			ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(1), ie.NewPDI(ie.NewSourceInterface(0)), ie.NewFARID(1)),
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			hdr := message.Header{
				Version:     1,
				HasSEID:     true,
				SEID:        0,
				MessageType: message.MsgTypeSessionEstablishmentRequest,
			}
			raw, _ := message.Marshal(hdr, tc.ies)
			_, err := message.ParseSessionEstablishmentRequest(raw)
			if err == nil {
				t.Errorf("%s: expected validation error; got nil", tc.name)
			}
		})
	}
}

// TestSessionEstablishmentResponseRoundTrip verifies SER response marshal+parse per Table 7.5.3.1-1.
func TestSessionEstablishmentResponseRoundTrip(t *testing.T) {
	upFSEID := ie.NewFSEID(42, netip.MustParseAddr("10.0.0.2"))
	createdPDR := ie.NewCreatedPDR(
		ie.NewPDRID(1),
		ie.NewFTEIDv4(0xABCD1234, netip.MustParseAddr("10.0.0.2")),
	)

	hdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           1, // CP-SEID from SER is echoed back in response header SEID
		MessageType:    message.MsgTypeSessionEstablishmentResponse,
		SequenceNumber: 10,
	}
	raw, err := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 2}),
		ie.NewCause(ie.CauseRequestAccepted),
		upFSEID,
		createdPDR,
	})
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	resp, err := message.ParseSessionEstablishmentResponse(raw)
	if err != nil {
		t.Fatalf("ParseSessionEstablishmentResponse() error: %v", err)
	}
	if resp.SequenceNumber != 10 {
		t.Errorf("SequenceNumber = %d; want 10", resp.SequenceNumber)
	}
	if resp.NodeID == nil {
		t.Error("NodeID IE missing")
	}
	if resp.Cause == nil {
		t.Error("Cause IE missing")
	}
	if resp.UPSEID == nil {
		t.Error("UP F-SEID IE missing on success response")
	}
	if len(resp.CreatedPDRs) != 1 {
		t.Errorf("CreatedPDRs count = %d; want 1", len(resp.CreatedPDRs))
	}
}

// TestSessionEstablishmentResponseSuccessMissingUPSEID verifies C11: UP F-SEID is
// mandatory on success (cause=1) per Table 7.5.3.1-1.
func TestSessionEstablishmentResponseSuccessMissingUPSEID(t *testing.T) {
	hdr := message.Header{
		Version:     1,
		HasSEID:     true,
		SEID:        1,
		MessageType: message.MsgTypeSessionEstablishmentResponse,
	}
	raw, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 2}),
		ie.NewCause(ie.CauseRequestAccepted),
		// UP F-SEID intentionally absent — must be rejected per C11
	})
	_, err := message.ParseSessionEstablishmentResponse(raw)
	if err == nil {
		t.Error("expected C11 validation error for missing UP F-SEID on success; got nil")
	}
}

// TestSessionModificationRoundTrip verifies session modification message marshal+parse
// per TS 29.244 Rel-15 §7.5.4 Table 7.5.4.1-1 / Table 7.5.5.1-1.
func TestSessionModificationRoundTrip(t *testing.T) {
	updateFP := ie.NewUpdateForwardingParameters(
		ie.NewDestinationInterface(ie.DestInterfaceAccess),
		ie.NewOuterHeaderCreation(ie.OHCDescGTPUUDPIPv4, 0x1234, netip.MustParseAddr("10.1.0.1")),
	)
	updateFAR := ie.NewUpdateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(ie.ApplyActionFORW),
		updateFP,
	)

	reqHdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           42, // UP-SEID from establishment
		MessageType:    message.MsgTypeSessionModificationRequest,
		SequenceNumber: 20,
	}
	raw, err := message.Marshal(reqHdr, []*ie.IE{updateFAR})
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	req, err := message.ParseSessionModificationRequest(raw)
	if err != nil {
		t.Fatalf("ParseSessionModificationRequest() error: %v", err)
	}
	if req.SEID != 42 {
		t.Errorf("SEID = %d; want 42", req.SEID)
	}
	if len(req.UpdateFARs) != 1 {
		t.Errorf("UpdateFARs count = %d; want 1", len(req.UpdateFARs))
	}

	// Build and parse the response.
	respHdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           1, // CP-SEID echoed back
		MessageType:    message.MsgTypeSessionModificationResponse,
		SequenceNumber: 20,
	}
	respRaw, _ := message.Marshal(respHdr, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted)})
	resp, err := message.ParseSessionModificationResponse(respRaw)
	if err != nil {
		t.Fatalf("ParseSessionModificationResponse() error: %v", err)
	}
	if resp.Cause == nil {
		t.Error("Cause IE missing in modification response")
	}
}

// TestSessionDeletionRoundTrip verifies session deletion message marshal+parse
// per TS 29.244 Rel-15 §7.5.6 Table 7.5.6.1-1 / Table 7.5.7.1-1.
// Deletion request carries no IEs; SEID in header identifies the session.
func TestSessionDeletionRoundTrip(t *testing.T) {
	reqHdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           42, // UP-SEID
		MessageType:    message.MsgTypeSessionDeletionRequest,
		SequenceNumber: 30,
	}
	raw, err := message.Marshal(reqHdr, nil) // no IEs per Table 7.5.6.1-1
	if err != nil {
		t.Fatalf("Marshal() error: %v", err)
	}

	req, err := message.ParseSessionDeletionRequest(raw)
	if err != nil {
		t.Fatalf("ParseSessionDeletionRequest() error: %v", err)
	}
	if req.SEID != 42 {
		t.Errorf("SEID = %d; want 42", req.SEID)
	}
	if req.SequenceNumber != 30 {
		t.Errorf("SequenceNumber = %d; want 30", req.SequenceNumber)
	}

	// Build and parse the response.
	respHdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           1,
		MessageType:    message.MsgTypeSessionDeletionResponse,
		SequenceNumber: 30,
	}
	respRaw, _ := message.Marshal(respHdr, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted)})
	resp, err := message.ParseSessionDeletionResponse(respRaw)
	if err != nil {
		t.Fatalf("ParseSessionDeletionResponse() error: %v", err)
	}
	if resp.Cause == nil {
		t.Error("Cause IE missing in deletion response")
	}
}

// TestSessionDeletionResponseMissingCause verifies M-IE validation per Table 7.5.7.1-1.
func TestSessionDeletionResponseMissingCause(t *testing.T) {
	hdr := message.Header{
		Version:     1,
		HasSEID:     true,
		SEID:        1,
		MessageType: message.MsgTypeSessionDeletionResponse,
	}
	raw, _ := message.Marshal(hdr, nil) // no Cause IE
	_, err := message.ParseSessionDeletionResponse(raw)
	if err == nil {
		t.Error("expected error for missing mandatory Cause IE; got nil")
	}
}

// FuzzParseSessionModificationRequest fuzzes the PFCP Session Modification Request
// parser per C20. ParseSessionModificationRequest was modified in Phase 9 to add
// CreatePDRs, CreateFARs, RemovePDRs, RemoveFARs fields.
func FuzzParseSessionModificationRequest(f *testing.F) {
	// Seed 1: request with Update FAR (existing path).
	updateFAR := ie.NewUpdateFAR(ie.NewFARID(1), ie.NewApplyAction(ie.ApplyActionFORW))
	reqHdr := message.Header{
		Version:     1,
		HasSEID:     true,
		SEID:        42,
		MessageType: message.MsgTypeSessionModificationRequest,
	}
	seed1, _ := message.Marshal(reqHdr, []*ie.IE{updateFAR})
	f.Add(seed1)
	// Seed 2: request with Create PDR (Phase 9 path).
	createPDR := ie.NewCreatePDR(
		ie.NewPDRID(3),
		ie.NewPrecedence(100),
		ie.NewPDI(ie.NewSourceInterface(ie.SourceInterfaceAccess)),
		ie.NewFARID(3),
	)
	seed2, _ := message.Marshal(reqHdr, []*ie.IE{createPDR})
	f.Add(seed2)
	// Seed 3: truncated.
	f.Add([]byte{0x21, 0x35, 0x00, 0x04})
	// Seed 4: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseSessionModificationRequest(b)
	})
}

// FuzzParseSessionModificationResponse fuzzes the PFCP Session Modification Response
// parser per C20. ParseSessionModificationResponse was modified in Phase 9 to add
// CreatedPDRs field per Table 7.5.5.1-1.
func FuzzParseSessionModificationResponse(f *testing.F) {
	// Seed 1: response with Cause only.
	respHdr := message.Header{
		Version:     1,
		HasSEID:     true,
		SEID:        1,
		MessageType: message.MsgTypeSessionModificationResponse,
	}
	seed1, _ := message.Marshal(respHdr, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted)})
	f.Add(seed1)
	// Seed 2: truncated.
	f.Add([]byte{0x21, 0x35, 0x00, 0x04})
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseSessionModificationResponse(b)
	})
}

// FuzzParseHeader fuzzes PFCP header parsing per C20.
// Seeds cover both node-level (S=0) and session-level (S=1) header forms per TS 29.244 §7.1.
func FuzzParseHeader(f *testing.F) {
	// Node-level header: Version=1, S=0, MsgType=5 (AssociationSetupRequest), Seq=1
	// From TestPFCPHeaderWire: [0x20, 0x05, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00]
	f.Add([]byte{0x20, 0x05, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00})

	// Session-level header: Version=1, S=1, MsgType=5, SEID=0x0102030405060708, Seq=3
	// From TestPFCPSessionHeaderWire
	f.Add([]byte{
		0x21, 0x05, 0x00, 0x0C,
		0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x00, 0x00, 0x03, 0x00,
	})

	// Session Modification Request header (MsgType=52=0x34)
	f.Add([]byte{0x21, 0x34, 0x00, 0x0C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00})

	// Truncated — 3 bytes (below minimum 4)
	f.Add([]byte{0x20, 0x05, 0x00})
	// Empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = message.ParseHeader(b)
	})
}

// ── C20 remediation: fuzz tests for Phase 4/5 message parsers ───────────────
// Seeds below are constructed the same way as the round-trip tests above
// (TestAssociationSetupRequestRoundTrip, TestHeartbeatRoundTrip, etc.) rather
// than synthesized, per C20's "drawn from golden wire vectors" requirement.

// FuzzParseAssociationSetupRequest fuzzes the PFCP Association Setup Request
// parser per C20. Seed mirrors TestAssociationSetupRequestRoundTrip.
func FuzzParseAssociationSetupRequest(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeAssociationSetupRequest,
		SequenceNumber: 42,
	}
	seed1, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 90, 250, 10}),
		ie.NewRecoveryTimeStamp(2208988800),
	})
	f.Add(seed1)
	// Seed 2: missing mandatory NodeID/RecoveryTimeStamp.
	seed2, _ := message.Marshal(hdr, nil)
	f.Add(seed2)
	// Seed 3: truncated.
	f.Add([]byte{0x20, 0x05, 0x00})
	// Seed 4: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseAssociationSetupRequest(b)
	})
}

// FuzzParseAssociationSetupResponse fuzzes the PFCP Association Setup Response
// parser per C20. Seed mirrors TestAssociationSetupResponseValidation.
func FuzzParseAssociationSetupResponse(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeAssociationSetupResponse,
		SequenceNumber: 1,
	}
	// Seed 1: valid — NodeID + Cause + RecoveryTimeStamp (all M-IEs present).
	seed1, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(2208988800),
	})
	f.Add(seed1)
	// Seed 2: missing mandatory RecoveryTimeStamp (existing rejection test).
	seed2, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
		ie.NewCause(ie.CauseRequestAccepted),
	})
	f.Add(seed2)
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseAssociationSetupResponse(b)
	})
}

// FuzzParseHeartbeatRequest fuzzes the PFCP Heartbeat Request parser per C20.
// Seed mirrors TestHeartbeatRoundTrip and TestHeartbeatRequestRejectsMissingTS.
func FuzzParseHeartbeatRequest(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeHeartbeatRequest,
		SequenceNumber: 7,
	}
	seed1, _ := message.Marshal(hdr, []*ie.IE{ie.NewRecoveryTimeStamp(2209000000)})
	f.Add(seed1)
	// Seed 2: missing mandatory Recovery Time Stamp.
	seed2, _ := message.Marshal(hdr, nil)
	f.Add(seed2)
	// Seed 3: truncated.
	f.Add([]byte{0x20, 0x01, 0x00})
	// Seed 4: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseHeartbeatRequest(b)
	})
}

// FuzzParseHeartbeatResponse fuzzes the PFCP Heartbeat Response parser per C20.
// Seed mirrors TestHeartbeatResponseRejectsMissingTS plus a valid counterpart.
func FuzzParseHeartbeatResponse(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeHeartbeatResponse,
		SequenceNumber: 1,
	}
	seed1, _ := message.Marshal(hdr, []*ie.IE{ie.NewRecoveryTimeStamp(2209000000)})
	f.Add(seed1)
	// Seed 2: missing mandatory Recovery Time Stamp.
	seed2, _ := message.Marshal(hdr, nil)
	f.Add(seed2)
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseHeartbeatResponse(b)
	})
}

// FuzzParseSessionEstablishmentRequest fuzzes the PFCP Session Establishment
// Request parser per C20. Seed mirrors TestSessionEstablishmentRequestRoundTrip
// and TestSessionEstablishmentRequestMissingMandatory.
func FuzzParseSessionEstablishmentRequest(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           0,
		MessageType:    message.MsgTypeSessionEstablishmentRequest,
		SequenceNumber: 10,
	}
	pdi := ie.NewPDI(ie.NewSourceInterface(ie.SourceInterfaceAccess), ie.NewFTEIDChoose())
	createPDR := ie.NewCreatePDR(ie.NewPDRID(1), ie.NewPrecedence(100), pdi, ie.NewFARID(1))
	fwdParams := ie.NewForwardingParameters(ie.NewDestinationInterface(ie.DestInterfaceCore))
	createFAR := ie.NewCreateFAR(ie.NewFARID(1), ie.NewApplyAction(ie.ApplyActionFORW), fwdParams)
	seed1, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
		ie.NewFSEID(1, netip.MustParseAddr("10.0.0.1")),
		createPDR, createFAR,
	})
	f.Add(seed1)
	// Seed 2: missing CreateFAR (existing M-IE rejection case).
	seed2, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 1}),
		ie.NewFSEID(1, netip.MustParseAddr("10.0.0.1")),
		createPDR,
	})
	f.Add(seed2)
	// Seed 3: truncated.
	f.Add([]byte{0x21, 0x32, 0x00})
	// Seed 4: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseSessionEstablishmentRequest(b)
	})
}

// FuzzParseSessionEstablishmentResponse fuzzes the PFCP Session Establishment
// Response parser per C20. Seed mirrors TestSessionEstablishmentResponseRoundTrip
// and TestSessionEstablishmentResponseSuccessMissingUPSEID (C11 case).
func FuzzParseSessionEstablishmentResponse(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           1,
		MessageType:    message.MsgTypeSessionEstablishmentResponse,
		SequenceNumber: 10,
	}
	upFSEID := ie.NewFSEID(42, netip.MustParseAddr("10.0.0.2"))
	createdPDR := ie.NewCreatedPDR(
		ie.NewPDRID(1),
		ie.NewFTEIDv4(0xABCD1234, netip.MustParseAddr("10.0.0.2")),
	)
	seed1, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 2}),
		ie.NewCause(ie.CauseRequestAccepted),
		upFSEID, createdPDR,
	})
	f.Add(seed1)
	// Seed 2: success cause but missing UP F-SEID — C11 rejection case.
	seed2, _ := message.Marshal(hdr, []*ie.IE{
		ie.NewNodeIDIPv4(net.IP{10, 0, 0, 2}),
		ie.NewCause(ie.CauseRequestAccepted),
	})
	f.Add(seed2)
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseSessionEstablishmentResponse(b)
	})
}

// FuzzParseSessionDeletionRequest fuzzes the PFCP Session Deletion Request
// parser per C20. Seed mirrors TestSessionDeletionRoundTrip (no IEs; SEID-only).
func FuzzParseSessionDeletionRequest(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           42,
		MessageType:    message.MsgTypeSessionDeletionRequest,
		SequenceNumber: 30,
	}
	seed1, _ := message.Marshal(hdr, nil)
	f.Add(seed1)
	// Seed 2: truncated.
	f.Add([]byte{0x21, 0x36, 0x00})
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseSessionDeletionRequest(b)
	})
}

// FuzzParseSessionDeletionResponse fuzzes the PFCP Session Deletion Response
// parser per C20. Seed mirrors TestSessionDeletionRoundTrip's response and
// TestSessionDeletionResponseMissingCause.
func FuzzParseSessionDeletionResponse(f *testing.F) {
	hdr := message.Header{
		Version:        1,
		HasSEID:        true,
		SEID:           1,
		MessageType:    message.MsgTypeSessionDeletionResponse,
		SequenceNumber: 30,
	}
	seed1, _ := message.Marshal(hdr, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted)})
	f.Add(seed1)
	// Seed 2: missing mandatory Cause.
	seed2, _ := message.Marshal(hdr, nil)
	f.Add(seed2)
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseSessionDeletionResponse(b)
	})
}

// ── Phase 11: Association Release and Node Report wire tests ─────────────────

// TestAssociationReleaseRequestWire verifies the wire encoding of a minimal
// PFCP Association Release Request per TS 29.244 Rel-15 §7.4.4.5 Table 7.4.4.5-1.
// Golden vector: MsgType=9, Seq=1, Node ID IE (Type=60, Len=5, IPv4=10.0.0.1).
//
//	Header (S=0): [0x20, 0x09, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x00]
//	Node ID IE:   [0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01]
func TestAssociationReleaseRequestWire(t *testing.T) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeAssociationReleaseRequest, // 9 per Table 7.3-1
		SequenceNumber: 1,
	}
	nodeID := ie.NewNodeIDIPv4(net.ParseIP("10.0.0.1"))
	raw, err := message.Marshal(hdr, []*ie.IE{nodeID})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	want := []byte{
		0x20, 0x09, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x00, // header: S=0, type=9, len=13, seq=1
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01, // NodeID(IPv4=10.0.0.1)
	}
	if len(raw) != len(want) {
		t.Fatalf("wire length = %d; want %d", len(raw), len(want))
	}
	for i, b := range want {
		if raw[i] != b {
			t.Errorf("byte[%d] = 0x%02X; want 0x%02X", i, raw[i], b)
		}
	}
	// Round-trip parse.
	req, parseErr := message.ParseAssociationReleaseRequest(raw)
	if parseErr != nil {
		t.Fatalf("ParseAssociationReleaseRequest: %v", parseErr)
	}
	if req.MessageType != message.MsgTypeAssociationReleaseRequest {
		t.Errorf("MessageType = %d; want %d", req.MessageType, message.MsgTypeAssociationReleaseRequest)
	}
	if req.NodeID == nil {
		t.Fatal("NodeID is nil")
	}
}

// TestNodeReportRequestWire verifies the wire encoding of a PFCP Node Report Request
// per TS 29.244 Rel-15 §7.4.5.1.1 Table 7.4.5.1.1-1.
// Golden vector: MsgType=12, Seq=1, Node ID + NodeReportType(UPFR) + UPFR grouped IE.
func TestNodeReportRequestWire(t *testing.T) {
	hdr := message.Header{
		Version:        1,
		MessageType:    message.MsgTypeNodeReportRequest, // 12 per Table 7.3-1
		SequenceNumber: 1,
	}
	failedPeer := ie.NewRemoteGTPUPeerIPv4(net.ParseIP("10.0.1.1"))
	upfr := ie.NewUserPlanPathFailureReport(failedPeer)
	ies := []*ie.IE{
		ie.NewNodeIDIPv4(net.ParseIP("10.0.0.1")),
		ie.NewNodeReportType(ie.NodeReportTypeUPFR), // UPFR=0x01 per §8.2.69
		upfr,
	}
	raw, err := message.Marshal(hdr, ies)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// Expected wire (27 IEs bytes + 8 header = 35 total; Length=31=0x001F):
	//   Header:       [0x20, 0x0C, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x00]
	//   NodeID IE:    [0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01]
	//   NRT IE:       [0x00, 0x65, 0x00, 0x01, 0x01]
	//   UPFR grouped: [0x00, 0x66, 0x00, 0x09,
	//                   0x00, 0x67, 0x00, 0x05, 0x02, 0x0A, 0x00, 0x01, 0x01]
	want := []byte{
		0x20, 0x0C, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x00, 0x65, 0x00, 0x01, 0x01,
		0x00, 0x66, 0x00, 0x09,
		0x00, 0x67, 0x00, 0x05, 0x02, 0x0A, 0x00, 0x01, 0x01,
	}
	if len(raw) != len(want) {
		t.Fatalf("wire length = %d; want %d", len(raw), len(want))
	}
	for i, b := range want {
		if raw[i] != b {
			t.Errorf("byte[%d] = 0x%02X; want 0x%02X", i, raw[i], b)
		}
	}
	// Round-trip.
	req, parseErr := message.ParseNodeReportRequest(raw)
	if parseErr != nil {
		t.Fatalf("ParseNodeReportRequest: %v", parseErr)
	}
	if req.NodeReportType == nil {
		t.Fatal("NodeReportType is nil")
	}
	if req.UserPlanPathFailureReport == nil {
		t.Fatal("UserPlanPathFailureReport is nil")
	}
}

func TestSessionReportRequestIdleDownlinkRoundTrip(t *testing.T) {
	report := ie.VectorCoreIdleDownlinkReport{
		CPSEID:          1001,
		UPSEID:          2002,
		PDRID:           3,
		FARID:           4,
		LocalTEID:       0x01020304,
		EBI:             6,
		QCI:             5,
		SourceInterface: 1,
		QoSValid:        true,
		DropReason:      ie.VectorCoreIdleDownlinkDropReleaseAccessBearers,
	}
	raw, err := message.Marshal(message.Header{
		Version:        1,
		HasSEID:        true,
		MessageType:    message.MsgTypeSessionReportRequest,
		SEID:           report.CPSEID,
		SequenceNumber: 0x112233,
	}, []*ie.IE{ie.NewVectorCoreIdleDownlinkReport(report)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	req, err := message.ParseSessionReportRequest(raw)
	if err != nil {
		t.Fatalf("ParseSessionReportRequest: %v", err)
	}
	if req.SEID != report.CPSEID {
		t.Fatalf("SEID = %d; want %d", req.SEID, report.CPSEID)
	}
	got, err := req.VectorCoreIdleDownlinkReport.VectorCoreIdleDownlinkReportValue()
	if err != nil {
		t.Fatalf("VectorCoreIdleDownlinkReportValue: %v", err)
	}
	if got != report {
		t.Fatalf("report = %+v; want %+v", got, report)
	}
}

func TestSessionReportResponseRoundTrip(t *testing.T) {
	raw, err := message.Marshal(message.Header{
		Version:        1,
		HasSEID:        true,
		MessageType:    message.MsgTypeSessionReportResponse,
		SEID:           44,
		SequenceNumber: 7,
	}, []*ie.IE{ie.NewCause(ie.CauseRequestAccepted)})
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	resp, err := message.ParseSessionReportResponse(raw)
	if err != nil {
		t.Fatalf("ParseSessionReportResponse: %v", err)
	}
	cause, err := resp.Cause.CauseValue()
	if err != nil {
		t.Fatalf("CauseValue: %v", err)
	}
	if cause != ie.CauseRequestAccepted {
		t.Fatalf("cause = %d; want %d", cause, ie.CauseRequestAccepted)
	}
}

// ── Phase 11: fuzz tests per C20 ─────────────────────────────────────────────

// FuzzParseAssociationReleaseRequest fuzzes the PFCP Association Release Request
// parser per C20. ParseAssociationReleaseRequest was introduced in Phase 11.
func FuzzParseAssociationReleaseRequest(f *testing.F) {
	// Seed 1: minimal valid request — golden vector from TestAssociationReleaseRequestWire.
	// MsgType=9, Seq=1, NodeID(IPv4=10.0.0.1).
	f.Add([]byte{
		0x20, 0x09, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
	})
	// Seed 2: header only, no IEs.
	f.Add([]byte{0x20, 0x09, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00})
	// Seed 3: truncated.
	f.Add([]byte{0x20, 0x09, 0x00})
	// Seed 4: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseAssociationReleaseRequest(b)
	})
}

// FuzzParseAssociationReleaseResponse fuzzes the PFCP Association Release Response
// parser per C20. ParseAssociationReleaseResponse was introduced in Phase 11.
func FuzzParseAssociationReleaseResponse(f *testing.F) {
	// Seed 1: valid response — NodeID + Cause(RequestAccepted).
	// MsgType=10, Seq=1, NodeID(IPv4=10.0.0.1), Cause=1.
	f.Add([]byte{
		0x20, 0x0A, 0x00, 0x12, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x00, 0x13, 0x00, 0x01, 0x01,
	})
	// Seed 2: missing Cause.
	f.Add([]byte{
		0x20, 0x0A, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
	})
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseAssociationReleaseResponse(b)
	})
}

// FuzzParseNodeReportRequest fuzzes the PFCP Node Report Request parser per C20.
// ParseNodeReportRequest was introduced in Phase 11.
func FuzzParseNodeReportRequest(f *testing.F) {
	// Seed 1: valid request — golden vector from TestNodeReportRequestWire.
	f.Add([]byte{
		0x20, 0x0C, 0x00, 0x1F, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x00, 0x65, 0x00, 0x01, 0x01,
		0x00, 0x66, 0x00, 0x09,
		0x00, 0x67, 0x00, 0x05, 0x02, 0x0A, 0x00, 0x01, 0x01,
	})
	// Seed 2: NRT with UPFR=1 but no UPFR grouped IE.
	f.Add([]byte{
		0x20, 0x0C, 0x00, 0x12, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x00, 0x65, 0x00, 0x01, 0x01,
	})
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseNodeReportRequest(b)
	})
}

// FuzzParseNodeReportResponse fuzzes the PFCP Node Report Response parser per C20.
// ParseNodeReportResponse was introduced in Phase 11.
func FuzzParseNodeReportResponse(f *testing.F) {
	// Seed 1: valid response — NodeID + Cause(RequestAccepted).
	// MsgType=13, Seq=1.
	f.Add([]byte{
		0x20, 0x0D, 0x00, 0x12, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
		0x00, 0x13, 0x00, 0x01, 0x01,
	})
	// Seed 2: missing Cause.
	f.Add([]byte{
		0x20, 0x0D, 0x00, 0x0D, 0x00, 0x00, 0x01, 0x00,
		0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x00, 0x00, 0x01,
	})
	// Seed 3: empty.
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = message.ParseNodeReportResponse(b)
	})
}

// FuzzParse fuzzes full PFCP message parsing (header + IEs) per C20.
// Seeds cover node-level and session-level messages with IEs.
func FuzzParse(f *testing.F) {
	// Heartbeat Request (node-level): header(8) + RecoveryTimeStamp IE (9 bytes)
	// MsgType=1 (HeartbeatRequest), Seq=7, RecoveryTS type=96(0x0060), len=4
	f.Add([]byte{
		0x20, 0x01, 0x00, 0x0D, 0x00, 0x00, 0x07, 0x00,
		0x00, 0x60, 0x00, 0x04, 0x83, 0xAA, 0x7E, 0x80,
	})

	// Node-level header with no IEs (AssociationSetupRequest)
	f.Add([]byte{0x20, 0x05, 0x00, 0x04, 0x00, 0x00, 0x01, 0x00})

	// Session-level message with Cause IE
	// MsgType=52 (SessionModificationResponse), session header + Cause=1
	f.Add([]byte{
		0x21, 0x35, 0x00, 0x11,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x00, 0x00, 0x01, 0x00,
		0x00, 0x13, 0x00, 0x01, 0x01,
	})

	// Truncated body
	f.Add([]byte{0x20, 0x01, 0x00, 0x09, 0x00, 0x00, 0x01, 0x00, 0x00})
	// Empty
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _, _ = message.Parse(b)
	})
}
