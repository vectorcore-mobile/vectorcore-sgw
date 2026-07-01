// Package message implements PFCP message encoding and decoding
// per 3GPP TS 29.244 Rel-15 §7.
package message

import (
	"encoding/binary"
	"fmt"

	"vectorcore-sgw/internal/pfcp/ie"
)

// Message type codes per TS 29.244 Rel-15 Table 7.3-1.
// Node-level types (confirmed by re-audit):
//
// Table 7.3-1 rows (extracted from docs/specs/29244-fa0.docx):
//
//	"1  | PFCP Heartbeat Request"
//	"2  | PFCP Heartbeat Response"
//	"5  | PFCP Association Setup Request"
//	"6  | PFCP Association Setup Response"
//	"9  | PFCP Association Release Request"
//	"10 | PFCP Association Release Response"
//	"12 | PFCP Node Report Request"
//	"13 | PFCP Node Report Response"
const (
	MsgTypeHeartbeatRequest           uint8 = 1  // Table 7.3-1: "1 | PFCP Heartbeat Request"
	MsgTypeHeartbeatResponse          uint8 = 2  // Table 7.3-1: "2 | PFCP Heartbeat Response"
	MsgTypeAssociationSetupRequest    uint8 = 5  // Table 7.3-1: "5 | PFCP Association Setup Request"
	MsgTypeAssociationSetupResponse   uint8 = 6  // Table 7.3-1: "6 | PFCP Association Setup Response"
	MsgTypeAssociationReleaseRequest  uint8 = 9  // Table 7.3-1: "9 | PFCP Association Release Request"
	MsgTypeAssociationReleaseResponse uint8 = 10 // Table 7.3-1: "10 | PFCP Association Release Response"
	MsgTypeNodeReportRequest          uint8 = 12 // Table 7.3-1: "12 | PFCP Node Report Request"
	MsgTypeNodeReportResponse         uint8 = 13 // Table 7.3-1: "13 | PFCP Node Report Response"
)

// Session-level message type codes per TS 29.244 Rel-15 Table 7.3-1
// (extracted from docs/specs/29244-fa0.docx, Table 7):
//
//	"50 | PFCP Session Establishment Request | X"
//	"51 | PFCP Session Establishment Response | X"
//	"52 | PFCP Session Modification Request | X"
//	"53 | PFCP Session Modification Response | X"
//	"54 | PFCP Session Deletion Request | X"
//	"55 | PFCP Session Deletion Response | X"
const (
	MsgTypeSessionEstablishmentRequest  uint8 = 50 // Table 7.3-1 row: "50 | PFCP Session Establishment Request"
	MsgTypeSessionEstablishmentResponse uint8 = 51 // Table 7.3-1 row: "51 | PFCP Session Establishment Response"
	MsgTypeSessionModificationRequest   uint8 = 52 // Table 7.3-1 row: "52 | PFCP Session Modification Request"
	MsgTypeSessionModificationResponse  uint8 = 53 // Table 7.3-1 row: "53 | PFCP Session Modification Response"
	MsgTypeSessionDeletionRequest       uint8 = 54 // Table 7.3-1 row: "54 | PFCP Session Deletion Request"
	MsgTypeSessionDeletionResponse      uint8 = 55 // Table 7.3-1 row: "55 | PFCP Session Deletion Response"
)

const (
	pfcpVersion           uint8 = 1
	headerLenNodeLevel          = 8  // S=0: flags(1)|type(1)|len(2)|seq(3)|spare(1)
	headerLenSessionLevel       = 16 // S=1: flags(1)|type(1)|len(2)|SEID(8)|seq(3)|spare(1)
)

// Header is a parsed PFCP message header per TS 29.244 Rel-15 §7.1.
//
// Node-level wire format (S=0):
//
//	Octet 1:    Version(3)|Spare(3)|MP(1)|S(1)
//	            Bits 8-6: Version=001 (0x20 in byte)
//	            Bits 5-3: Spare
//	            Bit 2: MP (mask 0x02) per TS 29.244 §7.2.2.1 Figure 7.2.2.1-1
//	            Bit 1: S  (mask 0x01) per TS 29.244 §7.2.2.1 Figure 7.2.2.1-1 — S=0 for node-level
//	Octet 2:    Message Type
//	Octets 3-4: Message Length (total - 4)
//	Octets 5-7: Sequence Number (24-bit big-endian)
//	Octet 8:    Spare
//
// Session-level wire format (S=1):
//
//	Octet 1:     Version(3)|Spare(3)|MP(1)|S(1) — bit 1 (S) = 0x01 set
//	Octet 2:     Message Type
//	Octets 3-4:  Message Length (total - 4)
//	Octets 5-12: SEID (8 bytes, big-endian)
//	Octets 13-15: Sequence Number (24-bit big-endian)
//	Octet 16:    Spare
type Header struct {
	Version        uint8
	HasSEID        bool // S flag; false for all Phase 4 node-level messages
	MessageType    uint8
	Length         uint16
	SEID           uint64 // populated only when HasSEID=true (Phase 5+ session messages)
	SequenceNumber uint32 // 24-bit
}

// ParseHeader decodes a PFCP message header from b.
// Returns the header, body bytes bounded by Length, and any error.
func ParseHeader(b []byte) (Header, []byte, error) {
	if len(b) < headerLenNodeLevel {
		return Header{}, nil, fmt.Errorf("PFCP header too short: %d bytes", len(b))
	}
	version := (b[0] >> 5) & 0x07
	if version != pfcpVersion {
		return Header{}, nil, fmt.Errorf("PFCP unsupported version: %d", version)
	}
	// S flag is bit 1 (LSB, mask 0x01) per TS 29.244 §7.2.2.1 Figure 7.2.2.1-1.
	// MP flag is bit 2 (mask 0x02). Bits 5-3 are spare. Bits 8-6 are Version.
	hasSEID := b[0]&0x01 != 0
	h := Header{
		Version:     version,
		HasSEID:     hasSEID,
		MessageType: b[1],
		Length:      binary.BigEndian.Uint16(b[2:4]),
	}

	var bodyStart int
	if hasSEID {
		if len(b) < headerLenSessionLevel {
			return Header{}, nil, fmt.Errorf("PFCP header (with SEID) too short: %d bytes", len(b))
		}
		h.SEID = binary.BigEndian.Uint64(b[4:12])
		h.SequenceNumber = uint32(b[12])<<16 | uint32(b[13])<<8 | uint32(b[14])
		bodyStart = headerLenSessionLevel
	} else {
		h.SequenceNumber = uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
		bodyStart = headerLenNodeLevel
	}

	declaredTotal := 4 + int(h.Length)
	if declaredTotal < bodyStart {
		return Header{}, nil, fmt.Errorf("PFCP declared length %d too small for header", h.Length)
	}
	if declaredTotal > len(b) {
		return Header{}, nil, fmt.Errorf("PFCP message truncated: declared %d bytes, received %d", declaredTotal, len(b))
	}
	return h, b[bodyStart:declaredTotal], nil
}

// MarshalHeader encodes a PFCP node-level header (S=0, no SEID).
// bodyLen is the byte count of IEs that follow.
func MarshalHeader(h Header, bodyLen int) []byte {
	buf := make([]byte, headerLenNodeLevel)
	// Octet 1: Version(3)=1 in bits 8-6 (0x20), S=0 (bit 1), MP=0 (bit 2), Spare bits 5-3.
	// Per TS 29.244 §7.2.2.1 Figure 7.2.2.1-1.
	buf[0] = pfcpVersion << 5 // Version=1 in bits 8-6; S=0, MP=0
	buf[1] = h.MessageType
	// Length = total - 4; total = 8 (node-level header) + bodyLen.
	binary.BigEndian.PutUint16(buf[2:4], uint16(headerLenNodeLevel-4+bodyLen))
	buf[4] = byte(h.SequenceNumber >> 16)
	buf[5] = byte(h.SequenceNumber >> 8)
	buf[6] = byte(h.SequenceNumber)
	// buf[7] = spare = 0
	return buf
}

// MarshalSessionHeader encodes a PFCP session-level header (S=1, with SEID).
// Per TS 29.244 §7.2.2.1 Figure 7.2.2.1-1: S flag is bit 1 (mask 0x01).
// bodyLen is the byte count of IEs that follow.
func MarshalSessionHeader(h Header, bodyLen int) []byte {
	buf := make([]byte, headerLenSessionLevel)
	// Octet 1: Version=1 (bits 8-6 = 0x20) | S=1 (bit 1 = 0x01). MP=0, Spare=0.
	buf[0] = (pfcpVersion << 5) | 0x01
	buf[1] = h.MessageType
	// Length = total - 4; total = 16 (session-level header) + bodyLen.
	binary.BigEndian.PutUint16(buf[2:4], uint16(headerLenSessionLevel-4+bodyLen))
	binary.BigEndian.PutUint64(buf[4:12], h.SEID)
	buf[12] = byte(h.SequenceNumber >> 16)
	buf[13] = byte(h.SequenceNumber >> 8)
	buf[14] = byte(h.SequenceNumber)
	// buf[15] = spare = 0
	return buf
}

// Marshal encodes a complete PFCP message (node-level or session-level).
// If h.HasSEID is true, a session-level header (S=1) with SEID is encoded.
func Marshal(h Header, ies []*ie.IE) ([]byte, error) {
	var body []byte
	for _, i := range ies {
		body = append(body, i.Marshal()...)
	}
	var hdr []byte
	if h.HasSEID {
		hdr = MarshalSessionHeader(h, len(body))
	} else {
		hdr = MarshalHeader(h, len(body))
	}
	return append(hdr, body...), nil
}

// Parse decodes a complete PFCP message.
func Parse(b []byte) (Header, []*ie.IE, error) {
	h, body, err := ParseHeader(b)
	if err != nil {
		return Header{}, nil, err
	}
	ies, err := ie.ParseIEs(body)
	if err != nil {
		return Header{}, nil, fmt.Errorf("PFCP IE parse: %w", err)
	}
	return h, ies, nil
}

// AssociationSetupRequest is a parsed PFCP Association Setup Request
// per TS 29.244 Rel-15 §7.4.4.1 Table 7.4.4.1-1.
// FIXED 2026-06-23: was cited §7.4.1/Table 7.4.1-1 — §7.4.1 is actually "General"
// (a generic intro clause for all node messages), not Association Setup. The real
// table is 7.4.4.1-1. Also CPFeatures was cited "CO"; the table's condition column
// literally reads "C": "This IE shall be present if the CP function sends this
// message and the CP function supports at least one CP feature defined in this IE."
type AssociationSetupRequest struct {
	Header
	NodeID            *ie.IE // M per Table 7.4.4.1-1
	RecoveryTimeStamp *ie.IE // M per Table 7.4.4.1-1
	CPFeatures        *ie.IE // C per Table 7.4.4.1-1
}

// ParseAssociationSetupRequest decodes raw PFCP bytes.
// Validates message type, S=0 (node-level), and M-IEs per Table 7.4.4.1-1.
func ParseAssociationSetupRequest(b []byte) (*AssociationSetupRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	// Per TS 29.244 §7.2.2: node-level messages must use S=0 (no SEID).
	if h.HasSEID {
		return nil, fmt.Errorf("AssociationSetupRequest: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeAssociationSetupRequest {
		return nil, fmt.Errorf("AssociationSetupRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeAssociationSetupRequest)
	}
	req := &AssociationSetupRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeNodeID:
			req.NodeID = i
		case ie.TypeRecoveryTimeStamp:
			req.RecoveryTimeStamp = i
		case ie.TypeCPFunctionFeatures:
			req.CPFeatures = i
		}
	}
	if req.NodeID == nil {
		return nil, fmt.Errorf("AssociationSetupRequest: missing mandatory Node ID IE (Table 7.4.4.1-1)")
	}
	if req.RecoveryTimeStamp == nil {
		return nil, fmt.Errorf("AssociationSetupRequest: missing mandatory Recovery Time Stamp IE (Table 7.4.4.1-1)")
	}
	return req, nil
}

// AssociationSetupResponse is a parsed PFCP Association Setup Response
// per TS 29.244 Rel-15 §7.4.4.2 Table 7.4.4.2-1.
// FIXED 2026-06-23: was cited §7.4.2/Table 7.4.2-1 (wrong section — see
// AssociationSetupRequest's comment above). UPFeatures/CPFeatures were cited "CO";
// the table's condition column for both literally reads "C".
type AssociationSetupResponse struct {
	Header
	NodeID            *ie.IE // M per Table 7.4.4.2-1
	Cause             *ie.IE // M per Table 7.4.4.2-1
	RecoveryTimeStamp *ie.IE // M per Table 7.4.4.2-1
	UPFeatures        *ie.IE // C per Table 7.4.4.2-1
	CPFeatures        *ie.IE // C per Table 7.4.4.2-1
}

// ParseAssociationSetupResponse decodes raw PFCP bytes.
// Validates message type, S=0 (node-level), and M-IEs per Table 7.4.4.2-1.
func ParseAssociationSetupResponse(b []byte) (*AssociationSetupResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.HasSEID {
		return nil, fmt.Errorf("AssociationSetupResponse: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeAssociationSetupResponse {
		return nil, fmt.Errorf("AssociationSetupResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeAssociationSetupResponse)
	}
	resp := &AssociationSetupResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeNodeID:
			resp.NodeID = i
		case ie.TypeCause:
			resp.Cause = i
		case ie.TypeRecoveryTimeStamp:
			resp.RecoveryTimeStamp = i
		case ie.TypeUPFunctionFeatures:
			resp.UPFeatures = i
		case ie.TypeCPFunctionFeatures:
			resp.CPFeatures = i
		}
	}
	// C11-equivalent: validate M-IEs on success path per Table 7.4.4.2-1.
	if resp.NodeID == nil {
		return nil, fmt.Errorf("AssociationSetupResponse: missing mandatory Node ID IE (Table 7.4.4.2-1)")
	}
	if resp.Cause == nil {
		return nil, fmt.Errorf("AssociationSetupResponse: missing mandatory Cause IE (Table 7.4.4.2-1)")
	}
	if resp.RecoveryTimeStamp == nil {
		return nil, fmt.Errorf("AssociationSetupResponse: missing mandatory Recovery Time Stamp IE (Table 7.4.4.2-1)")
	}
	return resp, nil
}

// HeartbeatRequest is a parsed PFCP Heartbeat Request per TS 29.244 §7.4.2.1
// Table 7.4.2.1-1 (corrected 2026-06-23 — §7.2.2 is "Message Header", the generic
// header-format clause, not the Heartbeat message definition).
type HeartbeatRequest struct {
	Header
	// RecoveryTimeStamp: M per TS 29.244 Rel-15 Tables 7.4.2.1-1 and 7.4.2.2-1.
	// Condition text: "Recovery Time Stamp" is mandatory in Heartbeat Request.
	RecoveryTimeStamp *ie.IE
}

// ParseHeartbeatRequest decodes raw PFCP bytes.
// Validates message type, S=0 (node-level), and M-IE per Tables 7.4.2.1-1/7.4.2.2-1.
func ParseHeartbeatRequest(b []byte) (*HeartbeatRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.HasSEID {
		return nil, fmt.Errorf("HeartbeatRequest: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeHeartbeatRequest {
		return nil, fmt.Errorf("HeartbeatRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeHeartbeatRequest)
	}
	req := &HeartbeatRequest{Header: h}
	for _, i := range ies {
		if i.Type == ie.TypeRecoveryTimeStamp {
			req.RecoveryTimeStamp = i
		}
	}
	// M-IE per TS 29.244 Rel-15 Tables 7.4.2.1-1 / 7.4.2.2-1:
	// Recovery Time Stamp — "M" (mandatory); condition: always present.
	if req.RecoveryTimeStamp == nil {
		return nil, fmt.Errorf("HeartbeatRequest: missing mandatory Recovery Time Stamp IE (Tables 7.4.2.1-1/7.4.2.2-1)")
	}
	return req, nil
}

// HeartbeatResponse is a parsed PFCP Heartbeat Response per TS 29.244 §7.4.2.2
// Table 7.4.2.2-1 (corrected 2026-06-23 — §7.2.3 is "Information Elements", a
// generic IE-presence-rules clause, not the Heartbeat Response message definition).
type HeartbeatResponse struct {
	Header
	// RecoveryTimeStamp: M per TS 29.244 Rel-15 Tables 7.4.2.1-1 and 7.4.2.2-1.
	// Condition text: "Recovery Time Stamp" is mandatory in Heartbeat Response.
	RecoveryTimeStamp *ie.IE
}

// ParseHeartbeatResponse decodes raw PFCP bytes.
// Validates message type, S=0 (node-level), and M-IE per Tables 7.4.2.1-1/7.4.2.2-1.
func ParseHeartbeatResponse(b []byte) (*HeartbeatResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.HasSEID {
		return nil, fmt.Errorf("HeartbeatResponse: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeHeartbeatResponse {
		return nil, fmt.Errorf("HeartbeatResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeHeartbeatResponse)
	}
	resp := &HeartbeatResponse{Header: h}
	for _, i := range ies {
		if i.Type == ie.TypeRecoveryTimeStamp {
			resp.RecoveryTimeStamp = i
		}
	}
	// M-IE per TS 29.244 Rel-15 Tables 7.4.2.1-1 / 7.4.2.2-1:
	// Recovery Time Stamp — "M" (mandatory); condition: always present.
	if resp.RecoveryTimeStamp == nil {
		return nil, fmt.Errorf("HeartbeatResponse: missing mandatory Recovery Time Stamp IE (Tables 7.4.2.1-1/7.4.2.2-1)")
	}
	return resp, nil
}

// ── Session-level messages (Phase 5) ─────────────────────────────────────────

// SessionEstablishmentRequest is a parsed PFCP Session Establishment Request
// per TS 29.244 Rel-15 §7.5.2 Table 7.5.2.1-1.
// The request is session-level (S=1, SEID field carries CP-SEID toward UP).
// On the initial request the SEID field is 0 (UP has no session yet);
// the CP F-SEID IE carries the SGW-C's assigned SEID and address.
type SessionEstablishmentRequest struct {
	Header
	// NodeID: M per Table 7.5.2.1-1 — identifies the CP function
	NodeID *ie.IE
	// CPSEID: M per Table 7.5.2.1-1 — CP Function's F-SEID for this session
	CPSEID *ie.IE
	// CreatePDRs: M (at least 1) per Table 7.5.2.1-1
	CreatePDRs []*ie.IE
	// CreateFARs: M (at least 1) per Table 7.5.2.1-1
	CreateFARs []*ie.IE
}

// ParseSessionEstablishmentRequest decodes raw PFCP bytes.
// Validates message type, S=1 (session-level), SEID=0 (initial request), and M-IEs per Table 7.5.2.1-1.
func ParseSessionEstablishmentRequest(b []byte) (*SessionEstablishmentRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	// Per TS 29.244 §7.2.2.4.1: session messages must use S=1.
	if !h.HasSEID {
		return nil, fmt.Errorf("SessionEstablishmentRequest: S flag must be 1 for session-level messages (§7.2.2.4.1)")
	}
	if h.MessageType != MsgTypeSessionEstablishmentRequest {
		return nil, fmt.Errorf("SessionEstablishmentRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeSessionEstablishmentRequest)
	}
	// Per TS 29.244 §7.2.2.4.2 (fixed 2026-06-23, was miscited §7.5.2): "PFCP Session
	// Establishment Request message on Sxa/Sxb/Sxc" is explicitly listed among the
	// SEID=0 cases (CP has no UP session context yet).
	if h.SEID != 0 {
		return nil, fmt.Errorf("SessionEstablishmentRequest: initial SEID must be 0, got %d (§7.2.2.4.2)", h.SEID)
	}
	req := &SessionEstablishmentRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeNodeID:
			req.NodeID = i
		case ie.TypeFSEID:
			req.CPSEID = i
		case ie.TypeCreatePDR:
			req.CreatePDRs = append(req.CreatePDRs, i)
		case ie.TypeCreateFAR:
			req.CreateFARs = append(req.CreateFARs, i)
		}
	}
	// C11-equivalent: validate M-IEs per Table 7.5.2.1-1.
	// "Node ID" — M, condition: "mandatory"
	if req.NodeID == nil {
		return nil, fmt.Errorf("SessionEstablishmentRequest: missing mandatory Node ID IE (Table 7.5.2.1-1)")
	}
	// "CP F-SEID" — M, condition: "mandatory"
	if req.CPSEID == nil {
		return nil, fmt.Errorf("SessionEstablishmentRequest: missing mandatory CP F-SEID IE (Table 7.5.2.1-1)")
	}
	// "Create PDR" — M (minimum 1), condition: "mandatory"
	if len(req.CreatePDRs) == 0 {
		return nil, fmt.Errorf("SessionEstablishmentRequest: missing mandatory Create PDR IE (Table 7.5.2.1-1)")
	}
	// "Create FAR" — M (minimum 1), condition: "mandatory"
	if len(req.CreateFARs) == 0 {
		return nil, fmt.Errorf("SessionEstablishmentRequest: missing mandatory Create FAR IE (Table 7.5.2.1-1)")
	}
	return req, nil
}

// SessionEstablishmentResponse is a parsed PFCP Session Establishment Response
// per TS 29.244 Rel-15 §7.5.2 Table 7.5.3.1-1.
type SessionEstablishmentResponse struct {
	Header
	// NodeID: M per Table 7.5.3.1-1
	NodeID *ie.IE
	// Cause: M per Table 7.5.3.1-1
	Cause *ie.IE
	// UPSEID: C per Table 7.5.3.1-1 — present on success (Cause=1)
	// Condition text: "shall be present if the Cause IE contains the value 'Request Accepted'"
	UPSEID *ie.IE
	// CreatedPDRs: C per Table 7.5.3.1-1 — present when CHOOSE was set in request
	// Condition text: "present if F-TEID IE with CHOOSE bit was set in the corresponding Create PDR"
	CreatedPDRs []*ie.IE
}

// ParseSessionEstablishmentResponse decodes raw PFCP bytes.
// Validates message type, S=1, and M/C-IEs per TS 29.244 Rel-15 Table 7.5.3.1-1.
func ParseSessionEstablishmentResponse(b []byte) (*SessionEstablishmentResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if !h.HasSEID {
		return nil, fmt.Errorf("SessionEstablishmentResponse: S flag must be 1 for session-level messages (§7.2.2.4.1)")
	}
	if h.MessageType != MsgTypeSessionEstablishmentResponse {
		return nil, fmt.Errorf("SessionEstablishmentResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeSessionEstablishmentResponse)
	}
	resp := &SessionEstablishmentResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeNodeID:
			resp.NodeID = i
		case ie.TypeCause:
			resp.Cause = i
		case ie.TypeFSEID:
			resp.UPSEID = i
		case ie.TypeCreatedPDR:
			resp.CreatedPDRs = append(resp.CreatedPDRs, i)
		}
	}
	// M-IEs per Table 7.5.3.1-1:
	if resp.NodeID == nil {
		return nil, fmt.Errorf("SessionEstablishmentResponse: missing mandatory Node ID IE (Table 7.5.3.1-1)")
	}
	if resp.Cause == nil {
		return nil, fmt.Errorf("SessionEstablishmentResponse: missing mandatory Cause IE (Table 7.5.3.1-1)")
	}
	// C11: C-IEs on success path per Table 7.5.3.1-1.
	// "UP F-SEID" — C, condition: "shall be present if Cause IE contains 'Request Accepted'"
	if causeVal, _ := resp.Cause.CauseValue(); causeVal == ie.CauseRequestAccepted {
		if resp.UPSEID == nil {
			return nil, fmt.Errorf("SessionEstablishmentResponse: missing UP F-SEID IE on success (Table 7.5.3.1-1: 'present if Cause=Request Accepted')")
		}
	}
	return resp, nil
}

// SessionModificationRequest is a parsed PFCP Session Modification Request
// per TS 29.244 Rel-15 §7.5.4 Table 7.5.4.1-1.
// Session-level (S=1), SEID = UP-SEID assigned by SGW-U at establishment.
type SessionModificationRequest struct {
	Header
	// CPSEID: CO per Table 7.5.4.1-1 — CP Function's F-SEID
	// Condition text: "may be present if the CP function wants to change its F-SEID"
	CPSEID *ie.IE
	// UpdateFARs: C per Table 7.5.4.1-1
	// Condition text: "present if the CP function wants to update a FAR"
	UpdateFARs []*ie.IE
	// UpdatePDRs: C per Table 7.5.4.1-1
	// Condition text: "present if the CP function wants to update a PDR"
	UpdatePDRs []*ie.IE
	// CreatePDRs: C per Table 7.5.4.1-1
	// Condition text: "present if the CP function wants to create a PDR"
	CreatePDRs []*ie.IE
	// CreateFARs: C per Table 7.5.4.1-1
	// Condition text: "present if the CP function wants to create a FAR"
	CreateFARs []*ie.IE
	// RemovePDRs: C per Table 7.5.4.1-1 — PDR IDs to remove
	// Condition text: "present if the CP function wants to remove a PDR"
	RemovePDRs []*ie.IE
	// RemoveFARs: C per Table 7.5.4.1-1 — FAR IDs to remove
	// Condition text: "present if the CP function wants to remove a FAR"
	RemoveFARs []*ie.IE
}

// ParseSessionModificationRequest decodes raw PFCP bytes.
// Validates message type and S=1 per TS 29.244 §7.2.2.4.1; Table 7.5.4.1-1 has no M-IEs.
func ParseSessionModificationRequest(b []byte) (*SessionModificationRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if !h.HasSEID {
		return nil, fmt.Errorf("SessionModificationRequest: S flag must be 1 for session-level messages (§7.2.2.4.1)")
	}
	if h.MessageType != MsgTypeSessionModificationRequest {
		return nil, fmt.Errorf("SessionModificationRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeSessionModificationRequest)
	}
	req := &SessionModificationRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeFSEID:
			req.CPSEID = i
		case ie.TypeUpdateFAR:
			req.UpdateFARs = append(req.UpdateFARs, i)
		case ie.TypeUpdatePDR:
			req.UpdatePDRs = append(req.UpdatePDRs, i)
		case ie.TypeCreatePDR:
			req.CreatePDRs = append(req.CreatePDRs, i)
		case ie.TypeCreateFAR:
			req.CreateFARs = append(req.CreateFARs, i)
		case ie.TypeRemovePDR:
			req.RemovePDRs = append(req.RemovePDRs, i)
		case ie.TypeRemoveFAR:
			req.RemoveFARs = append(req.RemoveFARs, i)
		}
	}
	return req, nil
}

// SessionModificationResponse is a parsed PFCP Session Modification Response
// per TS 29.244 Rel-15 §7.5.4 Table 7.5.5.1-1.
type SessionModificationResponse struct {
	Header
	// Cause: M per Table 7.5.5.1-1 — "This IE shall indicate the acceptance or rejection"
	Cause *ie.IE
	// CreatedPDRs: C per Table 7.5.5.1-1 — "present if cause=success, new PDR(s) were requested
	// to be created and the UP function was requested to allocate the local F-TEID"
	CreatedPDRs []*ie.IE
}

// ParseSessionModificationResponse decodes raw PFCP bytes.
// Validates message type, S=1, and M-IE Cause per TS 29.244 Rel-15 Table 7.5.5.1-1.
func ParseSessionModificationResponse(b []byte) (*SessionModificationResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if !h.HasSEID {
		return nil, fmt.Errorf("SessionModificationResponse: S flag must be 1 for session-level messages (§7.2.2.4.1)")
	}
	if h.MessageType != MsgTypeSessionModificationResponse {
		return nil, fmt.Errorf("SessionModificationResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeSessionModificationResponse)
	}
	resp := &SessionModificationResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeCause:
			resp.Cause = i
		case ie.TypeCreatedPDR:
			resp.CreatedPDRs = append(resp.CreatedPDRs, i)
		}
	}
	// M-IE per Table 7.5.5.1-1: "Cause" — mandatory.
	if resp.Cause == nil {
		return nil, fmt.Errorf("SessionModificationResponse: missing mandatory Cause IE (Table 7.5.5.1-1)")
	}
	return resp, nil
}

// SessionDeletionRequest is a PFCP Session Deletion Request per TS 29.244 Rel-15 §7.5.6.
// Session-level (S=1), SEID = UP-SEID assigned by SGW-U at establishment.
// The request carries no IEs per Table 7.5.6.1-1 (empty body).
type SessionDeletionRequest struct {
	Header
}

// ParseSessionDeletionRequest decodes raw PFCP bytes.
// Validates message type and S=1 per §7.2.2.4.1; Table 7.5.6.1-1 has no IEs.
func ParseSessionDeletionRequest(b []byte) (*SessionDeletionRequest, error) {
	h, _, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if !h.HasSEID {
		return nil, fmt.Errorf("SessionDeletionRequest: S flag must be 1 for session-level messages (§7.2.2.4.1)")
	}
	if h.MessageType != MsgTypeSessionDeletionRequest {
		return nil, fmt.Errorf("SessionDeletionRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeSessionDeletionRequest)
	}
	return &SessionDeletionRequest{Header: h}, nil
}

// SessionDeletionResponse is a parsed PFCP Session Deletion Response
// per TS 29.244 Rel-15 §7.5.6 Table 7.5.7.1-1.
type SessionDeletionResponse struct {
	Header
	// Cause: M per Table 7.5.7.1-1
	Cause *ie.IE
}

// ParseSessionDeletionResponse decodes raw PFCP bytes.
// Validates message type, S=1, and M-IE Cause per TS 29.244 Rel-15 Table 7.5.7.1-1.
func ParseSessionDeletionResponse(b []byte) (*SessionDeletionResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if !h.HasSEID {
		return nil, fmt.Errorf("SessionDeletionResponse: S flag must be 1 for session-level messages (§7.2.2.4.1)")
	}
	if h.MessageType != MsgTypeSessionDeletionResponse {
		return nil, fmt.Errorf("SessionDeletionResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeSessionDeletionResponse)
	}
	resp := &SessionDeletionResponse{Header: h}
	for _, i := range ies {
		if i.Type == ie.TypeCause {
			resp.Cause = i
		}
	}
	// M-IE per Table 7.5.7.1-1: "Cause" — mandatory.
	if resp.Cause == nil {
		return nil, fmt.Errorf("SessionDeletionResponse: missing mandatory Cause IE (Table 7.5.7.1-1)")
	}
	return resp, nil
}

// ── Phase 11: Association Release and Node Report messages ────────────────────

// AssociationReleaseRequest is a parsed PFCP Association Release Request
// per TS 29.244 Rel-15 §7.4.4.5 Table 7.4.4.5-1 (doc table 18).
// The CP function sends this to the UP function to release the association.
// Node-level (S=0).
type AssociationReleaseRequest struct {
	Header
	// NodeID: M per Table 7.4.4.5-1 — "This IE shall contain the unique identifier of the sending Node."
	NodeID *ie.IE
}

// ParseAssociationReleaseRequest decodes raw PFCP bytes.
// Validates message type, S=0, and M-IE per TS 29.244 Rel-15 Table 7.4.4.5-1.
func ParseAssociationReleaseRequest(b []byte) (*AssociationReleaseRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.HasSEID {
		return nil, fmt.Errorf("AssociationReleaseRequest: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeAssociationReleaseRequest {
		return nil, fmt.Errorf("AssociationReleaseRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeAssociationReleaseRequest)
	}
	req := &AssociationReleaseRequest{Header: h}
	for _, i := range ies {
		if i.Type == ie.TypeNodeID {
			req.NodeID = i
		}
	}
	// M-IE per Table 7.4.4.5-1: "Node ID" — "M" — "This IE shall contain the unique identifier of the sending Node."
	if req.NodeID == nil {
		return nil, fmt.Errorf("AssociationReleaseRequest: missing mandatory Node ID IE (Table 7.4.4.5-1)")
	}
	return req, nil
}

// AssociationReleaseResponse is a parsed PFCP Association Release Response
// per TS 29.244 Rel-15 §7.4.4.6 Table 7.4.4.6-1 (doc table 19).
// Node-level (S=0).
type AssociationReleaseResponse struct {
	Header
	// NodeID: M per Table 7.4.4.6-1 — "This IE shall contain the unique identifier of the sending Node."
	NodeID *ie.IE
	// Cause: M per Table 7.4.4.6-1 — "This IE shall indicate the acceptance or the rejection of the corresponding request message."
	Cause *ie.IE
}

// ParseAssociationReleaseResponse decodes raw PFCP bytes.
// Validates message type, S=0, and M-IEs per TS 29.244 Rel-15 Table 7.4.4.6-1.
func ParseAssociationReleaseResponse(b []byte) (*AssociationReleaseResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.HasSEID {
		return nil, fmt.Errorf("AssociationReleaseResponse: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeAssociationReleaseResponse {
		return nil, fmt.Errorf("AssociationReleaseResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeAssociationReleaseResponse)
	}
	resp := &AssociationReleaseResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeNodeID:
			resp.NodeID = i
		case ie.TypeCause:
			resp.Cause = i
		}
	}
	// M-IEs per Table 7.4.4.6-1:
	// "Node ID" — M — "This IE shall contain the unique identifier of the sending Node."
	if resp.NodeID == nil {
		return nil, fmt.Errorf("AssociationReleaseResponse: missing mandatory Node ID IE (Table 7.4.4.6-1)")
	}
	// "Cause" — M — "This IE shall indicate the acceptance or the rejection of the corresponding request message."
	if resp.Cause == nil {
		return nil, fmt.Errorf("AssociationReleaseResponse: missing mandatory Cause IE (Table 7.4.4.6-1)")
	}
	return resp, nil
}

// NodeReportRequest is a parsed PFCP Node Report Request per TS 29.244 Rel-15 §7.4.5.1.1
// Table 7.4.5.1.1-1 (doc table 20). Sent from UP function to CP function. Node-level (S=0).
type NodeReportRequest struct {
	Header
	// NodeID: M per Table 7.4.5.1.1-1 — "This IE shall contain the unique identifier of the sending Node."
	NodeID *ie.IE
	// NodeReportType: M per Table 7.4.5.1.1-1 — "This IE shall indicate the type of the report."
	NodeReportType *ie.IE
	// UserPlanPathFailureReport: C per Table 7.4.5.1.1-1 —
	// "This IE shall be present if the Node Report Type indicates a User Plane Path Failure Report."
	UserPlanPathFailureReport *ie.IE
}

// ParseNodeReportRequest decodes raw PFCP bytes.
// Validates message type, S=0, and M/C-IEs per TS 29.244 Rel-15 Table 7.4.5.1.1-1.
func ParseNodeReportRequest(b []byte) (*NodeReportRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.HasSEID {
		return nil, fmt.Errorf("NodeReportRequest: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeNodeReportRequest {
		return nil, fmt.Errorf("NodeReportRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeNodeReportRequest)
	}
	req := &NodeReportRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeNodeID:
			req.NodeID = i
		case ie.TypeNodeReportType:
			req.NodeReportType = i
		case ie.TypeUserPlanPathFailureReport:
			req.UserPlanPathFailureReport = i
		}
	}
	// M-IEs per Table 7.4.5.1.1-1:
	// "Node ID" — M — "This IE shall contain the unique identifier of the sending Node."
	if req.NodeID == nil {
		return nil, fmt.Errorf("NodeReportRequest: missing mandatory Node ID IE (Table 7.4.5.1.1-1)")
	}
	// "Node Report Type" — M — "This IE shall indicate the type of the report."
	if req.NodeReportType == nil {
		return nil, fmt.Errorf("NodeReportRequest: missing mandatory Node Report Type IE (Table 7.4.5.1.1-1)")
	}
	// C-IE: "User Plane Path Failure Report" — C —
	// "This IE shall be present if the Node Report Type indicates a User Plane Path Failure Report."
	if flags, _ := req.NodeReportType.NodeReportTypeFlags(); flags&ie.NodeReportTypeUPFR != 0 {
		if req.UserPlanPathFailureReport == nil {
			return nil, fmt.Errorf("NodeReportRequest: missing User Plane Path Failure Report IE when UPFR is set (Table 7.4.5.1.1-1)")
		}
	}
	return req, nil
}

// NodeReportResponse is a parsed PFCP Node Report Response per TS 29.244 Rel-15 §7.4.5.2.1
// Table 7.4.5.2.1-1 (doc table 22). Sent from CP function to UP function. Node-level (S=0).
type NodeReportResponse struct {
	Header
	// NodeID: M per Table 7.4.5.2.1-1 — "This IE shall contain the unique identifier of the sending Node."
	NodeID *ie.IE
	// Cause: M per Table 7.4.5.2.1-1 — "This IE shall indicate the acceptance or the rejection of the corresponding request message."
	Cause *ie.IE
	// OffendingIE: C per Table 7.4.5.2.1-1 —
	// "This IE shall be included if the rejection cause is due to a conditional or mandatory IE missing or faulty."
	OffendingIE *ie.IE
}

// ParseNodeReportResponse decodes raw PFCP bytes.
// Validates message type, S=0, and M-IEs per TS 29.244 Rel-15 Table 7.4.5.2.1-1.
func ParseNodeReportResponse(b []byte) (*NodeReportResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.HasSEID {
		return nil, fmt.Errorf("NodeReportResponse: S flag must be 0 for node-level messages (§7.2.2)")
	}
	if h.MessageType != MsgTypeNodeReportResponse {
		return nil, fmt.Errorf("NodeReportResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeNodeReportResponse)
	}
	resp := &NodeReportResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeNodeID:
			resp.NodeID = i
		case ie.TypeCause:
			resp.Cause = i
		}
	}
	// M-IEs per Table 7.4.5.2.1-1:
	// "Node ID" — M — "This IE shall contain the unique identifier of the sending Node."
	if resp.NodeID == nil {
		return nil, fmt.Errorf("NodeReportResponse: missing mandatory Node ID IE (Table 7.4.5.2.1-1)")
	}
	// "Cause" — M — "This IE shall indicate the acceptance or the rejection of the corresponding request message."
	if resp.Cause == nil {
		return nil, fmt.Errorf("NodeReportResponse: missing mandatory Cause IE (Table 7.4.5.2.1-1)")
	}
	return resp, nil
}
