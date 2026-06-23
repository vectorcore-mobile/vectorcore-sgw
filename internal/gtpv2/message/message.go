// Package message implements GTPv2-C message encoding and decoding
// per 3GPP TS 29.274 Sections 5 and 7.
package message

import (
	"encoding/binary"
	"fmt"

	"vectorcore-sgw/internal/gtpv2/ie"
)

// Message type codes per TS 29.274 Table 6.1-1.
const (
	MsgTypeEchoRequest                  uint8 = 1
	MsgTypeEchoResponse                 uint8 = 2
	// MsgTypeVersionNotSupported is sent when an unsupported GTP version is received
	// per TS 29.274 §7.7.2. Extracted from docs/specs/29274-f90.docx Table 5 (= Table 6.1-1):
	// "3 | Version Not Supported Indication | Version Not Supported Indication"
	MsgTypeVersionNotSupported          uint8 = 3
	MsgTypeCreateSessionRequest         uint8 = 32
	MsgTypeCreateSessionResponse        uint8 = 33
	MsgTypeModifyBearerRequest          uint8 = 34
	MsgTypeModifyBearerResponse         uint8 = 35
	MsgTypeDeleteSessionRequest         uint8 = 36
	MsgTypeDeleteSessionResponse        uint8 = 37
	// Dedicated bearer procedures per TS 29.274 Table 6.1-1 (docs/specs/29274-f90.docx Table 5):
	// "95 | Create Bearer Request", "96 | Create Bearer Response",
	// "97 | Update Bearer Request", "98 | Update Bearer Response",
	// "99 | Delete Bearer Request", "100 | Delete Bearer Response"
	MsgTypeCreateBearerRequest  uint8 = 95
	MsgTypeCreateBearerResponse uint8 = 96
	MsgTypeUpdateBearerRequest  uint8 = 97
	MsgTypeUpdateBearerResponse uint8 = 98
	MsgTypeDeleteBearerRequest  uint8 = 99
	MsgTypeDeleteBearerResponse uint8 = 100
	MsgTypeReleaseAccessBearersRequest  uint8 = 170
	MsgTypeReleaseAccessBearersResponse uint8 = 171
)

// ResponseTypeFor returns the response message type for a given request type
// per TS 29.274 Table 6.1-1. Returns (0, false) for unknown request types.
// Never compute response type arithmetically — use this function.
func ResponseTypeFor(reqType uint8) (uint8, bool) {
	switch reqType {
	case MsgTypeEchoRequest:
		return MsgTypeEchoResponse, true
	case MsgTypeCreateSessionRequest:
		return MsgTypeCreateSessionResponse, true
	case MsgTypeModifyBearerRequest:
		return MsgTypeModifyBearerResponse, true
	case MsgTypeDeleteSessionRequest:
		return MsgTypeDeleteSessionResponse, true
	case MsgTypeReleaseAccessBearersRequest:
		return MsgTypeReleaseAccessBearersResponse, true
	}
	return 0, false
}

// Header is a parsed GTPv2-C message header per TS 29.274 Rel-15 Section 5.1.
//
// Wire format when T=1 (TEID present):
//
//	Octet 1:    Version(3)=2 | P(1) | T(1)=1 | MP(1) | Spare(2)
//	Octet 2:    Message Type
//	Octet 3-4:  Message Length (total length of msg - 4)
//	Octet 5-8:  TEID
//	Octet 9-11: Sequence Number (big-endian, 3 bytes)
//	Octet 12:   MP=1 → bits 7-4: Message Priority, bits 3-0: Spare; MP=0 → Spare
//
// When T=0 (no TEID):
//
//	Octet 1:   Version(3)=2 | P(1) | T(1)=0 | MP(1) | Spare(2)
//	Octet 2:   Message Type
//	Octet 3-4: Message Length
//	Octet 5-7: Sequence Number
//	Octet 8:   MP=1 → bits 7-4: Message Priority, bits 3-0: Spare; MP=0 → Spare
type Header struct {
	Version         uint8
	PiggyBacked     bool
	HasTEID         bool
	MP              bool  // Message Priority indication flag (Rel-15 §5.1)
	MessagePriority uint8 // 0-15 when MP=true; 0=highest priority (§5.1)
	MessageType     uint8
	Length          uint16
	TEID            uint32
	SequenceNumber  uint32
}

const (
	headerLenWithTEID    = 12
	headerLenWithoutTEID = 8
)

// ErrVersionNotSupported is returned by ParseHeader when the GTP version field
// is not 2. Callers should send a Version Not Supported Indication per TS 29.274 §7.7.2.
type ErrVersionNotSupported struct {
	Version uint8
}

func (e *ErrVersionNotSupported) Error() string {
	return fmt.Sprintf("GTPv2-C unsupported version: %d", e.Version)
}

// MarshalVersionNotSupportedIndication builds a minimal Version Not Supported Indication
// per TS 29.274 Rel-15 §7.7.2. seq should be copied from the triggering packet if known.
// Message type 3 per Table 6.1-1 (docs/specs/29274-f90.docx): "Version Not Supported Indication".
func MarshalVersionNotSupportedIndication(seq uint32) []byte {
	h := Header{
		Version:        2,
		HasTEID:        false, // no TEID in VNSIND per §7.7.2
		MessageType:    MsgTypeVersionNotSupported,
		SequenceNumber: seq,
	}
	buf, _ := Marshal(h, nil)
	return buf
}

// ValidateTFlag enforces the T-flag rule per TS 29.274 §5:
// "The GTPv2-C message header for the Echo Request, Echo Response and Version Not Supported
// Indication messages shall not contain the TEID field."
// All other EPC-specific messages (type ≥ 4) must include the TEID (T=1).
// Returns a non-nil error if the T-flag does not match the message type.
func ValidateTFlag(h Header) error {
	switch h.MessageType {
	case MsgTypeEchoRequest, MsgTypeEchoResponse, MsgTypeVersionNotSupported:
		if h.HasTEID {
			return fmt.Errorf("GTPv2-C: message type %d must have T=0 (no TEID) per TS 29.274 §5", h.MessageType)
		}
	default:
		if !h.HasTEID {
			return fmt.Errorf("GTPv2-C: message type %d must have T=1 (TEID present) per TS 29.274 §5", h.MessageType)
		}
	}
	return nil
}

// ParseHeader decodes a GTPv2-C message header from b.
// Returns the header, the body bytes bounded by the declared Length field, and any error.
// Per TS 29.274 Rel-15 §5.1: Length = total_message_length - 4. IE parsing is bounded
// to the declared length; trailing data beyond it is not passed to the IE parser.
func ParseHeader(b []byte) (Header, []byte, error) {
	if len(b) < headerLenWithoutTEID {
		return Header{}, nil, fmt.Errorf("GTPv2-C header too short: %d bytes", len(b))
	}
	version := (b[0] >> 5) & 0x07
	if version != 2 {
		return Header{}, nil, &ErrVersionNotSupported{Version: version}
	}
	h := Header{
		Version:     version,
		PiggyBacked: b[0]&0x10 != 0,
		HasTEID:     b[0]&0x08 != 0,
		MP:          b[0]&0x04 != 0, // Message Priority flag per Rel-15 §5.1
		MessageType: b[1],
		Length:      binary.BigEndian.Uint16(b[2:4]),
	}

	minHeaderSize := headerLenWithoutTEID
	if h.HasTEID {
		minHeaderSize = headerLenWithTEID
	}
	if len(b) < minHeaderSize {
		return Header{}, nil, fmt.Errorf("GTPv2-C header (with TEID) too short: %d bytes", len(b))
	}

	// Parse TEID and sequence number before length check so they are available
	// in ErrInvalidLength for building §7.7.3 error responses.
	if h.HasTEID {
		h.TEID = binary.BigEndian.Uint32(b[4:8])
		h.SequenceNumber = uint32(b[8])<<16 | uint32(b[9])<<8 | uint32(b[10])
		// Octet 12: when MP=1, bits 7-4 = Message Priority per Rel-15 §5.1.
		if h.MP {
			h.MessagePriority = b[11] >> 4
		}
	} else {
		h.SequenceNumber = uint32(b[4])<<16 | uint32(b[5])<<8 | uint32(b[6])
		// Octet 8: when MP=1, bits 7-4 = Message Priority per Rel-15 §5.1.
		if h.MP {
			h.MessagePriority = b[7] >> 4
		}
	}

	// Validate declared length per TS 29.274 Rel-15 §5.1.
	declaredTotal := 4 + int(h.Length)
	if declaredTotal < minHeaderSize {
		return Header{}, nil, fmt.Errorf("GTPv2-C declared length %d too small for header", h.Length)
	}
	// Return ErrInvalidLength (not a plain error) so callers can send §7.7.3 responses.
	if declaredTotal > len(b) {
		return h, nil, &ErrInvalidLength{Hdr: h}
	}
	return h, b[minHeaderSize:declaredTotal], nil
}

// MarshalHeader encodes a GTPv2-C header.
// bodyLen is the byte length of the IEs that follow.
func MarshalHeader(h Header, bodyLen int) []byte {
	var buf []byte
	flags := uint8(0x40) // version=2
	if h.PiggyBacked {
		flags |= 0x10
	}
	if h.HasTEID {
		flags |= 0x08
	}
	if h.MP {
		flags |= 0x04 // MP flag per Rel-15 §5.1
	}
	if h.HasTEID {
		buf = make([]byte, headerLenWithTEID)
		buf[0] = flags
		buf[1] = h.MessageType
		binary.BigEndian.PutUint16(buf[2:4], uint16(headerLenWithTEID-4+bodyLen))
		binary.BigEndian.PutUint32(buf[4:8], h.TEID)
		buf[8] = byte(h.SequenceNumber >> 16)
		buf[9] = byte(h.SequenceNumber >> 8)
		buf[10] = byte(h.SequenceNumber)
		// Octet 12: bits 7-4 = Message Priority when MP=1, else spare=0.
		if h.MP {
			buf[11] = (h.MessagePriority & 0x0F) << 4
		}
	} else {
		buf = make([]byte, headerLenWithoutTEID)
		buf[0] = flags
		buf[1] = h.MessageType
		binary.BigEndian.PutUint16(buf[2:4], uint16(headerLenWithoutTEID-4+bodyLen))
		buf[4] = byte(h.SequenceNumber >> 16)
		buf[5] = byte(h.SequenceNumber >> 8)
		buf[6] = byte(h.SequenceNumber)
		// Octet 8: bits 7-4 = Message Priority when MP=1, else spare=0.
		if h.MP {
			buf[7] = (h.MessagePriority & 0x0F) << 4
		}
	}
	return buf
}

// Marshal encodes a complete GTPv2-C message (header + IEs) to wire format.
func Marshal(h Header, ies []*ie.IE) ([]byte, error) {
	var body []byte
	for _, i := range ies {
		body = append(body, i.Marshal()...)
	}
	hdr := MarshalHeader(h, len(body))
	return append(hdr, body...), nil
}

// ErrInvalidLength is returned by ParseHeader when the GTP declared length
// exceeds the received UDP payload. The Hdr field is populated with the
// decoded header for use in §7.7.3 "Invalid Length" error responses.
type ErrInvalidLength struct {
	Hdr Header
}

func (e *ErrInvalidLength) Error() string {
	return fmt.Sprintf("GTPv2-C message truncated: declared %d octets, received fewer", 4+int(e.Hdr.Length))
}

// MarshalInvalidLengthResponse builds a minimal GTPv2-C response with
// Cause=Invalid Length (67) per TS 29.274 Rel-15 §7.7.3.
// peerTEID is the request sender's control TEID; pass 0 when unknown.
func MarshalInvalidLengthResponse(reqHdr Header, peerTEID uint32) ([]byte, error) {
	respType, ok := ResponseTypeFor(reqHdr.MessageType)
	if !ok {
		return nil, fmt.Errorf("no response type for message type %d", reqHdr.MessageType)
	}
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    respType,
		TEID:           peerTEID,
		SequenceNumber: reqHdr.SequenceNumber,
	}
	return Marshal(h, []*ie.IE{ie.NewCause(ie.CauseInvalidLength, 0, 0, 0, nil)})
}

// Parse decodes a complete GTPv2-C message from wire bytes.
// Returns the header, decoded IEs, and any error.
func Parse(b []byte) (Header, []*ie.IE, error) {
	h, body, err := ParseHeader(b)
	if err != nil {
		return Header{}, nil, err
	}
	ies, err := ie.ParseIEs(body)
	if err != nil {
		return Header{}, nil, fmt.Errorf("IE parse: %w", err)
	}
	return h, ies, nil
}
