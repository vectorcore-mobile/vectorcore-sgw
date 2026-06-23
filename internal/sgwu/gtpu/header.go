// Package gtpu implements the GTP-U (GTPv1-U) protocol per 3GPP TS 29.281 V15.7.0.
// Phase 6 provides a userspace reference forwarder for functional validation.
package gtpu

import (
	"encoding/binary"
	"fmt"
)

// Port is the GTP-U UDP port per TS 29.281 §4.4.2.1:
// "The port number for GTP-U request messages is 2152. It is the registered port number for GTP-U."
const Port = 2152

// Message type constants per TS 29.281 Table 13 (Messages in GTP-U).
// Extracted column: "Msg. Value | Message Type | GTP-U".
const (
	MsgTypeEchoRequest     uint8 = 1   // Table 13: "1  | Echo Request      | GTP-U: X"
	MsgTypeEchoResponse    uint8 = 2   // Table 13: "2  | Echo Response     | GTP-U: X"
	MsgTypeErrorIndication uint8 = 26  // Table 13: "26 | Error Indication  | GTP-U: X"
	MsgTypeEndMarker       uint8 = 254 // Table 13: "254 | End Marker       | GTP-U: X"
	MsgTypeGPDU            uint8 = 255 // Table 13: "255 | G-PDU            | GTP-U: X"
)

// GTP-U header flag constants for octet 1 per TS 29.281 §5.1 Table 0 (Figure 5.1-1):
//
//	Bits 8-6: Version — "The version number shall be set to '1'." → 001 in bits 8-6 → 0x20 in wire byte
//	Bit  5:   PT      — "GTP (when PT is '1')" → 1<<4 = 0x10
//	Bit  4:   spare   — always 0
//	Bit  3:   E       — Extension Header flag → 1<<2 = 0x04
//	Bit  2:   S       — Sequence Number flag  → 1<<1 = 0x02
//	Bit  1:   PN      — N-PDU Number flag     → 1<<0 = 0x01
const (
	hdrVersionMask uint8 = 0xE0 // Bits 8-6 mask
	hdrVersionGTP  uint8 = 0x20 // Version=1 encoded: 1<<5 = 0x20
	hdrPTFlag      uint8 = 0x10 // Bit 5: PT=1 for GTP
	hdrEFlag       uint8 = 0x04 // Bit 3: E (Extension Header present)
	hdrSFlag       uint8 = 0x02 // Bit 2: S (Sequence Number present)
	hdrPNFlag      uint8 = 0x01 // Bit 1: PN (N-PDU Number present)
)

// MinLen is the minimum GTP-U header length per TS 29.281 §5.1:
// "The GTP-U header is a variable length header whose minimum length is 8 bytes."
const MinLen = 8

// OptFieldsLen is the length of the optional field group (SeqNum[2]+NPDUNum[1]+NextExtHdr[1])
// per TS 29.281 §5.1 NOTE 4:
// "This field shall be present if and only if any one or more of the S, PN and E flags are set."
const OptFieldsLen = 4

// Header is a decoded GTP-U header per TS 29.281 §5.1.
type Header struct {
	// Mandatory fields — always present in all 8-byte GTP-U headers.
	Version  uint8  // always 1 per §5.1
	PT       bool   // always true for GTP (not GTP')
	E        bool   // Extension Header flag
	S        bool   // Sequence Number flag
	PN       bool   // N-PDU Number flag
	MsgType  uint8  // message type per Table 13
	Length   uint16 // bytes after the mandatory 8-octet header (payload + optional fields if set)
	TEID     uint32 // Tunnel Endpoint Identifier

	// Optional fields — present when E|S|PN (§5.1 NOTE 4).
	SeqNum     uint16 // Sequence Number (meaningful when S=1)
	NPDUNum    uint8  // N-PDU Number (meaningful when PN=1)
	NextExtHdr uint8  // Next Extension Header Type — type of first ext hdr, or 0 when E=0/no chain

	// ExtHeaders holds the raw bytes of the extension header chain per §5.2.
	// Populated during Parse() when E=1 and NextExtHdr!=0; relayed verbatim in forwardGPDU.
	// Each extension header: [Length(1 byte, in 4-byte units)] [Content...] [NextType(1 byte)].
	ExtHeaders []byte
}

// HasOptFields reports whether the optional 4-byte field group is present.
// Per §5.1 NOTE 4, it is present when any of E, S, or PN is set.
func (h *Header) HasOptFields() bool {
	return h.E || h.S || h.PN
}

// WireLen returns the total on-wire header length in bytes (mandatory + optional + ext headers).
func (h *Header) WireLen() int {
	n := MinLen
	if h.HasOptFields() {
		n += OptFieldsLen + len(h.ExtHeaders)
	}
	return n
}

// Parse decodes a GTP-U header from wire bytes.
// Returns the header, the number of bytes consumed (header + extension headers), and any error.
// Per R15-REAUDIT-002: the declared Length field is bounds-checked against len(b).
// Per R15-REAUDIT-003: extension header chain is walked when E=1 per §5.2.
func Parse(b []byte) (Header, int, error) {
	if len(b) < MinLen {
		return Header{}, 0, fmt.Errorf("gtpu: packet too short: %d < %d", len(b), MinLen)
	}
	octet1 := b[0]
	version := (octet1 & hdrVersionMask) >> 5
	if version != 1 {
		return Header{}, 0, fmt.Errorf("gtpu: unsupported version %d (want 1)", version)
	}
	if octet1&hdrPTFlag == 0 {
		return Header{}, 0, fmt.Errorf("gtpu: PT=0 indicates GTP', not GTP-U")
	}

	h := Header{
		Version: version,
		PT:      true,
		E:       octet1&hdrEFlag != 0,
		S:       octet1&hdrSFlag != 0,
		PN:      octet1&hdrPNFlag != 0,
		MsgType: b[1],
		Length:  binary.BigEndian.Uint16(b[2:4]),
		TEID:    binary.BigEndian.Uint32(b[4:8]),
	}

	// R15-REAUDIT-002: bounds-check declared Length against received buffer per §5.1.
	// Length = "the length in octets of the part of the packet following the mandatory
	// 8-octet GTP header" — so total packet size must be at least MinLen + Length.
	totalDeclared := MinLen + int(h.Length)
	if totalDeclared > len(b) {
		return Header{}, 0, fmt.Errorf("gtpu: declared Length %d exceeds received %d bytes (total declared %d)",
			h.Length, len(b), totalDeclared)
	}

	consumed := MinLen
	if h.HasOptFields() {
		if len(b) < MinLen+OptFieldsLen {
			return Header{}, 0, fmt.Errorf("gtpu: too short for optional fields: %d < %d",
				len(b), MinLen+OptFieldsLen)
		}
		h.SeqNum = binary.BigEndian.Uint16(b[8:10])
		h.NPDUNum = b[10]
		h.NextExtHdr = b[11]
		consumed = MinLen + OptFieldsLen

		// R15-REAUDIT-003: walk extension header chain per §5.2 when E=1 and chain is non-empty.
		// Each extension header: [Length (1 byte, in 4-byte units)] [Content...] [Next Type (1 byte)]
		// where total bytes = Length*4. Chain ends when Next Type == 0x00.
		if h.E && h.NextExtHdr != 0 {
			extStart := consumed
			end := totalDeclared
			nextType := h.NextExtHdr
			for nextType != 0 {
				if consumed >= end {
					return Header{}, 0, fmt.Errorf("gtpu: extension header chain extends past declared Length")
				}
				extLen := int(b[consumed]) * 4
				if extLen < 4 {
					return Header{}, 0, fmt.Errorf("gtpu: extension header has invalid Length=0 (§5.2)")
				}
				if consumed+extLen > end {
					return Header{}, 0, fmt.Errorf("gtpu: extension header extends past declared Length")
				}
				// The last byte of this extension header is the Next Extension Header Type.
				nextType = b[consumed+extLen-1]
				consumed += extLen
			}
			if consumed > extStart {
				h.ExtHeaders = make([]byte, consumed-extStart)
				copy(h.ExtHeaders, b[extStart:consumed])
			}
		}
	}

	return h, consumed, nil
}

// Marshal encodes h to a wire-format byte slice.
// payloadLen is the length of the T-PDU payload that follows (NOT including extension headers).
// Per §5.1: "The length of the payload (the rest of the packet following the mandatory
// part of the GTP header, i.e. the first 8 octets)."
// ExtHeaders bytes are appended between the optional fields and the T-PDU.
func Marshal(h Header, payloadLen int) []byte {
	octet1 := hdrVersionGTP | hdrPTFlag
	if h.E {
		octet1 |= hdrEFlag
	}
	if h.S {
		octet1 |= hdrSFlag
	}
	if h.PN {
		octet1 |= hdrPNFlag
	}

	// Length counts the optional fields (if present) plus extension headers plus the payload.
	length := payloadLen
	if h.HasOptFields() {
		length += OptFieldsLen + len(h.ExtHeaders)
	}

	size := MinLen
	if h.HasOptFields() {
		size += OptFieldsLen + len(h.ExtHeaders)
	}
	buf := make([]byte, size)
	buf[0] = octet1
	buf[1] = h.MsgType
	binary.BigEndian.PutUint16(buf[2:4], uint16(length))
	binary.BigEndian.PutUint32(buf[4:8], h.TEID)
	if h.HasOptFields() {
		binary.BigEndian.PutUint16(buf[8:10], h.SeqNum)
		buf[10] = h.NPDUNum
		buf[11] = h.NextExtHdr
		if len(h.ExtHeaders) > 0 {
			copy(buf[MinLen+OptFieldsLen:], h.ExtHeaders)
		}
	}
	return buf
}
