// Package ie implements PFCP Information Elements per TS 29.244 Rel-15 §8.
//
// Wire format per §8.1: 2-byte Type | 2-byte Length (value octets only) | Value.
// This differs from GTPv2-C IEs which use 1-byte Type + 2-byte Length + 1-byte Instance.
//
// C10 ("Grouped IE Instance Numbers Spec-Cited") does not apply to this
// package: C10 is written around GTPv2-C's IE model, where TS 29.274's wire
// format carries a Spare+Instance octet per IE (see internal/gtpv2/ie's
// IE.Instance field) and grouped-IE tables have an explicit Instance column.
// PFCP has neither: this IE struct has no Instance field, and TS 29.244
// Rel-15 grouped-IE tables list "Information elements / P / Condition /
// Appl. / IE Type" with no Instance column. Verified against local
// docs/specs/29244-fa0.docx for PDI, Forwarding Parameters, Create/Update FAR,
// Created PDR, Remove PDR, and Remove FAR. Do not invent instance numbers for
// PFCP grouped children.
package ie

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// IE type codes per TS 29.244 Rel-15 Table 8.1.2-1.
//
// Node-level IE types — confirmed by re-audit against TS 29.244 V15.10.0:
const (
	TypeCause              uint16 = 19 // Table 8.1.2-1 row: Cause
	TypeUPFunctionFeatures uint16 = 43 // Table 8.1.2-1 row: UP Function Features
	TypeCPFunctionFeatures uint16 = 89 // Table 8.1.2-1 row: CP Function Features (NOT 54; 54 = Overload Control Information)
	TypeNodeID             uint16 = 60 // Table 8.1.2-1 row: Node ID
	TypeRecoveryTimeStamp  uint16 = 96 // Table 8.1.2-1 row: Recovery Time Stamp
)

// Session-level IE types per TS 29.244 Rel-15 Table 8.1.2-1
// (extracted from docs/specs/29244-fa0.docx, Table 75).
const (
	TypeCreatePDR                  uint16 = 1  // Table 8.1.2-1 row: "1 | Create PDR | Extendable / Table 7.5.2.2-1"
	TypePDI                        uint16 = 2  // Table 8.1.2-1 row: "2 | PDI | Extendable / Table 7.5.2.2-2"
	TypeCreateFAR                  uint16 = 3  // Table 8.1.2-1 row: "3 | Create FAR | Extendable / Table 7.5.2.3-1"
	TypeForwardingParameters       uint16 = 4  // Table 8.1.2-1 row: "4 | Forwarding Parameters | Extendable / Table 7.5.2.3-2"
	TypeCreateQER                  uint16 = 7  // Table 8.1.2-1 row: "7 | Create QER | Extendable / Table 7.5.2.5-1"
	TypeCreatedPDR                 uint16 = 8  // Table 8.1.2-1 row: "8 | Created PDR | Extendable / Table 7.5.3.2-1"
	TypeUpdatePDR                  uint16 = 9  // Table 8.1.2-1 row: "9 | Update PDR | Extendable / Table 7.5.4.2-1"
	TypeUpdateFAR                  uint16 = 10 // Table 8.1.2-1 row: "10 | Update FAR | Extendable / Table 7.5.4.3-1"
	TypeUpdateForwardingParameters uint16 = 11 // Table 8.1.2-1 row: "11 | Update Forwarding Parameters | Extendable / Table 7.5.4.3-2"
	// Remove PDR/FAR per TS 29.244 Table 75 (docs/specs/29244-fa0.docx):
	// Table 50: "Remove PDR IE Type = 15 (decimal)"
	// Table 51: "Remove FAR IE Type = 16 (decimal)"
	TypeRemovePDR            uint16 = 15  // Table 8.1.2-1 row: "15 | Remove PDR | Extendable / Table 7.5.4.6"
	TypeRemoveFAR            uint16 = 16  // Table 8.1.2-1 row: "16 | Remove FAR | Extendable / Table 7.5.4.7"
	TypeSourceInterface      uint16 = 20  // Table 8.1.2-1 row: "20 | Source Interface | Extendable / Clause 8.2.2"
	TypeFTEID                uint16 = 21  // Table 8.1.2-1 row: "21 | F-TEID | Extendable / Clause 8.2.3"
	TypeNetworkInstance      uint16 = 22  // Table 8.1.2-1 row: "22 | Network Instance | Variable Length / Clause 8.2.4"
	TypePrecedence           uint16 = 29  // Table 8.1.2-1 row: "29 | Precedence | Extendable / Clause 8.2.11"
	TypeDestinationInterface uint16 = 42  // Table 8.1.2-1 row: "42 | Destination Interface | Extendable / Clause 8.2.24"
	TypeApplyAction          uint16 = 44  // Table 8.1.2-1 row: "44 | Apply Action | Extendable / Clause 8.2.26"
	TypePDRID                uint16 = 56  // Table 8.1.2-1 row: "56 | PDR ID | Extendable / Clause 8.2 36"
	TypeFSEID                uint16 = 57  // Table 8.1.2-1 row: "57 | F-SEID | Extendable / Clause 8.2 37"
	TypeOuterHeaderCreation  uint16 = 84  // Table 8.1.2-1 row: "84 | Outer Header Creation | Extendable / Clause 8.2.56"
	TypeOuterHeaderRemoval   uint16 = 95  // Table 8.1.2-1 row: "95 | Outer Header Removal | Extendable / Clause 8.2.64"
	TypeFARID                uint16 = 108 // Table 8.1.2-1 row: "108 | FAR ID | Extendable / Clause 8.2.74"
	TypeQERID                uint16 = 109 // Table 8.1.2-1 row: "109 | QER ID | Extendable / Clause 8.2.75"
	// TypeActivatePredefinedRules: Table 8.1.2-1 row: "106 | Activate Predefined Rules | Variable Length / Clause 8.2.72 | Not Applicable"
	TypeActivatePredefinedRules uint16 = 106 // Table 8.1.2-1: "106 | Activate Predefined Rules"
)

// VectorCore private PFCP IE types. These are used only between VectorCore
// SGW-C and SGW-U peers to carry internal dataplane metadata that Rel-15 PFCP
// does not encode directly, such as EPC bearer QCI for DSCP marking.
const (
	TypeVectorCoreQoSMarking uint16 = 32768
)

// Phase 11 — Node Report and Association Release IE type codes per TS 29.244 Rel-15 Table 8.1.2-1
// (extracted from docs/specs/29244-fa0.docx, doc table indices 20/21/22):
//
//	§8.2.69: "101 | Node Report Type | Extendable / Clause 8.2.69"
//	§7.4.5.1.2 Table 7.4.5.1.2-1: "User Plane Path Failure Report IE Type = 102 (decimal)"
//	§8.2.70: "103 | Remote GTP-U Peer | Extendable / Clause 8.2.70"
//	§8.2.77: "111 | PFCP Association Release Request | Extendable / Clause 8.2.77"
const (
	TypeNodeReportType            uint16 = 101 // §8.2.69: "101 | Node Report Type"
	TypeUserPlanPathFailureReport uint16 = 102 // §7.4.5.1.2 Table 7.4.5.1.2-1: "IE Type = 102 (decimal)"
	TypeRemoteGTPUPeer            uint16 = 103 // §8.2.70: "103 | Remote GTP-U Peer"
	TypePFCPAssocReleaseRequest   uint16 = 111 // §8.2.77: "111 | PFCP Association Release Request"
)

// NodeReportType flags per TS 29.244 Rel-15 §8.2.69 Figure 8.2.69-1
// (extracted from docs/specs/29244-fa0.docx para 2651):
//
//	"Bit 1 – UPFR (User Plane Path Failure Report): when set to '1', this indicates a
//	 User Plane Path Failure Report."
//	"Bit 2 to 8 – Spare, for future use and set to '0'."
const (
	NodeReportTypeUPFR uint8 = 0x01 // §8.2.69: "Bit 1 – UPFR"
)

// PFCPAssocReleaseRequest flags per TS 29.244 Rel-15 §8.2.77
// (extracted from docs/specs/29244-fa0.docx para 2709):
//
//	"Bit 1 – SARR (PFCP Association Release Request): If this bit is set to '1', then the UP
//	 function requests the release of the PFCP association."
//	"Bit 2 to 8: Spare, for future use and set to '0'."
const (
	PFCPAssocReleaseRequestSARR uint8 = 0x01 // §8.2.77: "Bit 1 – SARR"
)

// RemoteGTPUPeer flags per TS 29.244 Rel-15 §8.2.70 Figure 8.2.70-1
// (extracted from docs/specs/29244-fa0.docx paras 2659-2663):
//
//	"Bit 1 – V6: If this bit is set to '1', then the IPv6 address field shall be present"
//	"Bit 2 – V4: If this bit is set to '1', then the IPv4 address field shall be present"
//	"Bit 3 – DI: If this bit is set to '1', then the Length of Destination Interface field
//	 and the Destination Interface field shall be present"
//	"Bit 4 – NI: If this bit is set to '1', then the Length of Network Instance field and
//	 the Network Instance field shall be present"
//	"Bit 5 to 8 - Spare, for future use and set to '0'."
const (
	RemoteGTPUPeerFlagV6 uint8 = 0x01 // §8.2.70: "Bit 1 – V6"
	RemoteGTPUPeerFlagV4 uint8 = 0x02 // §8.2.70: "Bit 2 – V4"
	RemoteGTPUPeerFlagDI uint8 = 0x04 // §8.2.70: "Bit 3 – DI"
	RemoteGTPUPeerFlagNI uint8 = 0x08 // §8.2.70: "Bit 4 – NI"
)

// Cause values per TS 29.244 Rel-15 §8.2.1 Table 8.2.1-1
// (extracted from docs/specs/29244-fa0.docx).
//
//	"1  — Request accepted (success)"
//	"64 — Request rejected (reason not specified)"
//	"65 — Session context not found"
//	"72 — No established PFCP Association"
//	"73 — Rule creation/modification Failure"
const (
	CauseRequestAccepted          uint8 = 1  // Table 8.2.1-1: "Request accepted (success)"
	CauseRequestRejected          uint8 = 64 // Table 8.2.1-1: "Request rejected (reason not specified)"
	CauseSessionContextNotFound   uint8 = 65 // Table 8.2.1-1: "Session context not found"
	CauseNoEstablishedAssociation uint8 = 72 // Table 8.2.1-1: "No established PFCP Association"
	CauseRuleCreationFailure      uint8 = 73 // Table 8.2.1-1: "Rule creation/modification Failure"
)

// Node ID type byte values per TS 29.244 Rel-15 §8.2.38 Table 8.2.38-2.
// FIXED 2026-06-23: was cited §8.2.8, which is actually the "MBR" clause per
// Table 8.1.2-1. Values were already correct: "0|IPv4 address, 1|IPv6 address, 2|FQDN".
const (
	NodeIDTypeIPv4 uint8 = 0x00
	NodeIDTypeIPv6 uint8 = 0x01
	NodeIDTypeFQDN uint8 = 0x02
)

// Source Interface values per TS 29.244 Rel-15 §8.2.2 Table 8.2.2-1
// (extracted from docs/specs/29244-fa0.docx, Table 79).
const (
	SourceInterfaceAccess     uint8 = 0 // Table 8.2.2-1 row: "Access | 0"
	SourceInterfaceCore       uint8 = 1 // Table 8.2.2-1 row: "Core | 1"
	SourceInterfaceSGiLAN     uint8 = 2 // Table 8.2.2-1 row: "SGi-LAN/N6-LAN | 2"
	SourceInterfaceCPFunction uint8 = 3 // Table 8.2.2-1 row: "CP-Function | 3"
)

// Destination Interface values per TS 29.244 Rel-15 §8.2.24 Table 8.2.24-1
// (extracted from docs/specs/29244-fa0.docx, Table 105).
const (
	DestInterfaceAccess     uint8 = 0 // Table 8.2.24-1 row: "Access | 0"
	DestInterfaceCore       uint8 = 1 // Table 8.2.24-1 row: "Core | 1"
	DestInterfaceSGiLAN     uint8 = 2 // Table 8.2.24-1 row: "SGi-LAN/N6-LAN | 2"
	DestInterfaceCPFunction uint8 = 3 // Table 8.2.24-1 row: "CP-Function | 3"
)

// Apply Action bit flags per TS 29.244 Rel-15 §8.2.26 (extracted from docs/specs/29244-fa0.docx).
// Figure 8.2.26-1 octet 5:
//
//	"Bit 1 – DROP (Drop)"                → 0x01
//	"Bit 2 – FORW (Forward)"             → 0x02
//	"Bit 3 – BUFF (Buffer)"              → 0x04
//	"Bit 4 – NOCP (Notify the CP function)" → 0x08
const (
	ApplyActionDROP uint8 = 0x01 // §8.2.26: "Bit 1 – DROP (Drop)"
	ApplyActionFORW uint8 = 0x02 // §8.2.26: "Bit 2 – FORW (Forward)"
	ApplyActionBUFF uint8 = 0x04 // §8.2.26: "Bit 3 – BUFF (Buffer)"
	ApplyActionNOCP uint8 = 0x08 // §8.2.26: "Bit 4 – NOCP (Notify the CP function)"
)

// UP Function Features bit flags per TS 29.244 Rel-15 Table 8.2.25-1
// (extracted from docs/specs/29244-fa0.docx).
// Table 8.2.25-1 row: "5/5 | FTUP | Sxa, Sxb, N4 | F-TEID allocation / release in the UP
// function is supported by the UP function."
// Octet 5 / bit 5 → 2^(5-1) = 0x10.
const (
	UPFunctionFeaturesFTUP uint8 = 0x10 // Table 8.2.25-1: octet 5, bit 5 "FTUP"
)

// Outer Header Creation Description values per TS 29.244 Rel-15 §8.2.56.
// Encoded as a 2-byte big-endian field.
const (
	// OHCDescGTPUUDPIPv4 signals GTP-U/UDP/IPv4 outer header creation.
	// §8.2.56 Figure 8.2.56-1 Octet 5 Bit 8 (MSB of first octet of 2-octet field).
	// Confirmed by TS 29.244 V15.10.0 re-audit 2026-06-20 against local spec.
	OHCDescGTPUUDPIPv4 uint16 = 0x0100
)

// Outer Header Removal Description values per TS 29.244 Rel-15 §8.2.64.
const (
	OHRDescGTPUUDPIPv4 uint8 = 0
)

// PFCP F-TEID flag bits per TS 29.244 Rel-15 §8.2.3 (extracted from docs/specs/29244-fa0.docx).
// Octet 5 of F-TEID IE value, per Figure 8.2.3-1:
//
//	"Bit 1 – V4"              → 0x01
//	"Bit 2 – V6"              → 0x02
//	"Bit 3 – CH (CHOOSE)"     → 0x04
//	"Bit 4 – CHID (CHOOSE ID)"→ 0x08
//	Bits 5-8: Spare
//
// R15-001 FIX: prior code had CH=0x08, CHID=0x04 — reversed. Now corrected per spec.
const (
	FTEIDFlagV4   uint8 = 0x01 // §8.2.3 bit 1: "Bit 1 – V4"
	FTEIDFlagV6   uint8 = 0x02 // §8.2.3 bit 2: "Bit 2 – V6"
	FTEIDFlagCH   uint8 = 0x04 // §8.2.3 bit 3: "Bit 3 – CH (CHOOSE)"
	FTEIDFlagCHID uint8 = 0x08 // §8.2.3 bit 4: "Bit 4 – CHID (CHOOSE ID)"
)

// PFCP F-SEID flag bits per TS 29.244 Rel-15 §8.2.37 Figure 8.2.37-1
// (extracted from docs/specs/29244-fa0.docx para 2346-2347):
//
//	"Bit 1 – V6: If this bit is set to '1', then IPv6 address field shall be present"
//	"Bit 2 – V4: If this bit is set to '1', then IPv4 address field shall be present"
const (
	FSEIDFlagV6 uint8 = 0x01 // §8.2.37 Figure 8.2.37-1: "Bit 1 – V6"
	FSEIDFlagV4 uint8 = 0x02 // §8.2.37 Figure 8.2.37-1: "Bit 2 – V4"
)

// IE is a decoded PFCP Information Element.
type IE struct {
	Type  uint16
	Value []byte
}

// Marshal encodes the IE to wire format per TS 29.244 §8.1.
func (ie *IE) Marshal() []byte {
	buf := make([]byte, 4+len(ie.Value))
	binary.BigEndian.PutUint16(buf[0:2], ie.Type)
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(ie.Value)))
	copy(buf[4:], ie.Value)
	return buf
}

// ParseIEs decodes all IEs from b.
func ParseIEs(b []byte) ([]*IE, error) {
	var ies []*IE
	for len(b) >= 4 {
		t := binary.BigEndian.Uint16(b[0:2])
		l := int(binary.BigEndian.Uint16(b[2:4]))
		if 4+l > len(b) {
			return nil, fmt.Errorf("PFCP IE type %d: declared length %d exceeds remaining %d bytes", t, l, len(b)-4)
		}
		val := make([]byte, l)
		copy(val, b[4:4+l])
		ies = append(ies, &IE{Type: t, Value: val})
		b = b[4+l:]
	}
	if len(b) != 0 {
		return nil, fmt.Errorf("PFCP IE parse: %d trailing bytes", len(b))
	}
	return ies, nil
}

// Find returns the first IE with the given type, or nil.
func Find(ies []*IE, t uint16) *IE {
	for _, ie := range ies {
		if ie.Type == t {
			return ie
		}
	}
	return nil
}

// FindAll returns all IEs with the given type.
func FindAll(ies []*IE, t uint16) []*IE {
	var out []*IE
	for _, ie := range ies {
		if ie.Type == t {
			out = append(out, ie)
		}
	}
	return out
}

// Children parses the grouped IE value as child IEs per TS 29.244 §8.1.
// Grouped IEs (Create PDR, PDI, Create FAR, etc.) contain concatenated child IE bytes.
func (ie *IE) Children() ([]*IE, error) {
	return ParseIEs(ie.Value)
}

// ── Grouped IE constructor ───────────────────────────────────────────────────

// newGrouped builds a grouped IE with the given type and child IEs.
// Used by Create PDR, PDI, Create FAR, Forwarding Parameters, etc.
func newGrouped(t uint16, children ...*IE) *IE {
	var body []byte
	for _, child := range children {
		body = append(body, child.Marshal()...)
	}
	return &IE{Type: t, Value: body}
}

// ── Node-level IE constructors ───────────────────────────────────────────────

// NewCause builds a Cause IE per TS 29.244 Rel-15 §8.2.1.
// Type=19, 1-byte value.
func NewCause(cause uint8) *IE {
	return &IE{Type: TypeCause, Value: []byte{cause}}
}

// CauseValue extracts the cause byte from a Cause IE.
func (ie *IE) CauseValue() (uint8, error) {
	if ie.Type != TypeCause {
		return 0, fmt.Errorf("IE type %d is not Cause (%d)", ie.Type, TypeCause)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Cause IE too short")
	}
	return ie.Value[0], nil
}

// NewNodeIDIPv4 builds a Node ID IE with IPv4 type per TS 29.244 Rel-15 §8.2.8.
// Type=60; value = NodeIDType byte (0x00) followed by 4-byte IPv4 address.
func NewNodeIDIPv4(ip net.IP) *IE {
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IPv4zero.To4()
	}
	val := make([]byte, 5)
	val[0] = NodeIDTypeIPv4
	copy(val[1:5], v4)
	return &IE{Type: TypeNodeID, Value: val}
}

// NodeIDIPv4 extracts the IPv4 address from a Node ID IE.
// Returns nil if the IE is not an IPv4 Node ID.
func (ie *IE) NodeIDIPv4() net.IP {
	if ie.Type != TypeNodeID || len(ie.Value) < 5 || ie.Value[0] != NodeIDTypeIPv4 {
		return nil
	}
	ip := make(net.IP, 4)
	copy(ip, ie.Value[1:5])
	return ip
}

// NewRecoveryTimeStamp builds a Recovery Time Stamp IE per TS 29.244 Rel-15 §8.2.11.
// Type=96; value = 4-byte NTP timestamp (seconds since 1900-01-01 00:00:00 UTC,
// big-endian). Callers must compute: ntpSec = unixSec + 2208988800.
func NewRecoveryTimeStamp(ntpSec uint32) *IE {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, ntpSec)
	return &IE{Type: TypeRecoveryTimeStamp, Value: val}
}

// RecoveryTimeStampValue extracts the NTP timestamp from a Recovery Time Stamp IE.
func (ie *IE) RecoveryTimeStampValue() (uint32, error) {
	if ie.Type != TypeRecoveryTimeStamp {
		return 0, fmt.Errorf("IE type %d is not Recovery Time Stamp (%d)", ie.Type, TypeRecoveryTimeStamp)
	}
	if len(ie.Value) < 4 {
		return 0, fmt.Errorf("Recovery Time Stamp IE too short: %d bytes", len(ie.Value))
	}
	return binary.BigEndian.Uint32(ie.Value[0:4]), nil
}

// ── Session-level IE constructors ────────────────────────────────────────────

// FSEID holds a decoded PFCP F-SEID per TS 29.244 Rel-15 §8.2.37.
type FSEID struct {
	SEID uint64
	IPv4 netip.Addr
}

// NewFSEID builds an F-SEID IE per TS 29.244 Rel-15 §8.2.37 Figure 8.2.37-1.
// Wire format: flags(1) | SEID(8) | IPv4(4 if V4=1).
// FSEIDFlagV4=0x02 (Bit 2), FSEIDFlagV6=0x01 (Bit 1) per §8.2.37 Figure 8.2.37-1.
func NewFSEID(seid uint64, v4 netip.Addr) *IE {
	flags := FSEIDFlagV4 // IPv4-only for v0
	val := make([]byte, 9)
	val[0] = flags
	binary.BigEndian.PutUint64(val[1:9], seid)
	if v4.IsValid() {
		ip4 := v4.As4()
		val = append(val, ip4[:]...)
	}
	return &IE{Type: TypeFSEID, Value: val}
}

// FSEIDValue decodes an F-SEID IE per TS 29.244 Rel-15 §8.2.37.
func (ie *IE) FSEIDValue() (FSEID, error) {
	if ie.Type != TypeFSEID {
		return FSEID{}, fmt.Errorf("IE type %d is not F-SEID (%d)", ie.Type, TypeFSEID)
	}
	if len(ie.Value) < 9 {
		return FSEID{}, fmt.Errorf("F-SEID IE too short: %d bytes", len(ie.Value))
	}
	flags := ie.Value[0]
	f := FSEID{
		SEID: binary.BigEndian.Uint64(ie.Value[1:9]),
	}
	if flags&FSEIDFlagV4 != 0 {
		if len(ie.Value) < 13 {
			return FSEID{}, fmt.Errorf("F-SEID IE with V4=1 too short: %d bytes (need 13)", len(ie.Value))
		}
		f.IPv4 = netip.AddrFrom4([4]byte(ie.Value[9:13]))
	}
	return f, nil
}

// FTEIDPFCP holds a decoded PFCP F-TEID per TS 29.244 Rel-15 §8.2.3.
type FTEIDPFCP struct {
	TEID uint32
	IPv4 netip.Addr
}

// NewFTEIDChoose builds a PFCP F-TEID IE with CH=1, V4=1 per TS 29.244 Rel-15 §8.2.3.
// §8.2.3: "At least one of the V4 and V6 flags shall be set to '1'... when the
// UP function is requested to allocate the F-TEID, i.e. when CHOOSE bit is set to '1'."
// Wire: flags=CH|V4=0x04|0x01=0x05. No TEID/IP fields (CH=1 means UP allocates them).
// Golden vector (from §8.2.3 Figure 8.2.3-1):
//
//	Type=21 (0x0015), Length=1 (0x0001), Value=[0x05]
func NewFTEIDChoose() *IE {
	return &IE{Type: TypeFTEID, Value: []byte{FTEIDFlagCH | FTEIDFlagV4}}
}

// NewFTEIDv4 builds a PFCP F-TEID IE with a static IPv4 TEID per TS 29.244 Rel-15 §8.2.3.
// Wire format when CH=0, V4=1: flags(1) | TEID(4) | IPv4(4).
// §8.2.3: "Octet 6 to 9 (TEID) shall be present and shall contain a GTP-U TEID,
// if the CH bit in octet 5 is not set."
func NewFTEIDv4(teid uint32, v4 netip.Addr) *IE {
	val := make([]byte, 9)
	val[0] = FTEIDFlagV4
	binary.BigEndian.PutUint32(val[1:5], teid)
	if v4.IsValid() {
		ip4 := v4.As4()
		copy(val[5:9], ip4[:])
	}
	return &IE{Type: TypeFTEID, Value: val}
}

// FTEIDPFCPValue decodes a PFCP F-TEID IE per TS 29.244 Rel-15 §8.2.3.
// Returns (value, isCHOOSE, error). When isCHOOSE=true, value is zero.
func (ie *IE) FTEIDPFCPValue() (FTEIDPFCP, bool, error) {
	if ie.Type != TypeFTEID {
		return FTEIDPFCP{}, false, fmt.Errorf("IE type %d is not PFCP F-TEID (%d)", ie.Type, TypeFTEID)
	}
	if len(ie.Value) < 1 {
		return FTEIDPFCP{}, false, fmt.Errorf("PFCP F-TEID IE too short")
	}
	flags := ie.Value[0]
	if flags&FTEIDFlagCH != 0 {
		// Per §8.2.3: "At least one of the V4 and V6 flags shall be set to '1'...
		// when the UP function is requested to allocate the F-TEID (i.e. CHOOSE bit is set)."
		if flags&(FTEIDFlagV4|FTEIDFlagV6) == 0 {
			return FTEIDPFCP{}, false, fmt.Errorf("PFCP F-TEID CH=1 but neither V4 nor V6 set (§8.2.3)")
		}
		return FTEIDPFCP{}, true, nil
	}
	if len(ie.Value) < 5 {
		return FTEIDPFCP{}, false, fmt.Errorf("PFCP F-TEID IE too short for static TEID: %d bytes", len(ie.Value))
	}
	f := FTEIDPFCP{
		TEID: binary.BigEndian.Uint32(ie.Value[1:5]),
	}
	if flags&FTEIDFlagV4 != 0 {
		if len(ie.Value) < 9 {
			return FTEIDPFCP{}, false, fmt.Errorf("PFCP F-TEID IE with V4=1 too short: %d bytes (need 9)", len(ie.Value))
		}
		f.IPv4 = netip.AddrFrom4([4]byte(ie.Value[5:9]))
	}
	return f, false, nil
}

// NewPDRID builds a PDR ID IE per TS 29.244 Rel-15 §8.2.36, type=56 (Table 8.1.2-1), 2-byte unsigned.
func NewPDRID(id uint16) *IE {
	val := make([]byte, 2)
	binary.BigEndian.PutUint16(val, id)
	return &IE{Type: TypePDRID, Value: val}
}

// PDRIDValue decodes a PDR ID IE.
func (ie *IE) PDRIDValue() (uint16, error) {
	if ie.Type != TypePDRID {
		return 0, fmt.Errorf("IE type %d is not PDR ID (%d)", ie.Type, TypePDRID)
	}
	if len(ie.Value) < 2 {
		return 0, fmt.Errorf("PDR ID IE too short")
	}
	return binary.BigEndian.Uint16(ie.Value[0:2]), nil
}

// NewFARID builds a FAR ID IE per TS 29.244 Rel-15 §8.2.74, type=108 (Table 8.1.2-1), 4-byte unsigned.
func NewFARID(id uint32) *IE {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, id)
	return &IE{Type: TypeFARID, Value: val}
}

// FARIDValue decodes a FAR ID IE.
func (ie *IE) FARIDValue() (uint32, error) {
	if ie.Type != TypeFARID {
		return 0, fmt.Errorf("IE type %d is not FAR ID (%d)", ie.Type, TypeFARID)
	}
	if len(ie.Value) < 4 {
		return 0, fmt.Errorf("FAR ID IE too short")
	}
	return binary.BigEndian.Uint32(ie.Value[0:4]), nil
}

// NewQERID builds a QER ID IE per TS 29.244 Rel-15 §8.2.75, type=109 (Table 8.1.2-1), 4-byte unsigned.
func NewQERID(id uint32) *IE {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, id)
	return &IE{Type: TypeQERID, Value: val}
}

// QERIDValue decodes a QER ID IE.
func (ie *IE) QERIDValue() (uint32, error) {
	if ie.Type != TypeQERID {
		return 0, fmt.Errorf("IE type %d is not QER ID (%d)", ie.Type, TypeQERID)
	}
	if len(ie.Value) < 4 {
		return 0, fmt.Errorf("QER ID IE too short")
	}
	return binary.BigEndian.Uint32(ie.Value[0:4]), nil
}

// NewVectorCoreQoSMarking carries VectorCore-private PDR QoS metadata.
// Value format: version(1), flags(1), EBI(1), QCI(1). flags bit 0 = valid.
func NewVectorCoreQoSMarking(ebi, qci uint8, valid bool) *IE {
	flags := uint8(0)
	if valid {
		flags = 0x01
	}
	return &IE{Type: TypeVectorCoreQoSMarking, Value: []byte{1, flags, ebi, qci}}
}

func (ie *IE) VectorCoreQoSMarkingValue() (ebi, qci uint8, valid bool, err error) {
	if ie.Type != TypeVectorCoreQoSMarking {
		return 0, 0, false, fmt.Errorf("IE type %d is not VectorCore QoS Marking (%d)", ie.Type, TypeVectorCoreQoSMarking)
	}
	if len(ie.Value) < 4 {
		return 0, 0, false, fmt.Errorf("VectorCore QoS Marking IE too short")
	}
	if ie.Value[0] != 1 {
		return 0, 0, false, fmt.Errorf("unsupported VectorCore QoS Marking version %d", ie.Value[0])
	}
	return ie.Value[2], ie.Value[3], ie.Value[1]&0x01 != 0, nil
}

// NewPrecedence builds a Precedence IE per TS 29.244 Rel-15 §8.2.11, type=29 (Table 8.1.2-1), 4-byte unsigned.
// Lower value = higher priority.
func NewPrecedence(p uint32) *IE {
	val := make([]byte, 4)
	binary.BigEndian.PutUint32(val, p)
	return &IE{Type: TypePrecedence, Value: val}
}

// NewSourceInterface builds a Source Interface IE per TS 29.244 Rel-15 §8.2.2, type=20 (Table 8.1.2-1).
// value: 4-bit interface type in bits 1-4 (lower nibble); use SourceInterface* constants.
func NewSourceInterface(iface uint8) *IE {
	return &IE{Type: TypeSourceInterface, Value: []byte{iface & 0x0F}}
}

// SourceInterfaceValue decodes a Source Interface IE.
func (ie *IE) SourceInterfaceValue() (uint8, error) {
	if ie.Type != TypeSourceInterface {
		return 0, fmt.Errorf("IE type %d is not Source Interface (%d)", ie.Type, TypeSourceInterface)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Source Interface IE too short")
	}
	return ie.Value[0] & 0x0F, nil
}

// NewDestinationInterface builds a Destination Interface IE per TS 29.244 Rel-15 §8.2.24, type=42 (Table 8.1.2-1).
// value: 4-bit interface type in bits 1-4 (lower nibble); use DestInterface* constants.
func NewDestinationInterface(iface uint8) *IE {
	return &IE{Type: TypeDestinationInterface, Value: []byte{iface & 0x0F}}
}

// DestinationInterfaceValue decodes a Destination Interface IE.
func (ie *IE) DestinationInterfaceValue() (uint8, error) {
	if ie.Type != TypeDestinationInterface {
		return 0, fmt.Errorf("IE type %d is not Destination Interface (%d)", ie.Type, TypeDestinationInterface)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Destination Interface IE too short")
	}
	return ie.Value[0] & 0x0F, nil
}

// NewApplyAction builds an Apply Action IE per TS 29.244 Rel-15 §8.2.26, type=44 (Table 8.1.2-1).
// flags: OR of ApplyActionDROP, ApplyActionFORW, ApplyActionBUFF, etc.
func NewApplyAction(flags uint8) *IE {
	return &IE{Type: TypeApplyAction, Value: []byte{flags}}
}

// ApplyActionValue decodes an Apply Action IE.
func (ie *IE) ApplyActionValue() (uint8, error) {
	if ie.Type != TypeApplyAction {
		return 0, fmt.Errorf("IE type %d is not Apply Action (%d)", ie.Type, TypeApplyAction)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Apply Action IE too short")
	}
	return ie.Value[0], nil
}

// NewUPFunctionFeatures builds a UP Function Features IE per TS 29.244 Rel-15 §8.2.25.
// Type=43 (Table 8.1.2-1). Wire: 1-byte bitmask; bits defined in Table 8.2.25-1.
// Pass UPFunctionFeaturesFTUP to advertise F-TEID allocation support.
func NewUPFunctionFeatures(flags uint8) *IE {
	return &IE{Type: TypeUPFunctionFeatures, Value: []byte{flags}}
}

// UPFunctionFeaturesValue decodes a UP Function Features IE.
func (ie *IE) UPFunctionFeaturesValue() (uint8, error) {
	if ie.Type != TypeUPFunctionFeatures {
		return 0, fmt.Errorf("IE type %d is not UP Function Features (%d)", ie.Type, TypeUPFunctionFeatures)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("UP Function Features IE too short")
	}
	return ie.Value[0], nil
}

// OuterHeaderCreation holds a decoded Outer Header Creation IE.
type OuterHeaderCreation struct {
	Description uint16 // e.g. OHCDescGTPUUDPIPv4
	TEID        uint32
	IPv4        netip.Addr
}

// NewOuterHeaderCreation builds an Outer Header Creation IE per TS 29.244 Rel-15 §8.2.56, type=84 (Table 8.1.2-1).
// For GTP-U/UDP/IPv4: description=OHCDescGTPUUDPIPv4, TEID and IPv4 required.
// Wire format: Description(2) | TEID(4) | IPv4(4) for GTP-U/UDP/IPv4.
func NewOuterHeaderCreation(desc uint16, teid uint32, v4 netip.Addr) *IE {
	val := make([]byte, 6)
	binary.BigEndian.PutUint16(val[0:2], desc)
	binary.BigEndian.PutUint32(val[2:6], teid)
	if v4.IsValid() {
		ip4 := v4.As4()
		val = append(val, ip4[:]...)
	}
	return &IE{Type: TypeOuterHeaderCreation, Value: val}
}

// OuterHeaderCreationValue decodes an Outer Header Creation IE.
func (ie *IE) OuterHeaderCreationValue() (OuterHeaderCreation, error) {
	if ie.Type != TypeOuterHeaderCreation {
		return OuterHeaderCreation{}, fmt.Errorf("IE type %d is not Outer Header Creation (%d)", ie.Type, TypeOuterHeaderCreation)
	}
	if len(ie.Value) < 6 {
		return OuterHeaderCreation{}, fmt.Errorf("Outer Header Creation IE too short: %d bytes", len(ie.Value))
	}
	ohc := OuterHeaderCreation{
		Description: binary.BigEndian.Uint16(ie.Value[0:2]),
		TEID:        binary.BigEndian.Uint32(ie.Value[2:6]),
	}
	if ohc.Description == OHCDescGTPUUDPIPv4 {
		if len(ie.Value) < 10 {
			return OuterHeaderCreation{}, fmt.Errorf("Outer Header Creation GTP-U/UDP/IPv4 too short: %d bytes (need 10)", len(ie.Value))
		}
		ohc.IPv4 = netip.AddrFrom4([4]byte(ie.Value[6:10]))
	}
	return ohc, nil
}

// NewOuterHeaderRemoval builds an Outer Header Removal IE per TS 29.244 Rel-15 §8.2.64.
func NewOuterHeaderRemoval(desc uint8) *IE {
	return &IE{Type: TypeOuterHeaderRemoval, Value: []byte{desc}}
}

// ── Grouped IE constructors ──────────────────────────────────────────────────

// NewPDI builds a PDI grouped IE per TS 29.244 Rel-15 Table 7.5.2.2-2, type=2 (Table 8.1.2-1).
// Children include Source Interface (M) and optional F-TEID, Network Instance, UE IP Address.
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewPDI(children ...*IE) *IE {
	return newGrouped(TypePDI, children...)
}

// NewForwardingParameters builds a Forwarding Parameters grouped IE per TS 29.244 Rel-15 Table 7.5.2.3-2, type=4 (Table 8.1.2-1).
// Children include Destination Interface (M) and optional Outer Header Creation, Network Instance.
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewForwardingParameters(children ...*IE) *IE {
	return newGrouped(TypeForwardingParameters, children...)
}

// NewUpdateForwardingParameters builds an Update Forwarding Parameters grouped IE per TS 29.244 Rel-15 Table 7.5.4.3-2, type=11 (Table 8.1.2-1).
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewUpdateForwardingParameters(children ...*IE) *IE {
	return newGrouped(TypeUpdateForwardingParameters, children...)
}

// NewCreatePDR builds a Create PDR grouped IE per TS 29.244 Rel-15 Table 7.5.2.2-1, type=1 (Table 8.1.2-1).
// M-IEs: PDR ID, Precedence, PDI. FAR ID is C per Table 7.5.2.2-1: "present if the PDR is not linked to a predefined rule".
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewCreatePDR(children ...*IE) *IE {
	return newGrouped(TypeCreatePDR, children...)
}

// NewCreateFAR builds a Create FAR grouped IE per TS 29.244 Rel-15 Table 7.5.2.3-1, type=3 (Table 8.1.2-1).
// M-IEs: FAR ID, Apply Action. Forwarding Parameters is C per Table 7.5.2.3-1: "present if the Action is 'Forward'".
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewCreateFAR(children ...*IE) *IE {
	return newGrouped(TypeCreateFAR, children...)
}

// NewCreateQER builds a Create QER grouped IE per TS 29.244 Rel-15 Table 7.5.2.5-1, type=7 (Table 8.1.2-1).
// M-IEs include QER ID and Gate Status. MBR and GBR are conditional.
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewCreateQER(children ...*IE) *IE {
	return newGrouped(TypeCreateQER, children...)
}

// NewCreatedPDR builds a Created PDR grouped IE per TS 29.244 Rel-15 Table 7.5.3.2-1, type=8 (Table 8.1.2-1).
// M: PDR ID. C: F-TEID (present when CHOOSE was set in Create PDR F-TEID).
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewCreatedPDR(children ...*IE) *IE {
	return newGrouped(TypeCreatedPDR, children...)
}

// NewUpdateFAR builds an Update FAR grouped IE per TS 29.244 Rel-15 Table 7.5.4.3-1, type=10 (Table 8.1.2-1).
// M: FAR ID. C: Apply Action, Update Forwarding Parameters.
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewUpdateFAR(children ...*IE) *IE {
	return newGrouped(TypeUpdateFAR, children...)
}

// NewUpdatePDR builds an Update PDR grouped IE per TS 29.244 Rel-15 Table 7.5.4.2-1, type=9.
func NewUpdatePDR(children ...*IE) *IE {
	return newGrouped(TypeUpdatePDR, children...)
}

// NewRemovePDR builds a Remove PDR grouped IE per TS 29.244 Rel-15 Table 7.5.4.6-1, type=15 (Table 8.1.2-1).
// M: PDR ID. Instructs the UP function to remove a PDR from the session.
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewRemovePDR(children ...*IE) *IE {
	return newGrouped(TypeRemovePDR, children...)
}

// NewRemoveFAR builds a Remove FAR grouped IE per TS 29.244 Rel-15 Table 7.5.4.7-1, type=16 (Table 8.1.2-1).
// M: FAR ID. Instructs the UP function to remove a FAR from the session.
// PFCP has no child IE instance numbers; children are encoded as Type|Length|Value only.
func NewRemoveFAR(children ...*IE) *IE {
	return newGrouped(TypeRemoveFAR, children...)
}

// ── Phase 11: Node Report and Association Release IE constructors ─────────────

// NewNodeReportType builds a Node Report Type IE per TS 29.244 Rel-15 §8.2.69.
// Type=101. Octet 5 encodes flags: Bit 1 = UPFR.
// §8.2.69 Figure 8.2.69-1: "Octet 5 shall be encoded as follows:
// Bit 1 – UPFR (User Plane Path Failure Report): when set to '1', this indicates a
// User Plane Path Failure Report."
func NewNodeReportType(flags uint8) *IE {
	return &IE{Type: TypeNodeReportType, Value: []byte{flags}}
}

// NodeReportTypeFlags extracts the flags byte from a Node Report Type IE.
func (ie *IE) NodeReportTypeFlags() (uint8, error) {
	if ie.Type != TypeNodeReportType {
		return 0, fmt.Errorf("IE type %d is not Node Report Type (%d)", ie.Type, TypeNodeReportType)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Node Report Type IE too short")
	}
	return ie.Value[0], nil
}

// NewRemoteGTPUPeerIPv4 builds a Remote GTP-U Peer IE with IPv4 address per TS 29.244 Rel-15 §8.2.70.
// Type=103. Wire format: flags(1) | IPv4(4).
// §8.2.70 Figure 8.2.70-1: "Bit 2 – V4: If this bit is set to '1', then the IPv4 address
// field shall be present, otherwise the IPv4 address field shall not be present."
// Value bytes: [RemoteGTPUPeerFlagV4=0x02] | IPv4(4).
func NewRemoteGTPUPeerIPv4(ip net.IP) *IE {
	v4 := ip.To4()
	if v4 == nil {
		v4 = net.IPv4zero.To4()
	}
	val := make([]byte, 5)
	val[0] = RemoteGTPUPeerFlagV4
	copy(val[1:5], v4)
	return &IE{Type: TypeRemoteGTPUPeer, Value: val}
}

// RemoteGTPUPeerIPv4 extracts the IPv4 address from a Remote GTP-U Peer IE.
// Returns nil if the IE does not carry an IPv4 address (V4 flag not set).
func (ie *IE) RemoteGTPUPeerIPv4() net.IP {
	if ie.Type != TypeRemoteGTPUPeer || len(ie.Value) < 1 {
		return nil
	}
	if ie.Value[0]&RemoteGTPUPeerFlagV4 == 0 {
		return nil
	}
	if len(ie.Value) < 5 {
		return nil
	}
	ip := make(net.IP, 4)
	copy(ip, ie.Value[1:5])
	return ip
}

// NewUserPlanPathFailureReport builds a User Plane Path Failure Report grouped IE
// per TS 29.244 Rel-15 §7.4.5.1.2 Table 7.4.5.1.2-1. Type=102.
// M child IE: Remote GTP-U Peer (one per failing peer).
// Table 7.4.5.1.2-1: "User Plane Path Failure Report IE Type = 102 (decimal)"
func NewUserPlanPathFailureReport(children ...*IE) *IE {
	return newGrouped(TypeUserPlanPathFailureReport, children...)
}

// NewPFCPAssocReleaseRequest builds a PFCP Association Release Request IE
// per TS 29.244 Rel-15 §8.2.77. Type=111.
// flags: Bit 1 = SARR. §8.2.77: "Bit 1 – SARR (PFCP Association Release Request):
// If this bit is set to '1', then the UP function requests the release of the PFCP association."
func NewPFCPAssocReleaseRequest(flags uint8) *IE {
	return &IE{Type: TypePFCPAssocReleaseRequest, Value: []byte{flags}}
}

// PFCPAssocReleaseRequestFlags extracts the flags byte from a PFCP Association Release Request IE.
func (ie *IE) PFCPAssocReleaseRequestFlags() (uint8, error) {
	if ie.Type != TypePFCPAssocReleaseRequest {
		return 0, fmt.Errorf("IE type %d is not PFCP Association Release Request (%d)", ie.Type, TypePFCPAssocReleaseRequest)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("PFCP Association Release Request IE too short")
	}
	return ie.Value[0], nil
}
