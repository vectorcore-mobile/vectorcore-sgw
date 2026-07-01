// Package ie implements GTPv2-C Information Element encoding and decoding
// per 3GPP TS 29.274 Section 8.
package ie

import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// IE type values per TS 29.274 Table 8.1-1.
const (
	TypeIMSI           = 1
	TypeCause          = 2
	TypeRecovery       = 3
	TypeAPN            = 71
	TypeAMBR           = 72
	TypeEBI            = 73
	TypeIPAddress      = 74
	TypeMEI            = 75
	TypeMSISDN         = 76
	TypeIndication     = 77
	TypePCO            = 78
	TypePAA            = 79
	TypeBearerQoS      = 80
	TypeFlowQoS        = 81
	TypeRATType        = 82
	TypeServingNetwork = 83
	TypeBearerTFT      = 84 // TS 29.274 Table 8.1-1: "84 | EPS Bearer Level Traffic Flow Template (Bearer TFT) | Variable Length / 8.19"
	TypeULI            = 86
	TypeFTEID          = 87
	TypeBearerContext  = 93
	TypeChargingID     = 94
	TypeChargingChars  = 95
	TypePDNType        = 99
	TypePTI            = 100
	TypeAPNRestriction = 127 // FIXED 2026-06-23: was 167 ("Change to Report Flags" / §8.98).
	// Real value per Table 8.1-1: "127 | APN Restriction | Extendable / 8.57 | 1". Unused
	// elsewhere in this codebase, so this was a latent wire-format bug, not yet triggered.
	TypeUETimeZone    = 114
	TypeNodeType      = 135
	TypeSelectionMode = 128 // §8.58
)

// Cause values per TS 29.274 Rel-15 Table 8.4-1.
const (
	CauseRequestAccepted          uint8 = 16
	CauseRequestAcceptedPartially uint8 = 17
	CauseContextNotFound          uint8 = 64
	CauseInvalidMessageFormat     uint8 = 65
	CauseVersionNotSupported      uint8 = 66
	CauseInvalidLength            uint8 = 67
	CauseMandatoryIEIncorrect     uint8 = 69
	CauseMandatoryIEMissing       uint8 = 70
	CauseSystemFailure            uint8 = 72
	CauseNoResourcesAvailable     uint8 = 73 // "No resources available"
	CauseMissingOrUnknownAPN      uint8 = 78 // FIXED 2026-06-23: was 79, which Table 8.4-1 marks
	// "Shall not be used" (reserved). Real value: "78 | Missing or unknown APN". Unused
	// elsewhere in this codebase, so this was a latent wire-format bug, not yet triggered.
	CausePreferredPDNTypeNotSupported uint8 = 83
	CauseAllDynamicAddressesOccupied  uint8 = 84
	CauseRequestRejected              uint8 = 94 // "Request rejected (reason not specified)"
	CauseConditionalIEMissing         uint8 = 103
)

// RAT Type values per TS 29.274 Rel-15 Table 8.17-1.
const (
	RATTypeUTRAN   = 1
	RATTypeGERAN   = 2
	RATTypeWLAN    = 3
	RATTypeGAN     = 4
	RATTypeHSPA    = 5
	RATTypeEUTRAN  = 6
	RATTypeVirtual = 7
	RATTypeNBIoT   = 8 // EUTRAN-NB-IoT
	// FIXED 2026-06-23: was named RATTypeHSPAEvolution. Table 8.17-1 lists value 5 as
	// "HSPA Evolution" (already RATTypeHSPA above) and value 9 as "LTE-M" — this constant's
	// previous name conflated the two. Unused elsewhere in this codebase, so this was a
	// latent naming/citation error (the value 9 itself was not wrong), not yet triggered.
	RATTypeLTEM = 9
)

// PDN Type values per TS 29.274 Section 8.34.
const (
	PDNTypeIPv4   = 1
	PDNTypeIPv6   = 2
	PDNTypeIPv4v6 = 3
)

// Interface Type values for F-TEID per TS 29.274 Table 8.22-1.
const (
	IFTypeS1UENB   = 0
	IFTypeS1USGW   = 1
	IFTypeS5S8USGW = 4
	IFTypeS5S8UPGW = 5
	IFTypeS11MMEC  = 10
	IFTypeS11S4SGW = 11
	IFTypeS5S8CSGW = 6
	IFTypeS5S8CPGW = 7
)

// IE is a GTPv2-C Information Element per TS 29.274 Section 8.1.
//
// Wire format:
//
//	Octet 1:   Type
//	Octet 2-3: Length (value length, not including Type, Length, Spare+Instance)
//	Octet 4:   Spare(4) | Instance(4)
//	Octet 5+:  Value (Length octets)
type IE struct {
	Type     uint8
	Instance uint8
	Value    []byte
}

// Marshal encodes the IE to wire format.
func (ie *IE) Marshal() []byte {
	buf := make([]byte, 4+len(ie.Value))
	buf[0] = ie.Type
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(ie.Value)))
	buf[3] = ie.Instance & 0x0F
	copy(buf[4:], ie.Value)
	return buf
}

// ParseIEs decodes a slice of IEs from a byte slice.
func ParseIEs(b []byte) ([]*IE, error) {
	var ies []*IE
	for len(b) > 0 {
		if len(b) < 4 {
			return nil, fmt.Errorf("IE header truncated: %d bytes remain", len(b))
		}
		typ := b[0]
		length := binary.BigEndian.Uint16(b[1:3])
		instance := b[3] & 0x0F
		b = b[4:]
		if int(length) > len(b) {
			return nil, fmt.Errorf("IE type %d value truncated: need %d, have %d", typ, length, len(b))
		}
		val := make([]byte, length)
		copy(val, b[:length])
		ies = append(ies, &IE{Type: typ, Instance: instance, Value: val})
		b = b[length:]
	}
	return ies, nil
}

// FindFirst returns the first IE with the given type and instance 0, or nil.
func FindFirst(ies []*IE, typ uint8) *IE {
	return FindInstance(ies, typ, 0)
}

// FindInstance returns the first IE with the given type and instance, or nil.
func FindInstance(ies []*IE, typ, instance uint8) *IE {
	for _, ie := range ies {
		if ie.Type == typ && ie.Instance == instance {
			return ie
		}
	}
	return nil
}

// FindAll returns all IEs with the given type.
func FindAll(ies []*IE, typ uint8) []*IE {
	var out []*IE
	for _, ie := range ies {
		if ie.Type == typ {
			out = append(out, ie)
		}
	}
	return out
}

// ── Constructors ────────────────────────────────────────────────────────────

func NewIMSI(imsi string) *IE {
	return &IE{Type: TypeIMSI, Value: encodeTBCD(imsi)}
}

func NewMSISDN(msisdn string) *IE {
	return &IE{Type: TypeMSISDN, Value: encodeE164(msisdn)}
}

func NewMEI(mei string) *IE {
	return &IE{Type: TypeMEI, Value: encodeTBCD(mei)}
}

func NewCause(cause, pce, bce, cs uint8, offendingIE *IE) *IE {
	// Per TS 29.274 Rel-15 §8.4: bit 0 (LSB) = CS, bit 1 = BCE, bit 2 = PCE.
	flags := (cs & 1) | ((bce & 1) << 1) | ((pce & 1) << 2)
	v := []byte{cause, flags}
	if offendingIE != nil {
		v = append(v, offendingIE.Type, 0, 0, offendingIE.Instance&0x0F)
	}
	return &IE{Type: TypeCause, Value: v}
}

func NewRecovery(restartCounter uint8) *IE {
	return &IE{Type: TypeRecovery, Value: []byte{restartCounter}}
}

func NewRATType(ratType uint8) *IE {
	return &IE{Type: TypeRATType, Value: []byte{ratType}}
}

// NewSelectionMode creates a Selection Mode IE per TS 29.274 Rel-15 §8.58.
// mode bits 1-0: 0=subscribed+verified, 1=MS provided+not verified,
// 2=network provided+not verified, 3=reserved.
func NewSelectionMode(mode uint8) *IE {
	return &IE{Type: TypeSelectionMode, Value: []byte{mode & 0x03}}
}

func NewAPN(apn string) *IE {
	return &IE{Type: TypeAPN, Value: encodeAPN(apn)}
}

func NewPDNType(pdnType uint8) *IE {
	return &IE{Type: TypePDNType, Value: []byte{pdnType & 0x07}}
}

func NewServingNetwork(mcc, mnc string) *IE {
	return &IE{Type: TypeServingNetwork, Value: encodePLMN(mcc, mnc)}
}

func NewEBI(ebi uint8) *IE {
	return &IE{Type: TypeEBI, Value: []byte{ebi & 0x0F}}
}

// NewEBIInstance creates an EBI IE with a specific instance number.
// Per TS 29.274 Table 7.2.9.2-1: EBI inst=0 is LBI (default bearer);
// EBI inst=1 is EPS Bearer ID for dedicated bearer deletion.
func NewEBIInstance(instance uint8, ebi uint8) *IE {
	return &IE{Type: TypeEBI, Instance: instance, Value: []byte{ebi & 0x0F}}
}

// NewFTEID creates an F-TEID IE per TS 29.274 Rel-15 Section 8.22.
//
// Wire layout (Figure 8.22-1):
//
//	Value[0]:   V4(bit7=0x80) | V6(bit6=0x40) | Interface Type(bits5-0)
//	Value[1-4]: TEID (big-endian)
//	Value[5-8]: IPv4 address (present only when V4=1)
func NewFTEID(instance, ifType uint8, teid uint32, v4 netip.Addr) *IE {
	flags := ifType & 0x3F
	if v4.IsValid() {
		flags |= 0x80 // V4 bit = bit 7
	}
	v := make([]byte, 5)
	v[0] = flags
	binary.BigEndian.PutUint32(v[1:5], teid)
	if v4.IsValid() {
		ip4 := v4.As4()
		v = append(v, ip4[:]...)
	}
	return &IE{Type: TypeFTEID, Instance: instance, Value: v}
}

// NewPAA creates a PAA IE for IPv4 per TS 29.274 Section 8.14.
func NewPAA(pdnType uint8, v4 netip.Addr) *IE {
	v := []byte{pdnType & 0x07}
	if pdnType == PDNTypeIPv4 && v4.IsValid() {
		ip4 := v4.As4()
		v = append(v, ip4[:]...)
	}
	return &IE{Type: TypePAA, Value: v}
}

// NewAMBR creates an AMBR IE per TS 29.274 Section 8.7.
func NewAMBR(uplinkKbps, downlinkKbps uint32) *IE {
	v := make([]byte, 8)
	binary.BigEndian.PutUint32(v[0:4], uplinkKbps)
	binary.BigEndian.PutUint32(v[4:8], downlinkKbps)
	return &IE{Type: TypeAMBR, Value: v}
}

// NewBearerQoS creates a Bearer QoS IE per TS 29.274 Section 8.15.
func NewBearerQoS(pci, pl, pvi, qci uint8, mbrUL, mbrDL, gbrUL, gbrDL uint64) *IE {
	v := make([]byte, 22)
	v[0] = ((pci & 1) << 6) | ((pl & 0x0F) << 2) | (pvi & 1)
	v[1] = qci
	putUint40(v[2:7], mbrUL)
	putUint40(v[7:12], mbrDL)
	putUint40(v[12:17], gbrUL)
	putUint40(v[17:22], gbrDL)
	return &IE{Type: TypeBearerQoS, Value: v}
}

// NewBearerTFT creates an EPS Bearer Level TFT IE per TS 29.274 §8.19.
// Type=84 per Table 8.1-1. The raw bytes are the TFT value from TS 24.008 §10.5.6.12,
// forwarded verbatim between PGW and MME. Figure 8.19-1: octet 1 = Type=84, octets 5+(n+4) = TFT.
func NewBearerTFT(raw []byte) *IE {
	v := make([]byte, len(raw))
	copy(v, raw)
	return &IE{Type: TypeBearerTFT, Value: v}
}

// NewBearerContext creates a grouped Bearer Context IE per TS 29.274 Section 8.28.
func NewBearerContext(instance uint8, children ...*IE) *IE {
	var body []byte
	for _, child := range children {
		body = append(body, child.Marshal()...)
	}
	return &IE{Type: TypeBearerContext, Instance: instance, Value: body}
}

// NewIndication creates an Indication IE per TS 29.274 Section 8.12.
// flags is a variadic list of flag bytes (octet 5, 6, ...).
func NewIndication(flags ...uint8) *IE {
	return &IE{Type: TypeIndication, Value: flags}
}

// ── Decoders ────────────────────────────────────────────────────────────────

// IMSI returns the IMSI string decoded from the IE value.
func (ie *IE) IMSI() (string, error) {
	if ie.Type != TypeIMSI {
		return "", fmt.Errorf("IE type %d is not IMSI", ie.Type)
	}
	return decodeTBCD(ie.Value), nil
}

// MEIValue returns the IMEI/IMEISV string decoded from the MEI IE.
func (ie *IE) MEIValue() (string, error) {
	if ie.Type != TypeMEI {
		return "", fmt.Errorf("IE type %d is not MEI", ie.Type)
	}
	return decodeTBCD(ie.Value), nil
}

// MSISDN returns the MSISDN string decoded from the IE value.
func (ie *IE) MSISDN() (string, error) {
	if ie.Type != TypeMSISDN {
		return "", fmt.Errorf("IE type %d is not MSISDN", ie.Type)
	}
	return decodeE164(ie.Value), nil
}

// CauseValue returns the cause code from a Cause IE.
func (ie *IE) CauseValue() (uint8, error) {
	if ie.Type != TypeCause {
		return 0, fmt.Errorf("IE type %d is not Cause", ie.Type)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Cause IE too short")
	}
	return ie.Value[0], nil
}

// SelectionModeValue returns the Selection Mode value (bits 1-0) per TS 29.274 §8.58.
func (ie *IE) SelectionModeValue() (uint8, error) {
	if ie.Type != TypeSelectionMode {
		return 0, fmt.Errorf("IE type %d is not Selection Mode", ie.Type)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Selection Mode IE too short")
	}
	return ie.Value[0] & 0x03, nil
}

// RATTypeValue returns the RAT Type value.
func (ie *IE) RATTypeValue() (uint8, error) {
	if ie.Type != TypeRATType {
		return 0, fmt.Errorf("IE type %d is not RAT Type", ie.Type)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("RAT Type IE too short")
	}
	return ie.Value[0], nil
}

// APNValue returns the APN string decoded from the APN IE.
func (ie *IE) APNValue() (string, error) {
	if ie.Type != TypeAPN {
		return "", fmt.Errorf("IE type %d is not APN", ie.Type)
	}
	return decodeAPN(ie.Value), nil
}

// PDNTypeValue returns the PDN Type value.
func (ie *IE) PDNTypeValue() (uint8, error) {
	if ie.Type != TypePDNType {
		return 0, fmt.Errorf("IE type %d is not PDN Type", ie.Type)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("PDN Type IE too short")
	}
	return ie.Value[0] & 0x07, nil
}

// EBIValue returns the EPS Bearer ID value.
func (ie *IE) EBIValue() (uint8, error) {
	if ie.Type != TypeEBI {
		return 0, fmt.Errorf("IE type %d is not EBI", ie.Type)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("EBI IE too short")
	}
	return ie.Value[0] & 0x0F, nil
}

// FTEID decodes an F-TEID IE per TS 29.274 Rel-15 Section 8.22.
type FTEID struct {
	IntfType uint8
	TEID     uint32
	IPv4     netip.Addr
}

// FTEIDValue decodes the F-TEID IE value per TS 29.274 Rel-15 §8.22 Figure 8.22-1.
//
//	Value[0]: V4(bit7=0x80)|V6(bit6=0x40)|Interface Type(bits5-0)
//	Value[1-4]: TEID
//	Value[5-8]: IPv4 (if V4=1)
func (ie *IE) FTEIDValue() (FTEID, error) {
	if ie.Type != TypeFTEID {
		return FTEID{}, fmt.Errorf("IE type %d is not F-TEID", ie.Type)
	}
	if len(ie.Value) < 5 {
		return FTEID{}, fmt.Errorf("F-TEID IE too short: %d bytes", len(ie.Value))
	}
	flags := ie.Value[0]
	f := FTEID{
		IntfType: flags & 0x3F,
		TEID:     binary.BigEndian.Uint32(ie.Value[1:5]),
	}
	// Per TS 29.274 §8.22: V4=1 requires at least 9 value octets (5 base + 4 IPv4).
	if flags&0x80 != 0 {
		if len(ie.Value) < 9 {
			return FTEID{}, fmt.Errorf("F-TEID IE with V4=1 too short: %d value bytes (need 9)", len(ie.Value))
		}
		f.IPv4 = netip.AddrFrom4([4]byte(ie.Value[5:9]))
	}
	return f, nil
}

// PAA decodes the PAA IE.
type PAA struct {
	PDNType uint8
	IPv4    netip.Addr
}

// PAAValue decodes the PAA IE value.
func (ie *IE) PAAValue() (PAA, error) {
	if ie.Type != TypePAA {
		return PAA{}, fmt.Errorf("IE type %d is not PAA", ie.Type)
	}
	if len(ie.Value) < 1 {
		return PAA{}, fmt.Errorf("PAA IE too short")
	}
	p := PAA{PDNType: ie.Value[0] & 0x07}
	// Per TS 29.274 §8.14: PDN Type IPv4 requires 5 value octets (1 type + 4 IPv4).
	if p.PDNType == PDNTypeIPv4 {
		if len(ie.Value) < 5 {
			return PAA{}, fmt.Errorf("PAA IE with IPv4 PDN type too short: %d value bytes (need 5)", len(ie.Value))
		}
		p.IPv4 = netip.AddrFrom4([4]byte(ie.Value[1:5]))
	}
	return p, nil
}

// ServingNetworkValue decodes the Serving Network IE.
func (ie *IE) ServingNetworkValue() (mcc, mnc string, err error) {
	if ie.Type != TypeServingNetwork {
		return "", "", fmt.Errorf("IE type %d is not Serving Network", ie.Type)
	}
	if len(ie.Value) < 3 {
		return "", "", fmt.Errorf("Serving Network IE too short")
	}
	return decodePLMN(ie.Value)
}

// ChildIEs parses the grouped IE value into child IEs.
func (ie *IE) ChildIEs() ([]*IE, error) {
	return ParseIEs(ie.Value)
}

// BearerTFTValue returns the raw TFT bytes from an EPS Bearer Level TFT IE (type 84).
// Per TS 29.274 §8.19 Figure 8.19-1: value field = verbatim TFT from TS 24.008 §10.5.6.12.
func (ie *IE) BearerTFTValue() ([]byte, error) {
	if ie.Type != TypeBearerTFT {
		return nil, fmt.Errorf("IE type %d is not Bearer TFT", ie.Type)
	}
	out := make([]byte, len(ie.Value))
	copy(out, ie.Value)
	return out, nil
}

// RecoveryValue returns the restart counter from a Recovery IE.
func (ie *IE) RecoveryValue() (uint8, error) {
	if ie.Type != TypeRecovery {
		return 0, fmt.Errorf("IE type %d is not Recovery", ie.Type)
	}
	if len(ie.Value) < 1 {
		return 0, fmt.Errorf("Recovery IE too short")
	}
	return ie.Value[0], nil
}

// ── Encoding helpers ─────────────────────────────────────────────────────────

// encodeTBCD encodes a digit string to TBCD per 3GPP TS 29.002.
func encodeTBCD(digits string) []byte {
	out := make([]byte, (len(digits)+1)/2)
	for i, c := range digits {
		d := byte(c - '0')
		if i%2 == 0 {
			out[i/2] = d
		} else {
			out[i/2] |= d << 4
		}
	}
	if len(digits)%2 != 0 {
		out[len(out)-1] |= 0xF0
	}
	return out
}

func decodeTBCD(b []byte) string {
	out := make([]byte, 0, len(b)*2)
	for _, v := range b {
		lo := v & 0x0F
		hi := (v >> 4) & 0x0F
		out = append(out, '0'+lo)
		if hi != 0x0F {
			out = append(out, '0'+hi)
		}
	}
	return string(out)
}

// encodeE164 encodes an E.164 number (strips leading '+', TBCD with 0x0F pad).
func encodeE164(num string) []byte {
	if len(num) > 0 && num[0] == '+' {
		num = num[1:]
	}
	return encodeTBCD(num)
}

func decodeE164(b []byte) string {
	return decodeTBCD(b)
}

// encodeAPN encodes an APN string to the label-length format per TS 23.003.
func encodeAPN(apn string) []byte {
	if apn == "" {
		return []byte{0}
	}
	var out []byte
	start := 0
	for i := 0; i <= len(apn); i++ {
		if i == len(apn) || apn[i] == '.' {
			label := apn[start:i]
			out = append(out, byte(len(label)))
			out = append(out, []byte(label)...)
			start = i + 1
		}
	}
	return out
}

func decodeAPN(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	var out []byte
	i := 0
	for i < len(b) {
		n := int(b[i])
		i++
		if i+n > len(b) {
			break
		}
		if len(out) > 0 {
			out = append(out, '.')
		}
		out = append(out, b[i:i+n]...)
		i += n
	}
	return string(out)
}

// encodePLMN encodes MCC/MNC to 3 bytes per 3GPP TS 29.274 Section 8.18.
func encodePLMN(mcc, mnc string) []byte {
	for len(mcc) < 3 {
		mcc += "0"
	}
	for len(mnc) < 2 {
		mnc = "0" + mnc
	}
	b := make([]byte, 3)
	b[0] = (digit(mcc[0])) | (digit(mcc[1]) << 4)
	if len(mnc) == 2 {
		b[1] = digit(mcc[2]) | 0xF0
	} else {
		b[1] = digit(mcc[2]) | (digit(mnc[2]) << 4)
	}
	b[2] = digit(mnc[0]) | (digit(mnc[1]) << 4)
	return b
}

func decodePLMN(b []byte) (mcc, mnc string, err error) {
	if len(b) < 3 {
		return "", "", fmt.Errorf("PLMN too short")
	}
	d0 := b[0] & 0x0F
	d1 := (b[0] >> 4) & 0x0F
	d2 := b[1] & 0x0F
	d3 := (b[1] >> 4) & 0x0F
	d4 := b[2] & 0x0F
	d5 := (b[2] >> 4) & 0x0F
	mcc = fmt.Sprintf("%d%d%d", d0, d1, d2)
	if d3 == 0x0F {
		mnc = fmt.Sprintf("%d%d", d4, d5)
	} else {
		mnc = fmt.Sprintf("%d%d%d", d4, d5, d3)
	}
	return mcc, mnc, nil
}

func digit(c byte) byte {
	if c >= '0' && c <= '9' {
		return c - '0'
	}
	return 0
}

func putUint40(b []byte, v uint64) {
	b[0] = byte(v >> 32)
	b[1] = byte(v >> 24)
	b[2] = byte(v >> 16)
	b[3] = byte(v >> 8)
	b[4] = byte(v)
}
