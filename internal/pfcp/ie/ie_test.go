package ie_test

import (
	"net"
	"net/netip"
	"testing"

	"vectorcore-sgw/internal/pfcp/ie"
)

// TestCauseIEWire verifies Cause IE encoding per TS 29.244 Rel-15 §8.2.1.
// Type=19 (0x0013), Length=1 (0x0001), Value=cause byte.
func TestCauseIEWire(t *testing.T) {
	c := ie.NewCause(ie.CauseRequestAccepted)
	raw := c.Marshal()

	// Expected: [0x00,0x13, 0x00,0x01, 0x01]
	want := []byte{0x00, 0x13, 0x00, 0x01, 0x01}
	if len(raw) != len(want) {
		t.Fatalf("Cause IE wire length = %d; want %d", len(raw), len(want))
	}
	for i, b := range want {
		if raw[i] != b {
			t.Errorf("Cause IE byte[%d] = 0x%02X; want 0x%02X", i, raw[i], b)
		}
	}

	got, err := c.CauseValue()
	if err != nil {
		t.Fatalf("CauseValue() error: %v", err)
	}
	if got != ie.CauseRequestAccepted {
		t.Errorf("CauseValue() = %d; want %d", got, ie.CauseRequestAccepted)
	}
}

func TestVectorCoreIdleDownlinkReportRoundTrip(t *testing.T) {
	report := ie.VectorCoreIdleDownlinkReport{
		CPSEID:          0x0102030405060708,
		UPSEID:          0x1112131415161718,
		PDRID:           7,
		FARID:           9,
		LocalTEID:       0xAABBCCDD,
		EBI:             6,
		QCI:             5,
		SourceInterface: 1,
		QoSValid:        true,
		DropReason:      ie.VectorCoreIdleDownlinkDropReleaseAccessBearers,
	}
	got, err := ie.NewVectorCoreIdleDownlinkReport(report).VectorCoreIdleDownlinkReportValue()
	if err != nil {
		t.Fatalf("VectorCoreIdleDownlinkReportValue: %v", err)
	}
	if got != report {
		t.Fatalf("report = %+v; want %+v", got, report)
	}
}

func TestVectorCoreIdleDownlinkReportRejectsWrongVersion(t *testing.T) {
	reportIE := ie.NewVectorCoreIdleDownlinkReport(ie.VectorCoreIdleDownlinkReport{})
	reportIE.Value[0] = 2
	if _, err := reportIE.VectorCoreIdleDownlinkReportValue(); err == nil {
		t.Fatal("VectorCoreIdleDownlinkReportValue accepted unsupported version")
	}
}

// TestNodeIDIPv4Wire verifies Node ID IE encoding per TS 29.244 Rel-15 §8.2.8.
// Type=60 (0x003C), Length=5 (0x0005), Value=[NodeIDType=0x00, IPv4[4]].
func TestNodeIDIPv4Wire(t *testing.T) {
	ip := net.ParseIP("10.90.250.10").To4() // 0x0A5AFA0A
	n := ie.NewNodeIDIPv4(ip)
	raw := n.Marshal()

	// Expected: [0x00,0x3C, 0x00,0x05, 0x00, 0x0A,0x5A,0xFA,0x0A]
	want := []byte{0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x5A, 0xFA, 0x0A}
	if len(raw) != len(want) {
		t.Fatalf("Node ID IE wire length = %d; want %d", len(raw), len(want))
	}
	for i, b := range want {
		if raw[i] != b {
			t.Errorf("Node ID IE byte[%d] = 0x%02X; want 0x%02X", i, raw[i], b)
		}
	}

	got := n.NodeIDIPv4()
	if got == nil || !got.Equal(ip) {
		t.Errorf("NodeIDIPv4() = %v; want %v", got, ip)
	}
}

// TestRecoveryTimeStampWire verifies Recovery Time Stamp IE encoding per TS 29.244 §8.2.11.
// Type=96 (0x0060), Length=4 (0x0004), Value=NTP timestamp big-endian.
// Using Unix=0 → NTP=2208988800 (0x83AA7E80).
func TestRecoveryTimeStampWire(t *testing.T) {
	const unixZeroNTP uint32 = 2208988800 // Unix epoch (1970-01-01) as NTP timestamp
	r := ie.NewRecoveryTimeStamp(unixZeroNTP)
	raw := r.Marshal()

	// Expected: [0x00,0x60, 0x00,0x04, 0x83,0xAA,0x7E,0x80]
	want := []byte{0x00, 0x60, 0x00, 0x04, 0x83, 0xAA, 0x7E, 0x80}
	if len(raw) != len(want) {
		t.Fatalf("Recovery TS IE wire length = %d; want %d", len(raw), len(want))
	}
	for i, b := range want {
		if raw[i] != b {
			t.Errorf("Recovery TS IE byte[%d] = 0x%02X; want 0x%02X", i, raw[i], b)
		}
	}

	got, err := r.RecoveryTimeStampValue()
	if err != nil {
		t.Fatalf("RecoveryTimeStampValue() error: %v", err)
	}
	if got != unixZeroNTP {
		t.Errorf("RecoveryTimeStampValue() = %d; want %d", got, unixZeroNTP)
	}
}

// TestParseIEsRoundTrip verifies that ParseIEs correctly decodes a multi-IE buffer.
func TestParseIEsRoundTrip(t *testing.T) {
	ip := net.ParseIP("192.168.1.1").To4()
	orig := []*ie.IE{
		ie.NewNodeIDIPv4(ip),
		ie.NewCause(ie.CauseRequestAccepted),
		ie.NewRecoveryTimeStamp(2208988800),
	}

	var buf []byte
	for _, i := range orig {
		buf = append(buf, i.Marshal()...)
	}

	parsed, err := ie.ParseIEs(buf)
	if err != nil {
		t.Fatalf("ParseIEs() error: %v", err)
	}
	if len(parsed) != len(orig) {
		t.Fatalf("ParseIEs() returned %d IEs; want %d", len(parsed), len(orig))
	}
	for i, p := range parsed {
		if p.Type != orig[i].Type {
			t.Errorf("IE[%d] type = %d; want %d", i, p.Type, orig[i].Type)
		}
	}
}

// ── Session-level IE wire tests (C14 / C17) ──────────────────────────────────

// TestPDRIDWire verifies PDR ID IE encoding per TS 29.244 Rel-15 §8.2 (§Table 8.1.2-1).
// Type=56 (0x0038), Length=2, Value=uint16 big-endian.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1: "56 | PDR ID | Extendable / Clause 8.2.36"
func TestPDRIDWire(t *testing.T) {
	p := ie.NewPDRID(1)
	raw := p.Marshal()
	// Type=56=0x0038, Len=2, Value=[0x00,0x01]
	want := []byte{0x00, 0x38, 0x00, 0x02, 0x00, 0x01}
	checkWire(t, "PDR ID", raw, want)

	got, err := p.PDRIDValue()
	if err != nil {
		t.Fatalf("PDRIDValue() error: %v", err)
	}
	if got != 1 {
		t.Errorf("PDRIDValue() = %d; want 1", got)
	}
}

// TestFARIDWire verifies FAR ID IE encoding per TS 29.244 Rel-15 §8.2.
// Type=108 (0x006C), Length=4, Value=uint32 big-endian.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1: "108 | FAR ID | Extendable / Clause 8.2.74"
func TestFARIDWire(t *testing.T) {
	f := ie.NewFARID(1)
	raw := f.Marshal()
	// Type=108=0x006C, Len=4, Value=[0x00,0x00,0x00,0x01]
	want := []byte{0x00, 0x6C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x01}
	checkWire(t, "FAR ID", raw, want)

	got, err := f.FARIDValue()
	if err != nil {
		t.Fatalf("FARIDValue() error: %v", err)
	}
	if got != 1 {
		t.Errorf("FARIDValue() = %d; want 1", got)
	}
}

// TestPrecedenceWire verifies Precedence IE encoding per TS 29.244 Rel-15 §8.2.
// Type=29 (0x001D), Length=4, Value=uint32 big-endian.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1: "29 | Precedence | Extendable / Clause 8.2.11"
func TestPrecedenceWire(t *testing.T) {
	p := ie.NewPrecedence(100)
	raw := p.Marshal()
	// Type=29=0x001D, Len=4, Value=[0x00,0x00,0x00,0x64]
	want := []byte{0x00, 0x1D, 0x00, 0x04, 0x00, 0x00, 0x00, 0x64}
	checkWire(t, "Precedence", raw, want)
}

// TestSourceInterfaceWire verifies Source Interface IE encoding per TS 29.244 Rel-15 §8.2.2.
// Type=20 (0x0014), Length=1.
// C17: tests both Access(0) and Core(1) flag states.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1 row "20 | Source Interface" and
// Table 8.2.2-1 rows "Access | 0" and "Core | 1".
func TestSourceInterfaceWire(t *testing.T) {
	tests := []struct {
		name  string
		iface uint8
		want  []byte
	}{
		// Access interface (value=0x00 per §8.2.2) — tests state 0
		{"Access", ie.SourceInterfaceAccess, []byte{0x00, 0x14, 0x00, 0x01, 0x00}},
		// Core interface (value=0x01 per §8.2.2) — tests state 1
		{"Core", ie.SourceInterfaceCore, []byte{0x00, 0x14, 0x00, 0x01, 0x01}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			i := ie.NewSourceInterface(tc.iface)
			raw := i.Marshal()
			checkWire(t, "Source Interface/"+tc.name, raw, tc.want)

			got, err := i.SourceInterfaceValue()
			if err != nil {
				t.Fatalf("SourceInterfaceValue() error: %v", err)
			}
			if got != tc.iface {
				t.Errorf("SourceInterfaceValue() = %d; want %d", got, tc.iface)
			}
		})
	}
}

// TestDestinationInterfaceWire verifies Destination Interface IE encoding per §8.2.25.
// Type=42 (0x002A), Length=1.
// C17: tests both Access(0) and Core(1) flag states.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1 row "42 | Destination Interface" and
// Table 8.2.24-1 rows "Access | 0" and "Core | 1".
func TestDestinationInterfaceWire(t *testing.T) {
	tests := []struct {
		name  string
		iface uint8
		want  []byte
	}{
		// Access interface (state 0)
		{"Access", ie.DestInterfaceAccess, []byte{0x00, 0x2A, 0x00, 0x01, 0x00}},
		// Core interface (state 1)
		{"Core", ie.DestInterfaceCore, []byte{0x00, 0x2A, 0x00, 0x01, 0x01}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			i := ie.NewDestinationInterface(tc.iface)
			raw := i.Marshal()
			checkWire(t, "Dest Interface/"+tc.name, raw, tc.want)

			got, err := i.DestinationInterfaceValue()
			if err != nil {
				t.Fatalf("DestinationInterfaceValue() error: %v", err)
			}
			if got != tc.iface {
				t.Errorf("DestinationInterfaceValue() = %d; want %d", got, tc.iface)
			}
		})
	}
}

// TestApplyActionWire verifies Apply Action IE encoding per TS 29.244 Rel-15 §8.2.26.
// Type=44 (0x002C), Length=1.
// C17 — tests all spec-defined flag states: DROP(bit1), FORW(bit2), BUFF(bit3), NOCP(bit4).
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1 row "44 | Apply Action" and
// Figure 8.2.26-1: "Bit 1 DROP=0x01, Bit 2 FORW=0x02, Bit 3 BUFF=0x04, Bit 4 NOCP=0x08".
func TestApplyActionWire(t *testing.T) {
	tests := []struct {
		name  string
		flags uint8
		want  []byte
	}{
		// DROP only (bit 1 = 0x01)
		{"DROP", ie.ApplyActionDROP, []byte{0x00, 0x2C, 0x00, 0x01, 0x01}},
		// FORW only (bit 2 = 0x02)
		{"FORW", ie.ApplyActionFORW, []byte{0x00, 0x2C, 0x00, 0x01, 0x02}},
		// BUFF (bit 3 = 0x04)
		{"BUFF", ie.ApplyActionBUFF, []byte{0x00, 0x2C, 0x00, 0x01, 0x04}},
		// NOCP (bit 4 = 0x08)
		{"NOCP", ie.ApplyActionNOCP, []byte{0x00, 0x2C, 0x00, 0x01, 0x08}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a := ie.NewApplyAction(tc.flags)
			raw := a.Marshal()
			checkWire(t, "Apply Action/"+tc.name, raw, tc.want)

			got, err := a.ApplyActionValue()
			if err != nil {
				t.Fatalf("ApplyActionValue() error: %v", err)
			}
			if got != tc.flags {
				t.Errorf("ApplyActionValue() = 0x%02X; want 0x%02X", got, tc.flags)
			}
		})
	}
}

// TestFTEIDPFCPChooseWire verifies PFCP F-TEID IE with CH=1, V4=1 per TS 29.244 Rel-15 §8.2.3.
// Spec §8.2.3 Figure 8.2.3-1: "Bit 3 – CH (CHOOSE)" = 0x04, "Bit 1 – V4" = 0x01.
// Spec §8.2.3: "At least one of the V4 and V6 flags shall be set to '1'... when CHOOSE bit
// is set to '1'." So CHOOSE+IPv4 encoding = CH|V4 = 0x04|0x01 = 0x05.
// Golden vector: Type=21 (0x0015), Length=1 (0x0001), Value=[0x05].
// C17 flag states: CH=1 (CHOOSE/V4) and static V4 (CH=0, V4=1) tested separately.
// R15-001 FIX: prior test expected 0x08 (wrong CH bit). Now verified from spec §8.2.3.
func TestFTEIDPFCPChooseWire(t *testing.T) {
	f := ie.NewFTEIDChoose()
	raw := f.Marshal()
	// Golden vector from TS 29.244 §8.2.3 Figure 8.2.3-1:
	// Type=21=0x0015, Len=1=0x0001, Value=[CH|V4=0x05]
	want := []byte{0x00, 0x15, 0x00, 0x01, 0x05}
	checkWire(t, "PFCP F-TEID CHOOSE", raw, want)

	_, isCH, err := f.FTEIDPFCPValue()
	if err != nil {
		t.Fatalf("FTEIDPFCPValue() error: %v", err)
	}
	if !isCH {
		t.Errorf("FTEIDPFCPValue() isCHOOSE = false; want true")
	}
}

// TestFTEIDPFCPChooseV6Wire verifies PFCP F-TEID IE with CH=1, V6=1 per TS 29.244 Rel-15 §8.2.3.
// C17: test CH+V6 flag state (third state of the CHOOSE encoding).
// Golden vector: Type=21 (0x0015), Length=1 (0x0001), Value=[CH|V6=0x04|0x02=0x06].
func TestFTEIDPFCPChooseV6Wire(t *testing.T) {
	// Build a CHOOSE+V6 IE manually (NewFTEIDChoose uses V4 by default).
	f := &ie.IE{Type: ie.TypeFTEID, Value: []byte{ie.FTEIDFlagCH | ie.FTEIDFlagV6}}
	raw := f.Marshal()
	// Golden vector: Type=21=0x0015, Len=1=0x0001, Value=[0x06]
	want := []byte{0x00, 0x15, 0x00, 0x01, 0x06}
	checkWire(t, "PFCP F-TEID CHOOSE+V6", raw, want)

	_, isCH, err := f.FTEIDPFCPValue()
	if err != nil {
		t.Fatalf("FTEIDPFCPValue() error: %v", err)
	}
	if !isCH {
		t.Errorf("FTEIDPFCPValue() isCHOOSE = false; want true")
	}
}

// TestUPFunctionFeaturesWire verifies UP Function Features IE per TS 29.244 §8.2.25.
// Type=43 (0x002B), Length=1. Table 8.2.25-1: "5/5, FTUP" = octet 5 bit 5 = 0x10.
// Golden vector: Type=43=0x002B, Len=1=0x0001, Value=[FTUP=0x10].
func TestUPFunctionFeaturesWire(t *testing.T) {
	f := ie.NewUPFunctionFeatures(ie.UPFunctionFeaturesFTUP)
	raw := f.Marshal()
	// Type=43=0x002B, Len=1, Value=[0x10]
	want := []byte{0x00, 0x2B, 0x00, 0x01, 0x10}
	checkWire(t, "UP Function Features FTUP", raw, want)

	got, err := f.UPFunctionFeaturesValue()
	if err != nil {
		t.Fatalf("UPFunctionFeaturesValue() error: %v", err)
	}
	if got != ie.UPFunctionFeaturesFTUP {
		t.Errorf("UPFunctionFeaturesValue() = 0x%02X; want 0x%02X", got, ie.UPFunctionFeaturesFTUP)
	}
}

// TestUPFunctionFeaturesZeroWire verifies UP Function Features with no bits set (C17 state 0).
func TestUPFunctionFeaturesZeroWire(t *testing.T) {
	f := ie.NewUPFunctionFeatures(0)
	raw := f.Marshal()
	want := []byte{0x00, 0x2B, 0x00, 0x01, 0x00}
	checkWire(t, "UP Function Features zero", raw, want)
}

// TestFTEIDPFCPStaticWire verifies PFCP F-TEID IE with V4=1 per TS 29.244 Rel-15 §8.2.3.
// Type=21 (0x0015), Length=9, Value=[V4=0x01, TEID(4), IPv4(4)].
// C17: second flag state — static TEID (not CHOOSE).
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1 row "21 | F-TEID" and
// Figure 8.2.3-1: "Bit 1 – V4" = 0x01.
func TestFTEIDPFCPStaticWire(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1") // 0x0A 0x00 0x00 0x01
	f := ie.NewFTEIDv4(0x00000001, v4)
	raw := f.Marshal()
	// Type=21=0x0015, Len=9, Value=[0x01, 0x00,0x00,0x00,0x01, 0x0A,0x00,0x00,0x01]
	want := []byte{0x00, 0x15, 0x00, 0x09, 0x01, 0x00, 0x00, 0x00, 0x01, 0x0A, 0x00, 0x00, 0x01}
	checkWire(t, "PFCP F-TEID static V4", raw, want)

	val, isCH, err := f.FTEIDPFCPValue()
	if err != nil {
		t.Fatalf("FTEIDPFCPValue() error: %v", err)
	}
	if isCH {
		t.Errorf("FTEIDPFCPValue() isCHOOSE = true; want false")
	}
	if val.TEID != 0x00000001 {
		t.Errorf("FTEIDPFCPValue() TEID = 0x%08X; want 0x00000001", val.TEID)
	}
	if val.IPv4 != v4 {
		t.Errorf("FTEIDPFCPValue() IPv4 = %v; want %v", val.IPv4, v4)
	}
}

// TestFSEIDWire verifies F-SEID IE encoding per TS 29.244 Rel-15 §8.2.37.
// Type=57 (0x0039), Length=13 for V4, Value=[flags(1), SEID(8), IPv4(4)].
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1 row "57 | F-SEID" and
// Figure 8.2.37-1: "Bit 2 – V4" = 0x02.
func TestFSEIDWire(t *testing.T) {
	v4 := netip.MustParseAddr("192.168.1.1") // 0xC0 0xA8 0x01 0x01
	f := ie.NewFSEID(1, v4)
	raw := f.Marshal()
	// Type=57=0x0039, Len=13=0x000D
	// Value=[0x02, 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x01, 0xC0,0xA8,0x01,0x01]
	want := []byte{
		0x00, 0x39, 0x00, 0x0D,
		0x02,                                           // V4 flag
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, // SEID=1
		0xC0, 0xA8, 0x01, 0x01, // IPv4
	}
	checkWire(t, "F-SEID", raw, want)

	val, err := f.FSEIDValue()
	if err != nil {
		t.Fatalf("FSEIDValue() error: %v", err)
	}
	if val.SEID != 1 {
		t.Errorf("FSEIDValue() SEID = %d; want 1", val.SEID)
	}
	if val.IPv4 != v4 {
		t.Errorf("FSEIDValue() IPv4 = %v; want %v", val.IPv4, v4)
	}
}

// TestOuterHeaderCreationWire verifies Outer Header Creation IE per TS 29.244 Rel-15 §8.2.56.
// Type=84 (0x0054), Length=10 for GTP-U/UDP/IPv4.
// Value=[desc(2), TEID(4), IPv4(4)].
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1 row "84 | Outer Header Creation" and
// Figure 8.2.56-1: Octet 5 Bit 8 (MSB of first octet) = GTP-U/UDP/IPv4 → 0x0100 big-endian.
func TestOuterHeaderCreationWire(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.2") // 0x0A 0x00 0x00 0x02
	ohc := ie.NewOuterHeaderCreation(ie.OHCDescGTPUUDPIPv4, 0xDEADBEEF, v4)
	raw := ohc.Marshal()
	// Type=84=0x0054, Len=10=0x000A
	// Value=[0x01,0x00, 0xDE,0xAD,0xBE,0xEF, 0x0A,0x00,0x00,0x02]
	want := []byte{
		0x00, 0x54, 0x00, 0x0A,
		0x01, 0x00, // desc=OHCDescGTPUUDPIPv4
		0xDE, 0xAD, 0xBE, 0xEF, // TEID
		0x0A, 0x00, 0x00, 0x02, // IPv4
	}
	checkWire(t, "Outer Header Creation", raw, want)

	val, err := ohc.OuterHeaderCreationValue()
	if err != nil {
		t.Fatalf("OuterHeaderCreationValue() error: %v", err)
	}
	if val.Description != ie.OHCDescGTPUUDPIPv4 {
		t.Errorf("OuterHeaderCreationValue() Desc = 0x%04X; want 0x%04X", val.Description, ie.OHCDescGTPUUDPIPv4)
	}
	if val.TEID != 0xDEADBEEF {
		t.Errorf("OuterHeaderCreationValue() TEID = 0x%08X; want 0xDEADBEEF", val.TEID)
	}
	if val.IPv4 != v4 {
		t.Errorf("OuterHeaderCreationValue() IPv4 = %v; want %v", val.IPv4, v4)
	}
}

// TestGroupedIEChildren verifies grouped IE (PDI) marshaling and child parse round-trip.
// PDI type=2 (0x0002) per TS 29.244 §Table 8.1.2-1.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1: "2 | PDI | Extendable / Table 7.5.2.2-2"
func TestGroupedIEChildren(t *testing.T) {
	srcIface := ie.NewSourceInterface(ie.SourceInterfaceAccess)
	fteid := ie.NewFTEIDChoose()
	pdi := ie.NewPDI(srcIface, fteid)

	// Grouped IE wire: type(2)|len(2)|[children concatenated]
	children, err := pdi.Children()
	if err != nil {
		t.Fatalf("PDI.Children() error: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("PDI.Children() returned %d children; want 2", len(children))
	}
	if children[0].Type != ie.TypeSourceInterface {
		t.Errorf("PDI child[0] type = %d; want %d (Source Interface)", children[0].Type, ie.TypeSourceInterface)
	}
	if children[1].Type != ie.TypeFTEID {
		t.Errorf("PDI child[1] type = %d; want %d (F-TEID)", children[1].Type, ie.TypeFTEID)
	}

	// Verify the PDI type in wire output (type 2 = 0x0002).
	raw := pdi.Marshal()
	if raw[0] != 0x00 || raw[1] != 0x02 {
		t.Errorf("PDI type bytes = [0x%02X,0x%02X]; want [0x00,0x02]", raw[0], raw[1])
	}
}

// TestCreatePDRGrouped verifies Create PDR grouped IE marshaling and parse.
// Type=1 (0x0001); must contain PDR ID, Precedence, PDI, FAR ID.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1: "1 | Create PDR | Extendable / Table 7.5.2.2-1"
func TestCreatePDRGrouped(t *testing.T) {
	pdi := ie.NewPDI(ie.NewSourceInterface(ie.SourceInterfaceAccess))
	cpdr := ie.NewCreatePDR(
		ie.NewPDRID(1),
		ie.NewPrecedence(100),
		pdi,
		ie.NewFARID(1),
	)

	children, err := cpdr.Children()
	if err != nil {
		t.Fatalf("CreatePDR.Children() error: %v", err)
	}
	if len(children) != 4 {
		t.Fatalf("CreatePDR children count = %d; want 4", len(children))
	}

	types := []uint16{ie.TypePDRID, ie.TypePrecedence, ie.TypePDI, ie.TypeFARID}
	for i, want := range types {
		if children[i].Type != want {
			t.Errorf("CreatePDR child[%d] type = %d; want %d", i, children[i].Type, want)
		}
	}

	// Verify type byte in wire: Create PDR = type 1 = 0x0001.
	raw := cpdr.Marshal()
	if raw[0] != 0x00 || raw[1] != 0x01 {
		t.Errorf("Create PDR type bytes = [0x%02X,0x%02X]; want [0x00,0x01]", raw[0], raw[1])
	}
}

// TestPFCPGroupedIEChildrenHaveNoInstanceOctet documents the C10 boundary for PFCP.
// TS 29.244 Rel-15 §8.1 encodes IEs as Type(2)|Length(2)|Value with no GTPv2-C
// instance octet. Grouped IE tables such as Table 7.5.2.2-1 and 7.5.2.2-2
// therefore cite child IE type and presence only.
func TestPFCPGroupedIEChildrenHaveNoInstanceOctet(t *testing.T) {
	pdi := ie.NewPDI(ie.NewSourceInterface(ie.SourceInterfaceAccess))
	raw := pdi.Marshal()

	// PDI: type=2, len=5, then child Source Interface: type=20, len=1, value=Access(0).
	// If PFCP had a GTPv2-style child instance octet, this vector would be 10 bytes
	// instead of 9 and the Source Interface value would shift by one byte.
	want := []byte{
		0x00, 0x02, 0x00, 0x05,
		0x00, 0x14, 0x00, 0x01, 0x00,
	}
	checkWire(t, "PDI without child instance octet", raw, want)
}

// TestCreateFARGrouped verifies Create FAR grouped IE marshaling.
// Type=3 (0x0003); must contain FAR ID, Apply Action, Forwarding Parameters.
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1: "3 | Create FAR | Extendable / Table 7.5.2.3-1"
func TestCreateFARGrouped(t *testing.T) {
	fwdParams := ie.NewForwardingParameters(
		ie.NewDestinationInterface(ie.DestInterfaceCore),
		ie.NewOuterHeaderCreation(ie.OHCDescGTPUUDPIPv4, 1, netip.MustParseAddr("10.0.0.1")),
	)
	cfar := ie.NewCreateFAR(
		ie.NewFARID(1),
		ie.NewApplyAction(ie.ApplyActionFORW),
		fwdParams,
	)

	children, err := cfar.Children()
	if err != nil {
		t.Fatalf("CreateFAR.Children() error: %v", err)
	}
	if len(children) != 3 {
		t.Fatalf("CreateFAR children count = %d; want 3", len(children))
	}

	// Verify type byte: Create FAR = type 3 = 0x0003.
	raw := cfar.Marshal()
	if raw[0] != 0x00 || raw[1] != 0x03 {
		t.Errorf("Create FAR type bytes = [0x%02X,0x%02X]; want [0x00,0x03]", raw[0], raw[1])
	}
}

// TestCreatedPDRGrouped verifies Created PDR grouped IE (in session est response).
// Type=8 (0x0008); contains PDR ID (M) and F-TEID (C when CHOOSE was set).
// Verified from docs/specs/29244-fa0.docx Table 8.1.2-1: "8 | Created PDR | Extendable / Table 7.5.3.2-1"
func TestCreatedPDRGrouped(t *testing.T) {
	v4 := netip.MustParseAddr("10.0.0.1")
	createdPDR := ie.NewCreatedPDR(
		ie.NewPDRID(1),
		ie.NewFTEIDv4(0x12345678, v4),
	)

	children, err := createdPDR.Children()
	if err != nil {
		t.Fatalf("CreatedPDR.Children() error: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("CreatedPDR children count = %d; want 2", len(children))
	}
	if children[0].Type != ie.TypePDRID {
		t.Errorf("CreatedPDR child[0] type = %d; want %d (PDR ID)", children[0].Type, ie.TypePDRID)
	}
	if children[1].Type != ie.TypeFTEID {
		t.Errorf("CreatedPDR child[1] type = %d; want %d (F-TEID)", children[1].Type, ie.TypeFTEID)
	}

	// Verify type byte: Created PDR = type 8 = 0x0008.
	raw := createdPDR.Marshal()
	if raw[0] != 0x00 || raw[1] != 0x08 {
		t.Errorf("Created PDR type bytes = [0x%02X,0x%02X]; want [0x00,0x08]", raw[0], raw[1])
	}
}

// TestUpdateFARWire verifies the full wire encoding of an Update FAR grouped IE as
// sent in a PFCP Session Modification Request per TS 29.244 Rel-15 §7.5.4.
//
// Critical type numbers (root cause of Phase 4/5 bugs when taken from memory):
//
//	Table 7.5.4.3-1: "Octet 1 and 2 | Update FAR IE Type = 10 (decimal)"
//	Table 7.5.4.3-2: "Octet 1 and 2 | Update Forwarding Parameters IE Type = 11 (decimal)"
//	Table 8.1.2-1:     "108 | FAR ID", "44 | Apply Action", "42 | Destination Interface"
//
// The Phase 8 use case: Core→Access downlink FAR upgraded from DROP to FORW with
// eNB outer header (TEID from Modify Bearer Request, IP from eNB F-TEID).
func TestUpdateFARWire(t *testing.T) {
	// Build exactly the Update FAR that pfcpclient.ModifySession sends after MBReq.
	updateFP := ie.NewUpdateForwardingParameters(
		ie.NewDestinationInterface(ie.DestInterfaceAccess), // 0 per §8.2.24 Table 8.2.24-1
		ie.NewOuterHeaderCreation(ie.OHCDescGTPUUDPIPv4, 0x1234ABCD, netip.MustParseAddr("10.1.0.1")),
	)
	updateFAR := ie.NewUpdateFAR(
		ie.NewFARID(2),
		ie.NewApplyAction(ie.ApplyActionFORW),
		updateFP,
	)
	raw := updateFAR.Marshal()

	// Full expected 40-byte wire:
	//   [0x00,0x0A, 0x00,0x24]                              UpdateFAR: type=10, len=36
	//   [0x00,0x6C, 0x00,0x04, 0x00,0x00,0x00,0x02]        FAR ID: type=108, len=4, val=2
	//   [0x00,0x2C, 0x00,0x01, 0x02]                        Apply Action: type=44, len=1, FORW
	//   [0x00,0x0B, 0x00,0x13]                              UpdateFP: type=11, len=19
	//     [0x00,0x2A, 0x00,0x01, 0x00]                      DestInterface: type=42, Access=0
	//     [0x00,0x54, 0x00,0x0A,                            OHC: type=84, len=10
	//      0x01,0x00,                                        desc=OHCDescGTPUUDPIPv4=0x0100
	//      0x12,0x34,0xAB,0xCD,                             TEID=0x1234ABCD
	//      0x0A,0x01,0x00,0x01]                             IP=10.1.0.1
	want := []byte{
		0x00, 0x0A, 0x00, 0x24, // UpdateFAR: type=10, len=36
		0x00, 0x6C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02, // FAR ID: type=108, val=2
		0x00, 0x2C, 0x00, 0x01, 0x02, // Apply Action: type=44, FORW
		0x00, 0x0B, 0x00, 0x13, // UpdateFP: type=11, len=19
		0x00, 0x2A, 0x00, 0x01, 0x00, // DestInterface: type=42, Access=0
		0x00, 0x54, 0x00, 0x0A, // OHC: type=84, len=10
		0x01, 0x00, // desc=OHCDescGTPUUDPIPv4
		0x12, 0x34, 0xAB, 0xCD, // TEID
		0x0A, 0x01, 0x00, 0x01, // IP=10.1.0.1
	}
	checkWire(t, "UpdateFAR", raw, want)

	// Named assertions for the critical type bytes.
	// Table 7.5.4.3-1: UpdateFAR type=10
	if raw[0] != 0x00 || raw[1] != 0x0A {
		t.Errorf("UpdateFAR IE type bytes[0:2] = [0x%02X,0x%02X]; want [0x00,0x0A] (Table 7.5.4.3-1 type=10)", raw[0], raw[1])
	}
	// Table 7.5.4.3-2: UpdateForwardingParameters type=11
	if raw[17] != 0x00 || raw[18] != 0x0B {
		t.Errorf("UpdateFP IE type bytes[17:19] = [0x%02X,0x%02X]; want [0x00,0x0B] (Table 7.5.4.3-2 type=11)", raw[17], raw[18])
	}
}

// FuzzParseIEs fuzzes PFCP IE parsing per C20.
// Seeds are golden wire vectors from prior phase wire tests derived from spec figures.
// The fuzzer must not panic; returning an error is acceptable.
func FuzzParseIEs(f *testing.F) {
	// Cause IE: type=19(0x0013), len=1, val=1 (CauseRequestAccepted) — TestCauseIEWire
	f.Add([]byte{0x00, 0x13, 0x00, 0x01, 0x01})

	// AMBR IE: type=60(0x003C), len=5 — TestAMBRWire
	f.Add([]byte{0x00, 0x3C, 0x00, 0x05, 0x00, 0x0A, 0x5A, 0xFA, 0x0A})

	// F-SEID IE: type=57(0x0039), len=13, V4=1, SEID=1, IP=192.168.1.1 — TestFSEIDWire
	f.Add([]byte{
		0x00, 0x39, 0x00, 0x0D,
		0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0xC0, 0xA8, 0x01, 0x01,
	})

	// Outer Header Creation: type=84(0x0054), len=10 — TestOuterHeaderCreationWire
	f.Add([]byte{
		0x00, 0x54, 0x00, 0x0A,
		0x01, 0x00, 0xDE, 0xAD, 0xBE, 0xEF, 0x0A, 0x00, 0x00, 0x02,
	})

	// UpdateFAR grouped IE (40 bytes) — TestUpdateFARWire
	f.Add([]byte{
		0x00, 0x0A, 0x00, 0x24,
		0x00, 0x6C, 0x00, 0x04, 0x00, 0x00, 0x00, 0x02,
		0x00, 0x2C, 0x00, 0x01, 0x02,
		0x00, 0x0B, 0x00, 0x13,
		0x00, 0x2A, 0x00, 0x01, 0x00,
		0x00, 0x54, 0x00, 0x0A,
		0x01, 0x00, 0x12, 0x34, 0xAB, 0xCD, 0x0A, 0x01, 0x00, 0x01,
	})

	// Known-bad: truncated header
	f.Add([]byte{0x00, 0x13})
	// Empty input
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ie.ParseIEs(b)
	})
}

// ── Phase 11 IE wire tests ────────────────────────────────────────────────────

// TestNodeReportTypeWire verifies the NodeReportType IE wire encoding per TS 29.244 §8.2.69.
// Golden vector from spec:
//
//	Type=101 (0x0065), Length=1 (0x0001), Value=[0x01] (UPFR bit)
func TestNodeReportTypeWire(t *testing.T) {
	got := ie.NewNodeReportType(ie.NodeReportTypeUPFR).Marshal()
	// §8.2.69 Figure 8.2.69-1: "Bit 1 – UPFR": value byte = 0x01
	want := []byte{0x00, 0x65, 0x00, 0x01, 0x01}
	checkWire(t, "NodeReportType(UPFR)", got, want)

	// Round-trip: flags must survive encode/decode.
	parsed, err := ie.ParseIEs(want)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("ParseIEs round-trip failed: %v", err)
	}
	flags, err := parsed[0].NodeReportTypeFlags()
	if err != nil {
		t.Fatalf("NodeReportTypeFlags: %v", err)
	}
	if flags != ie.NodeReportTypeUPFR {
		t.Errorf("NodeReportTypeFlags = 0x%02X; want 0x%02X", flags, ie.NodeReportTypeUPFR)
	}
}

// TestRemoteGTPUPeerWire verifies the RemoteGTPUPeer IE wire encoding per TS 29.244 §8.2.70.
// Golden vector from spec:
//
//	Type=103 (0x0067), Length=5 (0x0005), Value=[0x02, IP4(4)]
//	§8.2.70 Figure 8.2.70-1: "Bit 2 – V4" = 0x02; followed by 4-byte IPv4 address.
func TestRemoteGTPUPeerWire(t *testing.T) {
	ip := net.ParseIP("10.0.1.1").To4()
	got := ie.NewRemoteGTPUPeerIPv4(ip).Marshal()
	// §8.2.70: flags byte = RemoteGTPUPeerFlagV4 = 0x02; then IPv4 = 10.0.1.1.
	want := []byte{0x00, 0x67, 0x00, 0x05, 0x02, 0x0A, 0x00, 0x01, 0x01}
	checkWire(t, "RemoteGTPUPeer(V4=10.0.1.1)", got, want)

	// Round-trip: IPv4 must survive encode/decode.
	parsed, err := ie.ParseIEs(want)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("ParseIEs round-trip failed: %v", err)
	}
	gotIP := parsed[0].RemoteGTPUPeerIPv4()
	if gotIP == nil || !gotIP.Equal(ip) {
		t.Errorf("RemoteGTPUPeerIPv4 = %v; want %v", gotIP, ip)
	}
}

// TestRemoteGTPUPeerNoV4 verifies that RemoteGTPUPeerIPv4 returns nil when V4 flag is not set.
// Covers the "only V6" case per §8.2.70: "Either the V4 or the V6 bit shall be set to '1'."
func TestRemoteGTPUPeerNoV4(t *testing.T) {
	// Build an IE with V6 flag only (no IPv4 field).
	v6only := &ie.IE{Type: ie.TypeRemoteGTPUPeer, Value: []byte{ie.RemoteGTPUPeerFlagV6}}
	if got := v6only.RemoteGTPUPeerIPv4(); got != nil {
		t.Errorf("RemoteGTPUPeerIPv4 on V6-only IE = %v; want nil", got)
	}
}

// TestPFCPAssocReleaseRequestWire verifies the PFCP Association Release Request IE encoding
// per TS 29.244 §8.2.77.
// Golden vector from spec:
//
//	Type=111 (0x006F), Length=1 (0x0001), Value=[0x01] (SARR bit)
//	§8.2.77: "Bit 1 – SARR": value byte = 0x01.
func TestPFCPAssocReleaseRequestWire(t *testing.T) {
	got := ie.NewPFCPAssocReleaseRequest(ie.PFCPAssocReleaseRequestSARR).Marshal()
	want := []byte{0x00, 0x6F, 0x00, 0x01, 0x01}
	checkWire(t, "PFCPAssocReleaseRequest(SARR)", got, want)

	// Round-trip.
	parsed, err := ie.ParseIEs(want)
	if err != nil || len(parsed) != 1 {
		t.Fatalf("ParseIEs round-trip failed: %v", err)
	}
	flags, err := parsed[0].PFCPAssocReleaseRequestFlags()
	if err != nil {
		t.Fatalf("PFCPAssocReleaseRequestFlags: %v", err)
	}
	if flags != ie.PFCPAssocReleaseRequestSARR {
		t.Errorf("PFCPAssocReleaseRequestFlags = 0x%02X; want 0x%02X", flags, ie.PFCPAssocReleaseRequestSARR)
	}
}

// checkWire is a helper that compares raw wire bytes to expected bytes.
func checkWire(t *testing.T, name string, raw, want []byte) {
	t.Helper()
	if len(raw) != len(want) {
		t.Fatalf("%s wire length = %d; want %d", name, len(raw), len(want))
	}
	for i, b := range want {
		if raw[i] != b {
			t.Errorf("%s byte[%d] = 0x%02X; want 0x%02X", name, i, raw[i], b)
		}
	}
}
