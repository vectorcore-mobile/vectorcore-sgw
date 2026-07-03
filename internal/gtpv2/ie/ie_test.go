package ie_test

import (
	"bytes"
	"net/netip"
	"testing"

	"vectorcore-sgw/internal/gtpv2/ie"
)

func TestIMSIRoundtrip(t *testing.T) {
	imsi := "311430000000001"
	encoded := ie.NewIMSI(imsi)
	wire := encoded.Marshal()

	parsed, err := ie.ParseIEs(wire)
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("expected 1 IE, got %d", len(parsed))
	}
	got, err := parsed[0].IMSI()
	if err != nil {
		t.Fatalf("IMSI(): %v", err)
	}
	if got != imsi {
		t.Errorf("IMSI: got %q, want %q", got, imsi)
	}
}

func TestAPNRoundtrip(t *testing.T) {
	apn := "internet"
	encoded := ie.NewAPN(apn)
	wire := encoded.Marshal()

	parsed, err := ie.ParseIEs(wire)
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	got, err := parsed[0].APNValue()
	if err != nil {
		t.Fatalf("APNValue: %v", err)
	}
	if got != apn {
		t.Errorf("APN: got %q, want %q", got, apn)
	}
}

func TestAPNMultiLabel(t *testing.T) {
	apn := "internet.mnc435.mcc311.gprs"
	got, err := ie.NewAPN(apn).APNValue()
	if err != nil {
		t.Fatal(err)
	}
	if got != apn {
		t.Errorf("got %q, want %q", got, apn)
	}
}

func TestFTEIDRoundtrip(t *testing.T) {
	addr := netip.MustParseAddr("10.90.250.10")
	f := ie.NewFTEID(0, ie.IFTypeS11S4SGW, 0xDEADBEEF, addr)
	wire := f.Marshal()

	parsed, err := ie.ParseIEs(wire)
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	got, err := parsed[0].FTEIDValue()
	if err != nil {
		t.Fatalf("FTEIDValue: %v", err)
	}
	if got.TEID != 0xDEADBEEF {
		t.Errorf("TEID: got 0x%08X, want 0xDEADBEEF", got.TEID)
	}
	if got.IntfType != ie.IFTypeS11S4SGW {
		t.Errorf("IntfType: got %d, want %d", got.IntfType, ie.IFTypeS11S4SGW)
	}
	if got.IPv4 != addr {
		t.Errorf("IPv4: got %v, want %v", got.IPv4, addr)
	}
}

// TestFTEIDWireBytes verifies the F-TEID IE wire encoding against the byte layout
// in TS 29.274 Rel-15 §8.22 Figure 8.22-1. Round-trip tests alone are insufficient
// per compliance rule C6 — this test compares raw bytes to spec-derived values.
func TestFTEIDWireBytes(t *testing.T) {
	// S11-MME interface type = 10 = 0x0A; with V4 set: byte0 = 0x80|0x0A = 0x8A
	addr := netip.MustParseAddr("10.1.2.3")
	f := ie.NewFTEID(0, ie.IFTypeS11MMEC, 0xAABBCCDD, addr)

	// Per TS 29.274 Rel-15 §8.22 Figure 8.22-1:
	//   Value[0]: V4(0x80) | Interface Type(10=0x0A) = 0x8A
	//   Value[1-4]: TEID = 0xAABBCCDD
	//   Value[5-8]: IPv4 = 10.1.2.3
	want := []byte{0x8A, 0xAA, 0xBB, 0xCC, 0xDD, 10, 1, 2, 3}
	if !bytes.Equal(f.Value, want) {
		t.Errorf("F-TEID wire bytes (with IPv4):\ngot  %v\nwant %v", f.Value, want)
	}
}

// TestFTEIDWireBytesNoIPv4 verifies encoding when no IPv4 address is present.
func TestFTEIDWireBytesNoIPv4(t *testing.T) {
	// S5/S8-C SGW interface type = 6 = 0x06; no V4 bit: byte0 = 0x06
	f := ie.NewFTEID(0, ie.IFTypeS5S8CSGW, 0x12345678, netip.Addr{})

	// Per TS 29.274 Rel-15 §8.22 Figure 8.22-1:
	//   Value[0]: Interface Type(6) = 0x06 (no V4 bit)
	//   Value[1-4]: TEID = 0x12345678
	want := []byte{0x06, 0x12, 0x34, 0x56, 0x78}
	if !bytes.Equal(f.Value, want) {
		t.Errorf("F-TEID wire bytes (no IPv4):\ngot  %v\nwant %v", f.Value, want)
	}
}

func TestPAAIPv4(t *testing.T) {
	addr := netip.MustParseAddr("192.168.1.100")
	paa := ie.NewPAA(ie.PDNTypeIPv4, addr)
	got, err := paa.PAAValue()
	if err != nil {
		t.Fatal(err)
	}
	if got.PDNType != ie.PDNTypeIPv4 {
		t.Errorf("PDNType: got %d, want %d", got.PDNType, ie.PDNTypeIPv4)
	}
	if got.IPv4 != addr {
		t.Errorf("IPv4: got %v, want %v", got.IPv4, addr)
	}
}

func TestServingNetwork(t *testing.T) {
	sn := ie.NewServingNetwork("311", "435")
	mcc, mnc, err := sn.ServingNetworkValue()
	if err != nil {
		t.Fatal(err)
	}
	if mcc != "311" {
		t.Errorf("MCC: got %q, want %q", mcc, "311")
	}
	if mnc != "435" {
		t.Errorf("MNC: got %q, want %q", mnc, "435")
	}
}

func TestCauseRoundtrip(t *testing.T) {
	c := ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil)
	got, err := c.CauseValue()
	if err != nil {
		t.Fatal(err)
	}
	if got != ie.CauseRequestAccepted {
		t.Errorf("Cause: got %d, want %d", got, ie.CauseRequestAccepted)
	}
}

// TestCauseFlagByteWire verifies the Cause IE flag octet bit positions against
// TS 29.274 Rel-15 §8.4: bit 0 (LSB) = CS, bit 1 = BCE, bit 2 = PCE.
// Per C14: raw wire tests required for all non-trivial IEs.
func TestCauseFlagByteWire(t *testing.T) {
	for _, tc := range []struct {
		name         string
		pce, bce, cs uint8
		wantFlags    byte
	}{
		{"CS=1 only", 0, 0, 1, 0x01},
		{"BCE=1 only", 0, 1, 0, 0x02},
		{"PCE=1 only", 1, 0, 0, 0x04},
		{"PCE+BCE+CS", 1, 1, 1, 0x07},
		{"all zero", 0, 0, 0, 0x00},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := ie.NewCause(ie.CauseRequestAccepted, tc.pce, tc.bce, tc.cs, nil)
			// Value[0] = cause code, Value[1] = flags octet.
			if len(c.Value) < 2 {
				t.Fatalf("Cause IE value too short: %d bytes", len(c.Value))
			}
			if c.Value[1] != tc.wantFlags {
				t.Errorf("flags byte = 0x%02X; want 0x%02X (pce=%d bce=%d cs=%d)",
					c.Value[1], tc.wantFlags, tc.pce, tc.bce, tc.cs)
			}
		})
	}
}

func TestBearerContextGrouped(t *testing.T) {
	ebi := ie.NewEBI(5)
	fteid := ie.NewFTEID(0, ie.IFTypeS1USGW, 0xCAFEBABE, netip.MustParseAddr("10.1.2.3"))
	bc := ie.NewBearerContext(0, ebi, fteid)

	children, err := bc.ChildIEs()
	if err != nil {
		t.Fatalf("ChildIEs: %v", err)
	}
	if len(children) != 2 {
		t.Fatalf("expected 2 child IEs, got %d", len(children))
	}
	ebiVal, err := children[0].EBIValue()
	if err != nil {
		t.Fatal(err)
	}
	if ebiVal != 5 {
		t.Errorf("EBI: got %d, want 5", ebiVal)
	}
}

func TestSecondaryRATUsageDataReportOpaqueRoundtrip(t *testing.T) {
	raw := []byte{0x01, 0x06, 0x00, 0x11, 0x22, 0x33}
	report := ie.NewSecondaryRATUsageDataReport(raw)
	raw[0] = 0xff

	if report.Type != ie.TypeSecondaryRATUsageDataReport {
		t.Fatalf("type = %d, want %d", report.Type, ie.TypeSecondaryRATUsageDataReport)
	}
	if report.Instance != 0 {
		t.Fatalf("instance = %d, want 0", report.Instance)
	}
	want := []byte{0x01, 0x06, 0x00, 0x11, 0x22, 0x33}
	if !bytes.Equal(report.Value, want) {
		t.Fatalf("constructor did not preserve raw payload copy: got %x want %x", report.Value, want)
	}

	parsed, err := ie.ParseIEs(report.Marshal())
	if err != nil {
		t.Fatalf("ParseIEs: %v", err)
	}
	if len(parsed) != 1 {
		t.Fatalf("parsed IE count = %d, want 1", len(parsed))
	}
	got, err := parsed[0].SecondaryRATUsageDataReportValue()
	if err != nil {
		t.Fatalf("SecondaryRATUsageDataReportValue: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("payload = %x, want %x", got, want)
	}
	got[0] = 0xee
	if parsed[0].Value[0] == 0xee {
		t.Fatal("SecondaryRATUsageDataReportValue returned aliased payload")
	}
}

func TestSecondaryRATUsageDataReportRejectsWrongIEType(t *testing.T) {
	if _, err := ie.NewRATType(ie.RATTypeEUTRAN).SecondaryRATUsageDataReportValue(); err == nil {
		t.Fatal("expected error for wrong IE type")
	}
}

func TestMultipleIEsSameType(t *testing.T) {
	bc1 := ie.NewBearerContext(0, ie.NewEBI(5))
	bc2 := ie.NewBearerContext(1, ie.NewEBI(6))
	var buf []byte
	buf = append(buf, bc1.Marshal()...)
	buf = append(buf, bc2.Marshal()...)

	ies, err := ie.ParseIEs(buf)
	if err != nil {
		t.Fatal(err)
	}
	if len(ies) != 2 {
		t.Fatalf("expected 2 IEs, got %d", len(ies))
	}
	if ies[0].Instance != 0 || ies[1].Instance != 1 {
		t.Errorf("instance mismatch: %d, %d", ies[0].Instance, ies[1].Instance)
	}
}

func TestTruncatedIE(t *testing.T) {
	_, err := ie.ParseIEs([]byte{0x01, 0x00}) // header cut short
	if err == nil {
		t.Error("expected error for truncated IE header")
	}
}

// FuzzParseIEs fuzzes GTPv2-C IE parsing per C20.
// Seeds are golden wire vectors extracted from spec figures in prior phase wire tests.
// The fuzzer must not panic; returning an error is acceptable.
func FuzzParseIEs(f *testing.F) {
	// IMSI IE wire: type=1, len=8, BCD-packed "311430000000001" (TestIMSIRoundtrip)
	imsiWire := ie.NewIMSI("311430000000001").Marshal()
	f.Add(imsiWire)

	// F-TEID wire (with IPv4): type=87, len=9, flags+TEID+IP (TestFTEIDWireBytesWithIPv4)
	// §8.22 Figure 8.22-1: [0x8A,0xAA,0xBB,0xCC,0xDD,10,1,2,3]
	fTEIDWire := ie.NewFTEID(0, ie.IFTypeS11MMEC, 0xAABBCCDD, netip.MustParseAddr("10.1.2.3")).Marshal()
	f.Add(fTEIDWire)

	// Cause IE wire: type=2, len=2, cause=16, flags=0 (TestCauseFlagByteWire)
	causeWire := ie.NewCause(ie.CauseRequestAccepted, 0, 0, 0, nil).Marshal()
	f.Add(causeWire)

	// Bearer Context grouped IE with EBI child (TestBearerContextChildIEs)
	bcWire := ie.NewBearerContext(0, ie.NewEBI(5)).Marshal()
	f.Add(bcWire)

	// Truncated header — known-bad input for coverage
	f.Add([]byte{0x01, 0x00})
	// Empty input
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, b []byte) {
		_, _ = ie.ParseIEs(b)
	})
}
