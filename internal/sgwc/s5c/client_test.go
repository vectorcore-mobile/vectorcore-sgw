package s5c

import (
	"net/netip"
	"testing"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/session"
)

// TestBuildCSReqMandatoryIEs verifies that buildCSReq produces a wire message
// containing all M (mandatory) IEs per TS 29.274 Rel-15 Table 7.2.1-1, S5/S8-C column.
// Specifically: RAT Type (M), Sender F-TEID inst 0 (M), APN (M), PDN Type (M),
// PAA (M), AMBR (M), Bearer Context inst 0 (M with EBI + BearerQoS).
func TestBuildCSReqMandatoryIEs(t *testing.T) {
	s11req := makeS11CSReq(t)
	sgwIP, _ := netip.ParseAddr("10.1.0.1")
	const sgwS5CTEID = 0xABCD1234

	raw, err := buildCSReq(s11req, sgwS5CTEID, sgwIP, 42, nil, bearer.FTEID{})
	if err != nil {
		t.Fatalf("buildCSReq: %v", err)
	}

	h, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.MessageType != message.MsgTypeCreateSessionRequest {
		t.Errorf("MessageType = %d; want %d", h.MessageType, message.MsgTypeCreateSessionRequest)
	}
	// Header TEID must be 0 on initial CSReq (PGW TEID unknown) per §5.5.1.
	if h.TEID != 0 {
		t.Errorf("header TEID = 0x%08X; want 0x00000000", h.TEID)
	}
	if h.SequenceNumber != 42 {
		t.Errorf("SequenceNumber = %d; want 42", h.SequenceNumber)
	}

	// Verify mandatory IEs per Table 7.2.1-1.
	for _, tc := range []struct {
		name     string
		ieType   uint8
		instance uint8
	}{
		{"RAT Type (M)", ie.TypeRATType, 0},
		{"Sender F-TEID inst 0 (M)", ie.TypeFTEID, 0},
		{"APN (M)", ie.TypeAPN, 0},
		{"PDN Type (M)", ie.TypePDNType, 0},
		{"PAA (M)", ie.TypePAA, 0},
		{"AMBR (M)", ie.TypeAMBR, 0},
		{"Bearer Context inst 0 (M)", ie.TypeBearerContext, 0},
	} {
		if ie.FindInstance(ies, tc.ieType, tc.instance) == nil {
			t.Errorf("mandatory IE missing: %s (type %d inst %d)", tc.name, tc.ieType, tc.instance)
		}
	}
}

// TestBuildCSReqSenderFTEIDWire verifies the Sender F-TEID wire encoding in the
// S5/S8-C CSReq per TS 29.274 §8.22 Figure 8.22-1.
//
// Expected wire layout for instance=0, IFType=IFTypeS5S8CSGW(6), TEID=0xABCD1234, IP=10.1.0.1:
//   Value[0] = 0x80 | 0x06 = 0x86  (V4=1, InterfaceType=6)
//   Value[1-4] = 0xAB, 0xCD, 0x12, 0x34
//   Value[5-8] = 10, 1, 0, 1
func TestBuildCSReqSenderFTEIDWire(t *testing.T) {
	s11req := makeS11CSReq(t)
	sgwIP, _ := netip.ParseAddr("10.1.0.1")
	const sgwS5CTEID = 0xABCD1234

	raw, err := buildCSReq(s11req, sgwS5CTEID, sgwIP, 1, nil, bearer.FTEID{})
	if err != nil {
		t.Fatalf("buildCSReq: %v", err)
	}

	_, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	fteidIE := ie.FindInstance(ies, ie.TypeFTEID, 0)
	if fteidIE == nil {
		t.Fatal("Sender F-TEID (instance 0) not found")
	}

	// Per §8.22 Figure 8.22-1: Value[0] = V4(bit7) | IfType(bits5-0).
	want := []byte{
		0x80 | ie.IFTypeS5S8CSGW, // 0x86: V4=1, InterfaceType=6
		0xAB, 0xCD, 0x12, 0x34,   // TEID big-endian
		10, 1, 0, 1,               // IPv4
	}
	if len(fteidIE.Value) != len(want) {
		t.Fatalf("F-TEID value length = %d; want %d", len(fteidIE.Value), len(want))
	}
	for i, b := range want {
		if fteidIE.Value[i] != b {
			t.Errorf("F-TEID Value[%d] = 0x%02X; want 0x%02X", i, fteidIE.Value[i], b)
		}
	}
}

// TestBuildCSReqHeaderTEIDZero verifies the header TEID is 0 on the initial
// Create Session Request to PGW, per TS 29.274 §5.5.1 (PGW TEID not yet known).
func TestBuildCSReqHeaderTEIDZero(t *testing.T) {
	s11req := makeS11CSReq(t)
	sgwIP, _ := netip.ParseAddr("10.1.0.1")

	raw, err := buildCSReq(s11req, 0xDEADBEEF, sgwIP, 1, nil, bearer.FTEID{})
	if err != nil {
		t.Fatalf("buildCSReq: %v", err)
	}
	h, _, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.TEID != 0 {
		t.Errorf("header TEID = 0x%08X; want 0x00000000 (§5.5.1)", h.TEID)
	}
}

// TestBuildCSReqConditionalIEsForwarded verifies that Conditional IEs (IMSI, MSISDN, MEI,
// Serving Network, ULI, PCO) are forwarded when present in the S11 CSReq, and
// absent from the S5/S8-C CSReq when not present.
func TestBuildCSReqConditionalIEsForwarded(t *testing.T) {
	s11req := makeS11CSReq(t)
	s11req.ULI = &ie.IE{Type: ie.TypeULI, Value: []byte{0x01, 0x02}} // stub ULI
	s11req.PCO = &ie.IE{Type: ie.TypePCO, Value: []byte{0x80, 0x00}} // stub PCO

	sgwIP, _ := netip.ParseAddr("10.1.0.1")
	raw, err := buildCSReq(s11req, 0x1111, sgwIP, 1, nil, bearer.FTEID{})
	if err != nil {
		t.Fatalf("buildCSReq: %v", err)
	}
	_, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	for _, tc := range []struct {
		name   string
		ieType uint8
		want   bool
	}{
		{"IMSI (C, present)", ie.TypeIMSI, true},
		{"MSISDN (C, absent)", ie.TypeMSISDN, false},
		{"MEI (C, absent)", ie.TypeMEI, false},
		{"Serving Network (C, present)", ie.TypeServingNetwork, true},
		{"ULI (C, present)", ie.TypeULI, true},
		{"PCO (C, present)", ie.TypePCO, true},
	} {
		found := ie.FindFirst(ies, tc.ieType) != nil
		if found != tc.want {
			if tc.want {
				t.Errorf("%s: IE not forwarded but should be", tc.name)
			} else {
				t.Errorf("%s: IE unexpectedly present", tc.name)
			}
		}
	}
}

// TestBuildCSReqNoUserPlaneFTEID verifies that S5/S8-U SGW F-TEID is NOT included
// in the bearer context when the PFCP-allocated TEID is zero.
func TestBuildCSReqNoUserPlaneFTEID(t *testing.T) {
	s11req := makeS11CSReq(t)
	sgwIP, _ := netip.ParseAddr("10.1.0.1")

	raw, err := buildCSReq(s11req, 0x1234, sgwIP, 1, nil, bearer.FTEID{}) // zero FTEID → omit
	if err != nil {
		t.Fatalf("buildCSReq: %v", err)
	}
	_, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	bcIE := ie.FindInstance(ies, ie.TypeBearerContext, 0)
	if bcIE == nil {
		t.Fatal("Bearer Context not found")
	}
	children, err := bcIE.ChildIEs()
	if err != nil {
		t.Fatalf("ChildIEs: %v", err)
	}

	// TEID=0: no FTEID in bearer context.
	if ie.FindFirst(children, ie.TypeFTEID) != nil {
		t.Error("Bearer Context contains F-TEID — must be omitted when SGW-U TEID is zero")
	}
	if ie.FindFirst(children, ie.TypeEBI) == nil {
		t.Error("Bearer Context missing EBI (M per Table 7.2.1-2)")
	}
	if ie.FindFirst(children, ie.TypeBearerQoS) == nil {
		t.Error("Bearer Context missing Bearer Level QoS (M per Table 7.2.1-2)")
	}
}

// TestBuildCSReqWithUserPlaneFTEID verifies that the S5/S8-U SGW F-TEID (instance 2)
// IS included in the bearer context when the PFCP provisional session has allocated a TEID.
// R15-REAUDIT-001: SGW-U S5/S8-U TEID required per Table 7.2.1-2 on S5/S8-C interface.
func TestBuildCSReqWithUserPlaneFTEID(t *testing.T) {
	s11req := makeS11CSReq(t)
	sgwIP, _ := netip.ParseAddr("10.1.0.1")
	sgwUS5UFTEID := bearer.FTEID{TEID: 0xDEADBEEF, IPv4: mustParseAddr("10.2.0.1")}

	raw, err := buildCSReq(s11req, 0x1234, sgwIP, 1, nil, sgwUS5UFTEID)
	if err != nil {
		t.Fatalf("buildCSReq: %v", err)
	}
	_, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}

	bcIE := ie.FindInstance(ies, ie.TypeBearerContext, 0)
	if bcIE == nil {
		t.Fatal("Bearer Context not found")
	}
	children, err := bcIE.ChildIEs()
	if err != nil {
		t.Fatalf("ChildIEs: %v", err)
	}

	// R15-REAUDIT-001: S5/S8-U SGW F-TEID must be present as instance 2 per Table 7.2.1-2.
	fteidIE := ie.FindInstance(children, ie.TypeFTEID, 2)
	if fteidIE == nil {
		t.Fatal("Bearer Context missing S5/S8-U SGW F-TEID (instance 2) per Table 7.2.1-2")
	}
	f, err := fteidIE.FTEIDValue()
	if err != nil {
		t.Fatalf("FTEIDValue: %v", err)
	}
	if f.TEID != sgwUS5UFTEID.TEID {
		t.Errorf("S5/S8-U SGW F-TEID TEID = 0x%08X; want 0x%08X", f.TEID, sgwUS5UFTEID.TEID)
	}
	if f.IPv4 != sgwUS5UFTEID.IPv4 {
		t.Errorf("S5/S8-U SGW F-TEID IPv4 = %v; want %v", f.IPv4, sgwUS5UFTEID.IPv4)
	}
	// Verify interface type = S5S8USGW per Table 7.2.1-2.
	if len(fteidIE.Value) < 1 || (fteidIE.Value[0]&0x3F) != ie.IFTypeS5S8USGW {
		t.Errorf("S5/S8-U SGW F-TEID interface type wrong: got 0x%02X, want 0x%02X",
			fteidIE.Value[0]&0x3F, ie.IFTypeS5S8USGW)
	}
}

// TestBuildDSReqWire verifies buildDSReq sets header TEID = PGW S5/S8-C TEID
// per TS 29.274 §5.5.1 and includes EBI per Table 7.2.9.1-1.
func TestBuildDSReqWire(t *testing.T) {
	const pgwTEID = 0xCAFEBABE
	const ebi = 5

	sess := makeSession(pgwTEID, ebi)
	raw, err := buildDSReq(sess, 77, nil)
	if err != nil {
		t.Fatalf("buildDSReq: %v", err)
	}

	h, ies, err := message.Parse(raw)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if h.MessageType != message.MsgTypeDeleteSessionRequest {
		t.Errorf("MessageType = %d; want %d", h.MessageType, message.MsgTypeDeleteSessionRequest)
	}
	// Header TEID = PGW's S5/S8-C TEID per §5.5.1.
	if h.TEID != pgwTEID {
		t.Errorf("header TEID = 0x%08X; want 0x%08X", h.TEID, pgwTEID)
	}
	ebiIE := ie.FindFirst(ies, ie.TypeEBI)
	if ebiIE == nil {
		t.Fatal("EBI IE missing from DSReq (C per Table 7.2.9.1-1)")
	}
	got, _ := ebiIE.EBIValue()
	if got != ebi {
		t.Errorf("EBI = %d; want %d", got, ebi)
	}
}

// ── helpers ──────────────────────────────────────────────────────────────────

func makeS11CSReq(t *testing.T) *message.CreateSessionRequest {
	t.Helper()
	hdr := message.Header{
		Version:     2,
		HasTEID:     true,
		MessageType: message.MsgTypeCreateSessionRequest,
		TEID:        0,
		SequenceNumber: 1,
	}
	ies := []*ie.IE{
		ie.NewIMSI("001010000000001"),
		ie.NewRATType(ie.RATTypeEUTRAN),
		ie.NewServingNetwork("001", "01"),
		ie.NewSelectionMode(0), // R15-REAUDIT-007: required for E-UTRAN initial attach
		ie.NewFTEID(0, ie.IFTypeS11MMEC, 0x11223344, mustParseAddr("192.168.1.1")),
		ie.NewAPN("internet"),
		ie.NewPDNType(ie.PDNTypeIPv4),
		ie.NewPAA(ie.PDNTypeIPv4, netip.Addr{}),
		ie.NewAMBR(100000, 100000),
		ie.NewBearerContext(0,
			ie.NewEBI(5),
			ie.NewBearerQoS(0, 9, 0, 9, 0, 0, 0, 0),
		),
	}
	req, err := message.ParseCreateSessionRequest(hdr, ies)
	if err != nil {
		t.Fatalf("makeS11CSReq: %v", err)
	}
	return req
}

func makeSession(pgwTEID uint32, ebi uint8) *session.SGWSession {
	return &session.SGWSession{
		PGWControlFTEID: session.FTEID{
			TEID: pgwTEID,
			IPv4: mustParseAddr("172.16.0.1"),
		},
		DefaultBearerID: ebi,
	}
}

func mustParseAddr(s string) netip.Addr {
	a, _ := netip.ParseAddr(s)
	return a
}
