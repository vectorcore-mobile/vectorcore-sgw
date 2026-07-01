// Wire tests for GTP-U header encoding/parsing per TS 29.281 V15.7.0.
//
// C14: every golden byte vector is derived from the spec figure (§5.1 Figure 5.1-1),
//      not from encoder output.
// C17: all defined flag states for E, S, PN are exercised — both 0 and 1 for each bit.
//      The spec defines three independent flag bits; we test every combination that is
//      used in practice plus the all-set case to verify bit encoding.
//
// Octet 1 composition (from §5.1 Figure 5.1-1):
//   Version=1 → bits 8-6 = 001 → 0x20 in the byte
//   PT=1      → bit 5 = 1     → 0x10 in the byte
//   E flag    → bit 3         → 0x04
//   S flag    → bit 2         → 0x02
//   PN flag   → bit 1         → 0x01
//
// C17 Flag-state coverage:
//   State 1: E=0, S=0, PN=0  → octet1=0x30  (tested in TestGPDUNoFlagsWire)
//   State 2: E=0, S=1, PN=0  → octet1=0x32  (tested in TestEchoRequestWire, TestEchoResponseWire)
//   State 3: E=1, S=0, PN=0  → octet1=0x34  (tested in TestEFlagWire)
//   State 4: E=0, S=0, PN=1  → octet1=0x31  (tested in TestPNFlagWire)
//   State 5: E=1, S=1, PN=1  → octet1=0x37  (tested in TestAllFlagsWire)
//   States with S=1,PN=1 and others are covered transitively; all three bits 0→1 verified.
package gtpu

import (
	"bytes"
	"net/netip"
	"testing"
)

// TestGPDUNoFlagsWire verifies the minimal 8-byte GTP-U G-PDU header (E=0,S=0,PN=0).
// C17 flag state: E=0, S=0, PN=0 → octet 0 = Version(0x20)|PT(0x10) = 0x30
// Derived from §5.1 Figure 5.1-1 and §5.1 "minimum length is 8 bytes".
func TestGPDUNoFlagsWire(t *testing.T) {
	// Golden vector (spec-derived):
	//   [0] 0x30 = Version(0x20)|PT(0x10)|E(0)|S(0)|PN(0)
	//   [1] 0xFF = MsgType G-PDU (Table 6.1-1: "255 | G-PDU | GTP-U: X")
	//   [2..3] 0x00 0x00 = Length=0 (no payload, no optional fields)
	//   [4..7] 0x00 0x00 0x00 0x01 = TEID=1
	want := []byte{0x30, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}

	h := Header{Version: 1, PT: true, MsgType: MsgTypeGPDU, TEID: 1}
	got := Marshal(h, 0)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal G-PDU no-flags:\n  got  %#v\n  want %#v", got, want)
	}

	parsed, consumed, err := Parse(want)
	if err != nil {
		t.Fatalf("Parse G-PDU no-flags: %v", err)
	}
	if consumed != MinLen {
		t.Errorf("consumed = %d, want %d", consumed, MinLen)
	}
	if parsed.MsgType != MsgTypeGPDU || parsed.TEID != 1 || parsed.E || parsed.S || parsed.PN {
		t.Errorf("Parse G-PDU no-flags: unexpected fields: %+v", parsed)
	}
}

// TestEchoRequestWire verifies the Echo Request header with S=1, TEID=0, SeqNum=0x0042.
// C17 flag state: E=0, S=1, PN=0 → octet 0 = 0x30|0x02 = 0x32
// Derived from §5.1 Figure 5.1-1; S=1 required per §5.1: "For the Echo Request...S flag shall be set to '1'".
func TestEchoRequestWire(t *testing.T) {
	// Golden vector (spec-derived):
	//   [0]    0x32 = 0x20|0x10|0x02 (Version|PT|S)
	//   [1]    0x01 = MsgType Echo Request (Table 6.1-1)
	//   [2..3] 0x00 0x04 = Length=4 (optional fields only; §5.1 NOTE 4)
	//   [4..7] 0x00 0x00 0x00 0x00 = TEID=0 (§5.1: TEID=0 for Echo)
	//   [8..9] 0x00 0x42 = SeqNum=0x0042
	//   [10]   0x00 = NPDUNum=0
	//   [11]   0x00 = NextExtHdr=0
	want := []byte{0x32, 0x01, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00}

	h := Header{Version: 1, PT: true, S: true, MsgType: MsgTypeEchoRequest, TEID: 0, SeqNum: 0x0042}
	got := Marshal(h, 0)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal Echo Request:\n  got  %#v\n  want %#v", got, want)
	}

	parsed, consumed, err := Parse(want)
	if err != nil {
		t.Fatalf("Parse Echo Request: %v", err)
	}
	if consumed != MinLen+OptFieldsLen {
		t.Errorf("consumed = %d, want %d", consumed, MinLen+OptFieldsLen)
	}
	if parsed.MsgType != MsgTypeEchoRequest || parsed.TEID != 0 || parsed.SeqNum != 0x0042 || !parsed.S || parsed.E || parsed.PN {
		t.Errorf("Parse Echo Request: unexpected fields: %+v", parsed)
	}
}

// TestEchoResponseWire verifies the Echo Response wire format (MsgType=2, S=1).
// C17 flag state: S=1 (same octet1 pattern as Echo Request = 0x32).
// Derived from Table 6.1-1: "2 | Echo Response | GTP-U: X".
func TestEchoResponseWire(t *testing.T) {
	// Golden vector (spec-derived):
	//   [0]    0x32 = 0x20|0x10|0x02 (Version|PT|S)
	//   [1]    0x02 = MsgType Echo Response (Table 6.1-1)
	//   [2..3] 0x00 0x06 = Length = 4 (optional fields) + 2 (Recovery IE) = 6
	//   [4..7] 0x00 0x00 0x00 0x00 = TEID=0
	//   [8..9] 0x00 0x42 = SeqNum=0x0042 (echoed from request)
	//   [10]   0x00 = NPDUNum=0
	//   [11]   0x00 = NextExtHdr=0
	//   [12]   0x0E = IE type Recovery (Table 19: "14 | TV | Recovery | 8.2")
	//   [13]   0x00 = restart counter=0 per §7.2.2/§8.2
	want := []byte{0x32, 0x02, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x42, 0x00, 0x00, 0x0E, 0x00}

	h := Header{Version: 1, PT: true, S: true, MsgType: MsgTypeEchoResponse, TEID: 0, SeqNum: 0x0042}
	recovery := BuildRecovery()
	hdrBytes := Marshal(h, len(recovery))
	got := append(hdrBytes, recovery...)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal Echo Response:\n  got  %#v\n  want %#v", got, want)
	}
}

// TestEFlagWire verifies E=1 flag encoding in octet 0 with optional fields present.
// C17 flag state: E=1, S=0, PN=0 → octet 0 = 0x30|0x04 = 0x34
// Derived from §5.1 Figure 5.1-1: "Bit 3: E (Extension Header flag)".
func TestEFlagWire(t *testing.T) {
	// Golden vector (spec-derived):
	//   [0]    0x34 = 0x20|0x10|0x04 (Version|PT|E)
	//   [1]    0xFF = G-PDU
	//   [2..3] 0x00 0x04 = Length=4 (optional fields present because E=1)
	//   [4..7] 0xDE 0xAD 0xBE 0xEF = TEID=0xDEADBEEF
	//   [8..9] 0x00 0x00 = SeqNum=0
	//   [10]   0x00 = NPDUNum=0
	//   [11]   0x00 = NextExtHdr=0
	want := []byte{0x34, 0xFF, 0x00, 0x04, 0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00}

	h := Header{Version: 1, PT: true, E: true, MsgType: MsgTypeGPDU, TEID: 0xDEADBEEF}
	got := Marshal(h, 0)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal E-flag:\n  got  %#v\n  want %#v", got, want)
	}

	parsed, consumed, err := Parse(want)
	if err != nil {
		t.Fatalf("Parse E-flag: %v", err)
	}
	if consumed != MinLen+OptFieldsLen {
		t.Errorf("consumed = %d, want %d", consumed, MinLen+OptFieldsLen)
	}
	if !parsed.E || parsed.S || parsed.PN || parsed.TEID != 0xDEADBEEF {
		t.Errorf("Parse E-flag: unexpected: %+v", parsed)
	}
}

// TestPNFlagWire verifies PN=1 flag encoding with NPDUNum=7.
// C17 flag state: E=0, S=0, PN=1 → octet 0 = 0x30|0x01 = 0x31
// Derived from §5.1 Figure 5.1-1: "Bit 1: PN (N-PDU Number flag)".
func TestPNFlagWire(t *testing.T) {
	// Golden vector (spec-derived):
	//   [0]    0x31 = 0x20|0x10|0x01 (Version|PT|PN)
	//   [1]    0xFF = G-PDU
	//   [2..3] 0x00 0x04 = Length=4 (optional fields present because PN=1)
	//   [4..7] 0xAB 0xCD 0x12 0x34 = TEID=0xABCD1234
	//   [8..9] 0x00 0x00 = SeqNum=0
	//   [10]   0x07 = NPDUNum=7
	//   [11]   0x00 = NextExtHdr=0
	want := []byte{0x31, 0xFF, 0x00, 0x04, 0xAB, 0xCD, 0x12, 0x34, 0x00, 0x00, 0x07, 0x00}

	h := Header{Version: 1, PT: true, PN: true, MsgType: MsgTypeGPDU, TEID: 0xABCD1234, NPDUNum: 7}
	got := Marshal(h, 0)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal PN-flag:\n  got  %#v\n  want %#v", got, want)
	}

	parsed, consumed, err := Parse(want)
	if err != nil {
		t.Fatalf("Parse PN-flag: %v", err)
	}
	if consumed != MinLen+OptFieldsLen {
		t.Errorf("consumed = %d, want %d", consumed, MinLen+OptFieldsLen)
	}
	if parsed.E || parsed.S || !parsed.PN || parsed.NPDUNum != 7 || parsed.TEID != 0xABCD1234 {
		t.Errorf("Parse PN-flag: unexpected: %+v", parsed)
	}
}

// TestAllFlagsWire verifies all three flags E=1, S=1, PN=1 simultaneously.
// C17 flag state: E=1, S=1, PN=1 → octet 0 = 0x30|0x04|0x02|0x01 = 0x37
// Derived from §5.1 Figure 5.1-1: all three flag bits set at once.
func TestAllFlagsWire(t *testing.T) {
	// Golden vector (spec-derived):
	//   [0]    0x37 = 0x20|0x10|0x04|0x02|0x01 (Version|PT|E|S|PN)
	//   [1]    0xFF = G-PDU
	//   [2..3] 0x00 0x04 = Length=4
	//   [4..7] 0xCA 0xFE 0xBA 0xBE = TEID=0xCAFEBABE
	//   [8..9] 0x12 0x34 = SeqNum=0x1234
	//   [10]   0x00 = NPDUNum=0
	//   [11]   0x00 = NextExtHdr=0
	want := []byte{0x37, 0xFF, 0x00, 0x04, 0xCA, 0xFE, 0xBA, 0xBE, 0x12, 0x34, 0x00, 0x00}

	h := Header{Version: 1, PT: true, E: true, S: true, PN: true,
		MsgType: MsgTypeGPDU, TEID: 0xCAFEBABE, SeqNum: 0x1234}
	got := Marshal(h, 0)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal all-flags:\n  got  %#v\n  want %#v", got, want)
	}

	parsed, _, err := Parse(want)
	if err != nil {
		t.Fatalf("Parse all-flags: %v", err)
	}
	if !parsed.E || !parsed.S || !parsed.PN || parsed.TEID != 0xCAFEBABE || parsed.SeqNum != 0x1234 {
		t.Errorf("Parse all-flags: unexpected: %+v", parsed)
	}
}

// TestRecoveryIEWire verifies the Recovery IE wire format.
// C14: golden vector from §8.2 and Table 19.
// §8.2: TV format, type=14=0x0E, value=1 byte, restart counter=0 per §7.2.2.
func TestRecoveryIEWire(t *testing.T) {
	// Golden vector:
	//   [0] 0x0E = type 14 (Table 19: "14 | TV | Recovery | 8.2")
	//   [1] 0x00 = restart counter = 0 (§7.2.2: "shall be set to zero by the sender")
	want := []byte{0x0E, 0x00}
	got := BuildRecovery()
	if !bytes.Equal(got, want) {
		t.Errorf("BuildRecovery:\n  got  %#v\n  want %#v", got, want)
	}
}

// TestTEIDDataIIEWire verifies the Tunnel Endpoint Identifier Data I IE wire format.
// C14: golden vector from §8.3 and Table 19.
// §8.3: TV format, type=16=0x10, value=4-byte TEID big-endian.
func TestTEIDDataIIEWire(t *testing.T) {
	// Golden vector:
	//   [0]    0x10 = type 16 (Table 19: "16 | TV | Tunnel Endpoint Identifier Data I | 8.3")
	//   [1..4] 0x12 0x34 0x56 0x78 = TEID=0x12345678 big-endian
	want := []byte{0x10, 0x12, 0x34, 0x56, 0x78}
	got := BuildTEIDDataI(0x12345678)
	if !bytes.Equal(got, want) {
		t.Errorf("BuildTEIDDataI:\n  got  %#v\n  want %#v", got, want)
	}
}

// TestGTPUPeerAddressIPv4Wire verifies the GTP-U Peer Address IE for IPv4.
// C14: golden vector from §8.4 and Table 19.
// §8.4: TLV format, type=133=0x85, length=4 (IPv4), then 4-byte address.
func TestGTPUPeerAddressIPv4Wire(t *testing.T) {
	// Golden vector:
	//   [0]    0x85 = type 133 (Table 19: "133 | TLV | GSN Address (GTP-U Peer Address) | 8.4")
	//   [1..2] 0x00 0x04 = Length=4 (§8.4: "The Length field may have only two values (4 or 16)")
	//   [3..6] 0x0A 0x01 0x02 0x03 = IPv4 10.1.2.3
	want := []byte{0x85, 0x00, 0x04, 0x0A, 0x01, 0x02, 0x03}
	ip := netip.MustParseAddr("10.1.2.3")
	got, err := BuildGTPUPeerAddressIPv4(ip)
	if err != nil {
		t.Fatalf("BuildGTPUPeerAddressIPv4: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("BuildGTPUPeerAddressIPv4:\n  got  %#v\n  want %#v", got, want)
	}
}

// TestEndMarkerWire verifies EndMarker message type constant (254) encoding.
// C17 message-type coverage: test EndMarker=254 (Table 6.1-1: "254 | End Marker | GTP-U: X").
func TestEndMarkerWire(t *testing.T) {
	// Golden vector:
	//   [0]    0x30 = Version|PT, no flags
	//   [1]    0xFE = MsgType 254 = End Marker
	//   [2..3] 0x00 0x00 = Length=0
	//   [4..7] 0x00 0x00 0x00 0x05 = TEID=5
	want := []byte{0x30, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05}
	h := Header{Version: 1, PT: true, MsgType: MsgTypeEndMarker, TEID: 5}
	got := Marshal(h, 0)
	if !bytes.Equal(got, want) {
		t.Errorf("Marshal EndMarker:\n  got  %#v\n  want %#v", got, want)
	}
}

// TestErrorIndicationHeaderWire verifies the Error Indication header (MsgType=26, S=1, TEID=0).
// C17 message-type coverage: test ErrorIndication=26 (Table 6.1-1: "26 | Error Indication | GTP-U: X").
// Per §5.1: "Error Indication...the S flag shall be set to '1'".
// Per §5.1: TEID=0 for Error Indication.
func TestErrorIndicationHeaderWire(t *testing.T) {
	// Golden vector:
	//   [0]    0x32 = 0x20|0x10|0x02 (Version|PT|S)
	//   [1]    0x1A = MsgType 26 = Error Indication (Table 6.1-1)
	//   [2..3] 0x00 0x0C = Length = 4 (opt) + 5 (TEID IE) + 7 (peer addr IE) = 16? no wait:
	//          Length = OptFieldsLen(4) + TEIDDataI(5) + PeerAddr(7) = 16 → 0x00 0x10
	// Actually let me calculate: with SeqNum=0, no payload passed to Marshal(h, len(payload)):
	//   payload = TEID IE (5 bytes) + Peer Addr IE (7 bytes) = 12 bytes
	//   Length = OptFieldsLen(4) + 12 = 16 = 0x10
	//   So header bytes only (testing header + IE combo separately):
	//   Header [0..11]: [0x32, 0x1A, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]
	//   TEID Data I IE (5): [0x10, 0x00, 0x00, 0x00, 0x07] (TEID=7)
	//   Peer Address IE (7): [0x85, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01]
	teidIE := BuildTEIDDataI(7)
	peerIE, err := BuildGTPUPeerAddressIPv4(netip.MustParseAddr("10.0.0.1"))
	if err != nil {
		t.Fatalf("BuildGTPUPeerAddressIPv4: %v", err)
	}
	payload := append(teidIE, peerIE...)
	h := Header{Version: 1, PT: true, S: true, MsgType: MsgTypeErrorIndication, TEID: 0}
	hdrBytes := Marshal(h, len(payload))
	pkt := append(hdrBytes, payload...)

	wantHdr := []byte{0x32, 0x1A, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}
	wantTEID := []byte{0x10, 0x00, 0x00, 0x00, 0x07}
	wantPeer := []byte{0x85, 0x00, 0x04, 0x0A, 0x00, 0x00, 0x01}
	want := append(append(wantHdr, wantTEID...), wantPeer...)

	if !bytes.Equal(pkt, want) {
		t.Errorf("Error Indication packet:\n  got  %#v\n  want %#v", pkt, want)
	}
}

// TestParseRejectsShortPacket verifies that Parse returns an error for a truncated packet.
func TestParseRejectsShortPacket(t *testing.T) {
	_, _, err := Parse([]byte{0x30, 0xFF, 0x00})
	if err == nil {
		t.Error("Parse: expected error for short packet, got nil")
	}
}

// TestParseRejectsDeclaredLengthExceedsBuffer verifies the R15-REAUDIT-002 bounds check:
// per TS 29.281 §5.1, Parse() must reject packets where MinLen + declared Length > len(b).
// C14: golden vector with Length=100 but buffer only 8 bytes → totalDeclared=108 > 8.
func TestParseRejectsDeclaredLengthExceedsBuffer(t *testing.T) {
	// Golden vector:
	//   [0]    0x30 = Version|PT, no flags
	//   [1]    0xFF = G-PDU
	//   [2..3] 0x00 0x64 = Length=100 (declared; would need 108-byte buffer)
	//   [4..7] 0x00 0x00 0x00 0x01 = TEID=1
	// Buffer is only 8 bytes but declares 100 bytes of payload → must error.
	bad := []byte{0x30, 0xFF, 0x00, 0x64, 0x00, 0x00, 0x00, 0x01}
	_, _, err := Parse(bad)
	if err == nil {
		t.Error("Parse: expected error when declared Length exceeds buffer, got nil")
	}
}

// TestParseExtensionHeaderChain verifies R15-REAUDIT-003: Parse() walks the extension header
// chain per TS 29.281 §5.2 when E=1 and NextExtHdr != 0.
// C14: golden vector derived from §5.2 extension header structure:
//
//	Each extension header: [Length (1 byte, in 4-byte units)] [Content] [Next Type (1 byte)]
//
// Test encodes one extension header (4 bytes) terminating with Next Type = 0x00.
func TestParseExtensionHeaderChain(t *testing.T) {
	// Golden vector (spec-derived from §5.1 Figure 5.1-1 and §5.2):
	//   Bytes 0-7: mandatory header
	//     [0]    0x34 = Version(0x20)|PT(0x10)|E(0x04) — E=1, NextExtHdr will be non-zero
	//     [1]    0xFF = G-PDU
	//     [2..3] 0x00 0x08 = Length=8 (opt fields 4 + ext hdr 4 = 8 bytes after mandatory 8)
	//     [4..7] 0x00 0x00 0x00 0x01 = TEID=1
	//   Bytes 8-11: optional fields (present because E=1)
	//     [8..9] 0x00 0x00 = SeqNum=0
	//     [10]   0x00 = NPDUNum=0
	//     [11]   0x03 = NextExtHdr=0x03 (non-zero → extension header chain present)
	//   Bytes 12-15: first (and only) extension header per §5.2:
	//     [12]   0x01 = Length=1 (in 4-octet units → 4 bytes total for this header)
	//     [13]   0xDE = content byte 1
	//     [14]   0xAD = content byte 2
	//     [15]   0x00 = Next Extension Header Type=0x00 (end of chain)
	wire := []byte{
		0x34, 0xFF, 0x00, 0x08, // octet1|MsgType|Length
		0x00, 0x00, 0x00, 0x01, // TEID=1
		0x00, 0x00,             // SeqNum=0
		0x00,                   // NPDUNum=0
		0x03,                   // NextExtHdr=0x03 (chain present)
		0x01, 0xDE, 0xAD, 0x00, // ExtHdr: Length=1(4B), content=[0xDE,0xAD], Next=0x00
	}

	h, consumed, err := Parse(wire)
	if err != nil {
		t.Fatalf("Parse extension header chain: %v", err)
	}
	// consumed must cover mandatory(8) + optional(4) + ext header(4) = 16 bytes.
	if consumed != 16 {
		t.Errorf("consumed = %d; want 16", consumed)
	}
	if !h.E {
		t.Error("E flag = false; want true")
	}
	if h.NextExtHdr != 0x03 {
		t.Errorf("NextExtHdr = 0x%02X; want 0x03", h.NextExtHdr)
	}
	// ExtHeaders must contain the raw extension header bytes per §5.2.
	wantExt := []byte{0x01, 0xDE, 0xAD, 0x00}
	if len(h.ExtHeaders) != len(wantExt) {
		t.Fatalf("ExtHeaders length = %d; want %d", len(h.ExtHeaders), len(wantExt))
	}
	for i, b := range wantExt {
		if h.ExtHeaders[i] != b {
			t.Errorf("ExtHeaders[%d] = 0x%02X; want 0x%02X", i, h.ExtHeaders[i], b)
		}
	}
}

// TestParseRejectsWrongVersion verifies that Parse rejects version != 1.
func TestParseRejectsWrongVersion(t *testing.T) {
	// Octet 0: Version=2 (bits 8-6 = 010) → 0x40 | PT=1 → 0x50
	bad := []byte{0x50, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	_, _, err := Parse(bad)
	if err == nil {
		t.Error("Parse: expected error for version=2, got nil")
	}
}

// TestParseRejectsPTZero verifies that Parse rejects PT=0 (GTP' protocol).
func TestParseRejectsPTZero(t *testing.T) {
	// Octet 0: Version=1 (0x20), PT=0 → 0x20 (no PT bit)
	bad := []byte{0x20, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}
	_, _, err := Parse(bad)
	if err == nil {
		t.Error("Parse: expected error for PT=0, got nil")
	}
}
