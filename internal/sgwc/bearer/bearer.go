// Package bearer holds the SGW-C bearer state model per 3GPP TS 23.401.
package bearer

import "net/netip"

// BearerState is the lifecycle state of a bearer.
type BearerState string

const (
	BearerStatePending   BearerState = "pending"
	BearerStateActive    BearerState = "active"
	BearerStateModifying BearerState = "modifying"
	BearerStateDeleting  BearerState = "deleting"
	BearerStateDeleted   BearerState = "deleted"
)

// FTEID is a user-plane F-TEID stored in bearer state.
type FTEID struct {
	TEID uint32
	IPv4 netip.Addr
}

// ARP is the Allocation/Retention Priority per TS 23.401 Section 4.7.2.
type ARP struct {
	PriorityLevel        uint8 // 1-15; 1 is highest
	PreemptionCapability bool  // may this bearer preempt others?
	PreemptionVulnerability bool // may this bearer be preempted?
}

// TFT is a Traffic Flow Template per TS 23.401 Section 5.3.2 (stub for Phase 9).
type TFT struct {
	Raw []byte
}

// Bearer is the per-EPS-bearer state held in SGW-C per 3GPP TS 23.401.
type Bearer struct {
	EBI uint8
	QCI uint8
	ARP ARP

	// S1-U F-TEIDs
	ENBS1UFTEID FTEID // eNodeB's S1-U TEID (set on Modify Bearer Request)
	SGWS1UFTEID FTEID // SGW-U's S1-U TEID (set after PFCP Session Establishment)

	// S5/S8-U F-TEIDs
	PGWS5UFTEID FTEID // PGW-U's S5/S8-U TEID (set from PGW Create Session Response)
	SGWS5UFTEID FTEID // SGW-U's S5/S8-U TEID (set after PFCP, via CHOOSE bit)

	// MBR/GBR in kbps (0 = non-GBR)
	MBRUplink   uint64
	MBRDownlink uint64
	GBRUplink   uint64
	GBRDownlink uint64

	TFT   *TFT
	State BearerState

	// PFCP rule IDs for this bearer's PDR/FAR pair (uplink and downlink).
	// Index 0 = uplink (S1-U → S5/S8-U), Index 1 = downlink (S5/S8-U → S1-U).
	PDRIDs [2]uint32
	FARIDs [2]uint32
}
