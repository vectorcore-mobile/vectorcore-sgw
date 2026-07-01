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

// ARP is the Allocation/Retention Priority per TS 23.401 Rel-15 §4.7.3
// (corrected citation — was previously misattributed to §4.7.2, which is
// "The EPS bearer" general-concept clause, not the QoS parameters clause).
// §4.7.3: "The ARP shall contain information about the priority level
// (scalar), the pre-emption capability (flag) and the pre-emption
// vulnerability (flag)."
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
	// QCI (QoS Class Identifier) is a bearer-level QoS parameter per
	// TS 23.401 Rel-15 §4.7.3: "Each EPS bearer (GBR and Non-GBR) is
	// associated with the following bearer level QoS parameters:
	// - QoS Class Identifier (QCI); - Allocation and Retention Priority (ARP)."
	// §4.7.3 also states the QCI-to-standardized-characteristics mapping
	// table itself is in TS 23.203 (not present in docs/specs/ — per
	// CLAUDE.md's QoS spec table, TS 23.203 is required for "QCI table"
	// work). Not needed here: this field is stored and relayed verbatim
	// (from MME, to PGW, to SGW-U PFCP rules) and never interpreted against
	// the value table by this codebase. [TRAINING-MEMORY — unverified] would
	// apply only if/when QCI value semantics are interpreted; flagging this
	// gap now rather than waiting for that to happen silently.
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
