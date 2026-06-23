// bearer.go implements Create/Update/Delete Bearer Request and Response messages
// per 3GPP TS 29.274 Rel-15 §7.2.3, §7.2.4, §7.2.9.2, §7.2.10.2, §7.2.15, §7.2.16.
package message

import (
	"fmt"

	"vectorcore-sgw/internal/gtpv2/ie"
)

// ── Create Bearer Request (MsgType=95) ───────────────────────────────────────
// Per TS 29.274 Rel-15 Table 7.2.3-1 (docs/specs/29274-f90.docx Table at para 1045).
//
// On S11 interface — SGW-C relays PGW→MME:
//   LBI (EBI inst=0):          M  — "This IE shall be included to indicate the default bearer
//                                    associated with the PDN connection"
//   Bearer Contexts (BC inst=0): M  — "Several IEs with this type and instance values shall be
//                                    included as necessary to represent a list of Bearers"
//
// Per Table 7.2.3-2 (BC children on S11):
//   EBI (inst=0):              M  — "This IE shall be set to 0"
//   Bearer TFT (inst=0):       M  — "This IE can contain both uplink and downlink packet filters"
//   S1-U SGW F-TEID (inst=0):  C  — "This IE shall be sent on the S11 interface if S1-U is used"
//   S5/8-U PGW F-TEID (inst=1):C  — "This IE shall be sent on the S4, S5/S8 and S11 interfaces"
//   Bearer QoS (inst=0):       M  — (no condition text — Mandatory per column P)

// CreateBearerRequest is a parsed Create Bearer Request message.
type CreateBearerRequest struct {
	Header
	// LBI: M per Table 7.2.3-1 — "This IE shall be included to indicate the default bearer
	// associated with the PDN connection"
	LBI *ie.IE
	// BearerContexts: M per Table 7.2.3-1 — "Several IEs with this type and instance values
	// shall be included as necessary to represent a list of Bearers"
	BearerContexts []*ie.IE
}

// ParseCreateBearerRequest decodes raw GTPv2-C bytes into a CreateBearerRequest.
// Validates M-IEs per TS 29.274 Rel-15 Table 7.2.3-1.
func ParseCreateBearerRequest(b []byte) (*CreateBearerRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeCreateBearerRequest {
		return nil, fmt.Errorf("CreateBearerRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeCreateBearerRequest)
	}
	req := &CreateBearerRequest{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeEBI && i.Instance == 0:
			req.LBI = i
		case i.Type == ie.TypeBearerContext && i.Instance == 0:
			req.BearerContexts = append(req.BearerContexts, i)
		}
	}
	if req.LBI == nil {
		return nil, fmt.Errorf("CreateBearerRequest: missing M-IE LBI (EBI inst=0) per Table 7.2.3-1")
	}
	if len(req.BearerContexts) == 0 {
		return nil, fmt.Errorf("CreateBearerRequest: missing M-IE Bearer Contexts per Table 7.2.3-1")
	}
	return req, nil
}

// MarshalCreateBearerRequest builds a Create Bearer Request wire frame.
// peerTEID is the receiver's control TEID (MME's S11 TEID per C4).
// seq is the sequence number. ies are the message-level IEs.
func MarshalCreateBearerRequest(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeCreateBearerRequest, // Table 6.1-1: 95
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}

// ── Create Bearer Response (MsgType=96) ──────────────────────────────────────
// Per TS 29.274 Rel-15 Table 7.2.4-1 (docs/specs/29274-f90.docx).
//
// On S11 interface — MME→SGW-C:
//   Cause (inst=0):             M  — (no condition)
//   Bearer Contexts (BC inst=0): M  — "All bearer contexts in the CBReq shall be included"
//
// Per Table 7.2.4-2 (BC children on S11):
//   EBI (inst=0):               M
//   Cause (inst=0):             M  — "shall indicate if the bearer handling was successful"
//   S1-U eNodeB F-TEID (inst=0):C  — "This IE shall be sent on the S11 interface if S1-U is used"
//   S1-U SGW F-TEID (inst=1):   C  — "It shall be used to correlate the bearers with those in CBReq"

// CreateBearerResponse is a parsed Create Bearer Response.
type CreateBearerResponse struct {
	Header
	// Cause: M per Table 7.2.4-1
	Cause *ie.IE
	// BearerContexts: M per Table 7.2.4-1
	BearerContexts []*ie.IE
}

// ParseCreateBearerResponse decodes raw GTPv2-C bytes into a CreateBearerResponse.
// Validates M-IEs per TS 29.274 Rel-15 Table 7.2.4-1.
func ParseCreateBearerResponse(b []byte) (*CreateBearerResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeCreateBearerResponse {
		return nil, fmt.Errorf("CreateBearerResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeCreateBearerResponse)
	}
	resp := &CreateBearerResponse{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeCause && i.Instance == 0:
			resp.Cause = i
		case i.Type == ie.TypeBearerContext && i.Instance == 0:
			resp.BearerContexts = append(resp.BearerContexts, i)
		}
	}
	if resp.Cause == nil {
		return nil, fmt.Errorf("CreateBearerResponse: missing M-IE Cause per Table 7.2.4-1")
	}
	if len(resp.BearerContexts) == 0 {
		return nil, fmt.Errorf("CreateBearerResponse: missing M-IE Bearer Contexts per Table 7.2.4-1")
	}
	return resp, nil
}

// MarshalCreateBearerResponse builds a Create Bearer Response wire frame.
// peerTEID is the receiver's control TEID (PGW's S5/S8-C TEID per C4).
func MarshalCreateBearerResponse(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeCreateBearerResponse, // Table 6.1-1: 96
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}

// ── Update Bearer Request (MsgType=97) ───────────────────────────────────────
// Per TS 29.274 Rel-15 Table 7.2.15-1 (docs/specs/29274-f90.docx).
//
// On S11 interface — SGW-C relays PGW→MME:
//   Bearer Contexts (BC inst=0): M  — "shall contain contexts related to bearers needing QoS/TFT modification"
//   APN-AMBR (AMBR inst=0):     M  — "APN-AMBR"
//
// Per Table 7.2.15-2 (BC children):
//   EBI (inst=0):               M
//   TFT (Bearer TFT inst=0):    C  — "shall be included if message relates to TFT change"
//   Bearer QoS (inst=0):        C  — "shall be included if QoS modification is requested"

// UpdateBearerRequest is a parsed Update Bearer Request.
type UpdateBearerRequest struct {
	Header
	// BearerContexts: M per Table 7.2.15-1
	BearerContexts []*ie.IE
	// AMBR: M per Table 7.2.15-1 — "APN-AMBR"
	AMBR *ie.IE
}

// ParseUpdateBearerRequest decodes raw GTPv2-C bytes into an UpdateBearerRequest.
func ParseUpdateBearerRequest(b []byte) (*UpdateBearerRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeUpdateBearerRequest {
		return nil, fmt.Errorf("UpdateBearerRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeUpdateBearerRequest)
	}
	req := &UpdateBearerRequest{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeBearerContext && i.Instance == 0:
			req.BearerContexts = append(req.BearerContexts, i)
		case i.Type == ie.TypeAMBR && i.Instance == 0:
			req.AMBR = i
		}
	}
	if len(req.BearerContexts) == 0 {
		return nil, fmt.Errorf("UpdateBearerRequest: missing M-IE Bearer Contexts per Table 7.2.15-1")
	}
	if req.AMBR == nil {
		return nil, fmt.Errorf("UpdateBearerRequest: missing M-IE APN-AMBR per Table 7.2.15-1")
	}
	return req, nil
}

// MarshalUpdateBearerRequest builds an Update Bearer Request wire frame.
func MarshalUpdateBearerRequest(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeUpdateBearerRequest, // Table 6.1-1: 97
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}

// ── Update Bearer Response (MsgType=98) ──────────────────────────────────────
// Per TS 29.274 Rel-15 Table 7.2.16-1 (docs/specs/29274-f90.docx).
//
// On S11 interface — MME→SGW-C:
//   Cause (inst=0):             M
//   Bearer Contexts (BC inst=0): M  — "shall contain all bearer contexts in the Update Bearer Request"
//
// Per Table 7.2.16-2 (BC children):
//   EBI (inst=0):               M
//   Cause (inst=0):             M  — "indicates if the bearer handling was successful"

// UpdateBearerResponse is a parsed Update Bearer Response.
type UpdateBearerResponse struct {
	Header
	// Cause: M per Table 7.2.16-1
	Cause *ie.IE
	// BearerContexts: M per Table 7.2.16-1
	BearerContexts []*ie.IE
}

// ParseUpdateBearerResponse decodes raw GTPv2-C bytes into an UpdateBearerResponse.
func ParseUpdateBearerResponse(b []byte) (*UpdateBearerResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeUpdateBearerResponse {
		return nil, fmt.Errorf("UpdateBearerResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeUpdateBearerResponse)
	}
	resp := &UpdateBearerResponse{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeCause && i.Instance == 0:
			resp.Cause = i
		case i.Type == ie.TypeBearerContext && i.Instance == 0:
			resp.BearerContexts = append(resp.BearerContexts, i)
		}
	}
	if resp.Cause == nil {
		return nil, fmt.Errorf("UpdateBearerResponse: missing M-IE Cause per Table 7.2.16-1")
	}
	if len(resp.BearerContexts) == 0 {
		return nil, fmt.Errorf("UpdateBearerResponse: missing M-IE Bearer Contexts per Table 7.2.16-1")
	}
	return resp, nil
}

// MarshalUpdateBearerResponse builds an Update Bearer Response wire frame.
func MarshalUpdateBearerResponse(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeUpdateBearerResponse, // Table 6.1-1: 98
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}

// ── Delete Bearer Request (MsgType=99) ───────────────────────────────────────
// Per TS 29.274 Rel-15 Table 7.2.9.2-1 (docs/specs/29274-f90.docx).
//
// On S11 interface — SGW-C relays PGW→MME:
//   LBI (EBI inst=0):           C  — "shall be included when deleting the default bearer;
//                                     only when EPS Bearer IDs is not present"
//   EBIs (EBI inst=1):          C  — "shall be included for deleting dedicated bearers;
//                                     only when Linked EPS Bearer ID is not present.
//                                     Several IEs with this type and instance values"
// One of LBI or EBIs MUST be present.

// DeleteBearerRequest is a parsed Delete Bearer Request.
type DeleteBearerRequest struct {
	Header
	// LBI: C per Table 7.2.9.2-1 — "If the request corresponds to the bearer deactivation
	// procedure in case all bearers belonging to a PDN connection shall be released, then this
	// IE shall be included on the S5/S8, S4/S11 and S2a/S2b interfaces"
	LBI *ie.IE
	// EBIs: C per Table 7.2.9.2-1 — "This IE shall be included on S5/S8, S4/S11 and S2a/S2b
	// interfaces for deleting bearers different from the default one, i.e. for dedicated bearers"
	EBIs []*ie.IE
}

// ParseDeleteBearerRequest decodes raw GTPv2-C bytes into a DeleteBearerRequest.
// Validates that at least one of LBI or EBIs is present per Table 7.2.9.2-1.
func ParseDeleteBearerRequest(b []byte) (*DeleteBearerRequest, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeDeleteBearerRequest {
		return nil, fmt.Errorf("DeleteBearerRequest: wrong message type %d (want %d)", h.MessageType, MsgTypeDeleteBearerRequest)
	}
	req := &DeleteBearerRequest{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeEBI && i.Instance == 0:
			req.LBI = i
		case i.Type == ie.TypeEBI && i.Instance == 1:
			req.EBIs = append(req.EBIs, i)
		}
	}
	if req.LBI == nil && len(req.EBIs) == 0 {
		return nil, fmt.Errorf("DeleteBearerRequest: neither LBI (inst=0) nor EPS Bearer IDs (inst=1) present; one is required per Table 7.2.9.2-1")
	}
	return req, nil
}

// MarshalDeleteBearerRequest builds a Delete Bearer Request wire frame.
func MarshalDeleteBearerRequest(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeDeleteBearerRequest, // Table 6.1-1: 99
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}

// ── Delete Bearer Response (MsgType=100) ─────────────────────────────────────
// Per TS 29.274 Rel-15 Table 7.2.10.2-1 (docs/specs/29274-f90.docx).
//
// On S11 interface — MME→SGW-C:
//   Cause (inst=0):             M
//   LBI (EBI inst=0):           C  — "shall be included for default bearer deactivation"
//   Bearer Contexts (BC inst=0): C  — "shall be used for dedicated bearers;
//                                     at least one dedicated bearer shall be present"

// DeleteBearerResponse is a parsed Delete Bearer Response.
type DeleteBearerResponse struct {
	Header
	// Cause: M per Table 7.2.10.2-1 — (no condition text; unconditionally present)
	Cause *ie.IE
	// LBI: C per Table 7.2.10.2-1 — "If the response corresponds to the bearer deactivation
	// procedure in case all the bearers associated with the default bearer of a PDN connection
	// shall be released, this IE shall be included on the S4/S11, S5/S8 and S2a/S2b interfaces"
	LBI *ie.IE
	// BearerContexts: C per Table 7.2.10.2-1 — "It shall be used on the S4/S11, S5/S8 and
	// S2a/S2b interfaces for bearers different from default one. In this case at least one
	// bearer shall be included."
	BearerContexts []*ie.IE
}

// ParseDeleteBearerResponse decodes raw GTPv2-C bytes into a DeleteBearerResponse.
func ParseDeleteBearerResponse(b []byte) (*DeleteBearerResponse, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeDeleteBearerResponse {
		return nil, fmt.Errorf("DeleteBearerResponse: wrong message type %d (want %d)", h.MessageType, MsgTypeDeleteBearerResponse)
	}
	resp := &DeleteBearerResponse{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeCause && i.Instance == 0:
			resp.Cause = i
		case i.Type == ie.TypeEBI && i.Instance == 0:
			resp.LBI = i
		case i.Type == ie.TypeBearerContext && i.Instance == 0:
			resp.BearerContexts = append(resp.BearerContexts, i)
		}
	}
	if resp.Cause == nil {
		return nil, fmt.Errorf("DeleteBearerResponse: missing M-IE Cause per Table 7.2.10.2-1")
	}
	return resp, nil
}

// MarshalDeleteBearerResponse builds a Delete Bearer Response wire frame.
func MarshalDeleteBearerResponse(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeDeleteBearerResponse, // Table 6.1-1: 100
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}
