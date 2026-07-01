package message

import (
	"fmt"

	"vectorcore-sgw/internal/gtpv2/ie"
)

// CreateSessionRequest per TS 29.274 Section 7.2.1.
type CreateSessionRequest struct {
	Header         Header
	IMSI           *ie.IE
	MSISDN         *ie.IE
	MEI            *ie.IE
	RATType        *ie.IE
	ServingNetwork *ie.IE
	ULI            *ie.IE // User Location Information: C per Table 7.2.1-1, forwarded to PGW
	FTEID          *ie.IE // Sender F-TEID for control plane (instance 0)
	PGWFTEID       *ie.IE // PGW S5/S8 F-TEID (instance 1) — optional on S11
	APN            *ie.IE
	PDNType        *ie.IE
	PAA            *ie.IE
	AMBR           *ie.IE
	PCO            *ie.IE // Protocol Configuration Options: C per Table 7.2.1-1, forwarded to PGW
	APNRestriction *ie.IE // C per Table 7.2.1-1, forwarded to PGW when present
	UETimeZone     *ie.IE // C per Table 7.2.1-1, forwarded to PGW when present
	ChargingChars  *ie.IE // C per Table 7.2.1-1, forwarded to PGW when present
	SelectionMode  *ie.IE // C per Table 7.2.1-1 — forwarded verbatim to PGW
	BearerContexts []*ie.IE
	Indication     *ie.IE
	Recovery       *ie.IE
	PTI            *ie.IE
}

// ParseCreateSessionRequest decodes a Create Session Request.
func ParseCreateSessionRequest(h Header, ies []*ie.IE) (*CreateSessionRequest, error) {
	req := &CreateSessionRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeIMSI:
			req.IMSI = i
		case ie.TypeMSISDN:
			req.MSISDN = i
		case ie.TypeMEI:
			req.MEI = i
		case ie.TypeRATType:
			req.RATType = i
		case ie.TypeServingNetwork:
			req.ServingNetwork = i
		case ie.TypeULI:
			req.ULI = i
		case ie.TypeFTEID:
			if i.Instance == 0 {
				req.FTEID = i
			} else if i.Instance == 1 {
				req.PGWFTEID = i
			}
		case ie.TypeAPN:
			req.APN = i
		case ie.TypePDNType:
			req.PDNType = i
		case ie.TypePAA:
			req.PAA = i
		case ie.TypeAMBR:
			req.AMBR = i
		case ie.TypePCO:
			req.PCO = i
		case ie.TypeAPNRestriction:
			req.APNRestriction = i
		case ie.TypeUETimeZone:
			req.UETimeZone = i
		case ie.TypeChargingChars:
			req.ChargingChars = i
		case ie.TypeSelectionMode:
			req.SelectionMode = i
		case ie.TypeBearerContext:
			req.BearerContexts = append(req.BearerContexts, i)
		case ie.TypeIndication:
			req.Indication = i
		case ie.TypeRecovery:
			req.Recovery = i
		case ie.TypePTI:
			req.PTI = i
		}
	}
	if err := req.validate(); err != nil {
		return nil, err
	}
	return req, nil
}

// validate checks that all mandatory IEs per TS 29.274 Rel-15 Table 7.2.1-1 are present.
// Default Bearer Context contents are validated per Rel-15 Table 7.2.1-2.
func (req *CreateSessionRequest) validate() error {
	// IMSI: C per Rel-15 Table 7.2.1-1 — may be absent for unauthenticated (emergency) UEs.
	// MEI: C — used as the session identifier when IMSI is absent.
	// At least one UE identifier must be present.
	if req.IMSI == nil && req.MEI == nil {
		return &MissingIEError{IEType: ie.TypeIMSI, MsgType: MsgTypeCreateSessionRequest}
	}
	if req.RATType == nil {
		return &MissingIEError{IEType: ie.TypeRATType, MsgType: MsgTypeCreateSessionRequest}
	}
	if req.FTEID == nil {
		return &MissingIEError{IEType: ie.TypeFTEID, MsgType: MsgTypeCreateSessionRequest}
	}
	if req.APN == nil {
		return &MissingIEError{IEType: ie.TypeAPN, MsgType: MsgTypeCreateSessionRequest}
	}
	if req.PDNType == nil {
		return &MissingIEError{IEType: ie.TypePDNType, MsgType: MsgTypeCreateSessionRequest}
	}
	if len(req.BearerContexts) == 0 {
		return &MissingIEError{IEType: ie.TypeBearerContext, MsgType: MsgTypeCreateSessionRequest}
	}
	// EBI and Bearer Level QoS: both M within default Bearer Context per Rel-15 Table 7.2.1-2.
	children, err := req.BearerContexts[0].ChildIEs()
	if err != nil || ie.FindFirst(children, ie.TypeEBI) == nil {
		return &MissingIEError{IEType: ie.TypeEBI, MsgType: MsgTypeCreateSessionRequest}
	}
	if ie.FindFirst(children, ie.TypeBearerQoS) == nil {
		return &MissingIEError{IEType: ie.TypeBearerQoS, MsgType: MsgTypeCreateSessionRequest}
	}
	return nil
}

// CreateSessionResponse per TS 29.274 Section 7.2.2.
type CreateSessionResponse struct {
	Header         Header
	Cause          *ie.IE
	FTEID          *ie.IE // SGW S11 F-TEID (instance 0)
	PGWFTEID       *ie.IE // PGW S5/S8-C F-TEID (instance 1)
	PAA            *ie.IE
	AMBR           *ie.IE
	PCO            *ie.IE
	APNRestriction *ie.IE
	ChargingID     *ie.IE
	BearerContexts []*ie.IE
	Recovery       *ie.IE
}

// ParseCreateSessionResponse decodes a Create Session Response.
func ParseCreateSessionResponse(h Header, ies []*ie.IE) (*CreateSessionResponse, error) {
	resp := &CreateSessionResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeCause:
			resp.Cause = i
		case ie.TypeFTEID:
			if i.Instance == 0 {
				resp.FTEID = i
			} else if i.Instance == 1 {
				resp.PGWFTEID = i
			}
		case ie.TypePAA:
			resp.PAA = i
		case ie.TypeAMBR:
			resp.AMBR = i
		case ie.TypePCO:
			resp.PCO = i
		case ie.TypeAPNRestriction:
			resp.APNRestriction = i
		case ie.TypeChargingID:
			resp.ChargingID = i
		case ie.TypeBearerContext:
			resp.BearerContexts = append(resp.BearerContexts, i)
		case ie.TypeRecovery:
			resp.Recovery = i
		}
	}
	if resp.Cause == nil {
		return nil, &MissingIEError{IEType: ie.TypeCause, MsgType: MsgTypeCreateSessionResponse}
	}
	return resp, nil
}

// MarshalCreateSessionResponse builds a Create Session Response wire message.
//
// Per TS 29.274 Section 5.5.1, the TEID in a response header must be the
// receiver's TEID — i.e., the MME's S11 control TEID. On an initial attach
// the CSReq arrives with header TEID=0 (SGW TEID not yet assigned), so
// req.Header.TEID must NOT be used. The MME's TEID is extracted from the
// Sender F-TEID IE (instance 0) in the CSReq.
func MarshalCreateSessionResponse(req *CreateSessionRequest, cause uint8, ies ...*ie.IE) ([]byte, error) {
	var mmeTEID uint32
	if req.FTEID != nil {
		if f, err := req.FTEID.FTEIDValue(); err == nil {
			mmeTEID = f.TEID
		}
	}
	h := Header{
		Version:        2,
		HasTEID:        true, // CSResp always carries the MME's TEID
		MessageType:    MsgTypeCreateSessionResponse,
		TEID:           mmeTEID,
		SequenceNumber: req.Header.SequenceNumber,
	}
	allIEs := append([]*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)}, ies...)
	return Marshal(h, allIEs)
}

// MissingIEError is returned when a mandatory IE is absent.
type MissingIEError struct {
	IEType  uint8
	MsgType uint8
}

func (e *MissingIEError) Error() string {
	return fmt.Sprintf("mandatory IE type %d missing in message type %d", e.IEType, e.MsgType)
}
