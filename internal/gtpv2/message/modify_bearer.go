package message

import "vectorcore-sgw/internal/gtpv2/ie"

// ModifyBearerRequest per TS 29.274 Section 7.2.7.
type ModifyBearerRequest struct {
	Header         Header
	FTEID          *ie.IE   // Sender F-TEID (instance 0) — optional on S11 MBR
	BearerContexts []*ie.IE // Modified bearer contexts
	Indication     *ie.IE
	Recovery       *ie.IE
}

// ParseModifyBearerRequest decodes a Modify Bearer Request.
// Implements TS 29.274 Section 7.2.7 / Table 7.2.7-1.
// BearerContext (instance 0): C — conditional; may be absent in RAT-type-only
// or UE time-zone-only updates. Must NOT be rejected if absent.
func ParseModifyBearerRequest(h Header, ies []*ie.IE) (*ModifyBearerRequest, error) {
	req := &ModifyBearerRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeFTEID:
			if i.Instance == 0 {
				req.FTEID = i
			}
		case ie.TypeBearerContext:
			req.BearerContexts = append(req.BearerContexts, i)
		case ie.TypeIndication:
			req.Indication = i
		case ie.TypeRecovery:
			req.Recovery = i
		}
	}
	return req, nil
}

// ModifyBearerResponse per TS 29.274 Section 7.2.8.
type ModifyBearerResponse struct {
	Header         Header
	Cause          *ie.IE
	FTEID          *ie.IE   // SGW F-TEID (instance 0) — optional
	BearerContexts []*ie.IE
	Recovery       *ie.IE
}

func ParseModifyBearerResponse(h Header, ies []*ie.IE) (*ModifyBearerResponse, error) {
	resp := &ModifyBearerResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeCause:
			resp.Cause = i
		case ie.TypeFTEID:
			if i.Instance == 0 {
				resp.FTEID = i
			}
		case ie.TypeBearerContext:
			resp.BearerContexts = append(resp.BearerContexts, i)
		case ie.TypeRecovery:
			resp.Recovery = i
		}
	}
	if resp.Cause == nil {
		return nil, &MissingIEError{IEType: ie.TypeCause, MsgType: MsgTypeModifyBearerResponse}
	}
	return resp, nil
}

// MarshalModifyBearerResponse encodes a Modify Bearer Response.
// peerTEID is the MME's S11 control TEID per TS 29.274 Rel-15 §5.5.1 — the TEID
// assigned by the entity that will receive this response (the MME), NOT the
// request header TEID (which is the SGW's own TEID used for routing the request).
func MarshalModifyBearerResponse(req *ModifyBearerRequest, peerTEID uint32, cause uint8, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        req.Header.HasTEID,
		MessageType:    MsgTypeModifyBearerResponse,
		TEID:           peerTEID,
		SequenceNumber: req.Header.SequenceNumber,
	}
	allIEs := append([]*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)}, ies...)
	return Marshal(h, allIEs)
}
