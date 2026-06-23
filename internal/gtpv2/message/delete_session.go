package message

import "vectorcore-sgw/internal/gtpv2/ie"

// DeleteSessionRequest per TS 29.274 Section 7.2.9.1.
type DeleteSessionRequest struct {
	Header    Header
	Cause     *ie.IE // optional — present in SGW-to-PGW direction
	EBI       *ie.IE
	Indication *ie.IE
	Recovery  *ie.IE
}

// ParseDeleteSessionRequest decodes a Delete Session Request.
// Implements TS 29.274 Section 7.2.9.1 / Table 7.2.9.1-1.
// EBI: C — conditional; may be absent when the MME deletes by TEID alone
// (single default bearer case). Must NOT be rejected if absent.
func ParseDeleteSessionRequest(h Header, ies []*ie.IE) (*DeleteSessionRequest, error) {
	req := &DeleteSessionRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeCause:
			req.Cause = i
		case ie.TypeEBI:
			req.EBI = i
		case ie.TypeIndication:
			req.Indication = i
		case ie.TypeRecovery:
			req.Recovery = i
		}
	}
	return req, nil
}

// DeleteSessionResponse per TS 29.274 Section 7.2.9.2.
type DeleteSessionResponse struct {
	Header   Header
	Cause    *ie.IE
	Recovery *ie.IE
}

func ParseDeleteSessionResponse(h Header, ies []*ie.IE) (*DeleteSessionResponse, error) {
	resp := &DeleteSessionResponse{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeCause:
			resp.Cause = i
		case ie.TypeRecovery:
			resp.Recovery = i
		}
	}
	if resp.Cause == nil {
		return nil, &MissingIEError{IEType: ie.TypeCause, MsgType: MsgTypeDeleteSessionResponse}
	}
	return resp, nil
}

// MarshalDeleteSessionResponse encodes a Delete Session Response.
// peerTEID is the MME's S11 control TEID per TS 29.274 Rel-15 §5.5.1.
func MarshalDeleteSessionResponse(req *DeleteSessionRequest, peerTEID uint32, cause uint8) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        req.Header.HasTEID,
		MessageType:    MsgTypeDeleteSessionResponse,
		TEID:           peerTEID,
		SequenceNumber: req.Header.SequenceNumber,
	}
	return Marshal(h, []*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)})
}
