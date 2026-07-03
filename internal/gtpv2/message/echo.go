package message

import "vectorcore-sgw/internal/gtpv2/ie"

// EchoRequest is a GTPv2-C Echo Request per TS 29.274 Section 7.1.1.
type EchoRequest struct {
	Header   Header
	Recovery *ie.IE
}

// EchoResponse is a GTPv2-C Echo Response per TS 29.274 Section 7.1.2.
type EchoResponse struct {
	Header   Header
	Recovery *ie.IE
}

func ParseEchoRequest(h Header, ies []*ie.IE) *EchoRequest {
	req := &EchoRequest{Header: h}
	req.Recovery = ie.FindFirst(ies, ie.TypeRecovery)
	return req
}

func ParseEchoResponse(h Header, ies []*ie.IE) *EchoResponse {
	resp := &EchoResponse{Header: h}
	resp.Recovery = ie.FindFirst(ies, ie.TypeRecovery)
	return resp
}

// MarshalEchoRequest encodes an Echo Request with the given sequence number.
func MarshalEchoRequest(seq uint32, restartCounter *uint8) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        false,
		MessageType:    MsgTypeEchoRequest,
		SequenceNumber: seq,
	}
	var ies []*ie.IE
	if restartCounter != nil {
		ies = append(ies, ie.NewRecovery(*restartCounter))
	}
	return Marshal(h, ies)
}

// MarshalEchoResponse encodes an Echo Response for the given request.
func MarshalEchoResponse(req *EchoRequest, restartCounter uint8) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        false,
		MessageType:    MsgTypeEchoResponse,
		SequenceNumber: req.Header.SequenceNumber,
	}
	ies := []*ie.IE{ie.NewRecovery(restartCounter)}
	return Marshal(h, ies)
}
