package message

import "vectorcore-sgw/internal/gtpv2/ie"

// ReleaseAccessBearersRequest per TS 29.274 Section 7.2.21.1.
// Sent by MME to SGW to release S1-U bearers when UE transitions to idle mode.
type ReleaseAccessBearersRequest struct {
	Header     Header
	Indication *ie.IE
	Recovery   *ie.IE
}

func ParseReleaseAccessBearersRequest(h Header, ies []*ie.IE) *ReleaseAccessBearersRequest {
	req := &ReleaseAccessBearersRequest{Header: h}
	for _, i := range ies {
		switch i.Type {
		case ie.TypeIndication:
			req.Indication = i
		case ie.TypeRecovery:
			req.Recovery = i
		}
	}
	return req
}

// ReleaseAccessBearersResponse per TS 29.274 Section 7.2.21.2.
type ReleaseAccessBearersResponse struct {
	Header   Header
	Cause    *ie.IE
	Recovery *ie.IE
}

// MarshalReleaseAccessBearersResponse encodes a Release Access Bearers Response.
// peerTEID is the MME's S11 control TEID per TS 29.274 Rel-15 §5.5.1.
func MarshalReleaseAccessBearersResponse(req *ReleaseAccessBearersRequest, peerTEID uint32, cause uint8) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        req.Header.HasTEID,
		MessageType:    MsgTypeReleaseAccessBearersResponse,
		TEID:           peerTEID,
		SequenceNumber: req.Header.SequenceNumber,
	}
	return Marshal(h, []*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)})
}
