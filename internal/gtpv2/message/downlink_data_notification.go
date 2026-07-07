package message

import (
	"fmt"

	"vectorcore-sgw/internal/gtpv2/ie"
)

// DownlinkDataNotification is the SGW-to-MME/S4-SGSN trigger used by
// TS 23.401 network triggered service request and TS 23.007 network triggered
// service restoration. See TS 29.274 Rel-15 §7.2.11.1.
type DownlinkDataNotification struct {
	Header
	Cause       *ie.IE
	EBIs        []*ie.IE
	ARP         *ie.IE
	IMSI        *ie.IE
	SenderFTEID *ie.IE
	Indication  *ie.IE
	PagingInfo  []*ie.IE
}

func ParseDownlinkDataNotification(b []byte) (*DownlinkDataNotification, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeDownlinkDataNotification {
		return nil, fmt.Errorf("DownlinkDataNotification: wrong message type %d (want %d)", h.MessageType, MsgTypeDownlinkDataNotification)
	}
	req := &DownlinkDataNotification{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeCause && i.Instance == 0:
			req.Cause = i
		case i.Type == ie.TypeEBI && i.Instance == 0:
			req.EBIs = append(req.EBIs, i)
		case i.Type == ie.TypeARP && i.Instance == 0:
			req.ARP = i
		case i.Type == ie.TypeIMSI && i.Instance == 0:
			req.IMSI = i
		case i.Type == ie.TypeFTEID && i.Instance == 0:
			req.SenderFTEID = i
		case i.Type == ie.TypeIndication && i.Instance == 0:
			req.Indication = i
		case i.Type == ie.TypePagingAndServiceInformation && i.Instance == 0:
			req.PagingInfo = append(req.PagingInfo, i)
		}
	}
	return req, nil
}

func MarshalDownlinkDataNotification(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeDownlinkDataNotification,
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}

// DownlinkDataNotificationAck is the MME/S4-SGSN response to DDN.
// Cause is mandatory per TS 29.274 Rel-15 §7.2.11.2.
type DownlinkDataNotificationAck struct {
	Header
	Cause                        *ie.IE
	DataNotificationDelay        *ie.IE
	Recovery                     *ie.IE
	LowPriorityTrafficThrottling *ie.IE
	IMSI                         *ie.IE
	DLBufferingDuration          *ie.IE
	DLBufferingSuggestedPktCount *ie.IE
}

func ParseDownlinkDataNotificationAck(b []byte) (*DownlinkDataNotificationAck, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeDownlinkDataNotificationAck {
		return nil, fmt.Errorf("DownlinkDataNotificationAck: wrong message type %d (want %d)", h.MessageType, MsgTypeDownlinkDataNotificationAck)
	}
	resp := &DownlinkDataNotificationAck{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeCause && i.Instance == 0:
			resp.Cause = i
		case i.Type == ie.TypeDelayValue && i.Instance == 0:
			resp.DataNotificationDelay = i
		case i.Type == ie.TypeRecovery && i.Instance == 0:
			resp.Recovery = i
		case i.Type == ie.TypeThrottling && i.Instance == 0:
			resp.LowPriorityTrafficThrottling = i
		case i.Type == ie.TypeIMSI && i.Instance == 0:
			resp.IMSI = i
		case i.Type == ie.TypeEPCTimer && i.Instance == 0:
			resp.DLBufferingDuration = i
		case i.Type == ie.TypeIntegerNumber && i.Instance == 0:
			resp.DLBufferingSuggestedPktCount = i
		}
	}
	if resp.Cause == nil {
		return nil, fmt.Errorf("DownlinkDataNotificationAck: missing M-IE Cause per Table 7.2.11.2-1")
	}
	return resp, nil
}

func MarshalDownlinkDataNotificationAck(req *DownlinkDataNotification, peerTEID uint32, cause uint8, ies ...*ie.IE) ([]byte, error) {
	allIEs := append([]*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)}, ies...)
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeDownlinkDataNotificationAck,
		TEID:           peerTEID,
		SequenceNumber: req.Header.SequenceNumber,
	}
	return Marshal(h, allIEs)
}

// DownlinkDataNotificationFailureIndication reports paging/service failure
// from MME/S4-SGSN to SGW per TS 29.274 Rel-15 §7.2.11.3.
type DownlinkDataNotificationFailureIndication struct {
	Header
	Cause           *ie.IE
	OriginatingNode *ie.IE
	IMSI            *ie.IE
}

func ParseDownlinkDataNotificationFailureIndication(b []byte) (*DownlinkDataNotificationFailureIndication, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeDownlinkDataNotificationFailureIndication {
		return nil, fmt.Errorf("DownlinkDataNotificationFailureIndication: wrong message type %d (want %d)", h.MessageType, MsgTypeDownlinkDataNotificationFailureIndication)
	}
	ind := &DownlinkDataNotificationFailureIndication{Header: h}
	for _, i := range ies {
		switch {
		case i.Type == ie.TypeCause && i.Instance == 0:
			ind.Cause = i
		case i.Type == ie.TypeNodeType && i.Instance == 0:
			ind.OriginatingNode = i
		case i.Type == ie.TypeIMSI && i.Instance == 0:
			ind.IMSI = i
		}
	}
	if ind.Cause == nil {
		return nil, fmt.Errorf("DownlinkDataNotificationFailureIndication: missing M-IE Cause per Table 7.2.11.3-1")
	}
	return ind, nil
}

func MarshalDownlinkDataNotificationFailureIndication(peerTEID, seq uint32, cause uint8, ies ...*ie.IE) ([]byte, error) {
	allIEs := append([]*ie.IE{ie.NewCause(cause, 0, 0, 0, nil)}, ies...)
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeDownlinkDataNotificationFailureIndication,
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, allIEs)
}

// StopPagingIndication is sent by SGW to MME/S4-SGSN during NTSR with ISR,
// see TS 29.274 Rel-15 §7.2.23.
type StopPagingIndication struct {
	Header
	IMSI *ie.IE
}

func ParseStopPagingIndication(b []byte) (*StopPagingIndication, error) {
	h, ies, err := Parse(b)
	if err != nil {
		return nil, err
	}
	if h.MessageType != MsgTypeStopPagingIndication {
		return nil, fmt.Errorf("StopPagingIndication: wrong message type %d (want %d)", h.MessageType, MsgTypeStopPagingIndication)
	}
	ind := &StopPagingIndication{Header: h}
	ind.IMSI = ie.FindFirst(ies, ie.TypeIMSI)
	return ind, nil
}

func MarshalStopPagingIndication(peerTEID, seq uint32, ies ...*ie.IE) ([]byte, error) {
	h := Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    MsgTypeStopPagingIndication,
		TEID:           peerTEID,
		SequenceNumber: seq,
	}
	return Marshal(h, ies)
}
