package message_test

import (
	"net/netip"
	"testing"

	"vectorcore-sgw/internal/gtpv2/ie"
	"vectorcore-sgw/internal/gtpv2/message"
)

func TestDownlinkDataNotificationConstantsAndResponsePair(t *testing.T) {
	if message.MsgTypeDownlinkDataNotificationFailureIndication != 70 {
		t.Fatalf("DDN Failure Indication type = %d; want 70", message.MsgTypeDownlinkDataNotificationFailureIndication)
	}
	if message.MsgTypeStopPagingIndication != 73 {
		t.Fatalf("Stop Paging Indication type = %d; want 73", message.MsgTypeStopPagingIndication)
	}
	if message.MsgTypeDownlinkDataNotification != 176 {
		t.Fatalf("DDN type = %d; want 176", message.MsgTypeDownlinkDataNotification)
	}
	if message.MsgTypeDownlinkDataNotificationAck != 177 {
		t.Fatalf("DDN Ack type = %d; want 177", message.MsgTypeDownlinkDataNotificationAck)
	}
	resp, ok := message.ResponseTypeFor(message.MsgTypeDownlinkDataNotification)
	if !ok || resp != message.MsgTypeDownlinkDataNotificationAck {
		t.Fatalf("ResponseTypeFor(DDN) = %d,%v; want DDN Ack,true", resp, ok)
	}
	req, ok := message.RequestTypeForResponse(message.MsgTypeDownlinkDataNotificationAck)
	if !ok || req != message.MsgTypeDownlinkDataNotification {
		t.Fatalf("RequestTypeForResponse(DDN Ack) = %d,%v; want DDN,true", req, ok)
	}
}

func TestDownlinkDataNotificationRoundTripNTSRFields(t *testing.T) {
	wire, err := message.MarshalDownlinkDataNotification(
		0x801E0006,
		0x123456,
		ie.NewEBI(7),
		&ie.IE{Type: ie.TypeARP, Value: []byte{0x10}},
		ie.NewIMSI("311435300070599"),
		ie.NewFTEID(0, ie.IFTypeS11S4SGW, 0x737063B4, netip.MustParseAddr("10.90.250.59")),
	)
	if err != nil {
		t.Fatalf("MarshalDownlinkDataNotification: %v", err)
	}
	ddn, err := message.ParseDownlinkDataNotification(wire)
	if err != nil {
		t.Fatalf("ParseDownlinkDataNotification: %v", err)
	}
	if ddn.MessageType != message.MsgTypeDownlinkDataNotification || ddn.TEID != 0x801E0006 {
		t.Fatalf("header type/teid = %d/0x%08X; want 176/0x801E0006", ddn.MessageType, ddn.TEID)
	}
	if len(ddn.EBIs) != 1 {
		t.Fatalf("EBIs = %d; want 1", len(ddn.EBIs))
	}
	ebi, err := ddn.EBIs[0].EBIValue()
	if err != nil || ebi != 7 {
		t.Fatalf("EBI = %d err=%v; want 7,nil", ebi, err)
	}
	imsi, err := ddn.IMSI.IMSI()
	if err != nil || imsi != "311435300070599" {
		t.Fatalf("IMSI = %q err=%v; want 311435300070599,nil", imsi, err)
	}
	fteid, err := ddn.SenderFTEID.FTEIDValue()
	if err != nil {
		t.Fatalf("Sender F-TEID decode: %v", err)
	}
	if fteid.IntfType != ie.IFTypeS11S4SGW || fteid.TEID != 0x737063B4 || fteid.IPv4.String() != "10.90.250.59" {
		t.Fatalf("Sender F-TEID = %+v; want S11/S4 SGW 0x737063B4 10.90.250.59", fteid)
	}
}

func TestDownlinkDataNotificationAckRequiresCauseAndAllowsTEIDZero(t *testing.T) {
	rawMissingCause, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDownlinkDataNotificationAck,
		TEID:           0,
		SequenceNumber: 0x100,
	}, []*ie.IE{ie.NewIMSI("311435300070599")})
	if err != nil {
		t.Fatalf("Marshal missing-cause DDN Ack: %v", err)
	}
	if _, err := message.ParseDownlinkDataNotificationAck(rawMissingCause); err == nil {
		t.Fatal("expected missing Cause error for DDN Ack")
	}

	ddn := &message.DownlinkDataNotification{Header: message.Header{SequenceNumber: 0x100}}
	wire, err := message.MarshalDownlinkDataNotificationAck(
		ddn,
		0,
		ie.CauseRequestAccepted,
		ie.NewRecovery(25),
		&ie.IE{Type: ie.TypeDelayValue, Value: []byte{3}},
		&ie.IE{Type: ie.TypeThrottling, Value: []byte{40, 180}},
		ie.NewIMSI("311435300070599"),
	)
	if err != nil {
		t.Fatalf("MarshalDownlinkDataNotificationAck: %v", err)
	}
	ack, err := message.ParseDownlinkDataNotificationAck(wire)
	if err != nil {
		t.Fatalf("ParseDownlinkDataNotificationAck: %v", err)
	}
	if ack.TEID != 0 {
		t.Fatalf("DDN Ack TEID = 0x%08X; want 0 for older-peer interoperability", ack.TEID)
	}
	cause, err := ack.Cause.CauseValue()
	if err != nil || cause != ie.CauseRequestAccepted {
		t.Fatalf("Cause = %d err=%v; want accepted,nil", cause, err)
	}
	if ack.Recovery == nil || ack.DataNotificationDelay == nil || ack.LowPriorityTrafficThrottling == nil || ack.IMSI == nil {
		t.Fatalf("DDN Ack optional fields missing: recovery=%v delay=%v throttling=%v imsi=%v",
			ack.Recovery != nil, ack.DataNotificationDelay != nil, ack.LowPriorityTrafficThrottling != nil, ack.IMSI != nil)
	}
}

func TestDownlinkDataNotificationFailureIndicationRequiresCause(t *testing.T) {
	rawMissingCause, err := message.Marshal(message.Header{
		Version:        2,
		HasTEID:        true,
		MessageType:    message.MsgTypeDownlinkDataNotificationFailureIndication,
		TEID:           0x737063B4,
		SequenceNumber: 0x101,
	}, []*ie.IE{ie.NewIMSI("311435300070599")})
	if err != nil {
		t.Fatalf("Marshal missing-cause DDN Failure: %v", err)
	}
	if _, err := message.ParseDownlinkDataNotificationFailureIndication(rawMissingCause); err == nil {
		t.Fatal("expected missing Cause error for DDN Failure Indication")
	}

	wire, err := message.MarshalDownlinkDataNotificationFailureIndication(
		0x737063B4,
		0x101,
		ie.CauseRequestRejected,
		&ie.IE{Type: ie.TypeNodeType, Value: []byte{0}},
		ie.NewIMSI("311435300070599"),
	)
	if err != nil {
		t.Fatalf("MarshalDownlinkDataNotificationFailureIndication: %v", err)
	}
	ind, err := message.ParseDownlinkDataNotificationFailureIndication(wire)
	if err != nil {
		t.Fatalf("ParseDownlinkDataNotificationFailureIndication: %v", err)
	}
	if ind.Cause == nil || ind.OriginatingNode == nil || ind.IMSI == nil {
		t.Fatalf("DDN Failure fields missing: cause=%v node=%v imsi=%v", ind.Cause != nil, ind.OriginatingNode != nil, ind.IMSI != nil)
	}
}

func TestStopPagingIndicationRoundTrip(t *testing.T) {
	wire, err := message.MarshalStopPagingIndication(0x801E0006, 0x102, ie.NewIMSI("311435300070599"))
	if err != nil {
		t.Fatalf("MarshalStopPagingIndication: %v", err)
	}
	ind, err := message.ParseStopPagingIndication(wire)
	if err != nil {
		t.Fatalf("ParseStopPagingIndication: %v", err)
	}
	if ind.MessageType != message.MsgTypeStopPagingIndication || ind.TEID != 0x801E0006 {
		t.Fatalf("header type/teid = %d/0x%08X; want 73/0x801E0006", ind.MessageType, ind.TEID)
	}
	imsi, err := ind.IMSI.IMSI()
	if err != nil || imsi != "311435300070599" {
		t.Fatalf("IMSI = %q err=%v; want 311435300070599,nil", imsi, err)
	}
}
