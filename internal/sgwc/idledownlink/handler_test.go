package idledownlink

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"testing"
	"time"

	pfcpie "vectorcore-sgw/internal/pfcp/ie"
	"vectorcore-sgw/internal/sgwc/bearer"
	"vectorcore-sgw/internal/sgwc/ddncontrol"
	"vectorcore-sgw/internal/sgwc/session"
)

type fakeDDNSender struct {
	calls    int
	sessions []*session.SGWSession
}

func (f *fakeDDNSender) SendDownlinkDataNotification(context.Context, *session.SGWSession) (uint32, error) {
	f.calls++
	return uint32(0x1000 + f.calls), nil
}

func newTestHandler(t *testing.T, apn string, qci uint8) (*Handler, *fakeDDNSender, *session.SGWSession) {
	t.Helper()
	mgr := session.NewManager()
	sess, _, err := mgr.Create(session.CreateParams{
		IMSI:           "311435300070599",
		APN:            apn,
		RATType:        6,
		ServingNetwork: "311-435",
		MMEControlFTEID: session.FTEID{
			TEID: 0x11223344,
			IPv4: netip.MustParseAddr("10.90.250.77"),
		},
		DefaultEBI: 6,
		QCI:        qci,
		ARP:        bearer.ARP{PriorityLevel: 1},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	sess.SetPFCPBinding(session.PFCPSessionBinding{
		LocalFSEID:  session.FSEID{SEID: 1001, IPv4: netip.MustParseAddr("10.90.250.10")},
		SGWUFSEID:   session.FSEID{SEID: 2002, IPv4: netip.MustParseAddr("10.90.251.10")},
		SGWUName:    "sgwu-a",
		SGWUAddr:    "10.90.251.10:8805",
		Established: true,
	})
	ddn := &fakeDDNSender{}
	h := New(mgr, Config{
		Enabled:                  true,
		TriggerDDN:               true,
		ReportThrottle:           10 * time.Second,
		RequireReleaseAccessDrop: true,
		HighPriority:             []ddncontrol.PriorityRule{{APN: "ims", Reason: "ims-idle-downlink"}},
		Suppress:                 []ddncontrol.PriorityRule{{APN: "internet", QCI: 9, Reason: "internet-suppressed"}},
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	h.SetDDNSender(ddn)
	h.SetDDNControl(ddncontrol.NewState(ddncontrol.Config{Enabled: false}))
	return h, ddn, sess
}

func TestHandlerTriggersDDNForIMSIdleDownlink(t *testing.T) {
	h, ddn, sess := newTestHandler(t, "ims", 5)
	h.HandleReport("10.90.251.10:8805", pfcpie.VectorCoreIdleDownlinkReport{
		CPSEID:     1001,
		UPSEID:     2002,
		PDRID:      1,
		FARID:      2,
		LocalTEID:  0x01020304,
		EBI:        6,
		QCI:        5,
		QoSValid:   true,
		DropReason: pfcpie.VectorCoreIdleDownlinkDropReleaseAccessBearers,
	})
	if ddn.calls != 1 {
		t.Fatalf("DDN calls = %d; want 1", ddn.calls)
	}
	status := sess.MMERestorationSnapshot()
	if !status.DDNTriggered || status.DDNSequence != 0x1001 {
		t.Fatalf("DDN status = %+v; want triggered seq 0x1001", status)
	}
}

func TestHandlerSuppressesInternetIdleDownlink(t *testing.T) {
	h, ddn, _ := newTestHandler(t, "internet", 9)
	h.HandleReport("10.90.251.10:8805", pfcpie.VectorCoreIdleDownlinkReport{
		CPSEID:     1001,
		UPSEID:     2002,
		EBI:        6,
		QCI:        9,
		QoSValid:   true,
		DropReason: pfcpie.VectorCoreIdleDownlinkDropReleaseAccessBearers,
	})
	if ddn.calls != 0 {
		t.Fatalf("DDN calls = %d; want 0 for suppressed internet", ddn.calls)
	}
}

func TestHandlerThrottlesDuplicateIdleDownlinkReport(t *testing.T) {
	h, ddn, _ := newTestHandler(t, "ims", 5)
	report := pfcpie.VectorCoreIdleDownlinkReport{
		CPSEID:     1001,
		UPSEID:     2002,
		EBI:        6,
		QCI:        5,
		QoSValid:   true,
		DropReason: pfcpie.VectorCoreIdleDownlinkDropReleaseAccessBearers,
	}
	h.HandleReport("10.90.251.10:8805", report)
	h.HandleReport("10.90.251.10:8805", report)
	if ddn.calls != 1 {
		t.Fatalf("DDN calls = %d; want duplicate throttled", ddn.calls)
	}
}
