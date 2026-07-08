package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	"vectorcore-sgw/internal/sgwc/session"
	"vectorcore-sgw/internal/sgwc/sessioncheckpoint"
)

type SessionRecoveryStatusReader interface {
	Status() sessioncheckpoint.RuntimeStatus
}

type SessionRecoveryMetrics struct {
	status   SessionRecoveryStatusReader
	sessions interface {
		List() []*session.SGWSession
	}

	checkpointEnabled     *prometheus.Desc
	sessionsLoaded        *prometheus.Desc
	sessionsRestored      *prometheus.Desc
	peerSnapshotsLoaded   *prometheus.Desc
	gtpcPeersRestored     *prometheus.Desc
	pfcpPeersRestored     *prometheus.Desc
	flushes               *prometheus.Desc
	flushFailures         *prometheus.Desc
	sessionSaves          *prometheus.Desc
	sessionDeletes        *prometheus.Desc
	peerSaves             *prometheus.Desc
	sessionsByState       *prometheus.Desc
	reconciliationByState *prometheus.Desc
	repairPlansByAction   *prometheus.Desc
}

func NewSessionRecoveryMetrics(reg *prometheus.Registry, status SessionRecoveryStatusReader, sessions interface {
	List() []*session.SGWSession
}) *SessionRecoveryMetrics {
	m := &SessionRecoveryMetrics{
		status:   status,
		sessions: sessions,
		checkpointEnabled: prometheus.NewDesc(
			"sgwc_checkpoint_enabled",
			"Whether SGW-C session checkpointing is enabled.",
			nil,
			nil,
		),
		sessionsLoaded: prometheus.NewDesc(
			"sgwc_checkpoint_sessions_loaded",
			"Number of session snapshots loaded from checkpoint storage at startup.",
			nil,
			nil,
		),
		sessionsRestored: prometheus.NewDesc(
			"sgwc_checkpoint_sessions_restored",
			"Number of session snapshots restored at startup.",
			nil,
			nil,
		),
		peerSnapshotsLoaded: prometheus.NewDesc(
			"sgwc_checkpoint_peer_snapshots_loaded",
			"Number of peer Recovery IE snapshots loaded from checkpoint storage at startup.",
			nil,
			nil,
		),
		gtpcPeersRestored: prometheus.NewDesc(
			"sgwc_checkpoint_gtpc_peers_restored",
			"Number of GTP-C peer Recovery IE snapshots restored at startup.",
			nil,
			nil,
		),
		pfcpPeersRestored: prometheus.NewDesc(
			"sgwc_checkpoint_pfcp_peers_restored",
			"Number of PFCP peer Recovery Time Stamp snapshots restored at startup.",
			nil,
			nil,
		),
		flushes: prometheus.NewDesc(
			"sgwc_checkpoint_flushes_total",
			"Total SGW-C checkpoint writer flush attempts.",
			nil,
			nil,
		),
		flushFailures: prometheus.NewDesc(
			"sgwc_checkpoint_flush_failures_total",
			"Total SGW-C checkpoint writer flush failures.",
			nil,
			nil,
		),
		sessionSaves: prometheus.NewDesc(
			"sgwc_checkpoint_session_saves_total",
			"Total session snapshots saved by the SGW-C checkpoint writer.",
			nil,
			nil,
		),
		sessionDeletes: prometheus.NewDesc(
			"sgwc_checkpoint_session_deletes_total",
			"Total session snapshots deleted by the SGW-C checkpoint writer.",
			nil,
			nil,
		),
		peerSaves: prometheus.NewDesc(
			"sgwc_checkpoint_peer_saves_total",
			"Total peer Recovery IE snapshots saved by the SGW-C checkpoint writer.",
			nil,
			nil,
		),
		sessionsByState: prometheus.NewDesc(
			"sgwc_recovery_sessions",
			"Current SGW-C sessions by recovery/session state.",
			[]string{"state"},
			nil,
		),
		reconciliationByState: prometheus.NewDesc(
			"sgwc_pfcp_reconciliation_sessions",
			"Current SGW-C sessions by PFCP reconciliation state.",
			[]string{"state"},
			nil,
		),
		repairPlansByAction: prometheus.NewDesc(
			"sgwc_pfcp_repair_plan_sessions",
			"Current SGW-C sessions by PFCP repair plan action.",
			[]string{"action"},
			nil,
		),
	}
	if reg != nil {
		reg.MustRegister(m)
	}
	return m
}

func (m *SessionRecoveryMetrics) Describe(ch chan<- *prometheus.Desc) {
	ch <- m.checkpointEnabled
	ch <- m.sessionsLoaded
	ch <- m.sessionsRestored
	ch <- m.peerSnapshotsLoaded
	ch <- m.gtpcPeersRestored
	ch <- m.pfcpPeersRestored
	ch <- m.flushes
	ch <- m.flushFailures
	ch <- m.sessionSaves
	ch <- m.sessionDeletes
	ch <- m.peerSaves
	ch <- m.sessionsByState
	ch <- m.reconciliationByState
	ch <- m.repairPlansByAction
}

func (m *SessionRecoveryMetrics) Collect(ch chan<- prometheus.Metric) {
	if m == nil {
		return
	}
	status := sessioncheckpoint.RuntimeStatus{}
	if m.status != nil {
		status = m.status.Status()
	}
	enabled := 0.0
	if status.Enabled {
		enabled = 1
	}
	ch <- prometheus.MustNewConstMetric(m.checkpointEnabled, prometheus.GaugeValue, enabled)
	ch <- prometheus.MustNewConstMetric(m.sessionsLoaded, prometheus.GaugeValue, float64(status.SessionsLoaded))
	ch <- prometheus.MustNewConstMetric(m.sessionsRestored, prometheus.GaugeValue, float64(status.SessionsRestored))
	ch <- prometheus.MustNewConstMetric(m.peerSnapshotsLoaded, prometheus.GaugeValue, float64(status.PeerSnapshotsLoaded))
	ch <- prometheus.MustNewConstMetric(m.gtpcPeersRestored, prometheus.GaugeValue, float64(status.GTPCPeersRestored))
	ch <- prometheus.MustNewConstMetric(m.pfcpPeersRestored, prometheus.GaugeValue, float64(status.PFCPPeersRestored))
	ch <- prometheus.MustNewConstMetric(m.flushes, prometheus.CounterValue, float64(status.Flushes))
	ch <- prometheus.MustNewConstMetric(m.flushFailures, prometheus.CounterValue, float64(status.FlushFailures))
	ch <- prometheus.MustNewConstMetric(m.sessionSaves, prometheus.CounterValue, float64(status.SessionSaves))
	ch <- prometheus.MustNewConstMetric(m.sessionDeletes, prometheus.CounterValue, float64(status.SessionDeletes))
	ch <- prometheus.MustNewConstMetric(m.peerSaves, prometheus.CounterValue, float64(status.PeerSaves))

	sessionStates := make(map[string]int)
	reconciliationStates := make(map[string]int)
	repairActions := make(map[string]int)
	if m.sessions != nil {
		for _, sess := range m.sessions.List() {
			sessionStates[string(sess.GetState())]++
			reconciliationStates[string(sess.PFCPReconciliationSnapshot().State)]++
			repairActions[string(sess.PFCPRepairPlan().Action)]++
		}
	}
	for state, count := range sessionStates {
		ch <- prometheus.MustNewConstMetric(m.sessionsByState, prometheus.GaugeValue, float64(count), state)
	}
	for state, count := range reconciliationStates {
		ch <- prometheus.MustNewConstMetric(m.reconciliationByState, prometheus.GaugeValue, float64(count), state)
	}
	for action, count := range repairActions {
		ch <- prometheus.MustNewConstMetric(m.repairPlansByAction, prometheus.GaugeValue, float64(count), action)
	}
}
