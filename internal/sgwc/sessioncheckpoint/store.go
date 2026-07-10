// Package sessioncheckpoint defines the durable SGW-C session recovery contract.
//
// Phase 1 intentionally contains backend-neutral types only. The first concrete
// backend is SQLite, but the Store interface keeps the later Redis/etcd HA path
// from leaking into SGW-C session code.
package sessioncheckpoint

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"time"

	"vectorcore-sgw/internal/sgwc/bearer"
)

const (
	// CurrentSchemaVersion identifies the JSON snapshot schema stored by
	// checkpoint backends. Bump this when restore-incompatible fields change.
	CurrentSchemaVersion = 1

	BackendSQLite = "sqlite"
	BackendRedis  = "redis"
	BackendEtcd   = "etcd"
)

var (
	ErrNotFound           = errors.New("session checkpoint not found")
	ErrUnsupportedBackend = errors.New("unsupported session checkpoint backend")
)

// Store is the durable state backend used by SGW-C restart recovery.
type Store interface {
	SaveSession(ctx context.Context, snapshot SessionSnapshot) error
	DeleteSession(ctx context.Context, sessionID string) error
	LoadSession(ctx context.Context, sessionID string) (SessionSnapshot, error)
	LoadSessions(ctx context.Context) ([]SessionSnapshot, error)
	SavePeer(ctx context.Context, snapshot PeerSnapshot) error
	DeletePeer(ctx context.Context, role, addr string) error
	LoadPeers(ctx context.Context) ([]PeerSnapshot, error)
	Close() error
}

// SessionSnapshot is the durable subset of SGW-C session state. It intentionally
// omits mutexes, transaction trackers, timers, sockets, and goroutine-local state.
type SessionSnapshot struct {
	SchemaVersion      int                        `json:"schema_version"`
	SessionID          string                     `json:"session_id"`
	IMSI               string                     `json:"imsi"`
	APN                string                     `json:"apn"`
	RATType            uint8                      `json:"rat_type"`
	ServingNetwork     string                     `json:"serving_network"`
	MMEControlFTEID    FTEIDSnapshot              `json:"mme_control_fteid"`
	SGWS11FTEID        FTEIDSnapshot              `json:"sgw_s11_fteid"`
	PGWControlFTEID    FTEIDSnapshot              `json:"pgw_control_fteid"`
	SGWS5CFTEID        FTEIDSnapshot              `json:"sgw_s5c_fteid"`
	UEIPv4             string                     `json:"ue_ipv4,omitempty"`
	DefaultBearerID    uint8                      `json:"default_bearer_id"`
	Bearers            []BearerSnapshot           `json:"bearers"`
	PFCP               PFCPSessionBindingSnapshot `json:"pfcp"`
	PFCPReconciliation PFCPReconciliationSnapshot `json:"pfcp_reconciliation"`
	PGWFailure         PGWFailureSnapshot         `json:"pgw_failure"`
	MMERestoration     MMERestorationSnapshot     `json:"mme_restoration"`
	State              string                     `json:"state"`
	CreatedAt          time.Time                  `json:"created_at"`
	UpdatedAt          time.Time                  `json:"updated_at"`
	NextRuleID         uint32                     `json:"next_rule_id"`
}

type FTEIDSnapshot struct {
	TEID uint32 `json:"teid"`
	IPv4 string `json:"ipv4,omitempty"`
}

type PFCPSessionBindingSnapshot struct {
	LocalFSEID  FSEIDSnapshot `json:"local_fseid"`
	SGWUFSEID   FSEIDSnapshot `json:"sgwu_fseid"`
	SGWUName    string        `json:"sgwu_name"`
	SGWUAddr    string        `json:"sgwu_addr"`
	Established bool          `json:"established"`
}

type FSEIDSnapshot struct {
	SEID uint64 `json:"seid"`
	IPv4 string `json:"ipv4,omitempty"`
}

type PFCPReconciliationSnapshot struct {
	State  string    `json:"state"`
	At     time.Time `json:"at,omitempty"`
	Reason string    `json:"reason,omitempty"`
}

type PGWFailureSnapshot struct {
	PathState         string    `json:"path_state"`
	PGWAddr           string    `json:"pgw_addr"`
	PathDownAt        time.Time `json:"path_down_at,omitempty"`
	RestartDetectedAt time.Time `json:"restart_detected_at,omitempty"`
	RecoverySeen      bool      `json:"recovery_seen"`
	RecoveryCounter   uint8     `json:"recovery_counter"`
}

type MMERestorationSnapshot struct {
	State               string    `json:"state"`
	MMEAddr             string    `json:"mme_addr"`
	PathDownAt          time.Time `json:"path_down_at,omitempty"`
	RestartDetectedAt   time.Time `json:"restart_detected_at,omitempty"`
	RecoverySeen        bool      `json:"recovery_seen"`
	RecoveryCounter     uint8     `json:"recovery_counter"`
	RestorationPending  bool      `json:"restoration_pending"`
	PolicyAction        string    `json:"policy_action"`
	PolicyReason        string    `json:"policy_reason"`
	DDNTriggered        bool      `json:"ddn_triggered"`
	DDNTriggeredAt      time.Time `json:"ddn_triggered_at,omitempty"`
	DDNSequence         uint32    `json:"ddn_sequence"`
	DDNAcked            bool      `json:"ddn_acked"`
	DDNAckedAt          time.Time `json:"ddn_acked_at,omitempty"`
	DDNAckCause         uint8     `json:"ddn_ack_cause"`
	DDNFailureAt        time.Time `json:"ddn_failure_at,omitempty"`
	DDNFailureCause     uint8     `json:"ddn_failure_cause"`
	DDNFailureReason    string    `json:"ddn_failure_reason"`
	DDNControlAction    string    `json:"ddn_control_action"`
	DDNControlPriority  string    `json:"ddn_control_priority"`
	DDNControlReason    string    `json:"ddn_control_reason"`
	DDNControlRetryAt   time.Time `json:"ddn_control_retry_at,omitempty"`
	DDNControlDecidedAt time.Time `json:"ddn_control_decided_at,omitempty"`
	StopPagingSent      bool      `json:"stop_paging_sent"`
	StopPagingSentAt    time.Time `json:"stop_paging_sent_at,omitempty"`
	StopPagingSequence  uint32    `json:"stop_paging_sequence"`
	UserPlaneRestored   bool      `json:"user_plane_restored"`
	UserPlaneRestoredAt time.Time `json:"user_plane_restored_at,omitempty"`
	RestoredEBI         uint8     `json:"restored_ebi"`
}

type BearerSnapshot struct {
	EBI                     uint8              `json:"ebi"`
	QCI                     uint8              `json:"qci"`
	ARP                     bearer.ARP         `json:"arp"`
	ENBS1UFTEID             FTEIDSnapshot      `json:"enb_s1u_fteid"`
	SGWS1UFTEID             FTEIDSnapshot      `json:"sgw_s1u_fteid"`
	PGWS5UFTEID             FTEIDSnapshot      `json:"pgw_s5u_fteid"`
	SGWS5UFTEID             FTEIDSnapshot      `json:"sgw_s5u_fteid"`
	MBRUplink               uint64             `json:"mbr_uplink"`
	MBRDownlink             uint64             `json:"mbr_downlink"`
	GBRUplink               uint64             `json:"gbr_uplink"`
	GBRDownlink             uint64             `json:"gbr_downlink"`
	TFTRaw                  []byte             `json:"tft_raw,omitempty"`
	State                   bearer.BearerState `json:"state"`
	PDRIDs                  [2]uint32          `json:"pdr_ids"`
	FARIDs                  [2]uint32          `json:"far_ids"`
	LastControlActivityAt   time.Time          `json:"last_control_activity_at,omitempty"`
	LastUserPlaneActivityAt time.Time          `json:"last_user_plane_activity_at,omitempty"`
	LastActivitySource      string             `json:"last_activity_source,omitempty"`
	InactiveSince           time.Time          `json:"inactive_since,omitempty"`
	CleanupEligible         bool               `json:"cleanup_eligible"`
}

// PeerSnapshot persists peer Recovery IE state needed to distinguish local
// SGW-C restart from peer restart after checkpoint reload.
type PeerSnapshot struct {
	SchemaVersion     int       `json:"schema_version"`
	Role              string    `json:"role"`
	Addr              string    `json:"addr"`
	Name              string    `json:"name,omitempty"`
	State             string    `json:"state"`
	RecoverySeen      bool      `json:"recovery_seen"`
	RecoveryCounter   uint8     `json:"recovery_counter,omitempty"`
	RecoveryTimestamp uint32    `json:"recovery_timestamp,omitempty"`
	RestartDetectedAt time.Time `json:"restart_detected_at,omitempty"`
	Restarts          uint64    `json:"restarts,omitempty"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func Marshal(snapshot SessionSnapshot) ([]byte, error) {
	snapshot.SchemaVersion = CurrentSchemaVersion
	return json.Marshal(snapshot)
}

func Unmarshal(data []byte) (SessionSnapshot, error) {
	var snapshot SessionSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return SessionSnapshot{}, err
	}
	if snapshot.SchemaVersion != CurrentSchemaVersion {
		return SessionSnapshot{}, errors.New("unsupported session checkpoint schema version")
	}
	return snapshot, nil
}

func MarshalPeer(snapshot PeerSnapshot) ([]byte, error) {
	snapshot.SchemaVersion = CurrentSchemaVersion
	return json.Marshal(snapshot)
}

func UnmarshalPeer(data []byte) (PeerSnapshot, error) {
	var snapshot PeerSnapshot
	if err := json.Unmarshal(data, &snapshot); err != nil {
		return PeerSnapshot{}, err
	}
	if snapshot.SchemaVersion != CurrentSchemaVersion {
		return PeerSnapshot{}, errors.New("unsupported peer checkpoint schema version")
	}
	return snapshot, nil
}

func FTEIDFromBearer(f bearer.FTEID) FTEIDSnapshot {
	return FTEIDSnapshot{TEID: f.TEID, IPv4: addrString(f.IPv4)}
}

func addrString(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}
