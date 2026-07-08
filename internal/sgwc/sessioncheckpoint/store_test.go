package sessioncheckpoint

import (
	"testing"
	"time"
)

func TestMarshalSetsSchemaVersion(t *testing.T) {
	now := time.Unix(100, 0).UTC()
	raw, err := Marshal(SessionSnapshot{
		SessionID:       "sess-1",
		IMSI:            "311435300070599",
		APN:             "ims.mnc435.mcc311.gprs",
		DefaultBearerID: 6,
		State:           "active",
		CreatedAt:       now,
		UpdatedAt:       now,
		Bearers: []BearerSnapshot{
			{EBI: 6, QCI: 5, State: "active"},
			{EBI: 7, QCI: 1, State: "active", PDRIDs: [2]uint32{3, 4}, FARIDs: [2]uint32{3, 4}},
		},
	})
	if err != nil {
		t.Fatalf("Marshal snapshot: %v", err)
	}

	snapshot, err := Unmarshal(raw)
	if err != nil {
		t.Fatalf("Unmarshal snapshot: %v", err)
	}
	if snapshot.SchemaVersion != CurrentSchemaVersion {
		t.Fatalf("schema version = %d; want %d", snapshot.SchemaVersion, CurrentSchemaVersion)
	}
	if snapshot.SessionID != "sess-1" || snapshot.IMSI != "311435300070599" || len(snapshot.Bearers) != 2 {
		t.Fatalf("unexpected snapshot after round trip: %+v", snapshot)
	}
}

func TestUnmarshalRejectsUnsupportedSchemaVersion(t *testing.T) {
	_, err := Unmarshal([]byte(`{"schema_version":999,"session_id":"sess-1"}`))
	if err == nil {
		t.Fatal("Unmarshal succeeded with unsupported schema version")
	}
}
