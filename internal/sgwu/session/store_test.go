package session

import "testing"

func TestLocalTEIDInUse(t *testing.T) {
	store := NewStore()
	err := store.Create(&Session{
		CPSEID: 1,
		UPSEID: 1,
		PDRs: []PDR{
			{ID: 1, LocalTEID: 0x1000},
			{ID: 2, LocalTEID: 0x2000},
		},
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	if !store.localTEIDInUse(0x1000) {
		t.Fatal("localTEIDInUse(0x1000) = false, want true")
	}
	if store.localTEIDInUse(0x3000) {
		t.Fatal("localTEIDInUse(0x3000) = true, want false")
	}
}
