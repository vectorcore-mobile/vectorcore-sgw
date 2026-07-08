package teid

import "testing"

func TestReserveMarksTEIDUsed(t *testing.T) {
	a := NewAllocator()
	if !a.Reserve(0x1234) {
		t.Fatal("Reserve returned false for unused TEID")
	}
	if a.Reserve(0x1234) {
		t.Fatal("Reserve returned true for duplicate TEID")
	}
	if got := a.Len(); got != 1 {
		t.Fatalf("Len = %d; want 1", got)
	}
	a.Free(0x1234)
	if got := a.Len(); got != 0 {
		t.Fatalf("Len after Free = %d; want 0", got)
	}
}

func TestReserveRejectsZero(t *testing.T) {
	a := NewAllocator()
	if a.Reserve(0) {
		t.Fatal("Reserve accepted zero TEID")
	}
	if got := a.Len(); got != 0 {
		t.Fatalf("Len = %d; want 0", got)
	}
}
