package utils

import (
	"testing"
)

func TestNewIDRangeAllocator(t *testing.T) {
	allocator := NewIDRangeAllocator(10)
	if allocator == nil {
		t.Fatal("Expected allocator to be created")
	}
	if allocator.bitset == nil {
		t.Fatal("Expected bitset to be initialized")
	}
}

func TestAllocate_SingleID(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	id, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if id != 0 {
		t.Errorf("Expected first allocated ID to be 0, got %d", id)
	}
}

func TestAllocate_MultipleIDs(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	expectedIDs := []uint{0, 1, 2, 3, 4}
	allocatedIDs := make([]uint, 0, 5)

	for i := 0; i < 5; i++ {
		id, err := allocator.Allocate()
		if err != nil {
			t.Fatalf("Expected no error on allocation %d, got %v", i, err)
		}
		allocatedIDs = append(allocatedIDs, id)
	}

	for i, expected := range expectedIDs {
		if allocatedIDs[i] != expected {
			t.Errorf("Expected ID %d at position %d, got %d", expected, i, allocatedIDs[i])
		}
	}
}

func TestAllocate_PoolExhausted(t *testing.T) {
	allocator := NewIDRangeAllocator(2)

	// Allocate all available IDs
	_, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error on first allocation, got %v", err)
	}

	_, err = allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error on second allocation, got %v", err)
	}

	// Try to allocate when pool is exhausted
	_, err = allocator.Allocate()
	if err != ErrPoolExhausted {
		t.Errorf("Expected ErrPoolExhausted, got %v", err)
	}
}

func TestRelease_ValidID(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// Allocate an ID
	id, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error on allocation, got %v", err)
	}

	// Release the ID
	allocator.Release(id)

	// Should be able to allocate the same ID again
	newID, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error after release, got %v", err)
	}
	if newID != id {
		t.Errorf("Expected to get the same ID back after release, got %d instead of %d", newID, id)
	}
}

func TestRelease_OutOfRange(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// This should not panic or cause issues
	allocator.Release(10)
	allocator.Release(100)

	// Should still be able to allocate normally
	id, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error after out-of-range release, got %v", err)
	}
	if id != 0 {
		t.Errorf("Expected first ID to be 0, got %d", id)
	}
}

func TestAllocateAndRelease_Complex(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// Allocate all IDs
	ids := make([]uint, 5)
	for i := 0; i < 5; i++ {
		id, err := allocator.Allocate()
		if err != nil {
			t.Fatalf("Expected no error on allocation %d, got %v", i, err)
		}
		ids[i] = id
	}

	// Release middle ID
	allocator.Release(ids[2])

	// Allocate again - should get the released ID
	newID, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error after release, got %v", err)
	}
	if newID != ids[2] {
		t.Errorf("Expected to get released ID %d, got %d", ids[2], newID)
	}

	// Should be exhausted again
	_, err = allocator.Allocate()
	if err != ErrPoolExhausted {
		t.Errorf("Expected ErrPoolExhausted, got %v", err)
	}
}

func TestZeroSizeAllocator(t *testing.T) {
	allocator := NewIDRangeAllocator(0)

	_, err := allocator.Allocate()
	if err != ErrPoolExhausted {
		t.Errorf("Expected ErrPoolExhausted for zero-size allocator, got %v", err)
	}
}

func TestRelease_AlreadyReleased(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// Allocate and release an ID
	id, _ := allocator.Allocate()
	allocator.Release(id)

	// Release the same ID again - should not cause issues
	allocator.Release(id)

	// Should still be able to allocate it once
	newID, err := allocator.Allocate()
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
	if newID != id {
		t.Errorf("Expected to get ID %d, got %d", id, newID)
	}
}
