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

func TestIsAllocated(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// Initially, no IDs should be allocated
	for i := uint(0); i < 5; i++ {
		if allocator.IsAllocated(i) {
			t.Errorf("Expected ID %d to not be allocated initially", i)
		}
	}

	// Allocate some IDs
	id1, _ := allocator.Allocate()
	id2, _ := allocator.Allocate()

	// Check allocated IDs
	if !allocator.IsAllocated(id1) {
		t.Errorf("Expected ID %d to be allocated", id1)
	}
	if !allocator.IsAllocated(id2) {
		t.Errorf("Expected ID %d to be allocated", id2)
	}

	// Check non-allocated IDs
	for i := uint(0); i < 5; i++ {
		if i != id1 && i != id2 {
			if allocator.IsAllocated(i) {
				t.Errorf("Expected ID %d to not be allocated", i)
			}
		}
	}

	// Release an ID and check
	allocator.Release(id1)
	if allocator.IsAllocated(id1) {
		t.Errorf("Expected ID %d to not be allocated after release", id1)
	}
}

func TestIsAllocated_OutOfRange(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// Out-of-range IDs should be considered not allocated
	if allocator.IsAllocated(5) {
		t.Error("Expected out-of-range ID 5 to not be allocated")
	}
	if allocator.IsAllocated(10) {
		t.Error("Expected out-of-range ID 10 to not be allocated")
	}
	if allocator.IsAllocated(100) {
		t.Error("Expected out-of-range ID 100 to not be allocated")
	}
}

func TestSize(t *testing.T) {
	testCases := []uint{0, 1, 5, 10, 100}

	for _, size := range testCases {
		allocator := NewIDRangeAllocator(size)
		if allocator.Size() != size {
			t.Errorf("Expected size %d, got %d", size, allocator.Size())
		}
	}
}

func TestAllocatedCount(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// Initially, no IDs should be allocated
	if allocator.AllocatedCount() != 0 {
		t.Errorf("Expected allocated count to be 0 initially, got %d", allocator.AllocatedCount())
	}

	// Allocate some IDs and check count
	_, _ = allocator.Allocate()
	if allocator.AllocatedCount() != 1 {
		t.Errorf("Expected allocated count to be 1 after first allocation, got %d", allocator.AllocatedCount())
	}

	_, _ = allocator.Allocate()
	if allocator.AllocatedCount() != 2 {
		t.Errorf("Expected allocated count to be 2 after second allocation, got %d", allocator.AllocatedCount())
	}

	id3, _ := allocator.Allocate()
	if allocator.AllocatedCount() != 3 {
		t.Errorf("Expected allocated count to be 3 after third allocation, got %d", allocator.AllocatedCount())
	}

	// Release an ID and check count
	allocator.Release(id3)
	if allocator.AllocatedCount() != 2 {
		t.Errorf("Expected allocated count to be 2 after release, got %d", allocator.AllocatedCount())
	}

	// Release the same ID again - count should stay the same
	allocator.Release(id3)
	if allocator.AllocatedCount() != 2 {
		t.Errorf("Expected allocated count to remain 2 after releasing already released ID, got %d", allocator.AllocatedCount())
	}
}

func TestFreeCount(t *testing.T) {
	allocator := NewIDRangeAllocator(5)

	// Initially, all IDs should be free
	if allocator.FreeCount() != 5 {
		t.Errorf("Expected free count to be 5 initially, got %d", allocator.FreeCount())
	}

	// Allocate some IDs and check free count
	_, _ = allocator.Allocate()
	if allocator.FreeCount() != 4 {
		t.Errorf("Expected free count to be 4 after first allocation, got %d", allocator.FreeCount())
	}

	_, _ = allocator.Allocate()
	if allocator.FreeCount() != 3 {
		t.Errorf("Expected free count to be 3 after second allocation, got %d", allocator.FreeCount())
	}

	id3, _ := allocator.Allocate()
	if allocator.FreeCount() != 2 {
		t.Errorf("Expected free count to be 2 after third allocation, got %d", allocator.FreeCount())
	}

	// Release an ID and check free count
	allocator.Release(id3)
	if allocator.FreeCount() != 3 {
		t.Errorf("Expected free count to be 3 after release, got %d", allocator.FreeCount())
	}

	// Verify that allocated + free = total size
	if allocator.AllocatedCount()+allocator.FreeCount() != allocator.Size() {
		t.Errorf("Expected allocated (%d) + free (%d) to equal size (%d)",
			allocator.AllocatedCount(), allocator.FreeCount(), allocator.Size())
	}
}

func TestFreeCount_ZeroSize(t *testing.T) {
	allocator := NewIDRangeAllocator(0)

	if allocator.FreeCount() != 0 {
		t.Errorf("Expected free count to be 0 for zero-size allocator, got %d", allocator.FreeCount())
	}
}

func TestCount_Consistency(t *testing.T) {
	allocator := NewIDRangeAllocator(10)

	// Test that allocated + free always equals size
	for i := 0; i < 10; i++ {
		if allocator.AllocatedCount()+allocator.FreeCount() != allocator.Size() {
			t.Errorf("At step %d: allocated (%d) + free (%d) != size (%d)",
				i, allocator.AllocatedCount(), allocator.FreeCount(), allocator.Size())
		}
		allocator.Allocate()
	}

	// After all are allocated
	if allocator.AllocatedCount() != 10 {
		t.Errorf("Expected all 10 IDs to be allocated, got %d", allocator.AllocatedCount())
	}
	if allocator.FreeCount() != 0 {
		t.Errorf("Expected no free IDs, got %d", allocator.FreeCount())
	}

	// Release some and verify consistency
	allocator.Release(5)
	allocator.Release(3)
	allocator.Release(7)

	if allocator.AllocatedCount() != 7 {
		t.Errorf("Expected 7 allocated IDs after releases, got %d", allocator.AllocatedCount())
	}
	if allocator.FreeCount() != 3 {
		t.Errorf("Expected 3 free IDs after releases, got %d", allocator.FreeCount())
	}
	if allocator.AllocatedCount()+allocator.FreeCount() != allocator.Size() {
		t.Errorf("After releases: allocated (%d) + free (%d) != size (%d)",
			allocator.AllocatedCount(), allocator.FreeCount(), allocator.Size())
	}
}
