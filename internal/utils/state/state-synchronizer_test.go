package state

import (
	"errors"
	"strings"
	"testing"
)

// Test types for testing
type TestItem struct {
	ID   int
	Name string
}

type TestKey struct {
	ID   int
	Name string
}

// Mock implementations
type mockStateSynchronizer struct {
	items    []TestItem
	getErr   error
	addErr   error
	delErr   error
	addCalls []TestKey
	delCalls []TestItem
}

func (m *mockStateSynchronizer) get() ([]TestItem, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	return m.items, nil
}

func (m *mockStateSynchronizer) prepare(item TestItem) (TestItem, TestKey) {
	return item, TestKey(item)
}

func (m *mockStateSynchronizer) filter(item TestItem, prepared TestKey) bool {
	// This is a mock filter that will be overridden in individual tests
	// In real usage, this would filter by logical identity (e.g., same rule ID, same resource name, etc.)
	return true
}

func (m *mockStateSynchronizer) equal(item TestItem, prepared TestKey, target TestKey) bool {
	// Only compare if the items have the same ID (i.e., they represent the same logical entity)
	if prepared.ID != target.ID {
		return false
	}
	// If IDs match, compare all fields for equality
	return prepared.ID == target.ID && prepared.Name == target.Name
}

func (m *mockStateSynchronizer) add(key TestKey) error {
	if m.addCalls == nil {
		m.addCalls = []TestKey{}
	}
	m.addCalls = append(m.addCalls, key)
	if m.addErr != nil {
		return m.addErr
	}
	return nil
}

func (m *mockStateSynchronizer) delete(item TestItem) error {
	if m.delCalls == nil {
		m.delCalls = []TestItem{}
	}
	m.delCalls = append(m.delCalls, item)
	if m.delErr != nil {
		return m.delErr
	}
	return nil
}

func createTestSynchronizer(mock *mockStateSynchronizer) *StateSynchronizer[TestItem, TestKey] {
	return &StateSynchronizer[TestItem, TestKey]{
		Get:     mock.get,
		Prepare: mock.prepare,
		Filter:  mock.filter,
		Equal:   mock.equal,
		Add:     mock.add,
		Delete:  mock.delete,
	}
}

func TestStateSynchronizer_SyncSingle(t *testing.T) {
	t.Run("adds new item when not found", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
		}

		// Create synchronizer that filters by ID (only considers items with same ID as target)
		sync := &StateSynchronizer[TestItem, TestKey]{
			Get:     mock.get,
			Prepare: mock.prepare,
			Filter: func(item TestItem, prepared TestKey) bool {
				// Only consider items with ID 3 (same as target)
				return item.ID == 3
			},
			Equal:  mock.equal,
			Add:    mock.add,
			Delete: mock.delete,
		}

		newItem := TestKey{ID: 3, Name: "item3"}
		err := sync.SyncSingle(newItem)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.addCalls) != 1 {
			t.Errorf("expected 1 add call, got %d", len(mock.addCalls))
		}
		if mock.addCalls[0] != newItem {
			t.Errorf("expected add call with %v, got %v", newItem, mock.addCalls[0])
		}
		if len(mock.delCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mock.delCalls))
		}
	})

	t.Run("does nothing when item already exists and is equal", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
		}
		// Create synchronizer that filters by ID (only considers items with same ID as target)
		sync := &StateSynchronizer[TestItem, TestKey]{
			Get:     mock.get,
			Prepare: mock.prepare,
			Filter: func(item TestItem, prepared TestKey) bool {
				// Only consider items with ID 1 (same as target)
				return item.ID == 1
			},
			Equal:  mock.equal,
			Add:    mock.add,
			Delete: mock.delete,
		}

		existingItem := TestKey{ID: 1, Name: "item1"}
		err := sync.SyncSingle(existingItem)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.addCalls) != 0 {
			t.Errorf("expected 0 add calls, got %d", len(mock.addCalls))
		}
		if len(mock.delCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mock.delCalls))
		}
	})

	t.Run("deletes and adds when item exists but is not equal", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
		}
		// Create synchronizer that filters by ID (only considers items with same ID as target)
		sync := &StateSynchronizer[TestItem, TestKey]{
			Get:     mock.get,
			Prepare: mock.prepare,
			Filter: func(item TestItem, prepared TestKey) bool {
				// Only consider items with ID 1 (same as target)
				return item.ID == 1
			},
			Equal:  mock.equal,
			Add:    mock.add,
			Delete: mock.delete,
		}

		updatedItem := TestKey{ID: 1, Name: "updated_item1"}
		err := sync.SyncSingle(updatedItem)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.delCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mock.delCalls))
		}
		if mock.delCalls[0].ID != 1 {
			t.Errorf("expected delete call for item with ID 1, got %v", mock.delCalls[0])
		}
		if len(mock.addCalls) != 1 {
			t.Errorf("expected 1 add call, got %d", len(mock.addCalls))
		}
		if mock.addCalls[0] != updatedItem {
			t.Errorf("expected add call with %v, got %v", updatedItem, mock.addCalls[0])
		}
	})

	t.Run("returns error when get fails", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			getErr: errors.New("get error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.SyncSingle(TestKey{ID: 1, Name: "item1"})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "get error" {
			t.Errorf("expected 'get error', got %v", err)
		}
	})

	t.Run("returns error when add fails", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items:  []TestItem{},
			addErr: errors.New("add error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.SyncSingle(TestKey{ID: 1, Name: "item1"})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "add error" {
			t.Errorf("expected 'add error', got %v", err)
		}
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
			},
			delErr: errors.New("delete error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.SyncSingle(TestKey{ID: 1, Name: "updated_item1"})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "delete error" {
			t.Errorf("expected 'delete error', got %v", err)
		}
	})
}

func TestStateSynchronizer_SyncSet(t *testing.T) {
	t.Run("syncs empty set", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
		}
		sync := createTestSynchronizer(mock)

		err := sync.SyncSet([]TestKey{})

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.addCalls) != 0 {
			t.Errorf("expected 0 add calls, got %d", len(mock.addCalls))
		}
		if len(mock.delCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mock.delCalls))
		}
		deletedIDs := make(map[int]bool)
		for _, del := range mock.delCalls {
			deletedIDs[del.ID] = true
		}
		if !deletedIDs[1] || !deletedIDs[2] {
			t.Errorf("expected to delete items 1 and 2, deleted: %v", deletedIDs)
		}
	})

	t.Run("adds new items and keeps existing", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
			},
		}
		sync := createTestSynchronizer(mock)

		targetItems := []TestKey{
			{ID: 1, Name: "item1"}, // existing
			{ID: 2, Name: "item2"}, // new
		}
		err := sync.SyncSet(targetItems)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.addCalls) != 1 {
			t.Errorf("expected 1 add call, got %d", len(mock.addCalls))
		}
		if mock.addCalls[0].ID != 2 {
			t.Errorf("expected add call for item with ID 2, got %v", mock.addCalls[0])
		}
		if len(mock.delCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mock.delCalls))
		}
	})

	t.Run("removes items not in target set", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
				{ID: 3, Name: "item3"},
			},
		}
		sync := createTestSynchronizer(mock)

		targetItems := []TestKey{
			{ID: 1, Name: "item1"},
		}
		err := sync.SyncSet(targetItems)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.addCalls) != 0 {
			t.Errorf("expected 0 add calls, got %d", len(mock.addCalls))
		}
		if len(mock.delCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mock.delCalls))
		}
		deletedIDs := make(map[int]bool)
		for _, del := range mock.delCalls {
			deletedIDs[del.ID] = true
		}
		if !deletedIDs[2] || !deletedIDs[3] {
			t.Errorf("expected to delete items 2 and 3, deleted: %v", deletedIDs)
		}
	})

	t.Run("updates existing items when not equal", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
		}
		sync := createTestSynchronizer(mock)

		targetItems := []TestKey{
			{ID: 1, Name: "updated_item1"},
			{ID: 2, Name: "item2"},
		}
		err := sync.SyncSet(targetItems)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		// The current item with ID 1 doesn't equal any target item (because names differ), so it gets deleted
		if len(mock.delCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mock.delCalls))
		}
		if mock.delCalls[0].ID != 1 {
			t.Errorf("expected delete call for item with ID 1, got %v", mock.delCalls[0])
		}
		if len(mock.addCalls) != 1 {
			t.Errorf("expected 1 add call, got %d", len(mock.addCalls))
		}
		if mock.addCalls[0].Name != "updated_item1" {
			t.Errorf("expected add call for updated_item1, got %v", mock.addCalls[0])
		}
	})

	t.Run("returns error when get fails", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			getErr: errors.New("get error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.SyncSet([]TestKey{{ID: 1, Name: "item1"}})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "get error" {
			t.Errorf("expected 'get error', got %v", err)
		}
	})

	t.Run("returns error when add fails", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items:  []TestItem{},
			addErr: errors.New("add error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.SyncSet([]TestKey{{ID: 1, Name: "item1"}})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "add error" {
			t.Errorf("expected 'add error', got %v", err)
		}
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
			},
			delErr: errors.New("delete error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.SyncSet([]TestKey{})

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "delete error" {
			t.Errorf("expected 'delete error', got %v", err)
		}
	})
}

func TestStateSynchronizer_Clear(t *testing.T) {
	t.Run("clears all items", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
		}
		sync := createTestSynchronizer(mock)

		err := sync.Clear()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.delCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mock.delCalls))
		}
		deletedIDs := make(map[int]bool)
		for _, del := range mock.delCalls {
			deletedIDs[del.ID] = true
		}
		if !deletedIDs[1] || !deletedIDs[2] {
			t.Errorf("expected to delete items 1 and 2, deleted: %v", deletedIDs)
		}
		if len(mock.addCalls) != 0 {
			t.Errorf("expected 0 add calls, got %d", len(mock.addCalls))
		}
	})

	t.Run("clears only filtered items", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
		}
		// Override filter to only consider items with ID 1 for synchronization
		sync := &StateSynchronizer[TestItem, TestKey]{
			Get:     mock.get,
			Prepare: mock.prepare,
			Filter: func(item TestItem, prepared TestKey) bool {
				return item.ID == 1 // Only consider item with ID 1 for synchronization
			},
			Equal:  mock.equal,
			Add:    mock.add,
			Delete: mock.delete,
		}

		err := sync.Clear()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.delCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mock.delCalls))
		}
		if mock.delCalls[0].ID != 1 {
			t.Errorf("expected delete call for item with ID 1, got %v", mock.delCalls[0])
		}
	})

	t.Run("returns error when get fails", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			getErr: errors.New("get error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.Clear()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "get error" {
			t.Errorf("expected 'get error', got %v", err)
		}
	})

	t.Run("returns joined errors when multiple delete calls fail", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
			},
			delErr: errors.New("delete error"),
		}
		sync := createTestSynchronizer(mock)

		err := sync.Clear()

		if err == nil {
			t.Error("expected error, got nil")
		}
		// The error should contain both delete errors joined
		errorStr := err.Error()
		if errorStr != "delete error\ndelete error" {
			t.Errorf("expected joined delete errors, got %v", err)
		}
	})

	t.Run("clears empty state without error", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{},
		}
		sync := createTestSynchronizer(mock)

		err := sync.Clear()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mock.delCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mock.delCalls))
		}
	})
}

// Integration-style test with more realistic scenario
func TestStateSynchronizer_Integration(t *testing.T) {
	t.Run("complex synchronization scenario", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},     // will be kept
				{ID: 2, Name: "old_item2"}, // will be updated
				{ID: 3, Name: "item3"},     // will be deleted
			},
		}
		sync := createTestSynchronizer(mock)

		targetItems := []TestKey{
			{ID: 1, Name: "item1"},     // keep
			{ID: 2, Name: "new_item2"}, // update
			{ID: 4, Name: "item4"},     // add
		}

		err := sync.SyncSet(targetItems)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Should delete old_item2 (ID 2) and item3 (ID 3) - 2 delete calls total
		if len(mock.delCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mock.delCalls))
		}

		// Should add new_item2 and item4 - 2 add calls total
		if len(mock.addCalls) != 2 {
			t.Errorf("expected 2 add calls, got %d", len(mock.addCalls))
		}

		// Verify specific operations
		deletedIDs := make(map[int]bool)
		for _, del := range mock.delCalls {
			deletedIDs[del.ID] = true
		}
		if !deletedIDs[2] || !deletedIDs[3] {
			t.Errorf("expected to delete items 2 and 3, deleted: %v", deletedIDs)
		}

		addedIDs := make(map[int]bool)
		for _, add := range mock.addCalls {
			addedIDs[add.ID] = true
		}
		if !addedIDs[2] || !addedIDs[4] {
			t.Errorf("expected to add items 2 and 4, added: %v", addedIDs)
		}
	})
}

// Test with selective filtering to demonstrate real-world usage
func TestStateSynchronizer_SelectiveFiltering(t *testing.T) {
	t.Run("only manages items with specific prefix", func(t *testing.T) {
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "managed-item1"},   // should be managed
				{ID: 2, Name: "unmanaged-item2"}, // should be ignored
				{ID: 3, Name: "managed-item3"},   // should be managed
			},
		}

		// Create synchronizer that only manages items with "managed-" prefix
		sync := &StateSynchronizer[TestItem, TestKey]{
			Get:     mock.get,
			Prepare: mock.prepare,
			Filter: func(item TestItem, prepared TestKey) bool {
				// Only manage items with "managed-" prefix
				return len(item.Name) >= 8 && item.Name[:8] == "managed-"
			},
			Equal:  mock.equal,
			Add:    mock.add,
			Delete: mock.delete,
		}

		// Try to sync with only one managed item
		targetItems := []TestKey{
			{ID: 1, Name: "managed-item1"}, // keep
			{ID: 4, Name: "managed-item4"}, // add new
		}

		err := sync.SyncSet(targetItems)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Should delete managed-item3 (ID 3) but leave unmanaged-item2 (ID 2) alone
		if len(mock.delCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mock.delCalls))
		}
		if mock.delCalls[0].ID != 3 {
			t.Errorf("expected delete call for item with ID 3, got %v", mock.delCalls[0])
		}

		// Should add managed-item4
		if len(mock.addCalls) != 1 {
			t.Errorf("expected 1 add call, got %d", len(mock.addCalls))
		}
		if mock.addCalls[0].ID != 4 {
			t.Errorf("expected add call for item with ID 4, got %v", mock.addCalls[0])
		}
	})
}

func TestStateSynchronizer_PrepareIntegration(t *testing.T) {
	t.Run("StateSynchronizer passes prepared items to Filter function", func(t *testing.T) {
		var capturedPreparedItems []TestKey
		var capturedOriginalItems []TestItem

		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "original1"},
				{ID: 2, Name: "original2"},
			},
		}

		sync := &StateSynchronizer[TestItem, TestKey]{
			Get: mock.get,
			Prepare: func(item TestItem) (TestItem, TestKey) {
				// Transform the item by modifying the name to show preparation happened
				preparedItem := TestItem{ID: item.ID, Name: "prepared-" + item.Name}
				preparedKey := TestKey{ID: item.ID, Name: "prepared-" + item.Name}
				return preparedItem, preparedKey
			},
			Filter: func(item TestItem, prepared TestKey) bool {
				capturedOriginalItems = append(capturedOriginalItems, item)
				capturedPreparedItems = append(capturedPreparedItems, prepared)
				return true
			},
			Equal: func(item TestItem, prepared TestKey, target TestKey) bool {
				return prepared.ID == target.ID
			},
			Add:    mock.add,
			Delete: mock.delete,
		}

		err := sync.SyncSingle(TestKey{ID: 3, Name: "new"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify Filter was called with prepared items
		if len(capturedPreparedItems) != 2 {
			t.Fatalf("expected 2 prepared items, got %d", len(capturedPreparedItems))
		}

		// Verify the prepared items have the modified names
		expectedPreparedItems := []TestKey{
			{ID: 1, Name: "prepared-original1"},
			{ID: 2, Name: "prepared-original2"},
		}

		for i, captured := range capturedPreparedItems {
			if captured != expectedPreparedItems[i] {
				t.Errorf("Filter received incorrect prepared item %d: got %v, want %v", i, captured, expectedPreparedItems[i])
			}
		}

		// Verify the original items were also modified by prepare
		expectedOriginalItems := []TestItem{
			{ID: 1, Name: "prepared-original1"},
			{ID: 2, Name: "prepared-original2"},
		}

		for i, captured := range capturedOriginalItems {
			if captured != expectedOriginalItems[i] {
				t.Errorf("Filter received incorrect original item %d: got %v, want %v", i, captured, expectedOriginalItems[i])
			}
		}
	})

	t.Run("StateSynchronizer passes prepared items to Equal function", func(t *testing.T) {
		var capturedPreparedItems []TestKey
		var capturedOriginalItems []TestItem
		var capturedTargetItems []TestKey

		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "original"},
			},
		}

		sync := &StateSynchronizer[TestItem, TestKey]{
			Get: mock.get,
			Prepare: func(item TestItem) (TestItem, TestKey) {
				// Add a prefix to show preparation happened
				preparedItem := TestItem{ID: item.ID, Name: "prep-" + item.Name}
				preparedKey := TestKey{ID: item.ID, Name: "prep-" + item.Name}
				return preparedItem, preparedKey
			},
			Filter: func(item TestItem, prepared TestKey) bool {
				return true // Include all items
			},
			Equal: func(item TestItem, prepared TestKey, target TestKey) bool {
				capturedOriginalItems = append(capturedOriginalItems, item)
				capturedPreparedItems = append(capturedPreparedItems, prepared)
				capturedTargetItems = append(capturedTargetItems, target)
				return prepared.ID == target.ID
			},
			Add:    mock.add,
			Delete: mock.delete,
		}

		targetItem := TestKey{ID: 1, Name: "target"}
		err := sync.SyncSingle(targetItem)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify Equal was called with prepared items
		if len(capturedPreparedItems) != 1 {
			t.Fatalf("expected 1 prepared item in Equal, got %d", len(capturedPreparedItems))
		}

		// Verify the prepared item has the modified name
		expectedPreparedItem := TestKey{ID: 1, Name: "prep-original"}
		if capturedPreparedItems[0] != expectedPreparedItem {
			t.Errorf("Equal received incorrect prepared item: got %v, want %v", capturedPreparedItems[0], expectedPreparedItem)
		}

		// Verify the original item was also modified by prepare
		expectedOriginalItem := TestItem{ID: 1, Name: "prep-original"}
		if capturedOriginalItems[0] != expectedOriginalItem {
			t.Errorf("Equal received incorrect original item: got %v, want %v", capturedOriginalItems[0], expectedOriginalItem)
		}

		// Verify the target item is passed unchanged
		if capturedTargetItems[0] != targetItem {
			t.Errorf("Equal received incorrect target item: got %v, want %v", capturedTargetItems[0], targetItem)
		}
	})

	t.Run("StateSynchronizer uses prepare results consistently across SyncSet", func(t *testing.T) {
		var filterCalls []TestKey
		var equalCalls []TestKey

		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "item1"},
				{ID: 2, Name: "item2"},
				{ID: 3, Name: "item3"},
			},
		}

		sync := &StateSynchronizer[TestItem, TestKey]{
			Get: mock.get,
			Prepare: func(item TestItem) (TestItem, TestKey) {
				// Transform by adding a suffix
				preparedItem := TestItem{ID: item.ID, Name: item.Name + "-transformed"}
				preparedKey := TestKey{ID: item.ID, Name: item.Name + "-transformed"}
				return preparedItem, preparedKey
			},
			Filter: func(item TestItem, prepared TestKey) bool {
				filterCalls = append(filterCalls, prepared)
				return true
			},
			Equal: func(item TestItem, prepared TestKey, target TestKey) bool {
				equalCalls = append(equalCalls, prepared)
				return prepared.ID == target.ID && prepared.Name == target.Name
			},
			Add:    mock.add,
			Delete: mock.delete,
		}

		targetItems := []TestKey{
			{ID: 1, Name: "item1-transformed"}, // Should match
			{ID: 4, Name: "item4-new"},         // Should be added
		}

		err := sync.SyncSet(targetItems)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Verify Filter was called with all prepared items
		expectedFilterCalls := []TestKey{
			{ID: 1, Name: "item1-transformed"},
			{ID: 2, Name: "item2-transformed"},
			{ID: 3, Name: "item3-transformed"},
		}

		if len(filterCalls) != 3 {
			t.Fatalf("expected 3 filter calls, got %d", len(filterCalls))
		}

		for i, call := range filterCalls {
			if call != expectedFilterCalls[i] {
				t.Errorf("Filter call %d received incorrect prepared item: got %v, want %v", i, call, expectedFilterCalls[i])
			}
		}

		// Verify Equal was called with prepared items for comparison
		// Should be called for each existing item against each target item
		if len(equalCalls) == 0 {
			t.Error("Equal function was not called")
		}

		// All Equal calls should have the transformed names
		for i, call := range equalCalls {
			if !strings.HasSuffix(call.Name, "-transformed") {
				t.Errorf("Equal call %d did not receive prepared item: got %v", i, call)
			}
		}

		// Verify items 2 and 3 were deleted (not matching any target)
		if len(mock.delCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mock.delCalls))
		}

		// Verify item 4 was added
		if len(mock.addCalls) != 1 {
			t.Errorf("expected 1 add call, got %d", len(mock.addCalls))
		}
		if len(mock.addCalls) > 0 && mock.addCalls[0].ID != 4 {
			t.Errorf("expected add call for item 4, got %v", mock.addCalls[0])
		}
	})

	t.Run("StateSynchronizer handles prepare function that returns different types", func(t *testing.T) {
		// Test where prepare transforms the item significantly
		mock := &mockStateSynchronizer{
			items: []TestItem{
				{ID: 1, Name: "lowercaseitem"},
			},
		}

		var receivedInFilter TestKey
		var receivedInEqual TestKey

		sync := &StateSynchronizer[TestItem, TestKey]{
			Get: mock.get,
			Prepare: func(item TestItem) (TestItem, TestKey) {
				// Prepare function normalizes names to uppercase
				preparedItem := TestItem{ID: item.ID * 10, Name: "UPPER_" + item.Name}
				preparedKey := TestKey{ID: item.ID * 10, Name: "UPPER_" + item.Name}
				return preparedItem, preparedKey
			},
			Filter: func(item TestItem, prepared TestKey) bool {
				receivedInFilter = prepared
				return true
			},
			Equal: func(item TestItem, prepared TestKey, target TestKey) bool {
				receivedInEqual = prepared
				return prepared.ID == target.ID
			},
			Add:    mock.add,
			Delete: mock.delete,
		}

		err := sync.SyncSingle(TestKey{ID: 20, Name: "something"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		expectedPrepared := TestKey{ID: 10, Name: "UPPER_lowercaseitem"}

		if receivedInFilter != expectedPrepared {
			t.Errorf("Filter did not receive correctly prepared item: got %v, want %v", receivedInFilter, expectedPrepared)
		}

		if receivedInEqual != expectedPrepared {
			t.Errorf("Equal did not receive correctly prepared item: got %v, want %v", receivedInEqual, expectedPrepared)
		}
	})
}
