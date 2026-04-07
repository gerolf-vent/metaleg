package set

import (
	"testing"
)

func TestNew(t *testing.T) {
	s := New[string]()
	if s == nil {
		t.Error("expected non-nil set")
	}
	if len(s) != 0 {
		t.Errorf("expected empty set, got length %d", len(s))
	}
}

func TestNewWithItems(t *testing.T) {
	t.Run("creates set with items", func(t *testing.T) {
		s := NewWithItems("a", "b", "c")
		if len(s) != 3 {
			t.Errorf("expected set length 3, got %d", len(s))
		}
		if !s.Contains("a") || !s.Contains("b") || !s.Contains("c") {
			t.Error("expected set to contain all items")
		}
	})

	t.Run("handles duplicate items", func(t *testing.T) {
		s := NewWithItems("a", "b", "a", "c", "b")
		if len(s) != 3 {
			t.Errorf("expected set length 3 (duplicates removed), got %d", len(s))
		}
		if !s.Contains("a") || !s.Contains("b") || !s.Contains("c") {
			t.Error("expected set to contain all unique items")
		}
	})

	t.Run("creates empty set with no items", func(t *testing.T) {
		s := NewWithItems[int]()
		if len(s) != 0 {
			t.Errorf("expected empty set, got length %d", len(s))
		}
	})
}

func TestAdd(t *testing.T) {
	s := New[string]()
	
	s.Add("test")
	if !s.Contains("test") {
		t.Error("expected set to contain added item")
	}
	if len(s) != 1 {
		t.Errorf("expected set length 1, got %d", len(s))
	}

	// Adding same item should not increase size
	s.Add("test")
	if len(s) != 1 {
		t.Errorf("expected set length 1 after adding duplicate, got %d", len(s))
	}
}

func TestRemove(t *testing.T) {
	s := NewWithItems("a", "b", "c")
	
	s.Remove("b")
	if s.Contains("b") {
		t.Error("expected set to not contain removed item")
	}
	if len(s) != 2 {
		t.Errorf("expected set length 2 after removal, got %d", len(s))
	}

	// Removing non-existent item should not cause error
	s.Remove("non-existent")
	if len(s) != 2 {
		t.Errorf("expected set length unchanged after removing non-existent item, got %d", len(s))
	}
}

func TestContains(t *testing.T) {
	s := NewWithItems("a", "b", "c")
	
	if !s.Contains("a") {
		t.Error("expected set to contain 'a'")
	}
	if !s.Contains("b") {
		t.Error("expected set to contain 'b'")
	}
	if !s.Contains("c") {
		t.Error("expected set to contain 'c'")
	}
	if s.Contains("d") {
		t.Error("expected set to not contain 'd'")
	}
}

func TestEquals(t *testing.T) {
	t.Run("equal sets", func(t *testing.T) {
		s1 := NewWithItems("a", "b", "c")
		s2 := NewWithItems("c", "b", "a") // different order
		
		if !s1.Equals(s2) {
			t.Error("expected sets to be equal")
		}
		if !s2.Equals(s1) {
			t.Error("expected equality to be symmetric")
		}
	})

	t.Run("different sized sets", func(t *testing.T) {
		s1 := NewWithItems("a", "b")
		s2 := NewWithItems("a", "b", "c")
		
		if s1.Equals(s2) {
			t.Error("expected sets to not be equal (different sizes)")
		}
		if s2.Equals(s1) {
			t.Error("expected sets to not be equal (different sizes)")
		}
	})

	t.Run("same size different elements", func(t *testing.T) {
		s1 := NewWithItems("a", "b", "c")
		s2 := NewWithItems("a", "b", "d")
		
		if s1.Equals(s2) {
			t.Error("expected sets to not be equal (different elements)")
		}
	})

	t.Run("empty sets", func(t *testing.T) {
		s1 := New[string]()
		s2 := New[string]()
		
		if !s1.Equals(s2) {
			t.Error("expected empty sets to be equal")
		}
	})

	t.Run("one empty one non-empty", func(t *testing.T) {
		s1 := New[string]()
		s2 := NewWithItems("a")
		
		if s1.Equals(s2) {
			t.Error("expected empty and non-empty sets to not be equal")
		}
	})
}

func TestSetWithDifferentTypes(t *testing.T) {
	// Test with int type
	intSet := NewWithItems(1, 2, 3)
	if !intSet.Contains(2) {
		t.Error("expected int set to contain 2")
	}

	// Test with custom type
	type CustomType string
	customSet := NewWithItems(CustomType("a"), CustomType("b"))
	if !customSet.Contains(CustomType("a")) {
		t.Error("expected custom type set to contain 'a'")
	}
}

func TestSetOperationsSequence(t *testing.T) {
	// Test a sequence of operations
	s := New[string]()
	
	// Add several items
	s.Add("apple")
	s.Add("banana")
	s.Add("cherry")
	
	if len(s) != 3 {
		t.Errorf("expected 3 items after adds, got %d", len(s))
	}
	
	// Remove one
	s.Remove("banana")
	if len(s) != 2 {
		t.Errorf("expected 2 items after removal, got %d", len(s))
	}
	
	// Check remaining items
	if !s.Contains("apple") || !s.Contains("cherry") {
		t.Error("expected remaining items to be present")
	}
	if s.Contains("banana") {
		t.Error("expected removed item to not be present")
	}
	
	// Add duplicate
	s.Add("apple")
	if len(s) != 2 {
		t.Errorf("expected size unchanged after adding duplicate, got %d", len(s))
	}
}