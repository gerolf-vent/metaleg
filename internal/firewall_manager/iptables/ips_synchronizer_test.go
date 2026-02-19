package iptables

import (
	"errors"
	"net"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/ipset"
)

// Mock IPSet implementation for testing
type mockIPsSynchronizerIPSet struct {
	entries     map[string][]net.IP
	listErr     error
	ensureErr   error
	deleteErr   error
	ensureCalls []mockIPSetCall
	deleteCalls []mockIPSetCall
}

type mockIPSetCall struct {
	setName string
	ip      net.IP
}

func (m *mockIPsSynchronizerIPSet) ListSets() ([]string, error) {
	var sets []string
	for setName := range m.entries {
		sets = append(sets, setName)
	}
	return sets, nil
}

func (m *mockIPsSynchronizerIPSet) SetExists(setName string) (bool, error) {
	_, exists := m.entries[setName]
	return exists, nil
}

func (m *mockIPsSynchronizerIPSet) EnsureSet(setName string, proto ipset.Protocol) (bool, error) {
	if m.entries == nil {
		m.entries = make(map[string][]net.IP)
	}
	if _, exists := m.entries[setName]; !exists {
		m.entries[setName] = []net.IP{}
		return true, nil
	}
	return false, nil
}

func (m *mockIPsSynchronizerIPSet) DeleteSet(setName string) (bool, error) {
	if m.entries == nil {
		return false, nil
	}
	if _, exists := m.entries[setName]; exists {
		delete(m.entries, setName)
		return true, nil
	}
	return false, nil
}

func (m *mockIPsSynchronizerIPSet) EntryExists(setName string, entry net.IP) (bool, error) {
	entries, exists := m.entries[setName]
	if !exists {
		return false, nil
	}
	for _, existingIP := range entries {
		if existingIP.Equal(entry) {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockIPsSynchronizerIPSet) ListEntries(setName string) ([]net.IP, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.entries == nil {
		return []net.IP{}, nil
	}
	entries, exists := m.entries[setName]
	if !exists {
		return []net.IP{}, nil
	}
	// Return a copy to avoid external modifications
	result := make([]net.IP, len(entries))
	copy(result, entries)
	return result, nil
}

func (m *mockIPsSynchronizerIPSet) EnsureEntry(setName string, ip net.IP) (bool, error) {
	if m.ensureCalls == nil {
		m.ensureCalls = []mockIPSetCall{}
	}
	m.ensureCalls = append(m.ensureCalls, mockIPSetCall{setName: setName, ip: ip})

	if m.ensureErr != nil {
		return false, m.ensureErr
	}

	if m.entries == nil {
		m.entries = make(map[string][]net.IP)
	}
	if _, exists := m.entries[setName]; !exists {
		m.entries[setName] = []net.IP{}
	}

	// Check if IP already exists
	for _, existingIP := range m.entries[setName] {
		if existingIP.Equal(ip) {
			return false, nil // Already exists
		}
	}

	// Add the IP
	m.entries[setName] = append(m.entries[setName], ip)
	return true, nil
}

func (m *mockIPsSynchronizerIPSet) DeleteEntry(setName string, ip net.IP) (bool, error) {
	if m.deleteCalls == nil {
		m.deleteCalls = []mockIPSetCall{}
	}
	m.deleteCalls = append(m.deleteCalls, mockIPSetCall{setName: setName, ip: ip})

	if m.deleteErr != nil {
		return false, m.deleteErr
	}

	if m.entries == nil {
		return false, nil
	}
	entries, exists := m.entries[setName]
	if !exists {
		return false, nil
	}

	// Find and remove the IP
	for i, existingIP := range entries {
		if existingIP.Equal(ip) {
			m.entries[setName] = append(entries[:i], entries[i+1:]...)
			return true, nil
		}
	}

	return false, nil // IP not found
}

func (m *mockIPsSynchronizerIPSet) EnsureNetworkEntry(setName string, network *net.IPNet) (bool, error) {
	return false, errors.New("not implemented in mock")
}

func (m *mockIPsSynchronizerIPSet) DeleteNetworkEntry(setName string, network *net.IPNet) (bool, error) {
	return false, errors.New("not implemented in mock")
}

func (m *mockIPsSynchronizerIPSet) NetworkSetExists(name string) (bool, error) {
	return false, errors.New("not implemented in mock")
}

func (m *mockIPsSynchronizerIPSet) EnsureNetworkSet(name string, proto ipset.Protocol) (bool, error) {
	return false, errors.New("not implemented in mock")
}

func (m *mockIPsSynchronizerIPSet) DeleteNetworkSet(name string) (bool, error) {
	return false, errors.New("not implemented in mock")
}

func (m *mockIPsSynchronizerIPSet) NetworkEntryExists(name string, cidr net.IPNet) (bool, error) {
	return false, errors.New("not implemented in mock")
}

func (m *mockIPsSynchronizerIPSet) ListNetworkEntries(setName string) ([]net.IPNet, error) {
	return nil, errors.New("not implemented in mock")
}

func createTestIPsSynchronizer(mockIPSet ipset.IPSet) *IPSetIPsSynchronizer {
	return NewIPSetIPsSynchronizer(mockIPSet)
}

func TestNewIPSetIPsSynchronizer(t *testing.T) {
	mockIPSet := &mockIPsSynchronizerIPSet{}

	synchronizer := NewIPSetIPsSynchronizer(mockIPSet)

	if synchronizer.ips == nil {
		t.Error("expected ipset instance to be set")
	}
	if synchronizer.SetName != "" {
		t.Error("expected set name to be empty initially")
	}
	if synchronizer.Entries != nil {
		t.Error("expected entries to be nil initially")
	}
}

func TestIPSetIPsSynchronizer_Sync(t *testing.T) {
	t.Run("adds new IPs to empty set", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-set": {},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify IPs were added
		if len(mockIPSet.ensureCalls) != 2 {
			t.Errorf("expected 2 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		expectedIPs := []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
		}
		for i, expectedIP := range expectedIPs {
			if !mockIPSet.ensureCalls[i].ip.Equal(expectedIP) {
				t.Errorf("ensure call %d: expected IP %v, got %v", i, expectedIP, mockIPSet.ensureCalls[i].ip)
			}
			if mockIPSet.ensureCalls[i].setName != "test-set" {
				t.Errorf("ensure call %d: expected set name 'test-set', got %v", i, mockIPSet.ensureCalls[i].setName)
			}
		}

		// No deletions should occur
		if len(mockIPSet.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPSet.deleteCalls))
		}
	})

	t.Run("removes stale IPs from set", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-set": {
					net.ParseIP("192.168.1.1"),
					net.ParseIP("192.168.1.2"),
					net.ParseIP("192.168.1.3"), // This should be removed
				},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
			// 192.168.1.3 is not in desired state, should be deleted
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// No new IPs should be added
		if len(mockIPSet.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		// Verify stale IP was deleted
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}

		expectedDeleteIP := net.ParseIP("192.168.1.3")
		if !mockIPSet.deleteCalls[0].ip.Equal(expectedDeleteIP) {
			t.Errorf("delete call: expected IP %v, got %v", expectedDeleteIP, mockIPSet.deleteCalls[0].ip)
		}
		if mockIPSet.deleteCalls[0].setName != "test-set" {
			t.Errorf("delete call: expected set name 'test-set', got %v", mockIPSet.deleteCalls[0].setName)
		}
	})

	t.Run("adds and removes IPs in single sync", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-set": {
					net.ParseIP("192.168.1.1"), // Keep
					net.ParseIP("192.168.1.2"), // Remove
				},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{
			net.ParseIP("192.168.1.1"), // Keep existing
			net.ParseIP("192.168.1.3"), // Add new
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify new IP was added
		if len(mockIPSet.ensureCalls) != 1 {
			t.Errorf("expected 1 ensure call, got %d", len(mockIPSet.ensureCalls))
		}
		expectedAddIP := net.ParseIP("192.168.1.3")
		if !mockIPSet.ensureCalls[0].ip.Equal(expectedAddIP) {
			t.Errorf("ensure call: expected IP %v, got %v", expectedAddIP, mockIPSet.ensureCalls[0].ip)
		}

		// Verify stale IP was deleted
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}
		expectedDeleteIP := net.ParseIP("192.168.1.2")
		if !mockIPSet.deleteCalls[0].ip.Equal(expectedDeleteIP) {
			t.Errorf("delete call: expected IP %v, got %v", expectedDeleteIP, mockIPSet.deleteCalls[0].ip)
		}
	})

	t.Run("handles IPv6 addresses", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-ipv6-set": {},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-ipv6-set"
		synchronizer.Entries = []net.IP{
			net.ParseIP("2001:db8::1"),
			net.ParseIP("2001:db8::2"),
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify IPv6 IPs were added
		if len(mockIPSet.ensureCalls) != 2 {
			t.Errorf("expected 2 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		expectedIPs := []net.IP{
			net.ParseIP("2001:db8::1"),
			net.ParseIP("2001:db8::2"),
		}
		for i, expectedIP := range expectedIPs {
			if !mockIPSet.ensureCalls[i].ip.Equal(expectedIP) {
				t.Errorf("ensure call %d: expected IP %v, got %v", i, expectedIP, mockIPSet.ensureCalls[i].ip)
			}
		}
	})

	t.Run("handles empty desired state", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-set": {
					net.ParseIP("192.168.1.1"),
					net.ParseIP("192.168.1.2"),
				},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{} // Empty desired state

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// No additions should occur
		if len(mockIPSet.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		// All existing IPs should be deleted
		if len(mockIPSet.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPSet.deleteCalls))
		}
	})

	t.Run("handles nil desired state", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-set": {
					net.ParseIP("192.168.1.1"),
				},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = nil // nil desired state

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// No additions should occur
		if len(mockIPSet.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		// All existing IPs should be deleted
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}
	})

	t.Run("does nothing when state matches", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-set": {
					net.ParseIP("192.168.1.1"),
					net.ParseIP("192.168.1.2"),
				},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{
			net.ParseIP("192.168.1.1"),
			net.ParseIP("192.168.1.2"),
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// No operations should occur
		if len(mockIPSet.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}
		if len(mockIPSet.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPSet.deleteCalls))
		}
	})

	t.Run("returns error when ListEntries fails", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			listErr: errors.New("list entries error"),
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{net.ParseIP("192.168.1.1")}

		err := synchronizer.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "list entries error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("returns error when EnsureEntry fails", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries:   map[string][]net.IP{"test-set": {}},
			ensureErr: errors.New("ensure entry error"),
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{net.ParseIP("192.168.1.1")}

		err := synchronizer.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "ensure entry error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("returns error when DeleteEntry fails", func(t *testing.T) {
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"test-set": {net.ParseIP("192.168.1.1")},
			},
			deleteErr: errors.New("delete entry error"),
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IP{} // Empty desired state - will trigger delete

		err := synchronizer.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "delete entry error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})
}

func TestIPSetIPsSynchronizer_RealWorldScenario(t *testing.T) {
	t.Run("synchronizes service endpoint IPs", func(t *testing.T) {
		// Simulate existing service endpoint IPs in ipset
		mockIPSet := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"service-endpoints": {
					net.ParseIP("10.0.1.100"), // Keep - still active endpoint
					net.ParseIP("10.0.1.101"), // Remove - endpoint no longer exists
					net.ParseIP("10.0.1.102"), // Keep - still active endpoint
				},
			},
		}

		synchronizer := createTestIPsSynchronizer(mockIPSet)
		synchronizer.SetName = "service-endpoints"

		// New desired state: some endpoints changed
		synchronizer.Entries = []net.IP{
			net.ParseIP("10.0.1.100"), // Existing endpoint (keep)
			net.ParseIP("10.0.1.102"), // Existing endpoint (keep)
			net.ParseIP("10.0.1.103"), // New endpoint (add)
			net.ParseIP("10.0.1.104"), // New endpoint (add)
			// 10.0.1.101 removed from desired state (delete)
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify new endpoints were added
		if len(mockIPSet.ensureCalls) != 2 {
			t.Errorf("expected 2 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		expectedAdds := []net.IP{
			net.ParseIP("10.0.1.103"),
			net.ParseIP("10.0.1.104"),
		}
		for i, expectedIP := range expectedAdds {
			if !mockIPSet.ensureCalls[i].ip.Equal(expectedIP) {
				t.Errorf("ensure call %d: expected IP %v, got %v", i, expectedIP, mockIPSet.ensureCalls[i].ip)
			}
		}

		// Verify stale endpoint was removed
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}

		expectedDeleteIP := net.ParseIP("10.0.1.101")
		if !mockIPSet.deleteCalls[0].ip.Equal(expectedDeleteIP) {
			t.Errorf("delete call: expected IP %v, got %v", expectedDeleteIP, mockIPSet.deleteCalls[0].ip)
		}
	})

	t.Run("handles mixed IPv4 and IPv6 in separate sets", func(t *testing.T) {
		// Test IPv4 set
		mockIPSetV4 := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"allowlist-v4": {
					net.ParseIP("192.168.1.10"),
				},
			},
		}

		synchronizerV4 := createTestIPsSynchronizer(mockIPSetV4)
		synchronizerV4.SetName = "allowlist-v4"
		synchronizerV4.Entries = []net.IP{
			net.ParseIP("192.168.1.10"), // Keep existing
			net.ParseIP("192.168.1.20"), // Add new
		}

		err := synchronizerV4.Sync()
		if err != nil {
			t.Errorf("IPv4 sync failed: %v", err)
		}

		// Test IPv6 set
		mockIPSetV6 := &mockIPsSynchronizerIPSet{
			entries: map[string][]net.IP{
				"allowlist-v6": {
					net.ParseIP("2001:db8::10"),
				},
			},
		}

		synchronizerV6 := createTestIPsSynchronizer(mockIPSetV6)
		synchronizerV6.SetName = "allowlist-v6"
		synchronizerV6.Entries = []net.IP{
			net.ParseIP("2001:db8::10"), // Keep existing
			net.ParseIP("2001:db8::20"), // Add new
		}

		err = synchronizerV6.Sync()
		if err != nil {
			t.Errorf("IPv6 sync failed: %v", err)
		}

		// Verify both sets were synchronized correctly
		if len(mockIPSetV4.ensureCalls) != 1 {
			t.Errorf("IPv4: expected 1 ensure call, got %d", len(mockIPSetV4.ensureCalls))
		}
		if len(mockIPSetV6.ensureCalls) != 1 {
			t.Errorf("IPv6: expected 1 ensure call, got %d", len(mockIPSetV6.ensureCalls))
		}
	})
}
