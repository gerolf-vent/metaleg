package firewall_manager

import (
	"errors"
	"net"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/ipset"
)

// Mock IPSet implementation for testing ipnet synchronizer
type mockIPNetsSynchronizerIPSet struct {
	networkEntries map[string][]net.IPNet
	listErr        error
	ensureErr      error
	deleteErr      error
	ensureCalls    []mockIPNetSetCall
	deleteCalls    []mockIPNetSetCall
}

type mockIPNetSetCall struct {
	setName string
	network net.IPNet
}

func (m *mockIPNetsSynchronizerIPSet) ListSets() ([]string, error) {
	var sets []string
	for setName := range m.networkEntries {
		sets = append(sets, setName)
	}
	return sets, nil
}

func (m *mockIPNetsSynchronizerIPSet) SetExists(setName string) (bool, error) {
	_, exists := m.networkEntries[setName]
	return exists, nil
}

func (m *mockIPNetsSynchronizerIPSet) EnsureSet(setName string, proto ipset.Protocol) (bool, error) {
	if m.networkEntries == nil {
		m.networkEntries = make(map[string][]net.IPNet)
	}
	if _, exists := m.networkEntries[setName]; !exists {
		m.networkEntries[setName] = []net.IPNet{}
		return true, nil
	}
	return false, nil
}

func (m *mockIPNetsSynchronizerIPSet) DeleteSet(setName string) (bool, error) {
	if m.networkEntries == nil {
		return false, nil
	}
	if _, exists := m.networkEntries[setName]; exists {
		delete(m.networkEntries, setName)
		return true, nil
	}
	return false, nil
}

func (m *mockIPNetsSynchronizerIPSet) ListEntries(setName string) ([]net.IP, error) {
	return nil, errors.New("not implemented for network sets")
}

func (m *mockIPNetsSynchronizerIPSet) EntryExists(setName string, entry net.IP) (bool, error) {
	return false, errors.New("not implemented for network sets")
}

func (m *mockIPNetsSynchronizerIPSet) EnsureEntry(setName string, entry net.IP) (bool, error) {
	return false, errors.New("not implemented for network sets")
}

func (m *mockIPNetsSynchronizerIPSet) DeleteEntry(setName string, entry net.IP) (bool, error) {
	return false, errors.New("not implemented for network sets")
}

func (m *mockIPNetsSynchronizerIPSet) NetworkSetExists(name string) (bool, error) {
	_, exists := m.networkEntries[name]
	return exists, nil
}

func (m *mockIPNetsSynchronizerIPSet) EnsureNetworkSet(name string, proto ipset.Protocol) (bool, error) {
	if m.networkEntries == nil {
		m.networkEntries = make(map[string][]net.IPNet)
	}
	if _, exists := m.networkEntries[name]; !exists {
		m.networkEntries[name] = []net.IPNet{}
		return true, nil
	}
	return false, nil
}

func (m *mockIPNetsSynchronizerIPSet) DeleteNetworkSet(name string) (bool, error) {
	if m.networkEntries == nil {
		return false, nil
	}
	if _, exists := m.networkEntries[name]; exists {
		delete(m.networkEntries, name)
		return true, nil
	}
	return false, nil
}

func (m *mockIPNetsSynchronizerIPSet) NetworkEntryExists(name string, cidr net.IPNet) (bool, error) {
	entries, exists := m.networkEntries[name]
	if !exists {
		return false, nil
	}
	for _, existingNet := range entries {
		if existingNet.String() == cidr.String() {
			return true, nil
		}
	}
	return false, nil
}

func (m *mockIPNetsSynchronizerIPSet) ListNetworkEntries(setName string) ([]net.IPNet, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	if m.networkEntries == nil {
		return []net.IPNet{}, nil
	}
	entries, exists := m.networkEntries[setName]
	if !exists {
		return []net.IPNet{}, nil
	}
	// Return a copy to avoid external modifications
	result := make([]net.IPNet, len(entries))
	copy(result, entries)
	return result, nil
}

func (m *mockIPNetsSynchronizerIPSet) EnsureNetworkEntry(setName string, network *net.IPNet) (bool, error) {
	if m.ensureCalls == nil {
		m.ensureCalls = []mockIPNetSetCall{}
	}
	m.ensureCalls = append(m.ensureCalls, mockIPNetSetCall{setName: setName, network: *network})

	if m.ensureErr != nil {
		return false, m.ensureErr
	}

	if m.networkEntries == nil {
		m.networkEntries = make(map[string][]net.IPNet)
	}
	if _, exists := m.networkEntries[setName]; !exists {
		m.networkEntries[setName] = []net.IPNet{}
	}

	// Check if network already exists
	for _, existingNet := range m.networkEntries[setName] {
		if existingNet.String() == network.String() {
			return false, nil // Already exists
		}
	}

	// Add the network
	m.networkEntries[setName] = append(m.networkEntries[setName], *network)
	return true, nil
}

func (m *mockIPNetsSynchronizerIPSet) DeleteNetworkEntry(setName string, network *net.IPNet) (bool, error) {
	if m.deleteCalls == nil {
		m.deleteCalls = []mockIPNetSetCall{}
	}
	m.deleteCalls = append(m.deleteCalls, mockIPNetSetCall{setName: setName, network: *network})

	if m.deleteErr != nil {
		return false, m.deleteErr
	}

	if m.networkEntries == nil {
		return false, nil
	}
	entries, exists := m.networkEntries[setName]
	if !exists {
		return false, nil
	}

	// Find and remove the network
	for i, existingNet := range entries {
		if existingNet.String() == network.String() {
			m.networkEntries[setName] = append(entries[:i], entries[i+1:]...)
			return true, nil
		}
	}

	return false, nil // Network not found
}

func createTestIPNetsSynchronizer(mockIPSet ipset.IPSet) *IPSetIPNetsSynchronizer {
	return NewIPSetIPNetsSynchronizer(mockIPSet)
}

// Helper function to parse CIDR
func mustParseCIDR(cidr string) net.IPNet {
	_, network, err := net.ParseCIDR(cidr)
	if err != nil {
		panic(err)
	}
	return *network
}

func TestNewIPSetIPNetsSynchronizer(t *testing.T) {
	mockIPSet := &mockIPNetsSynchronizerIPSet{}

	synchronizer := NewIPSetIPNetsSynchronizer(mockIPSet)

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

func TestIPSetIPNetsSynchronizer_Sync(t *testing.T) {
	t.Run("adds new networks to empty set", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-set": {},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("192.168.1.0/24"),
			mustParseCIDR("10.0.0.0/16"),
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify networks were added
		if len(mockIPSet.ensureCalls) != 2 {
			t.Errorf("expected 2 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		expectedNetworks := []net.IPNet{
			mustParseCIDR("192.168.1.0/24"),
			mustParseCIDR("10.0.0.0/16"),
		}
		for i, expectedNet := range expectedNetworks {
			if mockIPSet.ensureCalls[i].network.String() != expectedNet.String() {
				t.Errorf("ensure call %d: expected network %v, got %v", i, expectedNet, mockIPSet.ensureCalls[i].network)
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

	t.Run("removes stale networks from set", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-set": {
					mustParseCIDR("192.168.1.0/24"),
					mustParseCIDR("10.0.0.0/16"),
					mustParseCIDR("172.16.0.0/12"), // This should be removed
				},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("192.168.1.0/24"),
			mustParseCIDR("10.0.0.0/16"),
			// 172.16.0.0/12 is not in desired state, should be deleted
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// No new networks should be added
		if len(mockIPSet.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		// Verify stale network was deleted
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}

		expectedDeleteNet := mustParseCIDR("172.16.0.0/12")
		if mockIPSet.deleteCalls[0].network.String() != expectedDeleteNet.String() {
			t.Errorf("delete call: expected network %v, got %v", expectedDeleteNet, mockIPSet.deleteCalls[0].network)
		}
		if mockIPSet.deleteCalls[0].setName != "test-set" {
			t.Errorf("delete call: expected set name 'test-set', got %v", mockIPSet.deleteCalls[0].setName)
		}
	})

	t.Run("adds and removes networks in single sync", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-set": {
					mustParseCIDR("192.168.1.0/24"), // Keep
					mustParseCIDR("10.0.0.0/16"),    // Remove
				},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("192.168.1.0/24"), // Keep existing
			mustParseCIDR("172.16.0.0/12"),  // Add new
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify new network was added
		if len(mockIPSet.ensureCalls) != 1 {
			t.Errorf("expected 1 ensure call, got %d", len(mockIPSet.ensureCalls))
		}
		expectedAddNet := mustParseCIDR("172.16.0.0/12")
		if mockIPSet.ensureCalls[0].network.String() != expectedAddNet.String() {
			t.Errorf("ensure call: expected network %v, got %v", expectedAddNet, mockIPSet.ensureCalls[0].network)
		}

		// Verify stale network was deleted
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}
		expectedDeleteNet := mustParseCIDR("10.0.0.0/16")
		if mockIPSet.deleteCalls[0].network.String() != expectedDeleteNet.String() {
			t.Errorf("delete call: expected network %v, got %v", expectedDeleteNet, mockIPSet.deleteCalls[0].network)
		}
	})

	t.Run("handles IPv6 networks", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-ipv6-set": {},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-ipv6-set"
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("2001:db8::/32"),
			mustParseCIDR("2001:db8:1::/48"),
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify IPv6 networks were added
		if len(mockIPSet.ensureCalls) != 2 {
			t.Errorf("expected 2 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		expectedNetworks := []net.IPNet{
			mustParseCIDR("2001:db8::/32"),
			mustParseCIDR("2001:db8:1::/48"),
		}
		for i, expectedNet := range expectedNetworks {
			if mockIPSet.ensureCalls[i].network.String() != expectedNet.String() {
				t.Errorf("ensure call %d: expected network %v, got %v", i, expectedNet, mockIPSet.ensureCalls[i].network)
			}
		}
	})

	t.Run("handles mixed network sizes", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"mixed-networks": {},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "mixed-networks"
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("192.168.1.0/24"),   // /24 subnet
			mustParseCIDR("10.0.0.0/8"),       // /8 supernet
			mustParseCIDR("172.16.1.0/30"),    // /30 small subnet
			mustParseCIDR("192.168.1.100/32"), // /32 host route
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify all networks were added correctly
		if len(mockIPSet.ensureCalls) != 4 {
			t.Errorf("expected 4 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}
	})

	t.Run("handles empty desired state", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-set": {
					mustParseCIDR("192.168.1.0/24"),
					mustParseCIDR("10.0.0.0/16"),
				},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{} // Empty desired state

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// No additions should occur
		if len(mockIPSet.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		// All existing networks should be deleted
		if len(mockIPSet.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPSet.deleteCalls))
		}
	})

	t.Run("handles nil desired state", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-set": {
					mustParseCIDR("192.168.1.0/24"),
				},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
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

		// All existing networks should be deleted
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}
	})

	t.Run("does nothing when state matches", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-set": {
					mustParseCIDR("192.168.1.0/24"),
					mustParseCIDR("10.0.0.0/16"),
				},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("192.168.1.0/24"),
			mustParseCIDR("10.0.0.0/16"),
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

	t.Run("returns error when ListNetworkEntries fails", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			listErr: errors.New("list network entries error"),
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{mustParseCIDR("192.168.1.0/24")}

		err := synchronizer.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "list network entries error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("returns error when EnsureNetworkEntry fails", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{"test-set": {}},
			ensureErr:      errors.New("ensure network entry error"),
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{mustParseCIDR("192.168.1.0/24")}

		err := synchronizer.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "ensure network entry error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("returns error when DeleteNetworkEntry fails", func(t *testing.T) {
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"test-set": {mustParseCIDR("192.168.1.0/24")},
			},
			deleteErr: errors.New("delete network entry error"),
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "test-set"
		synchronizer.Entries = []net.IPNet{} // Empty desired state - will trigger delete

		err := synchronizer.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "delete network entry error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})
}

func TestIPSetIPNetsSynchronizer_RealWorldScenario(t *testing.T) {
	t.Run("synchronizes firewall allowed networks", func(t *testing.T) {
		// Simulate existing firewall rules for allowed networks
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"allowed-networks": {
					mustParseCIDR("192.168.1.0/24"), // Keep - office network
					mustParseCIDR("10.10.0.0/16"),   // Remove - old VPN range
					mustParseCIDR("172.16.0.0/12"),  // Keep - internal services
				},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "allowed-networks"

		// New desired state: VPN range changed
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("192.168.1.0/24"), // Office network (keep)
			mustParseCIDR("172.16.0.0/12"),  // Internal services (keep)
			mustParseCIDR("10.20.0.0/16"),   // New VPN range (add)
			mustParseCIDR("203.0.113.0/24"), // External partner network (add)
			// 10.10.0.0/16 removed from desired state (delete)
		}

		err := synchronizer.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify new networks were added
		if len(mockIPSet.ensureCalls) != 2 {
			t.Errorf("expected 2 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		expectedAdds := []net.IPNet{
			mustParseCIDR("10.20.0.0/16"),
			mustParseCIDR("203.0.113.0/24"),
		}
		for i, expectedNet := range expectedAdds {
			if mockIPSet.ensureCalls[i].network.String() != expectedNet.String() {
				t.Errorf("ensure call %d: expected network %v, got %v", i, expectedNet, mockIPSet.ensureCalls[i].network)
			}
		}

		// Verify stale network was removed
		if len(mockIPSet.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPSet.deleteCalls))
		}

		expectedDeleteNet := mustParseCIDR("10.10.0.0/16")
		if mockIPSet.deleteCalls[0].network.String() != expectedDeleteNet.String() {
			t.Errorf("delete call: expected network %v, got %v", expectedDeleteNet, mockIPSet.deleteCalls[0].network)
		}
	})

	t.Run("handles service mesh network ranges", func(t *testing.T) {
		// Simulate Kubernetes service mesh network management
		mockIPSet := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"service-mesh-networks": {
					mustParseCIDR("10.96.0.0/12"), // Kubernetes service CIDR
				},
			},
		}

		synchronizer := createTestIPNetsSynchronizer(mockIPSet)
		synchronizer.SetName = "service-mesh-networks"
		synchronizer.Entries = []net.IPNet{
			mustParseCIDR("10.96.0.0/12"),  // Keep existing service CIDR
			mustParseCIDR("10.244.0.0/16"), // Add pod CIDR
			mustParseCIDR("10.100.0.0/16"), // Add ingress CIDR
		}

		err := synchronizer.Sync()
		if err != nil {
			t.Errorf("service mesh sync failed: %v", err)
		}

		// Verify pod and ingress CIDRs were added
		if len(mockIPSet.ensureCalls) != 2 {
			t.Errorf("expected 2 ensure calls, got %d", len(mockIPSet.ensureCalls))
		}

		// Verify no deletions (all existing networks were kept)
		if len(mockIPSet.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPSet.deleteCalls))
		}
	})

	t.Run("handles IPv4 and IPv6 dual stack", func(t *testing.T) {
		// Test dual-stack network configuration
		mockIPSetV4 := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"dual-stack-v4": {
					mustParseCIDR("192.168.0.0/16"),
				},
			},
		}

		mockIPSetV6 := &mockIPNetsSynchronizerIPSet{
			networkEntries: map[string][]net.IPNet{
				"dual-stack-v6": {
					mustParseCIDR("2001:db8::/32"),
				},
			},
		}

		// IPv4 synchronizer
		synchronizerV4 := createTestIPNetsSynchronizer(mockIPSetV4)
		synchronizerV4.SetName = "dual-stack-v4"
		synchronizerV4.Entries = []net.IPNet{
			mustParseCIDR("192.168.0.0/16"), // Keep existing
			mustParseCIDR("10.0.0.0/8"),     // Add new
		}

		// IPv6 synchronizer
		synchronizerV6 := createTestIPNetsSynchronizer(mockIPSetV6)
		synchronizerV6.SetName = "dual-stack-v6"
		synchronizerV6.Entries = []net.IPNet{
			mustParseCIDR("2001:db8::/32"),   // Keep existing
			mustParseCIDR("2001:db8:1::/48"), // Add new
		}

		err := synchronizerV4.Sync()
		if err != nil {
			t.Errorf("IPv4 sync failed: %v", err)
		}

		err = synchronizerV6.Sync()
		if err != nil {
			t.Errorf("IPv6 sync failed: %v", err)
		}

		// Verify both stacks were synchronized correctly
		if len(mockIPSetV4.ensureCalls) != 1 {
			t.Errorf("IPv4: expected 1 ensure call, got %d", len(mockIPSetV4.ensureCalls))
		}
		if len(mockIPSetV6.ensureCalls) != 1 {
			t.Errorf("IPv6: expected 1 ensure call, got %d", len(mockIPSetV6.ensureCalls))
		}
	})
}
