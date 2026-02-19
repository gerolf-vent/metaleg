package iptables

import (
	"fmt"
	"net"
	"strings"
	"testing"

	fm "github.com/gerolf-vent/metaleg/internal/firewall_manager"
	rm "github.com/gerolf-vent/metaleg/internal/route_manager"
	"github.com/gerolf-vent/metaleg/internal/utils/ipset"
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

// Mock IPTables implementation
type mockIPTablesForManager struct {
	protocol         iptables.Protocol
	ensureChainErr   error
	ensureRuleErr    error
	deleteRuleErr    error
	deleteChainErr   error
	listRulesErr     error
	rules            map[string][]string // chain -> rules
	ensureChainCalls []string
	ensureRuleCalls  [][]string
	deleteRuleCalls  [][]string
	deleteChainCalls []string
	listRulesCalls   []string
}

func (m *mockIPTablesForManager) IsIPv6() bool {
	return m.protocol == iptables.IPv6
}

func (m *mockIPTablesForManager) Protocol() iptables.Protocol {
	return m.protocol
}

func (m *mockIPTablesForManager) ChainExists(table iptables.Table, chain iptables.Chain) (bool, error) {
	return true, nil
}

func (m *mockIPTablesForManager) EnsureChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	if m.ensureChainCalls == nil {
		m.ensureChainCalls = []string{}
	}
	m.ensureChainCalls = append(m.ensureChainCalls, string(table)+":"+string(chain))
	return true, m.ensureChainErr
}

func (m *mockIPTablesForManager) FlushChain(table iptables.Table, chain iptables.Chain) error {
	return nil
}

func (m *mockIPTablesForManager) DeleteChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	if m.deleteChainCalls == nil {
		m.deleteChainCalls = []string{}
	}
	m.deleteChainCalls = append(m.deleteChainCalls, string(table)+":"+string(chain))
	return true, m.deleteChainErr
}

func (m *mockIPTablesForManager) RuleExists(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	return false, nil
}

func (m *mockIPTablesForManager) ListRules(table iptables.Table, chain iptables.Chain) ([][]string, error) {
	if m.listRulesCalls == nil {
		m.listRulesCalls = []string{}
	}
	m.listRulesCalls = append(m.listRulesCalls, string(table)+":"+string(chain))

	if m.listRulesErr != nil {
		return nil, m.listRulesErr
	}

	if m.rules == nil {
		return [][]string{}, nil
	}

	key := string(table) + ":" + string(chain)
	if rules, exists := m.rules[key]; exists {
		// Convert single rule string to proper format
		return [][]string{rules}, nil
	}

	return [][]string{}, nil
}

func (m *mockIPTablesForManager) EnsureRule(pos iptables.RulePosition, table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	if m.ensureRuleCalls == nil {
		m.ensureRuleCalls = [][]string{}
	}
	m.ensureRuleCalls = append(m.ensureRuleCalls, rulespec)
	return true, m.ensureRuleErr
}

func (m *mockIPTablesForManager) DeleteRule(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	if m.deleteRuleCalls == nil {
		m.deleteRuleCalls = [][]string{}
	}
	m.deleteRuleCalls = append(m.deleteRuleCalls, rulespec)
	return true, m.deleteRuleErr
}

// Mock IPSet implementation
type mockIPSetForManager struct {
	ensureSetErr          error
	ensureNetworkSetErr   error
	deleteSetErr          error
	listSetsErr           error
	sets                  []string
	ensureSetCalls        []string
	ensureNetworkSetCalls []string
	deleteSetCalls        []string
}

func (m *mockIPSetForManager) EnsureSet(name string, protocol ipset.Protocol) (bool, error) {
	if m.ensureSetCalls == nil {
		m.ensureSetCalls = []string{}
	}
	m.ensureSetCalls = append(m.ensureSetCalls, name)
	return true, m.ensureSetErr
}

func (m *mockIPSetForManager) EnsureNetworkSet(name string, protocol ipset.Protocol) (bool, error) {
	if m.ensureNetworkSetCalls == nil {
		m.ensureNetworkSetCalls = []string{}
	}
	m.ensureNetworkSetCalls = append(m.ensureNetworkSetCalls, name)
	return true, m.ensureNetworkSetErr
}

func (m *mockIPSetForManager) DeleteSet(name string) (bool, error) {
	if m.deleteSetCalls == nil {
		m.deleteSetCalls = []string{}
	}
	m.deleteSetCalls = append(m.deleteSetCalls, name)
	return true, m.deleteSetErr
}

func (m *mockIPSetForManager) ListSets() ([]string, error) {
	if m.listSetsErr != nil {
		return nil, m.listSetsErr
	}
	return m.sets, nil
}

func (m *mockIPSetForManager) SetExists(name string) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) ListEntries(setName string) ([]net.IP, error) {
	return []net.IP{}, nil
}

func (m *mockIPSetForManager) EntryExists(setName string, entry net.IP) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) EnsureEntry(setName string, entry net.IP) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) DeleteEntry(setName string, entry net.IP) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) NetworkSetExists(name string) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) DeleteNetworkSet(name string) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) NetworkEntryExists(name string, cidr net.IPNet) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) ListNetworkEntries(setName string) ([]net.IPNet, error) {
	return []net.IPNet{}, nil
}

func (m *mockIPSetForManager) EnsureNetworkEntry(setName string, cidr *net.IPNet) (bool, error) {
	return true, nil
}

func (m *mockIPSetForManager) DeleteNetworkEntry(setName string, cidr *net.IPNet) (bool, error) {
	return true, nil
}

func createMockIPTablesManager(nodeName string) (*Manager, *mockIPTablesForManager, *mockIPTablesForManager, *mockIPSetForManager) {
	mockIPT4 := &mockIPTablesForManager{protocol: iptables.IPv4}
	mockIPT6 := &mockIPTablesForManager{protocol: iptables.IPv6}
	mockIPS := &mockIPSetForManager{}

	_, excludeNet4, _ := net.ParseCIDR("10.0.0.0/8")
	_, excludeNet6, _ := net.ParseCIDR("2001:db8::/32")

	iptm := &Manager{
		nodeName:        nodeName,
		fwMask:          0x00F00000,
		excludeDstCIDRs: []net.IPNet{*excludeNet4, *excludeNet6},
		ipt4:            mockIPT4,
		ipt6:            mockIPT6,
		ips:             mockIPS,
	}

	return iptm, mockIPT4, mockIPT6, mockIPS
}

func TestNewManager(t *testing.T) {
	t.Run("creates manager with valid parameters", func(t *testing.T) {
		_, excludeNet, _ := net.ParseCIDR("10.0.0.0/8")
		excludeDstCIDRs := []net.IPNet{*excludeNet}

		// This test would require actual iptables/ipset binaries, so we'll skip it
		// in environments where they're not available
		t.Skip("Skipping integration test - requires iptables/ipset binaries")

		manager, err := NewManager("test-node", 0x00F00000, excludeDstCIDRs)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if manager == nil {
			t.Error("expected non-nil manager")
		}
		if manager.nodeName != "test-node" {
			t.Errorf("expected node name 'test-node', got %v", manager.nodeName)
		}
		if manager.fwMask != 0x00F00000 {
			t.Errorf("expected fw mask 0x00F00000, got 0x%08X", manager.fwMask)
		}
	})
}

func TestManager_Setup(t *testing.T) {
	t.Run("sets up chains and rules successfully", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPS // Suppress unused warning

		err := iptm.Setup()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify chains were created for both IPv4 and IPv6
		expectedChains := []string{
			"mangle:" + iptablesRTMarkChainName,
			"filter:" + iptablesRejectChainName,
			"nat:" + iptablesSNATChainName,
		}

		for _, expectedChain := range expectedChains {
			found := false
			for _, call := range mockIPT4.ensureChainCalls {
				if call == expectedChain {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected IPv4 chain %s to be created", expectedChain)
			}

			found = false
			for _, call := range mockIPT6.ensureChainCalls {
				if call == expectedChain {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected IPv6 chain %s to be created", expectedChain)
			}
		}

		// Verify exclude destination ipsets were created
		if len(mockIPS.ensureNetworkSetCalls) != 2 {
			t.Errorf("expected 2 network set calls (IPv4 and IPv6), got %d", len(mockIPS.ensureNetworkSetCalls))
		}
	})

	t.Run("handles chain creation error", func(t *testing.T) {
		iptm, mockIPT4, _, _ := createMockIPTablesManager("test-node")
		mockIPT4.ensureChainErr = fmt.Errorf("chain creation failed")

		err := iptm.Setup()

		if err == nil {
			t.Error("expected error due to chain creation failure")
		}
		if !strings.Contains(err.Error(), "chain creation failed") {
			t.Errorf("expected error to contain 'chain creation failed', got %v", err)
		}
	})

	t.Run("handles rule creation error", func(t *testing.T) {
		iptm, mockIPT4, _, _ := createMockIPTablesManager("test-node")
		mockIPT4.ensureRuleErr = fmt.Errorf("rule creation failed")

		err := iptm.Setup()

		if err == nil {
			t.Error("expected error due to rule creation failure")
		}
		if !strings.Contains(err.Error(), "rule creation failed") {
			t.Errorf("expected error to contain 'rule creation failed', got %v", err)
		}
	})

	t.Run("handles ipset creation error", func(t *testing.T) {
		iptm, _, _, mockIPS := createMockIPTablesManager("test-node")
		mockIPS.ensureNetworkSetErr = fmt.Errorf("ipset creation failed")

		err := iptm.Setup()

		if err == nil {
			t.Error("expected error due to ipset creation failure")
		}
		if !strings.Contains(err.Error(), "ipset creation failed") {
			t.Errorf("expected error to contain 'ipset creation failed', got %v", err)
		}
	})
}

func TestManager_Cleanup(t *testing.T) {
	t.Run("cleans up chains and rules successfully", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning
		mockIPS.sets = []string{"METALEG-SRC-TEST", "inet6:METALEG-SRC-TEST", "OTHER-SET"}

		err := iptm.Cleanup()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify chains were deleted for both IPv4 and IPv6
		expectedChains := []string{
			"mangle:" + iptablesRTMarkChainName,
			"filter:" + iptablesRejectChainName,
			"nat:" + iptablesSNATChainName,
		}

		for _, expectedChain := range expectedChains {
			found := false
			for _, call := range mockIPT4.deleteChainCalls {
				if call == expectedChain {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected IPv4 chain %s to be deleted", expectedChain)
			}

			found = false
			for _, call := range mockIPT6.deleteChainCalls {
				if call == expectedChain {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected IPv6 chain %s to be deleted", expectedChain)
			}
		}

		// Verify METALEG ipsets were deleted but not others
		expectedDeleted := []string{"METALEG-SRC-TEST", "inet6:METALEG-SRC-TEST"}
		for _, expected := range expectedDeleted {
			found := false
			for _, call := range mockIPS.deleteSetCalls {
				if call == expected {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected ipset %s to be deleted", expected)
			}
		}

		// Verify OTHER-SET was not deleted
		for _, call := range mockIPS.deleteSetCalls {
			if call == "OTHER-SET" {
				t.Error("expected OTHER-SET to not be deleted")
			}
		}
	})

	t.Run("handles deletion errors gracefully", func(t *testing.T) {
		iptm, mockIPT4, _, mockIPS := createMockIPTablesManager("test-node")
		mockIPT4.deleteChainErr = fmt.Errorf("deletion failed")
		mockIPS.listSetsErr = fmt.Errorf("list sets failed")

		err := iptm.Cleanup()

		// Should return an error but not panic
		if err == nil {
			t.Error("expected error due to deletion failures")
		}

		// Suppress unused variable warning
		_ = mockIPT4
	})
}

func TestManager_ReconcileEgressRule(t *testing.T) {
	t.Run("handles nil rule gracefully", func(t *testing.T) {
		iptm, _, _, _ := createMockIPTablesManager("test-node")

		err := iptm.ReconcileEgressRule(nil, true)

		if err != nil {
			t.Errorf("expected no error for nil rule, got %v", err)
		}
	})

	t.Run("reconciles rule for local gateway", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning

		rule := &fm.EgressRule{
			ID:         "test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SNATIPv6:   net.ParseIP("2001:db8:100::1"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			SrcIPv6s:   []net.IP{net.ParseIP("2001:db8::1")},
			GWNodeName: "test-node", // Local gateway
		}

		err := iptm.ReconcileEgressRule(rule, true)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify ipsets were created for both IPv4 and IPv6
		if len(mockIPS.ensureSetCalls) != 2 {
			t.Errorf("expected 2 ipset ensure calls, got %d", len(mockIPS.ensureSetCalls))
		}

		// For local gateway, SNAT rules should be created, not reject or mark rules
		// This is verified by the rule synchronizers being called appropriately
	})

	t.Run("reconciles rule for remote gateway", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning

		gwRoute := &rm.NodeRoute{
			Name:         "remote-node",
			IPv4:         net.ParseIP("10.0.1.10"),
			IPv6:         net.ParseIP("2001:db8::10"),
			ID:           1,
			IDAllocated:  true,
			FWMark:       0x00100000,
			RouteTableID: 100001,
			RuleCount:    1,
		}

		rule := &fm.EgressRule{
			ID:         "test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SNATIPv6:   net.ParseIP("2001:db8:100::1"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			SrcIPv6s:   []net.IP{net.ParseIP("2001:db8::1")},
			GWNodeName: "remote-node",
			GWRoute:    gwRoute,
		}

		err := iptm.ReconcileEgressRule(rule, true)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify ipsets were created
		if len(mockIPS.ensureSetCalls) != 2 {
			t.Errorf("expected 2 ipset ensure calls, got %d", len(mockIPS.ensureSetCalls))
		}
	})

	t.Run("removes rule when present is false", func(t *testing.T) {
		iptm, _, _, mockIPS := createMockIPTablesManager("test-node")

		rule := &fm.EgressRule{
			ID:         "test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "test-node",
		}

		err := iptm.ReconcileEgressRule(rule, false)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify ipsets were deleted
		if len(mockIPS.deleteSetCalls) != 2 {
			t.Errorf("expected 2 ipset delete calls, got %d", len(mockIPS.deleteSetCalls))
		}
	})

	t.Run("handles ipset creation error", func(t *testing.T) {
		iptm, _, _, mockIPS := createMockIPTablesManager("test-node")
		mockIPS.ensureSetErr = fmt.Errorf("ipset creation failed")

		rule := &fm.EgressRule{
			ID:         "test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "test-node",
		}

		err := iptm.ReconcileEgressRule(rule, true)

		if err == nil {
			t.Error("expected error due to ipset creation failure")
		}
		if !strings.Contains(err.Error(), "ipset creation failed") {
			t.Errorf("expected error to contain 'ipset creation failed', got %v", err)
		}
	})
}

func TestManager_CleanupStaleEgressRules(t *testing.T) {
	t.Run("handles empty rules map", func(t *testing.T) {
		iptm, _, _, _ := createMockIPTablesManager("test-node")

		err := iptm.CleanupStaleEgressRules(map[string]*fm.EgressRule{})

		if err != nil {
			t.Errorf("expected no error for empty rules, got %v", err)
		}
	})

	t.Run("handles nil rules map", func(t *testing.T) {
		iptm, _, _, _ := createMockIPTablesManager("test-node")

		err := iptm.CleanupStaleEgressRules(nil)

		if err != nil {
			t.Errorf("expected no error for nil rules, got %v", err)
		}
	})

	t.Run("cleans up stale rules successfully", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning
		_ = mockIPS  // Suppress unused warning

		rules := map[string]*fm.EgressRule{
			"rule1": {ID: "rule1"},
			"rule2": {ID: "rule2"},
		}

		err := iptm.CleanupStaleEgressRules(rules)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// The cleanup process involves rule cleaners which would be tested separately
	})
}

func TestManager_RuleCreationAndDeletion(t *testing.T) {
	t.Run("creates SNAT rules for local gateway", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")

		rule := &fm.EgressRule{
			ID:         "snat-test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SNATIPv6:   net.ParseIP("2001:db8:100::1"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.2")},
			SrcIPv6s:   []net.IP{net.ParseIP("2001:db8::1")},
			GWNodeName: "test-node", // Local gateway
		}

		err := iptm.ReconcileEgressRule(rule, true)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify ipsets were created for both IPv4 and IPv6
		if len(mockIPS.ensureSetCalls) != 2 {
			t.Errorf("expected 2 ipset ensure calls, got %d", len(mockIPS.ensureSetCalls))
		}

		// Verify rule hash calculation
		expectedIPv4Hash := rule.CalcIDHash(false)
		expectedIPv6Hash := rule.CalcIDHash(true)

		expectedIPSetNames := []string{
			"METALEG-SRC-" + expectedIPv4Hash,
			"inet6:METALEG-SRC-" + expectedIPv6Hash,
		}

		for i, expectedName := range expectedIPSetNames {
			if i < len(mockIPS.ensureSetCalls) && mockIPS.ensureSetCalls[i] != expectedName {
				t.Errorf("expected ipset name %s, got %s", expectedName, mockIPS.ensureSetCalls[i])
			}
		}

		// For local gateway, should create SNAT rules, not reject or mark rules
		// Verify both IPv4 and IPv6 iptables have rules added
		if len(mockIPT4.ensureRuleCalls) == 0 {
			t.Error("expected IPv4 iptables rules to be created")
		}
		if len(mockIPT6.ensureRuleCalls) == 0 {
			t.Error("expected IPv6 iptables rules to be created")
		}
	})

	t.Run("creates mark rules for remote gateway", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")

		gwRoute := &rm.NodeRoute{
			Name:         "remote-node",
			IPv4:         net.ParseIP("10.0.1.10"),
			IPv6:         net.ParseIP("2001:db8::10"),
			ID:           1,
			IDAllocated:  true,
			FWMark:       0x00100000,
			RouteTableID: 100001,
			RuleCount:    1,
		}

		rule := &fm.EgressRule{
			ID:         "mark-test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SNATIPv6:   net.ParseIP("2001:db8:100::1"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			SrcIPv6s:   []net.IP{net.ParseIP("2001:db8::1")},
			GWNodeName: "remote-node",
			GWRoute:    gwRoute,
		}

		err := iptm.ReconcileEgressRule(rule, true)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify ipsets were created
		if len(mockIPS.ensureSetCalls) != 2 {
			t.Errorf("expected 2 ipset ensure calls, got %d", len(mockIPS.ensureSetCalls))
		}

		// For remote gateway with allocated route, should create mark rules
		if len(mockIPT4.ensureRuleCalls) == 0 {
			t.Error("expected IPv4 iptables mark rules to be created")
		}
		if len(mockIPT6.ensureRuleCalls) == 0 {
			t.Error("expected IPv6 iptables mark rules to be created")
		}
	})

	t.Run("creates reject rules for unknown remote gateway", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT6 // Suppress unused warning

		rule := &fm.EgressRule{
			ID:         "reject-test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "unknown-node", // Remote gateway without route
			GWRoute:    nil,            // No route known
		}

		err := iptm.ReconcileEgressRule(rule, true)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Should create ipsets
		if len(mockIPS.ensureSetCalls) != 2 {
			t.Errorf("expected 2 ipset ensure calls, got %d", len(mockIPS.ensureSetCalls))
		}

		// Should create reject rules for unknown gateway
		if len(mockIPT4.ensureRuleCalls) == 0 {
			t.Error("expected IPv4 iptables reject rules to be created")
		}
	})

	t.Run("deletes rules when present is false", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning

		rule := &fm.EgressRule{
			ID:         "delete-test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "test-node",
		}

		err := iptm.ReconcileEgressRule(rule, false)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify ipsets were deleted
		if len(mockIPS.deleteSetCalls) != 2 {
			t.Errorf("expected 2 ipset delete calls, got %d", len(mockIPS.deleteSetCalls))
		}

		expectedIPv4Hash := rule.CalcIDHash(false)
		expectedIPv6Hash := rule.CalcIDHash(true)

		expectedDeletedSets := []string{
			"METALEG-SRC-" + expectedIPv4Hash,
			"inet6:METALEG-SRC-" + expectedIPv6Hash,
		}

		for i, expectedName := range expectedDeletedSets {
			if i < len(mockIPS.deleteSetCalls) && mockIPS.deleteSetCalls[i] != expectedName {
				t.Errorf("expected deleted ipset name %s, got %s", expectedName, mockIPS.deleteSetCalls[i])
			}
		}
	})

	t.Run("handles rule transitions between gateway types", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")

		rule := &fm.EgressRule{
			ID:         "transition-test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "test-node", // Start as local gateway
		}

		// First, create rule for local gateway (SNAT rules)
		err := iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Errorf("expected no error for local gateway, got %v", err)
		}

		// Reset mock counters
		mockIPT4.ensureRuleCalls = nil
		mockIPT6.ensureRuleCalls = nil
		mockIPS.ensureSetCalls = nil

		// Now change to remote gateway with route
		gwRoute := &rm.NodeRoute{
			Name:         "remote-node",
			IPv4:         net.ParseIP("10.0.1.10"),
			ID:           1,
			IDAllocated:  true,
			FWMark:       0x00100000,
			RouteTableID: 100001,
			RuleCount:    1,
		}

		rule.GWNodeName = "remote-node"
		rule.GWRoute = gwRoute

		// Reconcile again - should switch from SNAT to mark rules
		err = iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Errorf("expected no error for remote gateway transition, got %v", err)
		}

		// Should still create ipsets
		if len(mockIPS.ensureSetCalls) != 2 {
			t.Errorf("expected 2 ipset ensure calls after transition, got %d", len(mockIPS.ensureSetCalls))
		}

		// Should create new rules for remote gateway
		if len(mockIPT4.ensureRuleCalls) == 0 {
			t.Error("expected IPv4 rules to be created after transition")
		}
	})
}

func TestManager_SpecificRuleTypes(t *testing.T) {
	t.Run("verifies SNAT rule creation details", func(t *testing.T) {
		iptm, mockIPT4, _, _ := createMockIPTablesManager("test-node")

		rule := &fm.EgressRule{
			ID:         "snat-detail-test",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "test-node",
		}

		err := iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}

		// Check that rule specs contain expected elements for SNAT
		found := false
		for _, ruleSpec := range mockIPT4.ensureRuleCalls {
			// Look for SNAT rule characteristics
			ruleStr := strings.Join(ruleSpec, " ")
			if strings.Contains(ruleStr, "SNAT") && strings.Contains(ruleStr, "192.168.1.100") {
				found = true
				break
			}
		}

		if !found {
			t.Error("expected to find SNAT rule with target IP in rule specifications")
		}
	})

	t.Run("verifies mark rule creation details", func(t *testing.T) {
		iptm, mockIPT4, _, _ := createMockIPTablesManager("test-node")

		gwRoute := &rm.NodeRoute{
			Name:         "remote-node",
			ID:           1,
			IDAllocated:  true,
			FWMark:       0x00100000,
			RouteTableID: 100001,
			RuleCount:    1,
		}

		rule := &fm.EgressRule{
			ID:         "mark-detail-test",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "remote-node",
			GWRoute:    gwRoute,
		}

		err := iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}

		// Check that rule specs contain expected elements for MARK
		found := false
		for _, ruleSpec := range mockIPT4.ensureRuleCalls {
			ruleStr := strings.Join(ruleSpec, " ")
			if strings.Contains(ruleStr, "MARK") || strings.Contains(ruleStr, "mark") {
				found = true
				break
			}
		}

		if !found {
			t.Error("expected to find MARK rule in rule specifications")
		}
	})

	t.Run("verifies reject rule creation details", func(t *testing.T) {
		iptm, mockIPT4, _, _ := createMockIPTablesManager("test-node")

		rule := &fm.EgressRule{
			ID:         "reject-detail-test",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "unknown-node",
			GWRoute:    nil,
		}

		err := iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}

		// Check that rule specs contain expected elements for REJECT
		found := false
		for _, ruleSpec := range mockIPT4.ensureRuleCalls {
			ruleStr := strings.Join(ruleSpec, " ")
			if strings.Contains(ruleStr, "REJECT") || strings.Contains(ruleStr, "reject") {
				found = true
				break
			}
		}

		if !found {
			t.Error("expected to find REJECT rule in rule specifications")
		}
	})
}

func TestManager_Integration(t *testing.T) {
	t.Run("complete workflow", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning
		_ = mockIPS  // Suppress unused warning

		// Setup
		err := iptm.Setup()
		if err != nil {
			t.Fatalf("setup failed: %v", err)
		}

		// Create a rule
		rule := &fm.EgressRule{
			ID:         "integration-test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "test-node",
		}

		// Reconcile the rule
		err = iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Fatalf("reconcile failed: %v", err)
		}

		// Clean up stale rules
		err = iptm.CleanupStaleEgressRules(map[string]*fm.EgressRule{
			"integration-test-rule": rule,
		})
		if err != nil {
			t.Fatalf("cleanup stale failed: %v", err)
		}

		// Remove the rule
		err = iptm.ReconcileEgressRule(rule, false)
		if err != nil {
			t.Fatalf("remove rule failed: %v", err)
		}

		// Final cleanup
		err = iptm.Cleanup()
		if err != nil {
			t.Fatalf("cleanup failed: %v", err)
		}
	})
}

func TestManager_RuleSynchronization(t *testing.T) {
	t.Run("synchronizes multiple rules correctly", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT6 // Suppress unused warning

		rules := []*fm.EgressRule{
			{
				ID:         "rule-1",
				SNATIPv4:   net.ParseIP("192.168.1.100"),
				SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
				GWNodeName: "test-node", // Local gateway
			},
			{
				ID:         "rule-2",
				SNATIPv4:   net.ParseIP("192.168.1.101"),
				SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.2")},
				GWNodeName: "remote-node", // Remote gateway without route
			},
		}

		// Create both rules
		for _, rule := range rules {
			err := iptm.ReconcileEgressRule(rule, true)
			if err != nil {
				t.Errorf("failed to reconcile rule %s: %v", rule.ID, err)
			}
		}

		// Verify ipsets were created for both rules (2 rules × 2 protocols = 4 sets)
		if len(mockIPS.ensureSetCalls) != 4 {
			t.Errorf("expected 4 ipset ensure calls, got %d", len(mockIPS.ensureSetCalls))
		}

		// Verify rules were created for both IPv4 and IPv6
		if len(mockIPT4.ensureRuleCalls) == 0 {
			t.Error("expected IPv4 iptables rules to be created")
		}

		// Verify rule IDs are properly calculated and unique
		seenHashes := make(map[string]bool)
		for _, rule := range rules {
			hash := rule.CalcIDHash(false)
			if seenHashes[hash] {
				t.Errorf("duplicate hash found for rule %s: %s", rule.ID, hash)
			}
			seenHashes[hash] = true
		}
	})

	t.Run("handles rule updates correctly", func(t *testing.T) {
		iptm, mockIPT4, _, mockIPS := createMockIPTablesManager("test-node")

		rule := &fm.EgressRule{
			ID:         "update-test-rule",
			SNATIPv4:   net.ParseIP("192.168.1.100"),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
			GWNodeName: "test-node",
		}

		// Initial creation
		err := iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Errorf("initial rule creation failed: %v", err)
		}

		initialRuleCalls := len(mockIPT4.ensureRuleCalls)
		initialIPSetCalls := len(mockIPS.ensureSetCalls)

		// Reset counters
		mockIPT4.ensureRuleCalls = nil
		mockIPS.ensureSetCalls = nil

		// Update rule with new SNAT IP
		rule.SNATIPv4 = net.ParseIP("192.168.1.200")
		err = iptm.ReconcileEgressRule(rule, true)
		if err != nil {
			t.Errorf("rule update failed: %v", err)
		}

		// Should still create ipsets and rules (synchronization process)
		if len(mockIPS.ensureSetCalls) != 2 { // IPv4 and IPv6
			t.Errorf("expected 2 ipset ensure calls on update, got %d", len(mockIPS.ensureSetCalls))
		}

		if len(mockIPT4.ensureRuleCalls) == 0 {
			t.Error("expected iptables rules to be updated")
		}

		// Verify initial calls happened
		if initialRuleCalls == 0 {
			t.Error("expected initial rule calls to have occurred")
		}
		if initialIPSetCalls == 0 {
			t.Error("expected initial ipset calls to have occurred")
		}
	})

	t.Run("handles rule removal correctly", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning

		rules := []*fm.EgressRule{
			{
				ID:         "remove-rule-1",
				SNATIPv4:   net.ParseIP("192.168.1.100"),
				SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
				GWNodeName: "test-node",
			},
			{
				ID:         "remove-rule-2",
				SNATIPv4:   net.ParseIP("192.168.1.101"),
				SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.2")},
				GWNodeName: "test-node",
			},
		}

		// Create both rules
		for _, rule := range rules {
			err := iptm.ReconcileEgressRule(rule, true)
			if err != nil {
				t.Errorf("failed to create rule %s: %v", rule.ID, err)
			}
		}

		// Reset counters
		mockIPS.deleteSetCalls = nil

		// Remove first rule
		err := iptm.ReconcileEgressRule(rules[0], false)
		if err != nil {
			t.Errorf("failed to remove rule: %v", err)
		}

		// Verify ipsets were deleted for the removed rule
		if len(mockIPS.deleteSetCalls) != 2 { // IPv4 and IPv6
			t.Errorf("expected 2 ipset delete calls, got %d", len(mockIPS.deleteSetCalls))
		}

		// Verify correct ipset names were deleted
		expectedIPv4Hash := rules[0].CalcIDHash(false)
		expectedIPv6Hash := rules[0].CalcIDHash(true)
		expectedNames := []string{
			"METALEG-SRC-" + expectedIPv4Hash,
			"inet6:METALEG-SRC-" + expectedIPv6Hash,
		}

		for i, expectedName := range expectedNames {
			if i < len(mockIPS.deleteSetCalls) && mockIPS.deleteSetCalls[i] != expectedName {
				t.Errorf("expected deleted ipset %s, got %s", expectedName, mockIPS.deleteSetCalls[i])
			}
		}
	})
}

func TestManager_CleanupOperations(t *testing.T) {
	t.Run("cleans up all iptables chains and rules", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		mockIPS.sets = []string{
			"METALEG-SRC-ABCD1234",
			"inet6:METALEG-SRC-EFGH5678",
			"METALEG-EXCLUDE-DST-4",
			"inet6:METALEG-EXCLUDE-DST-6",
			"OTHER-UNRELATED-SET",
		}

		err := iptm.Cleanup()
		if err != nil {
			t.Errorf("cleanup failed: %v", err)
		}

		// Verify chain deletions for both IPv4 and IPv6
		expectedChainDeletions := []string{
			"mangle:" + iptablesRTMarkChainName,
			"filter:" + iptablesRejectChainName,
			"nat:" + iptablesSNATChainName,
		}

		for _, expectedDeletion := range expectedChainDeletions {
			foundIPv4 := false
			foundIPv6 := false

			for _, call := range mockIPT4.deleteChainCalls {
				if call == expectedDeletion {
					foundIPv4 = true
					break
				}
			}

			for _, call := range mockIPT6.deleteChainCalls {
				if call == expectedDeletion {
					foundIPv6 = true
					break
				}
			}

			if !foundIPv4 {
				t.Errorf("expected IPv4 chain deletion: %s", expectedDeletion)
			}
			if !foundIPv6 {
				t.Errorf("expected IPv6 chain deletion: %s", expectedDeletion)
			}
		}

		// Verify rule deletions for both IPv4 and IPv6
		expectedRuleDeletions := []string{
			"-j " + iptablesRTMarkChainName,
			"-j " + iptablesRejectChainName,
			"-j " + iptablesSNATChainName,
		}

		for _, expectedDeletion := range expectedRuleDeletions {
			foundIPv4 := false
			foundIPv6 := false

			for _, ruleCall := range mockIPT4.deleteRuleCalls {
				ruleStr := strings.Join(ruleCall, " ")
				if strings.Contains(ruleStr, expectedDeletion) {
					foundIPv4 = true
					break
				}
			}

			for _, ruleCall := range mockIPT6.deleteRuleCalls {
				ruleStr := strings.Join(ruleCall, " ")
				if strings.Contains(ruleStr, expectedDeletion) {
					foundIPv6 = true
					break
				}
			}

			if !foundIPv4 {
				t.Errorf("expected IPv4 rule deletion containing: %s", expectedDeletion)
			}
			if !foundIPv6 {
				t.Errorf("expected IPv6 rule deletion containing: %s", expectedDeletion)
			}
		}

		// Verify ipset cleanup - should delete METALEG sets but not others
		expectedIPSetDeletions := []string{
			"METALEG-SRC-ABCD1234",
			"inet6:METALEG-SRC-EFGH5678",
			"METALEG-EXCLUDE-DST-4",
			"inet6:METALEG-EXCLUDE-DST-6",
		}

		for _, expectedDeletion := range expectedIPSetDeletions {
			found := false
			for _, call := range mockIPS.deleteSetCalls {
				if call == expectedDeletion {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("expected ipset deletion: %s", expectedDeletion)
			}
		}

		// Verify OTHER-UNRELATED-SET was not deleted
		for _, call := range mockIPS.deleteSetCalls {
			if call == "OTHER-UNRELATED-SET" {
				t.Error("unexpected deletion of non-METALEG ipset")
			}
		}
	})

	t.Run("handles partial cleanup failures gracefully", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")

		// Set up various error conditions
		mockIPT4.deleteChainErr = fmt.Errorf("IPv4 chain deletion failed")
		mockIPT6.deleteRuleErr = fmt.Errorf("IPv6 rule deletion failed")
		mockIPS.listSetsErr = fmt.Errorf("ipset list failed")

		err := iptm.Cleanup()

		// Should return error but continue with other cleanup operations
		if err == nil {
			t.Error("expected cleanup to return error due to failures")
		}

		// Should still attempt cleanup operations despite errors
		if len(mockIPT4.deleteChainCalls) == 0 {
			t.Error("expected IPv4 chain deletion attempts")
		}
		if len(mockIPT6.deleteRuleCalls) == 0 {
			t.Error("expected IPv6 rule deletion attempts")
		}
	})

	t.Run("stale rule cleanup with multiple rules", func(t *testing.T) {
		iptm, mockIPT4, mockIPT6, mockIPS := createMockIPTablesManager("test-node")
		_ = mockIPT4 // Suppress unused warning
		_ = mockIPT6 // Suppress unused warning
		_ = mockIPS  // Suppress unused warning

		rules := map[string]*fm.EgressRule{
			"active-rule-1": {
				ID:         "active-rule-1",
				SNATIPv4:   net.ParseIP("192.168.1.100"),
				SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.1")},
				GWNodeName: "test-node",
			},
			"active-rule-2": {
				ID:         "active-rule-2",
				SNATIPv4:   net.ParseIP("192.168.1.101"),
				SrcIPv4s:   []net.IP{net.ParseIP("10.0.1.2")},
				GWNodeName: "remote-node",
			},
		}

		err := iptm.CleanupStaleEgressRules(rules)
		if err != nil {
			t.Errorf("stale rule cleanup failed: %v", err)
		}

		// The actual cleanup logic would be handled by the rule cleaners
		// This test verifies the method can be called without error
		// More detailed testing would require mocking the rule cleaners
	})
}
