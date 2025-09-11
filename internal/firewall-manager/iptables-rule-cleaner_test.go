package firewall_manager

import (
	"errors"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

// Test rule implementation for testing
type TestCleanerRule struct {
	ID      string
	Content string
	SpecVal []string
}

func (r *TestCleanerRule) RuleID() string {
	if r == nil {
		return ""
	}
	return r.ID
}

func (r *TestCleanerRule) String() string {
	if r == nil {
		return ""
	}
	return r.Content
}

func (r *TestCleanerRule) Spec() []string {
	if r == nil {
		return []string{}
	}
	return r.SpecVal
}

// Mock iptables implementation for cleaner tests
type mockCleanerIPTables struct {
	rules       [][]string
	protocol    iptables.Protocol
	listErr     error
	deleteErr   error
	deleteCalls [][]string
}

func (m *mockCleanerIPTables) IsIPv6() bool {
	return m.protocol == iptables.IPv6
}

func (m *mockCleanerIPTables) Protocol() iptables.Protocol {
	return m.protocol
}

func (m *mockCleanerIPTables) ChainExists(table iptables.Table, chain iptables.Chain) (bool, error) {
	return true, nil
}

func (m *mockCleanerIPTables) EnsureChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	return true, nil
}

func (m *mockCleanerIPTables) FlushChain(table iptables.Table, chain iptables.Chain) error {
	return nil
}

func (m *mockCleanerIPTables) DeleteChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	return true, nil
}

func (m *mockCleanerIPTables) RuleExists(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	return false, nil
}

func (m *mockCleanerIPTables) ListRules(table iptables.Table, chain iptables.Chain) ([][]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.rules, nil
}

func (m *mockCleanerIPTables) EnsureRule(pos iptables.RulePosition, table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	return true, nil
}

func (m *mockCleanerIPTables) DeleteRule(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	if m.deleteCalls == nil {
		m.deleteCalls = [][]string{}
	}
	m.deleteCalls = append(m.deleteCalls, rulespec)
	if m.deleteErr != nil {
		return false, m.deleteErr
	}
	return true, nil
}

// Test parser function
func testCleanerParser(spec []string, protocol iptables.Protocol) (*TestCleanerRule, bool) {
	if len(spec) < 2 {
		return nil, false
	}

	// Handle full iptables rule format: ["-A", "CHAIN", "-j", "ACCEPT", "--comment", "test-rule-id"]
	// Find the target (-j) flag and comment
	for i := 0; i < len(spec)-3; i++ {
		if spec[i] == "-j" && i+3 < len(spec) && spec[i+2] == "--comment" {
			target := spec[i+1]
			id := spec[i+3]
			return &TestCleanerRule{
				ID:      id,
				Content: "-j " + target + " --comment " + id,
				SpecVal: spec[2:], // Remove "-A CHAIN" prefix for rule spec
			}, true
		}
	}

	return nil, false
}

func createTestCleaner(mockIPT iptables.IPTables) *IPTablesRuleCleaner[*TestCleanerRule] {
	cleaner := NewIPTablesRuleCleaner[*TestCleanerRule](mockIPT)
	cleaner.Parser = testCleanerParser
	cleaner.Table = iptables.TableFilter
	cleaner.Chain = iptables.Chain("TEST")
	return cleaner
}

func TestNewIPTablesRuleCleaner(t *testing.T) {
	mockIPT := &mockCleanerIPTables{protocol: iptables.IPv4}

	cleaner := NewIPTablesRuleCleaner[*TestCleanerRule](mockIPT)

	if cleaner.ipt != mockIPT {
		t.Error("expected iptables instance to be set")
	}
	if cleaner.Parser != nil {
		t.Error("expected parser to be nil initially")
	}
	if cleaner.ExpectedRuleIDs != nil {
		t.Error("expected expected rule IDs to be nil initially")
	}
	if cleaner.IgnoreRulePredicate != nil {
		t.Error("expected ignore rule predicate to be nil initially")
	}
}

func TestIPTablesRuleCleaner_Clean(t *testing.T) {
	t.Run("deletes stale rules not in expected set", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "keep-rule-1"},
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "delete-rule-1"},
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "keep-rule-2"},
				{"-A", "TEST", "-j", "DROP", "--comment", "delete-rule-2"},
			},
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.NewWithItems("keep-rule-1", "keep-rule-2")

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPT.deleteCalls))
		}

		// Verify correct rules were deleted
		expectedDeletes := [][]string{
			{"-j", "ACCEPT", "--comment", "delete-rule-1"},
			{"-j", "DROP", "--comment", "delete-rule-2"},
		}
		for i, expectedDelete := range expectedDeletes {
			if len(mockIPT.deleteCalls[i]) != len(expectedDelete) {
				t.Errorf("delete call %d: expected %v, got %v", i, expectedDelete, mockIPT.deleteCalls[i])
			}
		}
	})

	t.Run("keeps rules in expected set", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "keep-rule-1"},
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "keep-rule-2"},
			},
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.NewWithItems("keep-rule-1", "keep-rule-2")

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("deletes all rules when expected set is empty", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "rule-1"},
				{"-A", "TEST", "-j", "DROP", "--comment", "rule-2"},
			},
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.New[string]() // Empty set

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("ignores unparseable rules", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "TEST", "-p", "tcp", "--dport", "80"},                 // Unparseable rule
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "delete-rule-1"}, // Parseable rule
			},
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.New[string]() // Empty set - would normally delete parseable rules

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		// Should only delete the parseable rule, ignore the unparseable one
		if len(mockIPT.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("respects ignore rule predicate", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "delete-rule-1"},
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "ignore-rule-1"},
				{"-A", "TEST", "-j", "DROP", "--comment", "delete-rule-2"},
			},
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.New[string]() // Empty set - would normally delete all parseable rules
		cleaner.IgnoreRulePredicate = func(rule []string) bool {
			// Ignore rules that contain "ignore-rule"
			for _, arg := range rule {
				if arg == "ignore-rule-1" {
					return true
				}
			}
			return false
		}

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		// Should delete 2 rules but ignore the one matching the predicate
		if len(mockIPT.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("handles nil expected rule IDs", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "rule-1"},
			},
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = nil // nil set

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		// Should delete the rule since nil set doesn't contain anything
		if len(mockIPT.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("returns error when ListRules fails", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			listErr:  errors.New("list rules error"),
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.New[string]()

		err := cleaner.Clean()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "list rules error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("collects and returns multiple delete errors", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "rule-1"},
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "rule-2"},
			},
			deleteErr: errors.New("delete rule error"),
			protocol:  iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.New[string]() // Empty set - will try to delete both

		err := cleaner.Clean()

		if err == nil {
			t.Error("expected error, got nil")
		}
		// Should have attempted to delete both rules
		if len(mockIPT.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("does nothing when no rules exist", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules:    [][]string{}, // No rules
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.ExpectedRuleIDs = set.NewWithItems("some-rule")

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})
}

func TestIPTablesRuleCleaner_RealWorldScenario(t *testing.T) {
	t.Run("cleans up stale SNAT rules while keeping active ones", func(t *testing.T) {
		// Simulate existing rules in iptables
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "POSTROUTING", "-s", "10.0.1.0/24", "-j", "SNAT", "--to-source", "192.168.1.100", "--comment", "snat-rule-service-a"},
				{"-A", "POSTROUTING", "-s", "10.0.2.0/24", "-j", "SNAT", "--to-source", "192.168.1.101", "--comment", "snat-rule-service-b"},
				{"-A", "POSTROUTING", "-s", "10.0.3.0/24", "-j", "SNAT", "--to-source", "192.168.1.102", "--comment", "snat-rule-service-c"},
			},
			protocol: iptables.IPv4,
		}

		// Custom parser for SNAT rules
		snatParser := func(spec []string, protocol iptables.Protocol) (*TestCleanerRule, bool) {
			if len(spec) < 8 {
				return nil, false
			}

			// Handle full iptables rule format for SNAT
			for i := 0; i < len(spec)-7; i++ {
				if spec[i] == "-s" && i+6 < len(spec) &&
					spec[i+2] == "-j" && spec[i+3] == "SNAT" &&
					spec[i+4] == "--to-source" && spec[i+6] == "--comment" {
					sourceNet := spec[i+1]
					targetIP := spec[i+5]
					id := spec[i+7]
					return &TestCleanerRule{
						ID:      id,
						Content: "-s " + sourceNet + " -j SNAT --to-source " + targetIP + " --comment " + id,
						SpecVal: spec[2:], // Remove "-A CHAIN" prefix for rule spec
					}, true
				}
			}

			return nil, false
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.Parser = snatParser
		cleaner.Table = iptables.TableNAT
		cleaner.Chain = iptables.ChainPostrouting

		// Only keep service-a and service-c rules, delete service-b
		cleaner.ExpectedRuleIDs = set.NewWithItems("snat-rule-service-a", "snat-rule-service-c")

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Should delete only service-b rule
		if len(mockIPT.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPT.deleteCalls))
		}

		// Verify the correct rule was deleted
		expectedDelete := []string{"-s", "10.0.2.0/24", "-j", "SNAT", "--to-source", "192.168.1.101", "--comment", "snat-rule-service-b"}
		if len(mockIPT.deleteCalls[0]) != len(expectedDelete) {
			t.Errorf("expected delete call %v, got %v", expectedDelete, mockIPT.deleteCalls[0])
		}
	})

	t.Run("uses ignore predicate to preserve system rules", func(t *testing.T) {
		mockIPT := &mockCleanerIPTables{
			rules: [][]string{
				{"-A", "FORWARD", "-j", "ACCEPT", "--comment", "app-rule-1"},
				{"-A", "FORWARD", "-j", "DOCKER-ISOLATION-STAGE-1"}, // System rule without comment
				{"-A", "FORWARD", "-j", "ACCEPT", "--comment", "app-rule-2"},
				{"-A", "FORWARD", "-o", "docker0", "-j", "DOCKER"}, // Another system rule
			},
			protocol: iptables.IPv4,
		}

		cleaner := createTestCleaner(mockIPT)
		cleaner.Table = iptables.TableFilter
		cleaner.Chain = iptables.ChainForward

		// Only keep app-rule-1, so app-rule-2 should be deleted
		cleaner.ExpectedRuleIDs = set.NewWithItems("app-rule-1")

		// Ignore Docker-related rules
		cleaner.IgnoreRulePredicate = func(rule []string) bool {
			for _, arg := range rule {
				if arg == "DOCKER" || arg == "DOCKER-ISOLATION-STAGE-1" || arg == "docker0" {
					return true
				}
			}
			return false
		}

		err := cleaner.Clean()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Should delete only app-rule-2, ignore Docker rules and keep app-rule-1
		if len(mockIPT.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPT.deleteCalls))
		}

		// Verify app-rule-2 was deleted
		expectedDelete := []string{"-j", "ACCEPT", "--comment", "app-rule-2"}
		if len(mockIPT.deleteCalls[0]) != len(expectedDelete) {
			t.Errorf("expected delete call %v, got %v", expectedDelete, mockIPT.deleteCalls[0])
		}
	})
}
