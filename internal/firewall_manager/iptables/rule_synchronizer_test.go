package iptables

import (
	"errors"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

// Test rule implementation for testing
type TestRule struct {
	ID      string
	Content string
	SpecVal []string
}

func (r *TestRule) RuleID() string {
	if r == nil {
		return ""
	}
	return r.ID
}

func (r *TestRule) String() string {
	if r == nil {
		return ""
	}
	return r.Content
}

func (r *TestRule) Spec() []string {
	if r == nil {
		return []string{}
	}
	return r.SpecVal
}

// Mock iptables implementation
type mockIPTables struct {
	rules       [][]string
	protocol    iptables.Protocol
	listErr     error
	ensureErr   error
	deleteErr   error
	ensureCalls [][]string
	deleteCalls [][]string
}

func (m *mockIPTables) IsIPv6() bool {
	return m.protocol == iptables.IPv6
}

func (m *mockIPTables) ChainExists(table iptables.Table, chain iptables.Chain) (bool, error) {
	return true, nil // Always return true for testing
}

func (m *mockIPTables) EnsureChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	return true, nil // Always return true for testing
}

func (m *mockIPTables) FlushChain(table iptables.Table, chain iptables.Chain) error {
	return nil // No-op for testing
}

func (m *mockIPTables) DeleteChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	return true, nil // Always return true for testing
}

func (m *mockIPTables) RuleExists(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	return false, nil // Always return false for testing
}

func (m *mockIPTables) ListRules(table iptables.Table, chain iptables.Chain) ([][]string, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	return m.rules, nil
}

func (m *mockIPTables) Protocol() iptables.Protocol {
	return m.protocol
}

func (m *mockIPTables) EnsureRule(pos iptables.RulePosition, table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	if m.ensureCalls == nil {
		m.ensureCalls = [][]string{}
	}
	m.ensureCalls = append(m.ensureCalls, rulespec)
	if m.ensureErr != nil {
		return false, m.ensureErr
	}
	return true, nil
}

func (m *mockIPTables) DeleteRule(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
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
func testParser(spec []string, protocol iptables.Protocol) (*TestRule, bool) {
	if len(spec) < 2 {
		return nil, false
	}

	// Handle full iptables rule format: ["-A", "CHAIN", "-j", "ACCEPT", "--comment", "test-rule-id"]
	// Find the target (-j) flag and comment
	for i := 0; i < len(spec)-3; i++ {
		if spec[i] == "-j" && i+3 < len(spec) && spec[i+2] == "--comment" {
			target := spec[i+1]
			id := spec[i+3]
			return &TestRule{
				ID:      id,
				Content: "-j " + target + " --comment " + id,
				SpecVal: spec[2:], // Remove "-A CHAIN" prefix for rule spec
			}, true
		}
	}

	return nil, false
}

func createTestSynchronizer(mockIPT iptables.IPTables) *RuleSynchronizer[*TestRule] {
	sync := NewRuleSynchronizer[*TestRule](mockIPT)
	sync.Parser = testParser
	sync.Table = iptables.TableFilter
	sync.Chain = iptables.Chain("TEST")
	return sync
}

func TestRuleSynchronizer_Sync(t *testing.T) {
	t.Run("adds new rule when present is true and rule doesn't exist", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules:    [][]string{},
			protocol: iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			Content: "-j ACCEPT --comment test-rule-1",
			SpecVal: []string{"-j", "ACCEPT", "--comment", "test-rule-1"},
		}
		sync.Present = true

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.ensureCalls) != 1 {
			t.Errorf("expected 1 ensure call, got %d", len(mockIPT.ensureCalls))
		}
		if len(mockIPT.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("does nothing when rule already exists and is identical", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "test-rule-1"},
			},
			protocol: iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			Content: "-j ACCEPT --comment test-rule-1",
			SpecVal: []string{"-j", "ACCEPT", "--comment", "test-rule-1"},
		}
		sync.Present = true

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPT.ensureCalls))
		}
		if len(mockIPT.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("updates rule when existing rule has same ID but different content", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "test-rule-1"},
			},
			protocol: iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			Content: "-j ACCEPT --comment test-rule-1 --extra-flag", // Different content
			SpecVal: []string{"-j", "ACCEPT", "--comment", "test-rule-1", "--extra-flag"},
		}
		sync.Present = true

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPT.deleteCalls))
		}
		if len(mockIPT.ensureCalls) != 1 {
			t.Errorf("expected 1 ensure call, got %d", len(mockIPT.ensureCalls))
		}
	})

	t.Run("ignores rules with different IDs", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "other-rule"},
				{"-A", "TEST", "-j", "DROP", "--comment", "another-rule"},
			},
			protocol: iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			Content: "-j ACCEPT --comment test-rule-1",
			SpecVal: []string{"-j", "ACCEPT", "--comment", "test-rule-1"},
		}
		sync.Present = true

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.ensureCalls) != 1 {
			t.Errorf("expected 1 ensure call, got %d", len(mockIPT.ensureCalls))
		}
		if len(mockIPT.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("removes rule when present is false", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "test-rule-1"},
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "other-rule"},
			},
			protocol: iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			Content: "-j ACCEPT --comment test-rule-1",
			SpecVal: []string{"-j", "ACCEPT", "--comment", "test-rule-1"},
		}
		sync.Present = false

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPT.ensureCalls))
		}
		if len(mockIPT.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPT.deleteCalls))
		}
		// Should only delete the rule with matching ID, not the other rule
		expectedDelete := []string{"-j", "ACCEPT", "--comment", "test-rule-1"}
		if len(mockIPT.deleteCalls[0]) != len(expectedDelete) {
			t.Errorf("expected delete call %v, got %v", expectedDelete, mockIPT.deleteCalls[0])
		}
	})

	t.Run("removes multiple rules with same ID when present is false", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "test-rule-1"},
				{"-A", "TEST", "-j", "DROP", "--comment", "test-rule-1"}, // Same ID, different content
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "other-rule"},
			},
			protocol: iptables.IPv4,
		}

		// Parser that recognizes both ACCEPT and DROP rules with same ID
		customParser := func(spec []string, protocol iptables.Protocol) (*TestRule, bool) {
			if len(spec) < 4 {
				return nil, false
			}

			// Handle full iptables rule format: ["-A", "CHAIN", "-j", "ACCEPT/DROP", "--comment", "test-rule-id"]
			for i := 0; i < len(spec)-3; i++ {
				if spec[i] == "-j" && i+3 < len(spec) && spec[i+2] == "--comment" {
					target := spec[i+1]
					if target == "ACCEPT" || target == "DROP" {
						id := spec[i+3]
						return &TestRule{
							ID:      id,
							Content: "-j " + target + " --comment " + id,
							SpecVal: spec[2:], // Remove "-A CHAIN" prefix for rule spec
						}, true
					}
				}
			}

			return nil, false
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Parser = customParser
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			Content: "-j ACCEPT --comment test-rule-1",
			SpecVal: []string{"-j", "ACCEPT", "--comment", "test-rule-1"},
		}
		sync.Present = false

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(mockIPT.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPT.ensureCalls))
		}
		if len(mockIPT.deleteCalls) != 2 {
			t.Errorf("expected 2 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("handles unparseable rules gracefully", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "TEST", "-p", "tcp", "--dport", "80"},               // Unparseable rule
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "test-rule-1"}, // Parseable rule
			},
			protocol: iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			Content: "-j ACCEPT --comment test-rule-1",
			SpecVal: []string{"-j", "ACCEPT", "--comment", "test-rule-1"},
		}
		sync.Present = true

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		// Should not try to add the rule since it already exists
		if len(mockIPT.ensureCalls) != 0 {
			t.Errorf("expected 0 ensure calls, got %d", len(mockIPT.ensureCalls))
		}
		if len(mockIPT.deleteCalls) != 0 {
			t.Errorf("expected 0 delete calls, got %d", len(mockIPT.deleteCalls))
		}
	})

	t.Run("returns error when ListRules fails", func(t *testing.T) {
		mockIPT := &mockIPTables{
			listErr:  errors.New("list rules error"),
			protocol: iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{ID: "test-rule-1"}
		sync.Present = true

		err := sync.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "failed to ensure iptables rule: list rules error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("returns error when EnsureRule fails", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules:     [][]string{},
			ensureErr: errors.New("ensure rule error"),
			protocol:  iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{
			ID:      "test-rule-1",
			SpecVal: []string{"-j", "ACCEPT"},
		}
		sync.Present = true

		err := sync.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "failed to ensure iptables rule: ensure rule error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("returns error when DeleteRule fails", func(t *testing.T) {
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "TEST", "-j", "ACCEPT", "--comment", "test-rule-1"},
			},
			deleteErr: errors.New("delete rule error"),
			protocol:  iptables.IPv4,
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Rule = &TestRule{ID: "test-rule-1"}
		sync.Present = false

		err := sync.Sync()

		if err == nil {
			t.Error("expected error, got nil")
		}
		if err.Error() != "failed to clear iptables rule: delete rule error" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})
}

func TestRuleSynchronizer_RealWorldScenario(t *testing.T) {
	t.Run("manages SNAT rules with different source IPs", func(t *testing.T) {
		// Simulate existing rules in iptables
		mockIPT := &mockIPTables{
			rules: [][]string{
				{"-A", "POSTROUTING", "-s", "10.0.1.0/24", "-j", "SNAT", "--to-source", "192.168.1.100", "--comment", "snat-rule-service-a"},
				{"-A", "POSTROUTING", "-s", "10.0.2.0/24", "-j", "SNAT", "--to-source", "192.168.1.101", "--comment", "snat-rule-service-b"},
			},
			protocol: iptables.IPv4,
		}

		// Custom parser for SNAT rules
		snatParser := func(spec []string, protocol iptables.Protocol) (*TestRule, bool) {
			if len(spec) < 8 {
				return nil, false
			}

			// Handle full iptables rule format: ["-A", "POSTROUTING", "-s", "10.0.1.0/24", "-j", "SNAT", "--to-source", "192.168.1.100", "--comment", "snat-rule-service-a"]
			for i := 0; i < len(spec)-7; i++ {
				if spec[i] == "-s" && i+6 < len(spec) &&
					spec[i+2] == "-j" && spec[i+3] == "SNAT" &&
					spec[i+4] == "--to-source" && spec[i+6] == "--comment" {
					sourceNet := spec[i+1]
					targetIP := spec[i+5]
					id := spec[i+7]
					return &TestRule{
						ID:      id, // Comment contains the rule ID
						Content: "-s " + sourceNet + " -j SNAT --to-source " + targetIP + " --comment " + id,
						SpecVal: spec[2:], // Remove "-A CHAIN" prefix for rule spec
					}, true
				}
			}

			return nil, false
		}

		sync := createTestSynchronizer(mockIPT)
		sync.Parser = snatParser
		sync.Table = iptables.TableNAT
		sync.Chain = iptables.ChainPostrouting

		// Update service-a rule with new target IP
		sync.Rule = &TestRule{
			ID:      "snat-rule-service-a",
			Content: "-s 10.0.1.0/24 -j SNAT --to-source 192.168.1.200 --comment snat-rule-service-a",
			SpecVal: []string{"-s", "10.0.1.0/24", "-j", "SNAT", "--to-source", "192.168.1.200", "--comment", "snat-rule-service-a"},
		}
		sync.Present = true

		err := sync.Sync()

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Should delete old rule and add new rule
		if len(mockIPT.deleteCalls) != 1 {
			t.Errorf("expected 1 delete call, got %d", len(mockIPT.deleteCalls))
		}
		if len(mockIPT.ensureCalls) != 1 {
			t.Errorf("expected 1 ensure call, got %d", len(mockIPT.ensureCalls))
		}

		// Verify the new rule spec
		expectedSpec := []string{"-s", "10.0.1.0/24", "-j", "SNAT", "--to-source", "192.168.1.200", "--comment", "snat-rule-service-a"}
		if len(mockIPT.ensureCalls[0]) != len(expectedSpec) {
			t.Errorf("expected ensure call %v, got %v", expectedSpec, mockIPT.ensureCalls[0])
		}
	})
}
