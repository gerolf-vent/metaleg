package route_manager

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func TestNewNetlinkRuleSynchronizer(t *testing.T) {
	synchronizer := NewNetlinkRuleSynchronizer()
	if synchronizer == nil {
		t.Errorf("Expected non-nil synchronizer")
	}
}

func TestNetlinkRuleSynchronizer_Sync_Unit(t *testing.T) {
	// Unit test - test the structure without actual netlink operations
	testRule := netlink.NewRule()
	testRule.Table = 100
	testRule.Family = netlink.FAMILY_V4
	testRule.Priority = 30001

	synchronizer := &NetlinkRuleSynchronizer{
		Rule: testRule,
		Filter: func(rule *netlink.Rule) bool {
			return rule != nil && rule.Table == testRule.Table
		},
		Equal: func(a, b *netlink.Rule) bool {
			return a.Table == b.Table &&
				a.Family == b.Family &&
				a.Priority == b.Priority
		},
		Present: true,
	}

	// Test that synchronizer structure is valid
	if synchronizer.Rule != testRule {
		t.Errorf("Rule not set correctly")
	}
	if synchronizer.Filter == nil {
		t.Errorf("Filter function not set")
	}
	if synchronizer.Equal == nil {
		t.Errorf("Equal function not set")
	}
	if !synchronizer.Present {
		t.Errorf("Present should be true")
	}
}

func TestNetlinkRuleSynchronizer_Sync_Integration(t *testing.T) {
	requireNetlinkWritePrivileges(t)

	testTableMin := 16000

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		var familyName string
		switch family {
		case netlink.FAMILY_V4:
			familyName = "IPv4"
		case netlink.FAMILY_V6:
			familyName = "IPv6"
		}

		t.Run("Family"+familyName, func(t *testing.T) {
			testRules := newTestRules(family, testTableMin, 2)
			testTableMax := testTableMin + len(testRules)

			// Get original rule count before test
			rules, err := netlink.RuleList(family)
			if err != nil {
				t.Errorf("Failed to list rules: %v", err)
			}
			orgRuleCount := len(rules)
			t.Logf("Original rules:\n%+v", rules)

			// Clear rules in table range
			clearRules(t, family, testTableMin, testTableMax)

			// Add a rule, which should be unaffected by sync
			if err := netlink.RuleAdd(testRules[1]); err != nil {
				t.Errorf("Failed to add test rule 1: %v", err)
			}
			defer netlink.RuleDel(testRules[1])

			// Verify only rule 1 exists
			verifyRuleCount(t, family, orgRuleCount+1)
			verifyRules(t, family, testTableMin, testTableMax, testRuleEqual, []*netlink.Rule{testRules[1]})

			// Create synchronizer to manage testRules[0]
			synchronizer := &NetlinkRuleSynchronizer{
				Rule: testRules[0],
				Filter: func(rule *netlink.Rule) bool {
					return rule != nil && rule.Table == testRules[0].Table && rule.Family == testRules[0].Family
				},
				Equal: func(a, b *netlink.Rule) bool {
					return true // Every filtered rule is to be considered equal
				},
				Present: true,
			}

			// Test adding a rule
			err = synchronizer.Sync()
			if err != nil {
				t.Errorf("Failed to sync rule (add): %v", err)
			}

			// Verify rule was added
			verifyRuleCount(t, family, orgRuleCount+2)
			verifyRules(t, family, testTableMin, testTableMax, testRuleEqual, testRules)

			// Test removing a rule
			synchronizer.Present = false
			err = synchronizer.Sync()
			if err != nil {
				t.Errorf("Failed to sync rule (remove): %v", err)
			}

			// Verify rule was removed
			verifyRuleCount(t, family, orgRuleCount+1)
			verifyRules(t, family, testTableMin, testTableMax, testRuleEqual, []*netlink.Rule{testRules[1]})
		})
	}
}
