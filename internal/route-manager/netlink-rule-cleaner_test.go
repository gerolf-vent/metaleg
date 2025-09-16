package route_manager

import (
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/vishvananda/netlink"
)

func TestNetlinkRuleCleaner_Clean_Unit(t *testing.T) {
	// Unit test - test the structure and logic without actual netlink operations
	expectedTables := set.New[int]()
	expectedTables.Add(15000)

	cleaner := &NetlinkRuleCleaner{
		TableIDMin:       10000,
		TableIDMax:       12000,
		ExpectedTableIDs: expectedTables,
		Family:           netlink.FAMILY_V4,
	}

	// Verify structure
	if cleaner.TableIDMin != 10000 {
		t.Errorf("Expected TableIDMin to be 10000, got %d", cleaner.TableIDMin)
	}
	if cleaner.TableIDMax != 12000 {
		t.Errorf("Expected TableIDMax to be 12000, got %d", cleaner.TableIDMax)
	}
	if !cleaner.ExpectedTableIDs.Contains(15000) {
		t.Errorf("Expected table 15000 to be in expected tables")
	}
	if cleaner.Family != netlink.FAMILY_V4 {
		t.Errorf("Expected Family to be FAMILY_V4, got %d", cleaner.Family)
	}
}

func TestNetlinkRuleCleaner_Clean_Integration(t *testing.T) {
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
			testRules := newTestRules(family, testTableMin, 3)
			testTableMax := testTableMin + len(testRules)

			// Set the third rule with out-of-range table
			testRules[2].Table = 15000

			// Get original rule count before test
			rules, err := netlink.RuleList(family)
			if err != nil {
				t.Errorf("Failed to list rules: %v", err)
			}
			orgRuleCount := len(rules)
			t.Logf("Original rules:\n%+v", rules)

			// Clear rules in table range
			clearRules(t, family, testTableMin, testTableMax)

			// Add test rules
			for i, rule := range testRules {
				if err := netlink.RuleAdd(rule); err != nil {
					t.Errorf("Failed to add test rule %d: %v", i, err)
				}
				defer netlink.RuleDel(rule)
			}

			// Verify rules were added
			verifyRuleCount(t, family, orgRuleCount+len(testRules))
			verifyRules(t, family, testTableMin, testTableMax, testRuleEqual, []*netlink.Rule{testRules[0], testRules[1]})
			verifyRules(t, family, testRules[2].Table, testRules[2].Table, testRuleEqual, []*netlink.Rule{testRules[2]})

			// Setup cleaner to preserve test rule 0, but not 1 (2 is out of range)
			expectedTables := set.New[int]()
			expectedTables.Add(testRules[1].Table)

			cleaner := &NetlinkRuleCleaner{
				TableIDMin:       testTableMin,
				TableIDMax:       testTableMax,
				ExpectedTableIDs: expectedTables,
				Family:           family,
			}

			// Run cleaner
			err = cleaner.Clean()
			if err != nil {
				t.Errorf("Clean failed: %v", err)
			}

			// Verify state after clean operation
			verifyRuleCount(t, family, orgRuleCount+2)
			verifyRules(t, family, testTableMin, testTableMax, testRuleEqual, []*netlink.Rule{testRules[1]})
			verifyRules(t, family, testRules[2].Table, testRules[2].Table, testRuleEqual, []*netlink.Rule{testRules[2]})
		})
	}
}

func TestNetlinkRuleCleaner_Clean_EmptyExpectedTables(t *testing.T) {
	requireNetlinkWritePrivileges(t)

	testTableMin := 16000
	testTableMax := testTableMin + 5

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		var familyName string
		switch family {
		case netlink.FAMILY_V4:
			familyName = "IPv4"
		case netlink.FAMILY_V6:
			familyName = "IPv6"
		}

		t.Run("Family"+familyName, func(t *testing.T) {
			// Get original rule count before test
			rules, err := netlink.RuleList(family)
			if err != nil {
				t.Errorf("Failed to list rules: %v", err)
			}
			orgRuleCount := len(rules)
			t.Logf("Original rules:\n%+v", rules)

			// Clear rule test range
			clearRules(t, family, testTableMin, testTableMax)

			// Verify no rule exists in the range
			verifyRuleCount(t, family, orgRuleCount)
			verifyRules(t, family, testTableMin, testTableMax, testRuleEqual, []*netlink.Rule{})

			// Test with empty expected tables (should clean everything in range)
			expectedTables := set.New[int]()

			cleaner := &NetlinkRuleCleaner{
				TableIDMin:       testTableMin,
				TableIDMax:       testTableMax,
				ExpectedTableIDs: expectedTables,
				Family:           family,
			}

			// This should not fail even if there are no rules to clean
			err = cleaner.Clean()
			if err != nil {
				t.Errorf("Clean with empty expected tables failed: %v", err)
			}

			// Verify still no rules exist
			verifyRuleCount(t, family, orgRuleCount)
			verifyRules(t, family, testTableMin, testTableMax, testRuleEqual, []*netlink.Rule{})
		})
	}
}
