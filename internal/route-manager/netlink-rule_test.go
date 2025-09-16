package route_manager

import (
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/vishvananda/netlink"
)

const (
	testFWMask = utils.FWMask(0xff)
)

func newTestRule(family int, table int, mark uint32) *netlink.Rule {
	mask := uint32(0xff)

	rule := netlink.NewRule()
	rule.Mark = mark
	rule.Mask = &mask
	rule.Table = table
	rule.Family = family
	return rule
}

func newTestRules(family int, tableRangeStart int, count int) []*netlink.Rule {
	var rules []*netlink.Rule

	for i := 0; i < count; i++ {
		rule := newTestRule(family, tableRangeStart+i, uint32(i+1))
		rules = append(rules, rule)
	}

	return rules
}

func testRuleEqual(a, b *netlink.Rule) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Mark == b.Mark &&
		((a.Mask == nil && b.Mask == nil) || (a.Mask != nil && b.Mask != nil && *a.Mask == *b.Mask)) &&
		a.Table == b.Table &&
		a.Family == b.Family
}

func clearRules(t *testing.T, family int, tableRangeStart, tableRangeEnd int) {
	t.Helper()

	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Errorf("Failed to list rules for cleanup: %v", err)
		return
	}

	for _, rule := range rules {
		if rule.Table >= tableRangeStart && rule.Table <= tableRangeEnd {
			if err := netlink.RuleDel(&rule); err != nil {
				t.Errorf("Failed to delete rule %+v: %v", rule, err)
			}
		}
	}
}

func verifyRules(t *testing.T, family int, tableRangeStart, tableRangeEnd int, equal func(a, b *netlink.Rule) bool, expectedRules []*netlink.Rule) {
	t.Helper()

	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("failed to list rules: %v", err)
	}

	// Filter rules to only those in the specified table range
	var filteredRules []netlink.Rule
	for _, rule := range rules {
		if rule.Table >= tableRangeStart && rule.Table <= tableRangeEnd {
			filteredRules = append(filteredRules, rule)
		}
	}
	rules = filteredRules

	if len(rules) != len(expectedRules) {
		t.Logf("Expected rules:\n%+v", expectedRules)
		t.Logf("Actual rules:\n%+v", rules)
		t.Fatalf("rule table has %d rules, expected %d", len(rules), len(expectedRules))
	}

	ruleMissmatchCount := 0

	// Check that every expected rule exists in the actual rules, regardless of order
	used := make([]bool, len(rules))
	for _, expected := range expectedRules {
		found := false
		for ai, actual := range rules {
			if used[ai] {
				continue
			}
			if equal(&actual, expected) {
				used[ai] = true
				found = true
				break
			}
		}
		if !found {
			t.Logf("rule table is missing rule: %+v", expected)
			ruleMissmatchCount++
		}
	}

	if ruleMissmatchCount > 0 {
		t.Logf("Expected rules:\n%+v", expectedRules)
		t.Logf("Actual rules:\n%+v", rules)
		t.Fatalf("%d rules did not match", ruleMissmatchCount)
	}
}

func verifyRuleCount(t *testing.T, family int, expectedCount int) {
	t.Helper()

	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Errorf("Failed to list rules: %v", err)
	}
	if len(rules) != expectedCount {
		t.Logf("Rules:\n%+v", rules)
		t.Errorf("Count of rules mismatch after setup: %d rules exist, but %d expected", len(rules), expectedCount)
	}
}
