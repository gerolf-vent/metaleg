package iptables

import (
	"errors"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

type RuleCleaner[T Rule] struct {
	Parser              func([]string, iptables.Protocol) (T, bool)
	Table               iptables.Table
	Chain               iptables.Chain
	ExpectedRuleIDs     set.Set[string]
	IgnoreRulePredicate func([]string) bool
	ipt                 iptables.IPTables
}

func NewRuleCleaner[T Rule](ipt iptables.IPTables) *RuleCleaner[T] {
	return &RuleCleaner[T]{
		ipt: ipt,
	}
}

func (c *RuleCleaner[T]) Clean() error {
	existingRules, err := c.ipt.ListRules(c.Table, c.Chain)
	if err != nil {
		return err
	}

	var errs []error

	for _, rule := range existingRules {
		// Check if we should ignore this rule
		if c.IgnoreRulePredicate != nil && c.IgnoreRulePredicate(rule) {
			continue
		}

		// Try to parse the rule
		parsedRule, ok := c.Parser(rule, c.ipt.Protocol())
		// If parsed and in expected set, keep it
		if ok && c.ExpectedRuleIDs != nil && c.ExpectedRuleIDs.Contains(parsedRule.RuleID()) {
			continue
		}

		// Delete the rule if it's not valid (not in expected set or unparseable)
		if _, err := c.ipt.DeleteRule(c.Table, c.Chain, rule[2:]...); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
