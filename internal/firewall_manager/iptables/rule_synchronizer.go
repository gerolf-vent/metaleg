package iptables

import (
	"fmt"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/state"
)

type RuleSynchronizer[T Rule] struct {
	Parser  func([]string, iptables.Protocol) (T, bool)
	Table   iptables.Table
	Chain   iptables.Chain
	Rule    T
	Present bool
	ipt     iptables.IPTables
}

func NewRuleSynchronizer[T Rule](ipt iptables.IPTables) *RuleSynchronizer[T] {
	return &RuleSynchronizer[T]{
		ipt: ipt,
	}
}

func (s *RuleSynchronizer[T]) Sync() error {
	stateSynchronizer := state.StateSynchronizer[[]string, T]{
		Get: func() ([][]string, error) {
			return s.ipt.ListRules(s.Table, s.Chain)
		},
		Prepare: func(existingRuleSpec []string) ([]string, T) {
			var zero T
			parsedRule, ok := s.Parser(existingRuleSpec, s.ipt.Protocol())
			if !ok {
				return existingRuleSpec[2:], zero
			}
			return existingRuleSpec[2:], parsedRule
		},
		Filter: func(existingRuleSpec []string, existingRule T) bool {
			return existingRule.RuleID() == s.Rule.RuleID()
		},
		Equal: func(existingRuleSpec []string, existingRule T, newRule T) bool {
			return existingRule.String() == newRule.String()
		},
		Add: func(newRule T) error {
			_, err := s.ipt.EnsureRule(iptables.Append, s.Table, s.Chain, newRule.Spec()...)
			return err
		},
		Delete: func(existingRuleSpec []string) error {
			_, err := s.ipt.DeleteRule(s.Table, s.Chain, existingRuleSpec...)
			return err
		},
	}

	if s.Present {
		if err := stateSynchronizer.SyncSingle(s.Rule); err != nil {
			return fmt.Errorf("failed to ensure iptables rule: %w", err)
		}
	} else {
		if err := stateSynchronizer.Clear(); err != nil {
			return fmt.Errorf("failed to clear iptables rule: %w", err)
		}
	}

	return nil
}
