package netlink

import (
	"fmt"

	"github.com/gerolf-vent/metaleg/internal/utils/state"
	"github.com/vishvananda/netlink"
)

// RuleSynchronizer synchronizes netlink rules using the state synchronizer pattern
type RuleSynchronizer struct {
	Rule    *netlink.Rule // The rule to synchronize
	Filter  func(*netlink.Rule) bool
	Equal   func(*netlink.Rule, *netlink.Rule) bool
	Present bool // Whether the rule should be present or absent
}

func NewRuleSynchronizer() *RuleSynchronizer {
	return &RuleSynchronizer{}
}

func (s *RuleSynchronizer) Sync() error {
	stateSynchronizer := state.StateSynchronizer[netlink.Rule, *netlink.Rule]{
		Get: func() ([]netlink.Rule, error) {
			return netlink.RuleList(s.Rule.Family)
		},
		Prepare: func(existingRule netlink.Rule) (netlink.Rule, *netlink.Rule) {
			return existingRule, &existingRule
		},
		Filter: func(existingRule netlink.Rule, _ *netlink.Rule) bool {
			return s.Filter(&existingRule)
		},
		Equal: func(_ netlink.Rule, existingRule *netlink.Rule, newRule *netlink.Rule) bool {
			return s.Equal(existingRule, newRule)
		},
		Add: func(newRule *netlink.Rule) error {
			return netlink.RuleAdd(newRule)
		},
		Delete: func(existingRule netlink.Rule) error {
			return netlink.RuleDel(&existingRule)
		},
	}

	if s.Present {
		if err := stateSynchronizer.SyncSingle(s.Rule); err != nil {
			return fmt.Errorf("failed to ensure netlink rule: %w", err)
		}
	} else {
		if err := stateSynchronizer.Clear(); err != nil {
			return fmt.Errorf("failed to clear netlink rule: %w", err)
		}
	}

	return nil
}
