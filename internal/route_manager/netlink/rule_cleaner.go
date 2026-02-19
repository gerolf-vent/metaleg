package netlink

import (
	"errors"
	"fmt"

	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/vishvananda/netlink"
)

// RuleCleaner provides functionality to clean up netlink routing rules
type RuleCleaner struct {
	TableIDMin       int
	TableIDMax       int
	ExpectedTableIDs set.Set[int]
	Family           int
}

func (c *RuleCleaner) Clean() error {
	var errs []error

	nlRules, err := netlink.RuleList(c.Family)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to list netlink rules: %w", err))
	} else {
		for _, r := range nlRules {
			if r.Table >= c.TableIDMin && r.Table <= c.TableIDMax && !c.ExpectedTableIDs.Contains(r.Table) {
				// The rule is in our table id range but not in the expected set, so delete it
				if err := netlink.RuleDel(&r); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete netlink rule: %w", err))
				}
			}
		}
	}

	return errors.Join(errs...)
}
