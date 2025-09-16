package route_manager

import (
	"errors"
	"fmt"

	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/vishvananda/netlink"
)

// NetlinkRuleCleaner provides functionality to clean up netlink routing rules
type NetlinkRuleCleaner struct {
	TableIDMin       int
	TableIDMax       int
	ExpectedTableIDs set.Set[int]
	Family           int
}

func (c *NetlinkRuleCleaner) Clean() error {
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
