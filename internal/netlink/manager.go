package netlink

import (
	"errors"
	"fmt"
	"net"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/vishvananda/netlink"
)

type Manager struct {
	state              core.State
	fwMask             utils.FWMask
	routeTableIDOffset uint32
	routeTableIDMin    int
	routeTableIDMax    int
}

func NewManager(state core.State) *Manager {
	return &Manager{
		state:              state,
		fwMask:             state.FWMask(),
		routeTableIDOffset: state.RouteTableIDOffset(),
		routeTableIDMin:    int(state.RouteTableIDOffset()),
		routeTableIDMax:    int(state.RouteTableIDOffset() + uint32(state.FWMask().Size()) - 1),
	}
}

func (m *Manager) Name() string {
	return "netlink"
}

func (m *Manager) Setup() error {
	// Nothing needed
	return nil
}

func (m *Manager) Purge() error {
	var errs []error

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Purge netlink rules (by using an empty expected set)
		errs = append(errs, m.cleanupNetlinkRules(set.New[int](), family))

		// Purging netlink routes is to expensive, because we would need to iterate through all the tables.
		// But they don't affect anything, so they can be left alone.
	}

	return errors.Join(errs...)
}

func (m *Manager) Reconcile(changes core.StateChange) error {
	if !changes.HasNodeChanges() {
		// Nothing to do
		return nil
	}

	var errs []error

	// Reconcile updated nodes
	for nodeName := range changes.NodesUpdated {
		nodeState, exists := m.state.GetNodeState(nodeName)
		if !exists {
			// Node no longer exists, skip
			continue
		}

		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			var gwIP net.IP
			var zeroIP net.IP
			var maskSize int
			if family == netlink.FAMILY_V4 {
				gwIP = nodeState.Node.IPv4
				zeroIP = net.IPv4zero // default route
				maskSize = 32
			} else {
				gwIP = nodeState.Node.IPv6
				zeroIP = net.IPv6zero // default route
				maskSize = 128
			}

			//
			// Synchronize the netlink rule
			//

			fwMarkRule := netlink.NewRule()
			fwMarkRule.Mark = nodeState.FWMark
			fwMarkRule.Mask = (*uint32)(&m.fwMask)
			fwMarkRule.Table = int(nodeState.RouteTableID)
			fwMarkRule.Family = family

			if gwIP != nil {
				// Ensure the rule exists
				errs = append(errs, m.ensureNetlinkRule(fwMarkRule))
			} else {
				// Ensure the rule is deleted
				errs = append(errs, m.deleteNetlinkRule(nodeState.RouteTableID, family))
			}

			//
			// Synchronize the netlink route
			//

			gwRoute := &netlink.Route{
				Dst: &net.IPNet{
					IP:   zeroIP,
					Mask: net.CIDRMask(0, maskSize),
				},
				Gw:     gwIP,
				Table:  int(nodeState.RouteTableID),
				Family: family,
			}

			if gwIP != nil {
				// Ensure the route exists
				errs = append(errs, m.ensureNetlinkRoute(gwRoute))
			} else {
				// Ensure the route is deleted
				errs = append(errs, m.deleteNetlinkRoute(nodeState.RouteTableID, family))
			}
		}

	}

	// Reconcile deleted nodes
	for _, nodeState := range changes.NodesDeleted {
		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			// Ensure the rule is deleted
			errs = append(errs, m.deleteNetlinkRule(nodeState.RouteTableID, family))

			// Ensure the route is deleted
			errs = append(errs, m.deleteNetlinkRoute(nodeState.RouteTableID, family))
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) Cleanup() error {
	expectedRouteTableIDs := set.New[int]()
	for _, nodeState := range m.state.GetNodeStates() {
		if nodeState.IDAllocated && nodeState.RouteTableID >= uint32(m.routeTableIDMin) && nodeState.RouteTableID <= uint32(m.routeTableIDMax) {
			expectedRouteTableIDs.Add(int(nodeState.RouteTableID))
		}
	}

	var errs []error

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Cleanup stale netlink rules
		errs = append(errs, m.cleanupNetlinkRules(expectedRouteTableIDs, family))

		// Cleanup netlink routes is too expensive, because we would need to iterate through all the tables.
		// But they don't affect anything, because the rules are gone.
	}

	return errors.Join(errs...)
}

func (m *Manager) ensureNetlinkRule(rule *netlink.Rule) error {
	existingRules, err := netlink.RuleList(rule.Family)
	if err != nil {
		return fmt.Errorf("failed to list netlink rules: %w", err)
	}

	present := false
	for _, existingRule := range existingRules {
		if existingRule.Table < m.routeTableIDMin || existingRule.Table > m.routeTableIDMax {
			// Extra guard to not render a host unreachable by deleting unrelated rules
			continue
		}
		if existingRule.Table == rule.Table {
			// Remove duplicate or conflicting rules
			if present == true || (existingRule.Mark != rule.Mark) || !maskEquals(existingRule.Mask, rule.Mask) {
				if err := netlink.RuleDel(&existingRule); err != nil {
					return fmt.Errorf("failed to delete conflicting netlink rule: %w", err)
				}
			} else {
				present = true
			}
		}
	}

	if !present {
		if err := netlink.RuleAdd(rule); err != nil {
			return fmt.Errorf("failed to add netlink rule: %w", err)
		}
	}

	return nil
}

func (m *Manager) deleteNetlinkRule(routeTableID uint32, family int) error {
	existingRules, err := netlink.RuleList(family)
	if err != nil {
		return fmt.Errorf("failed to list netlink rules: %w", err)
	}

	var errs []error

	for _, existingRule := range existingRules {
		if existingRule.Table < m.routeTableIDMin || existingRule.Table > m.routeTableIDMax {
			// Extra guard to not render a host unreachable by deleting unrelated rules
			continue
		}
		if existingRule.Table == int(routeTableID) {
			if err := netlink.RuleDel(&existingRule); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete netlink rule: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) cleanupNetlinkRules(expectedRouteTableIDs set.Set[int], family int) error {
	existingRules, err := netlink.RuleList(family)
	if err != nil {
		return fmt.Errorf("failed to list netlink rules: %w", err)
	}

	var errs []error

	for _, existingRule := range existingRules {
		if existingRule.Table >= m.routeTableIDMin && existingRule.Table <= m.routeTableIDMax {
			if !expectedRouteTableIDs.Contains(existingRule.Table) {
				if err := netlink.RuleDel(&existingRule); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete stale netlink rule: %w", err))
				}
			}
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) ensureNetlinkRoute(route *netlink.Route) error {
	// Extra guard to not render a host unreachable by deleting unrelated routes
	if route.Table < m.routeTableIDMin || route.Table > m.routeTableIDMax {
		return fmt.Errorf("route table ID %d out of managed range", route.Table)
	}

	existingRoutes, err := netlink.RouteListFiltered(route.Family, &netlink.Route{Table: route.Table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list netlink routes: %w", err)
	}

	present := false
	for _, existingRoute := range existingRoutes {
		if existingRoute.Table == route.Table && ipNetEquals(existingRoute.Dst, route.Dst) {
			// Remove duplicate or conflicting routes
			if present == true || !existingRoute.Gw.Equal(route.Gw) {
				if err := netlink.RouteDel(&existingRoute); err != nil {
					return fmt.Errorf("failed to delete conflicting netlink route: %w", err)
				}
			} else {
				present = true
			}
		}
	}

	if !present {
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("failed to add netlink route: %w", err)
		}
	}

	return nil
}

func (m *Manager) deleteNetlinkRoute(routeTableID uint32, family int) error {
	if int(routeTableID) < m.routeTableIDMin || int(routeTableID) > m.routeTableIDMax {
		return fmt.Errorf("route table ID %d out of managed range", routeTableID)
	}

	existingRoutes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: int(routeTableID)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list netlink routes: %w", err)
	}

	var errs []error

	for _, existingRoute := range existingRoutes {
		if existingRoute.Table == int(routeTableID) {
			if err := netlink.RouteDel(&existingRoute); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete netlink route: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}
