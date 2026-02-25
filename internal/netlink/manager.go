package netlink

import (
	"errors"
	"fmt"
	"net"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
)

type Manager struct {
	state  core.State
	logger logr.Logger

	fwMask             utils.FWMask
	routeTableIDOffset uint32
	routeTableIDMin    int
	routeTableIDMax    int
}

func NewManager(state core.State, logger logr.Logger) *Manager {
	return &Manager{
		state:              state,
		logger:             logger.WithName("netlink-manager"),
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
		if !exists || !nodeState.IDAllocated {
			// Node no longer exists or has no allocated Id, skip
			continue
		}

		m.logger.V(1).Info("Reconciling node", "node", nodeName, "routeTableID", nodeState.RouteTableID, "fwMark", nodeState.FWMark)

		for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
			var gwIP net.IP
			var dstIPNet net.IPNet
			if family == netlink.FAMILY_V4 {
				gwIP = nodeState.Node.IPv4
				dstIPNet = net.IPNet{
					IP:   net.IPv4zero, // default route
					Mask: net.CIDRMask(0, 32),
				}
			} else {
				gwIP = nodeState.Node.IPv6
				dstIPNet = net.IPNet{
					IP:   net.IPv6zero, // default route
					Mask: net.CIDRMask(0, 128),
				}
			}

			// Synchronize the netlink rules
			if gwIP != nil && !gwIP.IsUnspecified() {
				// Ensure the rule exists
				errs = append(errs, m.ensureNetlinkFWMarkRule(nodeState.RouteTableID, nodeState.FWMark, family))
			} else {
				// Ensure the rule is deleted
				errs = append(errs, m.deleteNetlinkRule(nodeState.RouteTableID, family))
			}

			// Synchronize the netlink routes
			if gwIP != nil && !gwIP.IsUnspecified() {
				// Ensure the route exists
				errs = append(errs, m.ensureNetlinkGWRoute(nodeState.RouteTableID, dstIPNet, gwIP, family))
			} else {
				// Ensure the route is deleted
				errs = append(errs, m.deleteNetlinkRoute(nodeState.RouteTableID, family))
			}
		}
	}

	// Reconcile deleted nodes
	for _, nodeState := range changes.NodesDeleted {
		// Skip nodes with no allocated ID
		if !nodeState.IDAllocated {
			continue
		}
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

func (m *Manager) ensureNetlinkFWMarkRule(routeTableID uint32, fwMark uint32, family int) error {
	familyStr := "ipv4"
	if family == netlink.FAMILY_V6 {
		familyStr = "ipv6"
	}

	existingRules, err := netlink.RuleList(family)
	if err != nil {
		return fmt.Errorf("failed to list netlink rules: %w", err)
	}

	present := false
	for _, existingRule := range existingRules {
		if existingRule.Table < m.routeTableIDMin || existingRule.Table > m.routeTableIDMax {
			// Extra guard to not render a host unreachable by deleting unrelated rules
			continue
		}
		if existingRule.Table == int(routeTableID) {
			// Remove duplicate or conflicting rules
			if present == true || (existingRule.Mark != fwMark) || !maskEquals(existingRule.Mask, (*uint32)(&m.fwMask)) {
				m.logger.V(3).Info("Deleting conflicting netlink FW mark rule", "family", familyStr, "table", routeTableID, "mark", existingRule.Mark, "expectedMark", fwMark)
				if err := netlink.RuleDel(&existingRule); err != nil {
					return fmt.Errorf("failed to delete conflicting netlink rule: %w", err)
				}
			} else {
				present = true
			}
		}
	}

	if !present {
		fwMarkRule := netlink.NewRule()
		fwMarkRule.Mark = fwMark
		fwMarkRule.Mask = (*uint32)(&m.fwMask)
		fwMarkRule.Table = int(routeTableID)
		fwMarkRule.Family = family

		m.logger.V(2).Info("Adding netlink FW mark rule", "family", familyStr, "table", routeTableID, "mark", fwMark)
		if err := netlink.RuleAdd(fwMarkRule); err != nil {
			return fmt.Errorf("failed to add netlink rule: %w", err)
		}
	}

	return nil
}

func (m *Manager) deleteNetlinkRule(routeTableID uint32, family int) error {
	familyStr := "ipv4"
	if family == netlink.FAMILY_V6 {
		familyStr = "ipv6"
	}

	existingRules, err := netlink.RuleListFiltered(family, &netlink.Rule{Table: int(routeTableID)}, netlink.RT_FILTER_TABLE)
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
			m.logger.V(2).Info("Deleting netlink rule", "family", familyStr, "table", routeTableID)
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

func (m *Manager) ensureNetlinkGWRoute(routeTableID uint32, dst net.IPNet, gw net.IP, family int) error {
	familyStr := "ipv4"
	if family == netlink.FAMILY_V6 {
		familyStr = "ipv6"
	}

	// Extra guard to not render a host unreachable by deleting unrelated routes
	if int(routeTableID) < m.routeTableIDMin || int(routeTableID) > m.routeTableIDMax {
		return fmt.Errorf("route table ID %d out of managed range", routeTableID)
	}

	m.logger.V(2).Info("Ensuring netlink gateway route", "family", familyStr, "table", routeTableID, "gw", gw.String())

	// Get the route the gw matches
	gwRoutes, err := netlink.RouteGet(gw)
	if err != nil {
		return fmt.Errorf("failed to get netlink route for gateway %q: %w", gw.String(), err)
	}
	if len(gwRoutes) == 0 {
		return fmt.Errorf("no netlink route found for gateway %q", gw.String())
	}

	linkIndex := gwRoutes[0].LinkIndex

	gwDst := net.IPNet{
		IP:   gw,
		Mask: net.CIDRMask(32, 32),
	}
	if family == netlink.FAMILY_V6 {
		gwDst.Mask = net.CIDRMask(128, 128)
	}

	existingRoutes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: int(routeTableID)}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return fmt.Errorf("failed to list netlink routes: %w", err)
	}

	defaultRoutePresent := false
	gwRoutePresent := false
	for _, existingRoute := range existingRoutes {
		if existingRoute.Table == int(routeTableID) {
			if ipNetEquals(existingRoute.Dst, &dst) {
				// Remove duplicate or conflicting routes
				if defaultRoutePresent == true || !existingRoute.Gw.Equal(gw) {
					m.logger.V(3).Info("Deleting conflicting default route", "family", familyStr, "table", routeTableID, "dst", existingRoute.Dst.String(), "gw", existingRoute.Gw.String(), "expectedGw", gw.String())
					if err := netlink.RouteDel(&existingRoute); err != nil {
						return fmt.Errorf("failed to delete conflicting netlink default route: %w", err)
					}
				} else {
					defaultRoutePresent = true
				}
			} else if ipNetEquals(existingRoute.Dst, &gwDst) {
				// Remove duplicate or conflicting gw routes
				if gwRoutePresent == true || existingRoute.LinkIndex != linkIndex {
					m.logger.V(3).Info("Deleting conflicting gateway host route", "family", familyStr, "table", routeTableID, "dst", existingRoute.Dst.String(), "linkIndex", existingRoute.LinkIndex, "expectedLinkIndex", linkIndex)
					if err := netlink.RouteDel(&existingRoute); err != nil {
						return fmt.Errorf("failed to delete conflicting netlink gw route: %w", err)
					}
				} else {
					gwRoutePresent = true
				}
			} else {
				// Remove any other routes in the table
				m.logger.V(3).Info("Deleting stale route from table", "family", familyStr, "table", routeTableID, "dst", existingRoute.Dst.String())
				if err := netlink.RouteDel(&existingRoute); err != nil {
					return fmt.Errorf("failed to delete stale netlink route: %w", err)
				}
			}
		}
	}

	if !gwRoutePresent {
		gwRoute := &netlink.Route{
			Dst:       &gwDst,
			LinkIndex: linkIndex,
			Table:     int(routeTableID),
			Family:    family,
		}

		m.logger.V(2).Info("Adding netlink gateway host route", "family", familyStr, "table", routeTableID, "dst", gwDst.String(), "linkIndex", linkIndex)
		if err := netlink.RouteAdd(gwRoute); err != nil {
			return fmt.Errorf("failed to add netlink gw route: %w", err)
		}
	}

	if !defaultRoutePresent {
		route := &netlink.Route{
			Dst:    &dst,
			Gw:     gw,
			Table:  int(routeTableID),
			Family: family,
		}

		m.logger.V(2).Info("Adding netlink default route", "family", familyStr, "table", routeTableID, "gw", gw.String())
		if err := netlink.RouteAdd(route); err != nil {
			return fmt.Errorf("failed to add netlink default route: %w", err)
		}
	}

	return nil
}

func (m *Manager) deleteNetlinkRoute(routeTableID uint32, family int) error {
	familyStr := "ipv4"
	if family == netlink.FAMILY_V6 {
		familyStr = "ipv6"
	}

	if int(routeTableID) < m.routeTableIDMin || int(routeTableID) > m.routeTableIDMax {
		return fmt.Errorf("route table ID %d out of managed range", routeTableID)
	}

	m.logger.V(2).Info("Deleting netlink routes", "family", familyStr, "table", routeTableID)

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
