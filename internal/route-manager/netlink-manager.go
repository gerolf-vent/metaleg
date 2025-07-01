package route_manager

import (
	"errors"
	"fmt"
	"math"
	"net"

	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/vishvananda/netlink"
)

type NetlinkManager struct {
	fwMask             utils.FWMask // Firewall mask for egress rules
	routeTableIDOffset uint32       // Offset for route table IDs
	idAllocator        *utils.IDRangeAllocator
}

func NewNetlinkManager(fwMask utils.FWMask, routeTableIDOffset uint32) (*NetlinkManager, error) {
	if fwMask.Size() <= 1 {
		return nil, fmt.Errorf("firewall mask too small")
	}

	if routeTableIDOffset > math.MaxUint32-uint32(fwMask.Size()) {
		return nil, fmt.Errorf("route table ID offset is too large")
	}

	return &NetlinkManager{
		fwMask:             fwMask,
		routeTableIDOffset: routeTableIDOffset,
		// We can't use the first element (0) in the range, because a fw mask with that
		// value would cause all traffic to be matched
		idAllocator: utils.NewIDRangeAllocator(fwMask.Size() - 1),
	}, nil
}

func (nlm *NetlinkManager) Setup() error {
	// NetlinkManager does not require any setup
	return nil
}

func (nlm *NetlinkManager) Cleanup() error {
	var errs []error

	routeTableIDMin := int(nlm.routeTableIDOffset)
	routeTableIDMax := int(uint(nlm.routeTableIDOffset) + nlm.fwMask.Size() - 1)

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Query all existing netlink rules for the family
		nlRules, err := netlink.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list netlink rules: %w", err))
		} else {
			// Cleanup any left-over rules
			for _, r := range nlRules {
				if r.Table >= routeTableIDMin && r.Table <= routeTableIDMax {
					if err := netlink.RuleDel(&r); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete netlink rule: %w", err))
					}
				}
			}
		}

		// Query all existing netlink routes for the family
		nlRoutes, err := netlink.RouteListFiltered(family, &netlink.Route{}, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list netlink routes: %w", err))
		} else {
			// Cleanup any left-over routes
			for _, r := range nlRoutes {
				if r.Table >= routeTableIDMin && r.Table <= routeTableIDMax {
					if err := netlink.RouteDel(&r); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete netlink route: %w", err))
					}
				}
			}
		}
	}

	return errors.Join(errs...)
}

func (nlm *NetlinkManager) ReconcileNodeRoute(route *NodeRoute, present bool) error {
	if route == nil {
		return nil
	}

	routeTableIDMin := int(nlm.routeTableIDOffset)
	routeTableIDMax := int(uint(nlm.routeTableIDOffset) + nlm.fwMask.Size() - 1)

	// Allocate an ID for the route if there are rules associated with it
	if route.RuleCount > 0 && !route.IDAllocated {
		// If the route has rules associated with it, we need to allocate an ID for it
		var err error
		route.ID, err = nlm.idAllocator.Allocate()
		if err != nil {
			return fmt.Errorf("failed to lazy allocate node route ID: %w", err)
		}
		route.IDAllocated = true
		// We can't use the first fw mark in range, because it's 0 and would cause all
		// traffic to be matched, so we shift the ID by 1
		route.FWMark = (uint32(route.ID) + 1) << uint32(nlm.fwMask.Shift())
		route.RouteTableID = nlm.routeTableIDOffset + uint32(route.ID)
	}

	// If the route has no ID allocated, we can't reconcile it, because we don't know
	// which route table ID to look for
	if !route.IDAllocated {
		return nil
	}

	// Validate the route table ID
	if route.RouteTableID < uint32(routeTableIDMin) || route.RouteTableID > uint32(routeTableIDMax) {
		return fmt.Errorf("route table ID %d is out of range (%d - %d)", route.RouteTableID, routeTableIDMin, routeTableIDMax)
	}

	// If the route has no rules associated with it, it should be absent (this can happen
	// if the the rule count was decreased to 0, but the id has not been released yet)
	if route.RuleCount == 0 {
		present = false
	}

	var errs []error

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		var gwIP net.IP
		var zeroIP net.IP
		if family == netlink.FAMILY_V4 {
			gwIP = route.IPv4
			zeroIP = net.IPv4zero
		} else {
			gwIP = route.IPv6
			zeroIP = net.IPv6zero
		}

		// Query all existing netlink rules for the family
		nrRules, err := netlink.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list netlink rules: %w", err))
		} else {
			// Cleanup any conflicting or left-over rules for the current node and try to
			// find the existing rule for the node
			var foundRule bool
			for _, r := range nrRules {
				if r.Table >= routeTableIDMin && r.Table <= routeTableIDMax && r.Table == int(route.RouteTableID) {
					if present && r.Mark == route.FWMark && r.Mask == (*uint32)(&nlm.fwMask) {
						foundRule = true
					} else {
						// If the rule does not match the current node's FW mark or mask, delete it
						if err := netlink.RuleDel(&r); err != nil {
							errs = append(errs, fmt.Errorf("failed to delete conflicting netlink rule: %w", err))
						}
					}
				}
			}

			// Create the rule for the node if it does not exist
			if present && !foundRule {
				// Create a new rule for the node if it does not exist
				newRule := netlink.NewRule()
				newRule.Mark = route.FWMark
				newRule.Mask = (*uint32)(&nlm.fwMask)
				newRule.Table = int(route.RouteTableID)
				newRule.Family = family
				if err := netlink.RuleAdd(newRule); err != nil {
					errs = append(errs, fmt.Errorf("failed to add netlink rule for node %s: %w", route.Name, err))
				}
			}
		}

		// Query all existing netlink routes for the family and the route table ID
		nlRoutes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: int(route.RouteTableID)}, netlink.RT_FILTER_TABLE)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list netlink routes: %w", err))
		} else {
			foundRoute := false
			for _, r := range nlRoutes {
				_, bits := r.Dst.Mask.Size()
				if present && !foundRoute && bits == 0 && r.Gw.Equal(gwIP) {
					foundRoute = true
				} else {
					// If the route does not match the current node's gateway IP, delete it
					if err := netlink.RouteDel(&r); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete conflicting netlink route: %w", err))
					}
				}
			}

			// Create the route for the node if it does not exist
			if present && !foundRoute {
				nlRoute := &netlink.Route{
					Dst: &net.IPNet{
						IP:   zeroIP,
						Mask: net.CIDRMask(0, family),
					},
					Gw:    gwIP,
					Table: int(route.RouteTableID),
				}
				if err := netlink.RouteAdd(nlRoute); err != nil {
					errs = append(errs, fmt.Errorf("failed to add netlink route for node %s: %w", route.Name, err))
				}
			}
		}
	}

	// If the route has no rules associated with it and the ID was allocated,
	// we can now release it's ID
	if route.RuleCount == 0 && route.IDAllocated {
		nlm.idAllocator.Release(route.ID)
		route.ID = 0
		route.IDAllocated = false
		route.FWMark = 0
		route.RouteTableID = 0
	}

	return errors.Join(errs...)
}

func (nlm *NetlinkManager) CleanupNodeRoutes(routes map[string]*NodeRoute) error {
	if len(routes) == 0 {
		return nil
	}

	routeTableIDMin := int(nlm.routeTableIDOffset)
	routeTableIDMax := int(uint(nlm.routeTableIDOffset) + nlm.fwMask.Size() - 1)

	expectedRouteTableIDs := set.New[int]()
	for _, route := range routes {
		if route.IDAllocated && route.RouteTableID >= uint32(routeTableIDMin) && route.RouteTableID <= uint32(routeTableIDMax) {
			expectedRouteTableIDs.Add(int(route.RouteTableID))
		}
	}

	var errs []error

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Query all existing netlink rules for the family
		nlRules, err := netlink.RuleList(family)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list netlink rules: %w", err))
		} else {
			// Cleanup any left-over rules
			for _, r := range nlRules {
				if r.Table >= routeTableIDMin && r.Table <= routeTableIDMax && !expectedRouteTableIDs.Contains(r.Table) {
					// The rule is in our table id range but not in the expected set, so delete it
					if err := netlink.RuleDel(&r); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete netlink rule: %w", err))
					}
				}
			}
		}

		// Query all existing netlink routes for the family
		nlRoutes, err := netlink.RouteListFiltered(family, &netlink.Route{}, 0)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list netlink routes: %w", err))
		} else {
			// Cleanup any left-over routes
			for _, r := range nlRoutes {
				if r.Table >= routeTableIDMin && r.Table <= routeTableIDMax && !expectedRouteTableIDs.Contains(r.Table) {
					// If the route is in our table id range but not in the expected set, delete it
					if err := netlink.RouteDel(&r); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete netlink route: %w", err))
					}
				}
			}
		}
	}

	return errors.Join(errs...)
}
