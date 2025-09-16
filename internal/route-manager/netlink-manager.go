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

	if !fwMask.IsContinous() {
		return nil, fmt.Errorf("firewall mask not continous")
	}

	if routeTableIDOffset > math.MaxUint32-uint32(fwMask.Size()) {
		return nil, fmt.Errorf("route table ID offset is too large")
	}

	return &NetlinkManager{
		fwMask:             fwMask,
		routeTableIDOffset: routeTableIDOffset,
		// We can't use the first element (0) in the range, because a fw mask with that
		// value would cause all traffic to be matched, so we start allocating from 1
		// and the id allocator must be created with a size reduced by 1
		idAllocator: utils.NewIDRangeAllocator(fwMask.Size() - 1),
	}, nil
}

func (nlm *NetlinkManager) Setup() error {
	// Nothing needed
	return nil
}

func (nlm *NetlinkManager) Cleanup() error {
	var errs []error

	routeTableIDMin := int(nlm.routeTableIDOffset)
	routeTableIDMax := int(uint(nlm.routeTableIDOffset) + nlm.fwMask.Size() - 1)

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		// Cleanup netlink rules
		ruleCleaner := &NetlinkRuleCleaner{
			TableIDMin:       routeTableIDMin,
			TableIDMax:       routeTableIDMax,
			ExpectedTableIDs: set.New[int](), // No expected table IDs, we want to clean up everything in range
			Family:           family,
		}
		if err := ruleCleaner.Clean(); err != nil {
			errs = append(errs, err)
		}

		// Cleanup netlink routes is to expensive, because we would need to iterate through all the tables.
		// But they don't affect anything, because the rules are gone.
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
		// traffic to be matched, so we add 1 to the ID here
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
			maskSize = 128
		}

		//
		// Synchronize the netlink rule
		//

		fwMarkRule := netlink.NewRule()
		fwMarkRule.Mark = route.FWMark
		fwMarkRule.Mask = (*uint32)(&nlm.fwMask)
		fwMarkRule.Table = int(route.RouteTableID)
		fwMarkRule.Family = family

		ruleSynchronizer := &NetlinkRuleSynchronizer{
			Rule: fwMarkRule,
			Filter: func(existingRule *netlink.Rule) bool {
				return existingRule != nil && existingRule.Table == fwMarkRule.Table
			},
			Equal: func(a, b *netlink.Rule) bool {
				return a.Mark == b.Mark &&
					((a.Mask == nil && b.Mask == nil) || (a.Mask != nil && b.Mask != nil && *a.Mask == *b.Mask)) &&
					a.Table == b.Table &&
					a.Family == b.Family
			},
			Present: present,
		}
		if err := ruleSynchronizer.Sync(); err != nil {
			errs = append(errs, err)
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
			Table:  int(route.RouteTableID),
			Family: family,
		}

		routeSynchronizer := &NetlinkRouteSynchronizer{
			Route: gwRoute,
			Filter: func(existingRoute *netlink.Route) bool {
				return existingRoute != nil && existingRoute.Table == gwRoute.Table
			},
			Equal: func(a, b *netlink.Route) bool {
				return a.Dst != nil && b.Dst != nil &&
					a.Dst.String() == b.Dst.String() &&
					a.Gw.Equal(b.Gw) &&
					a.Table == b.Table
			},
			Present: present,
		}
		if err := routeSynchronizer.Sync(); err != nil {
			errs = append(errs, err)
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

func (nlm *NetlinkManager) CleanupStaleNodeRoutes(routes map[string]*NodeRoute) error {
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
		// Cleanup netlink rules
		ruleCleaner := &NetlinkRuleCleaner{
			TableIDMin:       routeTableIDMin,
			TableIDMax:       routeTableIDMax,
			ExpectedTableIDs: expectedRouteTableIDs,
			Family:           family,
		}
		if err := ruleCleaner.Clean(); err != nil {
			errs = append(errs, err)
		}

		// Cleanup netlink routes is to expensive, because we would need to iterate through all the tables.
		// But they don't affect anything, because the rules are gone.
	}

	return errors.Join(errs...)
}
