package route_manager

import (
	"fmt"

	"github.com/gerolf-vent/metaleg/internal/utils/state"
	"github.com/vishvananda/netlink"
)

// NetlinkRouteSynchronizer synchronizes netlink routes using the state synchronizer pattern
type NetlinkRouteSynchronizer struct {
	Route   *netlink.Route // The route to synchronize
	Filter  func(*netlink.Route) bool
	Equal   func(*netlink.Route, *netlink.Route) bool
	Present bool // Whether the route should be present or absent
}

func NewNetlinkRouteSynchronizer() *NetlinkRouteSynchronizer {
	return &NetlinkRouteSynchronizer{}
}

func (s *NetlinkRouteSynchronizer) Sync() error {
	stateSynchronizer := state.StateSynchronizer[netlink.Route, *netlink.Route]{
		Get: func() ([]netlink.Route, error) {
			return netlink.RouteListFiltered(s.Route.Family, &netlink.Route{Table: s.Route.Table}, netlink.RT_FILTER_TABLE)
		},
		Prepare: func(existingRoute netlink.Route) (netlink.Route, *netlink.Route) {
			return existingRoute, &existingRoute
		},
		Filter: func(_ netlink.Route, _ *netlink.Route) bool {
			return s.Filter(s.Route)
		},
		Equal: func(existingRoute netlink.Route, _ *netlink.Route, newRoute *netlink.Route) bool {
			return s.Equal(&existingRoute, newRoute)
		},
		Add: func(newRoute *netlink.Route) error {
			return netlink.RouteAdd(newRoute)
		},
		Delete: func(existingRoute netlink.Route) error {
			return netlink.RouteDel(&existingRoute)
		},
	}

	if s.Present {
		if err := stateSynchronizer.SyncSingle(s.Route); err != nil {
			return fmt.Errorf("failed to ensure netlink route: %w", err)
		}
	} else {
		if err := stateSynchronizer.Clear(); err != nil {
			return fmt.Errorf("failed to clear netlink route: %w", err)
		}
	}

	return nil
}
