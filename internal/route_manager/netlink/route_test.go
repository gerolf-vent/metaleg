package netlink

import (
	"testing"

	"github.com/vishvananda/netlink"
)

func testRouteEqual(a, b *netlink.Route) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return ipNetEqual(a.Dst, b.Dst) &&
		ipEqual(a.Gw, b.Gw) &&
		a.Table == b.Table &&
		a.Family == b.Family
}

func clearRouteTable(t *testing.T, family int, table int) {
	t.Helper()

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Errorf("Failed to list routes for cleanup: %v", err)
		return
	}

	for _, route := range routes {
		if err := netlink.RouteDel(&route); err != nil {
			t.Errorf("Failed to delete route %+v: %v", route, err)
		}
	}
}

func verifyRouteTable(t *testing.T, family int, table int, equal func(a, b *netlink.Route) bool, expectedRoutes []*netlink.Route) {
	t.Helper()

	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("failed to list routes: %v", err)
	}

	if len(routes) != len(expectedRoutes) {
		t.Logf("Expected routes:\n%+v", expectedRoutes)
		t.Logf("Actual routes:\n%+v", routes)
		t.Fatalf("route table %d has %d routes, expected %d", table, len(routes), len(expectedRoutes))
	}

	routeMissmatchCount := 0

	// Check that every expected route exists in the actual routes, regardless of order
	used := make([]bool, len(routes))
	for _, expected := range expectedRoutes {
		found := false
		for ai, actual := range routes {
			if used[ai] {
				continue
			}
			if equal(&actual, expected) {
				used[ai] = true
				found = true
				break
			}
		}
		if !found {
			t.Logf("route table %d is missing route: %+v", table, expected)
			routeMissmatchCount++
		}
	}

	if routeMissmatchCount > 0 {
		t.Logf("Expected routes:\n%+v", expectedRoutes)
		t.Logf("Actual routes:\n%+v", routes)
		t.Fatalf("%d routes did not match", routeMissmatchCount)
	}
}

func verifyMainRouteTable(t *testing.T, family int, expectedRouteCount int) {
	t.Helper()

	mainRoutes, err := netlink.RouteList(nil, family)
	if err != nil {
		t.Errorf("Failed to list main routes: %v", err)
	}
	if len(mainRoutes) != expectedRouteCount {
		t.Logf("Main routes:\n%+v", mainRoutes)
		t.Fatalf("Count of main routes mismatch after setup: %d routes exist, but %d expected", len(mainRoutes), expectedRouteCount)
	}
}
