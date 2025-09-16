package route_manager

import (
	"net"
	"testing"

	"github.com/vishvananda/netlink"
)

func TestNewNetlinkRouteSynchronizer(t *testing.T) {
	synchronizer := NewNetlinkRouteSynchronizer()
	if synchronizer == nil {
		t.Errorf("Expected non-nil synchronizer")
	}
}

func TestNetlinkRouteSynchronizer_Sync_Unit(t *testing.T) {
	testTable := 10000

	// Unit test - test the structure without actual netlink operations
	_, testNet, _ := net.ParseCIDR("127.0.1.0/24")
	testRoute := &netlink.Route{
		Dst:   testNet,
		Gw:    net.ParseIP("127.0.1.1"),
		Table: testTable,
	}

	synchronizer := &NetlinkRouteSynchronizer{
		Route: testRoute,
		Filter: func(route *netlink.Route) bool {
			return route != nil && route.Table == testTable
		},
		Equal: func(a, b *netlink.Route) bool {
			return a.Dst != nil && b.Dst != nil &&
				a.Dst.String() == b.Dst.String() &&
				a.Gw.Equal(b.Gw) &&
				a.Table == b.Table
		},
		Present: true,
	}

	// Test that synchronizer structure is valid
	if synchronizer.Route != testRoute {
		t.Errorf("Route not set correctly")
	}
	if synchronizer.Filter == nil {
		t.Errorf("Filter function not set")
	}
	if synchronizer.Equal == nil {
		t.Errorf("Equal function not set")
	}
	if !synchronizer.Present {
		t.Errorf("Present should be true")
	}
}

func TestNetlinkRouteSynchronizer_Sync_Integration(t *testing.T) {
	requireNetlinkWritePrivileges(t)

	testTable := 12003

	// Create test interface
	testIf := createTestInterface(t, "64d381d8")
	defer destroyTestInterface(t, testIf)

	ipv4Gws, ipv6Gws := testIf.GetTestRouteTargets(2)

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		var familyName string
		var gws []net.IP
		var dst *net.IPNet
		var conflictingSubnet *net.IPNet
		switch family {
		case netlink.FAMILY_V4:
			familyName = "IPv4"
			gws = ipv4Gws
			dst = &net.IPNet{
				IP:   net.IPv4zero,
				Mask: net.CIDRMask(0, 32),
			}
			_, conflictingSubnet, _ = net.ParseCIDR("203.0.113.96/27")
		case netlink.FAMILY_V6:
			familyName = "IPv6"
			gws = ipv6Gws
			dst = &net.IPNet{
				IP:   net.IPv6zero,
				Mask: net.CIDRMask(0, 128),
			}
			_, conflictingSubnet, _ = net.ParseCIDR("2001:db8::2/64")
		}

		t.Run("Family"+familyName, func(t *testing.T) {
			testRoute := &netlink.Route{
				Dst:    dst,
				Gw:     gws[0],
				Table:  testTable,
				Family: family,
			}

			conflictingRoute := &netlink.Route{
				Dst:    conflictingSubnet,
				Gw:     gws[1],
				Table:  testTable,
				Family: family,
			}

			// Count the routes in the main table
			mainRoutes, err := netlink.RouteList(nil, family)
			if err != nil {
				t.Fatalf("Failed to list main routes: %v", err)
			}
			mainRuleCount := len(mainRoutes)
			t.Logf("Main routes:\n%+v", mainRoutes)

			// Clear the test table
			clearRouteTable(t, family, testTable)

			// Add the unrelated route
			if err := netlink.RouteAdd(conflictingRoute); err != nil {
				t.Fatalf("Failed to add unrelated route: %v", err)
			}
			defer netlink.RouteDel(conflictingRoute)

			// Verify the unrelated route exists
			verifyRouteTable(t, family, testTable, testRouteEqual, []*netlink.Route{conflictingRoute})

			// Verify main route table is unchanged
			verifyMainRouteTable(t, family, mainRuleCount)

			// Create synchronizer that affects the whole test table
			synchronizer := &NetlinkRouteSynchronizer{
				Route: testRoute,
				Filter: func(route *netlink.Route) bool {
					return route != nil && route.Table == testTable
				},
				Equal:   testRouteEqual,
				Present: true,
			}

			// Sync to add the test route
			err = synchronizer.Sync()
			if err != nil {
				t.Fatalf("Failed to sync route (add): %v", err)
			}

			// Verify both routes exist
			verifyRouteTable(t, family, testTable, testRouteEqual, []*netlink.Route{testRoute})

			// Verify main route table is unchanged
			verifyMainRouteTable(t, family, mainRuleCount)

			// Sync to remove the test route
			synchronizer.Present = false
			err = synchronizer.Sync()
			if err != nil {
				t.Fatalf("Failed to sync route (remove): %v", err)
			}

			// Verify final state
			verifyRouteTable(t, family, testTable, testRouteEqual, []*netlink.Route{})

			// Verify main route table is unchanged
			verifyMainRouteTable(t, family, mainRuleCount)

			// Clean up route table
			clearRouteTable(t, family, testTable)
		})
	}
}

func TestNetlinkRouteSynchronizer_Sync_InvalidRoute(t *testing.T) {
	requireNetlinkWritePrivileges(t)

	testTable := 12001

	// Create test interface with real network
	testIf := createTestInterface(t, "cd3b4e6f")
	defer destroyTestInterface(t, testIf)

	for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
		var familyName string
		switch family {
		case netlink.FAMILY_V4:
			familyName = "IPv4"
		case netlink.FAMILY_V6:
			familyName = "IPv6"
		}

		t.Run("Family"+familyName, func(t *testing.T) {
			// Test with invalid route (no destination - this should fail to add)
			testRoute := &netlink.Route{
				Table:     testTable,
				Family:    family,
				LinkIndex: testIf.Link.Attrs().Index,
				Scope:     netlink.SCOPE_LINK,
				// Dst is intentionally nil to make this an invalid route
			}

			// Clear the test table before starting
			clearRouteTable(t, family, testTable)

			synchronizer := &NetlinkRouteSynchronizer{
				Route: testRoute,
				Filter: func(route *netlink.Route) bool {
					return route != nil && route.Table == testTable
				},
				Equal:   testRouteEqual,
				Present: true,
			}

			// This should fail due to invalid route, which is expected
			err := synchronizer.Sync()
			if err == nil {
				t.Errorf("Expected error when syncing invalid route, but got none")
			}

			// Clean up route table
			clearRouteTable(t, family, testTable)
		})
	}
}
