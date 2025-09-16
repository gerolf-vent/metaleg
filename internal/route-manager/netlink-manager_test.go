package route_manager

import (
	"net"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/vishvananda/netlink"
)

func TestNewNetlinkManager(t *testing.T) {
	tests := []struct {
		name               string
		fwMask             utils.FWMask
		routeTableIDOffset uint32
		expectError        bool
		expectedErr        string
	}{
		{
			name:               "valid parameters",
			fwMask:             utils.FWMask(0xFF000000), // 8 bits, assuming this creates a mask with size > 1
			routeTableIDOffset: 10000,
			expectError:        false,
		},
		{
			name:               "fw mask too small",
			fwMask:             utils.FWMask(0x00000000), // size 0, which is <= 1
			routeTableIDOffset: 10000,
			expectError:        true,
			expectedErr:        "firewall mask too small",
		},
		{
			name:               "table offset to large",
			fwMask:             utils.FWMask(0x0F00000),
			routeTableIDOffset: 0xFFFFFFFF,
			expectError:        true,
			expectedErr:        "route table ID offset is too large",
		},
		{
			name:               "firewall mask not continous",
			fwMask:             utils.FWMask(0x0F00F00),
			routeTableIDOffset: 10000,
			expectError:        true,
			expectedErr:        "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			manager, err := NewNetlinkManager(tt.fwMask, tt.routeTableIDOffset)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
				if manager != nil {
					t.Errorf("Expected manager to be nil on error")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if manager == nil {
					t.Errorf("Expected manager to be non-nil")
				}
			}
		})
	}
}

func TestNetlinkManager_Setup(t *testing.T) {
	fwMask := utils.FWMask(0xFF000000)
	manager, err := NewNetlinkManager(fwMask, 10000)
	if err != nil {
		t.Fatalf("Failed to create NetlinkManager: %v", err)
	}

	err = manager.Setup()
	if err != nil {
		t.Errorf("Setup failed: %v", err)
	}
}

func TestNetlinkManager_Cleanup(t *testing.T) {
	requireNetlinkWritePrivileges(t)

	testTableOffset := uint32(10000)

	fwMask := utils.FWMask(0xFF000000)
	manager, err := NewNetlinkManager(fwMask, testTableOffset)
	if err != nil {
		t.Fatalf("Failed to create NetlinkManager: %v", err)
	}

	testRulesIPv4 := newTestRules(netlink.FAMILY_V4, int(testTableOffset), 3)
	for _, rule := range testRulesIPv4 {
		if err := netlink.RuleAdd(rule); err != nil {
			t.Fatalf("Failed to create test route: %v", err)
		}
	}
	verifyRules(t, netlink.FAMILY_V4, int(testTableOffset), int(testTableOffset)+3, testRuleEqual, testRulesIPv4)

	testRulesIPv6 := newTestRules(netlink.FAMILY_V6, int(testTableOffset), 3)
	for _, rule := range testRulesIPv6 {
		if err := netlink.RuleAdd(rule); err != nil {
			t.Fatalf("Failed to create test route: %v", err)
		}
	}
	verifyRules(t, netlink.FAMILY_V6, int(testTableOffset), int(testTableOffset)+3, testRuleEqual, testRulesIPv6)

	err = manager.Cleanup()
	if err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	verifyRules(t, netlink.FAMILY_ALL, int(testTableOffset), int(testTableOffset)+3, testRuleEqual, nil)
}

func TestNetlinkManager_ReconcileNodeRoute(t *testing.T) {
	requireNetlinkWritePrivileges(t)

	// Create test interface with real network for routing
	testIf := createTestInterface(t, "88741f05")
	defer destroyTestInterface(t, testIf)

	routeTableOffset := uint32(11000)
	fwMask := utils.FWMask(0xFF000000)
	fwMaskVal := uint32(fwMask)

	manager, err := NewNetlinkManager(fwMask, routeTableOffset)
	if err != nil {
		t.Fatalf("Failed to create NetlinkManager: %v", err)
	}

	err = manager.Setup()
	if err != nil {
		t.Errorf("Setup failed: %v", err)
	}
	defer manager.Cleanup()

	testRoute := &NodeRoute{
		Name:        "test",
		IPv4:        testIf.IPv4Gw,
		IPv6:        testIf.IPv6Gw,
		RuleCount:   1,
		IDAllocated: false,
	}

	tests := []struct {
		name        string
		route       *NodeRoute
		prepare     func(t *testing.T, route *NodeRoute)
		verify      func(t *testing.T, route *NodeRoute)
		expectError bool
		expectedErr string
		present     bool
	}{
		{
			name:        "nil route",
			route:       nil,
			present:     true,  // Should be a no-op
			expectError: false, // Just verify that it doesn't panic
		},
		{
			name: "route without allocated ID and no rules",
			route: &NodeRoute{
				Name:        "test",
				IPv4:        testIf.IPv4Gw,
				IPv6:        testIf.IPv6Gw,
				RuleCount:   0,
				IDAllocated: false,
			},
			verify: func(t *testing.T, route *NodeRoute) {
				if route == nil {
					t.Errorf("Expected route to be non-nil")
					return
				}
				if route.IDAllocated {
					t.Errorf("Expected route ID to be unallocated")
				}
				if manager.idAllocator.AllocatedCount() != 0 {
					t.Errorf("Unexpected number of allocated IDs: %d, expected %d", manager.idAllocator.AllocatedCount(), 0)
				}

				// There should be no rules for this node route
				verifyRules(t, netlink.FAMILY_ALL, int(routeTableOffset), int(routeTableOffset), testRuleEqual, nil)
			},
			present: true,
		},
		{
			name: "route allocated ID and no rules",
			route: &NodeRoute{
				Name:         "test",
				IPv4:         testIf.IPv4Gw,
				IPv6:         testIf.IPv6Gw,
				RuleCount:    0,
				IDAllocated:  true,
				ID:           0,
				FWMark:       0x01000000,
				RouteTableID: routeTableOffset,
			},
			verify: func(t *testing.T, route *NodeRoute) {
				if route == nil {
					t.Errorf("Expected route to be non-nil")
					return
				}
				if route.IDAllocated {
					t.Errorf("Expected route ID to be released")
				}
				if manager.idAllocator.AllocatedCount() != 0 {
					t.Errorf("Unexpected number of allocated IDs: %d, expected %d", manager.idAllocator.AllocatedCount(), 0)
				}

				// There should be no rules for this node route
				verifyRules(t, netlink.FAMILY_ALL, int(routeTableOffset), int(routeTableOffset), testRuleEqual, nil)
			},
			present: false,
		},
		{
			name:  "route with rules to be added",
			route: testRoute,
			verify: func(t *testing.T, route *NodeRoute) {
				if route == nil {
					t.Errorf("Expected route to be non-nil")
					return
				}
				if !route.IDAllocated {
					t.Errorf("Expected route ID to be allocated")
				}
				if manager.idAllocator.AllocatedCount() != 1 {
					t.Errorf("Unexpected number of allocated IDs: %d, expected %d", manager.idAllocator.AllocatedCount(), 1)
				}

				// There should be rules and routes for this node route
				for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
					expectedRules := []*netlink.Rule{
						{Mark: (uint32(route.ID) + 1) << uint32(fwMask.Shift()), Mask: &fwMaskVal, Table: int(routeTableOffset), Family: family},
					}
					var expectedRoutes []*netlink.Route
					switch family {
					case netlink.FAMILY_V4:
						expectedRoutes = []*netlink.Route{
							{Gw: route.IPv4, Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Table: int(routeTableOffset), Family: family},
						}
					case netlink.FAMILY_V6:
						expectedRoutes = []*netlink.Route{
							{Gw: route.IPv6, Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Table: int(routeTableOffset), Family: family},
						}
					}
					verifyRules(t, family, int(routeTableOffset), int(routeTableOffset), testRuleEqual, expectedRules)
					for _, r := range expectedRoutes {
						verifyRouteTable(t, family, r.Table, testRouteEqual, []*netlink.Route{r})
					}
				}
			},
			present: true,
		},
		{
			name:  "route with rules to be removed",
			route: testRoute,
			prepare: func(t *testing.T, route *NodeRoute) {
				if route == nil {
					t.Fatalf("Route is nil in prepare function")
				}
				// Set the rule count to 0 to ensure the route id gets released
				route.RuleCount = 0
			},
			verify: func(t *testing.T, route *NodeRoute) {
				if route == nil {
					t.Errorf("Expected route to be non-nil")
					return
				}
				if route.IDAllocated {
					t.Errorf("Expected route ID to be released")
				}
				if manager.idAllocator.AllocatedCount() != 0 {
					t.Errorf("Unexpected number of allocated IDs: %d, expected %d", manager.idAllocator.AllocatedCount(), 0)
				}

				// There should be no rules and routes left for this node route
				for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
					verifyRules(t, family, int(routeTableOffset), int(routeTableOffset), testRuleEqual, nil)
					verifyRouteTable(t, family, int(routeTableOffset), testRouteEqual, nil)
				}
			},
			present: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prepare != nil {
				tt.prepare(t, tt.route)
			}
			err := manager.ReconcileNodeRoute(tt.route, tt.present)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			}
			if !tt.expectError {
				if err != nil {
					t.Errorf("ReconcileNodeRoute failed: %v", err)
				} else if tt.verify != nil {
					tt.verify(t, tt.route)
				}
			}
		})
	}
}

func TestNetlinkManager_CleanupStaleNodeRoutes(t *testing.T) {
	requireNetlinkWritePrivileges(t)

	// Create test interface with real network for routing
	testIf := createTestInterface(t, "88741f05")
	defer destroyTestInterface(t, testIf)

	routeTableOffset := uint32(13000)

	testIPv4s, testIPv6s := testIf.GetTestRouteTargets(3)

	testRulesIPv4 := newTestRules(netlink.FAMILY_V4, int(routeTableOffset), 3)
	testRulesIPv6 := newTestRules(netlink.FAMILY_V6, int(routeTableOffset), 3)
	testRoutesIPv4 := []*netlink.Route{
		{Gw: testIPv4s[0], Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Table: int(routeTableOffset), Family: netlink.FAMILY_V4},
		{Gw: testIPv4s[1], Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Table: int(routeTableOffset) + 1, Family: netlink.FAMILY_V4},
		{Gw: testIPv4s[2], Dst: &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}, Table: int(routeTableOffset) + 2, Family: netlink.FAMILY_V4},
	}
	testRoutesIPv6 := []*netlink.Route{
		{Gw: testIPv6s[0], Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Table: int(routeTableOffset), Family: netlink.FAMILY_V6},
		{Gw: testIPv6s[1], Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Table: int(routeTableOffset) + 1, Family: netlink.FAMILY_V6},
		{Gw: testIPv6s[2], Dst: &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}, Table: int(routeTableOffset) + 2, Family: netlink.FAMILY_V6},
	}

	manager, err := NewNetlinkManager(testFWMask, routeTableOffset)
	if err != nil {
		t.Fatalf("Failed to create NetlinkManager: %v", err)
	}

	testRoutes := map[string]*NodeRoute{
		"node1": {
			Name:         "node1",
			IPv4:         testIPv4s[0],
			IPv6:         testIPv6s[0],
			ID:           0,
			IDAllocated:  true,
			FWMark:       testRulesIPv4[0].Mark,
			RouteTableID: uint32(testRulesIPv4[0].Table),
			RuleCount:    1,
		},
		"node2": {
			Name:         "node2",
			IPv4:         testIPv4s[1],
			IPv6:         testIPv6s[1],
			ID:           1,
			IDAllocated:  true,
			FWMark:       testRulesIPv4[1].Mark,
			RouteTableID: uint32(testRulesIPv4[1].Table),
			RuleCount:    1,
		},
	}

	tests := []struct {
		name        string
		routes      map[string]*NodeRoute
		prepare     func(t *testing.T)
		verify      func(t *testing.T)
		expectError bool
		expectedErr string
	}{
		{
			name:   "nil routes map",
			routes: nil,
			prepare: func(t *testing.T) {
				clearRules(t, netlink.FAMILY_ALL, int(routeTableOffset), int(routeTableOffset)+3)
				for _, r := range append(testRulesIPv4, testRulesIPv6...) {
					if err := netlink.RuleAdd(r); err != nil {
						t.Fatalf("Failed to add test rule: %v", err)
					}
				}
			},
			verify: func(t *testing.T) {
				verifyRules(t, netlink.FAMILY_ALL, int(routeTableOffset), int(routeTableOffset)+3, testRuleEqual, nil)
			},
		},
		{
			name:   "empty routes map",
			routes: map[string]*NodeRoute{},
			prepare: func(t *testing.T) {
				clearRules(t, netlink.FAMILY_ALL, int(routeTableOffset), int(routeTableOffset)+3)
				for _, r := range append(testRulesIPv4, testRulesIPv6...) {
					if err := netlink.RuleAdd(r); err != nil {
						t.Fatalf("Failed to add test rule: %v", err)
					}
				}
			},
			verify: func(t *testing.T) {
				verifyRules(t, netlink.FAMILY_ALL, int(routeTableOffset), int(routeTableOffset)+3, testRuleEqual, nil)
			},
		},
		{
			name: "routes with allocated IDs",
			prepare: func(t *testing.T) {
				clearRules(t, netlink.FAMILY_ALL, int(routeTableOffset), int(routeTableOffset)+3)
				for _, r := range append(testRulesIPv4, testRulesIPv6...) {
					if err := netlink.RuleAdd(r); err != nil {
						t.Fatalf("Failed to add test rule: %v", err)
					}
				}
				for _, r := range append(testRoutesIPv4, testRoutesIPv6...) {
					clearRouteTable(t, r.Family, r.Table)
					if err := netlink.RouteAdd(r); err != nil {
						t.Fatalf("Failed to add test route: %v", err)
					}
				}
			},
			routes: testRoutes,
			verify: func(t *testing.T) {
				for _, family := range []int{netlink.FAMILY_V4, netlink.FAMILY_V6} {
					var expectedRules []*netlink.Rule
					var expectedRoutes []*netlink.Route
					switch family {
					case netlink.FAMILY_V4:
						expectedRules = testRulesIPv4[:2]
						expectedRoutes = testRoutesIPv4[:2]
					case netlink.FAMILY_V6:
						expectedRules = testRulesIPv6[:2]
						expectedRoutes = testRoutesIPv6[:2]
					}
					verifyRules(t, family, int(routeTableOffset), int(routeTableOffset)+3, testRuleEqual, expectedRules)
					for _, r := range expectedRoutes {
						verifyRouteTable(t, family, r.Table, testRouteEqual, []*netlink.Route{r})
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.prepare != nil {
				tt.prepare(t)
			}
			err := manager.CleanupStaleNodeRoutes(tt.routes)
			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
				} else if tt.expectedErr != "" && err.Error() != tt.expectedErr {
					t.Errorf("Expected error %q, got %q", tt.expectedErr, err.Error())
				}
			}
			if !tt.expectError {
				if err != nil {
					t.Errorf("ReconcileNodeRoute failed: %v", err)
				} else if tt.verify != nil {
					tt.verify(t)
				}
			}
		})
	}
}
