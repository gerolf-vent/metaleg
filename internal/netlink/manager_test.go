package netlink

import (
	"bytes"
	"net"
	"os"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/mock"
	"github.com/go-logr/logr"
	"github.com/vishvananda/netlink"
)

func requireNetlinkTestsEnabled(t *testing.T) {
	t.Helper()
	v := os.Getenv("METALEG_TEST_NETLINK")
	if v != "yes" && v != "true" {
		t.Skip("Skipping netlink test: METALEG_TEST_NETLINK is not set to 'yes' or 'true'")
	}
}

// testNet holds the test network configuration (veth pair with IPv4/IPv6 addresses).
type testNet struct {
	GatewayIPv4 net.IP
	GatewayIPv6 net.IP
}

// setupTestNet creates a veth pair with IPv4 and IPv6 addresses for testing.
// The returned testNet contains gateway IPs that are routable from the test environment.
// The veth pair is cleaned up when the test completes.
func setupTestNet(t *testing.T) *testNet {
	t.Helper()

	veth0 := "mltest0"
	veth1 := "mltest1"

	vethLink := &netlink.Veth{
		LinkAttrs: netlink.LinkAttrs{Name: veth0},
		PeerName:  veth1,
	}
	if err := netlink.LinkAdd(vethLink); err != nil {
		t.Fatalf("Failed to create veth pair: %v", err)
	}

	t.Cleanup(func() {
		link, err := netlink.LinkByName(veth0)
		if err == nil {
			netlink.LinkDel(link)
		}
	})

	link0, err := netlink.LinkByName(veth0)
	if err != nil {
		t.Fatalf("Failed to get %s: %v", veth0, err)
	}
	link1, err := netlink.LinkByName(veth1)
	if err != nil {
		t.Fatalf("Failed to get %s: %v", veth1, err)
	}

	// Only assign addresses to the local end (veth0). The gateway IPs
	// (192.168.249.2, fd00:dead:beef::2) are left unassigned so the kernel
	// treats them as remote on-link addresses reachable via the connected
	// subnet, which matches how real gateway nodes appear.
	addr4_0, _ := netlink.ParseAddr("192.168.249.1/24")
	if err := netlink.AddrAdd(link0, addr4_0); err != nil {
		t.Fatalf("Failed to add IPv4 addr to %s: %v", veth0, err)
	}

	addr6_0, _ := netlink.ParseAddr("fd00:dead:beef::1/64")
	if err := netlink.AddrAdd(link0, addr6_0); err != nil {
		t.Fatalf("Failed to add IPv6 addr to %s: %v", veth0, err)
	}

	if err := netlink.LinkSetUp(link0); err != nil {
		t.Fatalf("Failed to bring up %s: %v", veth0, err)
	}
	if err := netlink.LinkSetUp(link1); err != nil {
		t.Fatalf("Failed to bring up %s: %v", veth1, err)
	}

	return &testNet{
		GatewayIPv4: net.ParseIP("192.168.249.2"),
		GatewayIPv6: net.ParseIP("fd00:dead:beef::2"),
	}
}

// cleanupRulesAndRoutes removes all netlink rules and routes created by a manager
// in the test's route table range for both IPv4 and IPv6.
func cleanupRulesAndRoutes(t *testing.T, m *Manager) {
	t.Helper()
	if err := m.Purge(); err != nil {
		t.Logf("Warning: cleanup purge failed: %v", err)
	}
}

func listManagedRules(t *testing.T, m *Manager, family int) []netlink.Rule {
	t.Helper()
	rules, err := netlink.RuleList(family)
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}
	var managed []netlink.Rule
	for _, r := range rules {
		if r.Table >= m.routeTableIDMin && r.Table <= m.routeTableIDMax {
			managed = append(managed, r)
		}
	}
	return managed
}

func listManagedRoutes(t *testing.T, tableID int, family int) []netlink.Route {
	t.Helper()
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: tableID}, netlink.RT_FILTER_TABLE)
	if err != nil {
		t.Fatalf("Failed to list routes for table %d: %v", tableID, err)
	}
	return routes
}

// --- Tests ---

func TestManager_Name(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	m := NewManager(mock.NewState(), logr.Discard())
	if m.Name() != "netlink" {
		t.Errorf("Expected name 'netlink', got %q", m.Name())
	}
}

func TestSetup_ReturnsNoError(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	m := NewManager(mock.NewState(), logr.Discard())
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup returned unexpected error: %v", err)
	}
}

// --- Reconcile ---

func TestReconcile_NoChanges(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	m := NewManager(mock.NewState(), logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })
	sc := core.NewStateChange()
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile with no changes failed: %v", err)
	}
}

func TestReconcile_AddIPv4Rule(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	routeTableID := state.RouteTableIDOff + 1
	fwMark := uint32(1) << state.FWMaskVal.Shift()
	state.NodeStates["gw-node"] = core.NodeState{
		Node:         core.Node{Name: "gw-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           1,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}

	sc := core.NewStateChange()
	sc.NodesUpdated.Add("gw-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify fw mark rule was created with correct values
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	found := false
	expectedMask := uint32(state.FWMaskVal)
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			found = true
			if r.Mark != fwMark {
				t.Errorf("Rule mark = %d, want %d", r.Mark, fwMark)
			}
			if r.Mask == nil || *r.Mask != expectedMask {
				got := uint32(0)
				if r.Mask != nil {
					got = *r.Mask
				}
				t.Errorf("Rule mask = 0x%x, want 0x%x", got, expectedMask)
			}
			break
		}
	}
	if !found {
		t.Error("Expected IPv4 FW mark rule to be created")
	}

	// Verify routes were created with correct values
	routes := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	if len(routes) == 0 {
		t.Fatal("Expected IPv4 routes to be created in route table")
	}

	hasDefaultRoute := false
	hasGWRoute := false
	expectedGWDst := &net.IPNet{IP: gwIP, Mask: net.CIDRMask(32, 32)}
	expectedDefaultDst := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(expectedDefaultDst.IP) && bytes.Equal(r.Dst.Mask, expectedDefaultDst.Mask) {
			hasDefaultRoute = true
			if !r.Gw.Equal(gwIP) {
				t.Errorf("Default route Gw = %v, want %v", r.Gw, gwIP)
			}
		}
		if r.Dst != nil && r.Dst.IP.Equal(expectedGWDst.IP) && bytes.Equal(r.Dst.Mask, expectedGWDst.Mask) {
			hasGWRoute = true
		}
	}
	if !hasDefaultRoute {
		t.Error("Expected default route (0.0.0.0/0) in route table")
	}
	if !hasGWRoute {
		t.Errorf("Expected gateway host route (%v/32) in route table", gwIP)
	}
}

func TestReconcile_AddIPv6Rule(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv6

	routeTableID := state.RouteTableIDOff + 2
	fwMark := uint32(2) << state.FWMaskVal.Shift()
	state.NodeStates["gw-node-v6"] = core.NodeState{
		Node:         core.Node{Name: "gw-node-v6", IPv6: gwIP},
		IDAllocated:  true,
		ID:           2,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}

	sc := core.NewStateChange()
	sc.NodesUpdated.Add("gw-node-v6")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	rules := listManagedRules(t, m, netlink.FAMILY_V6)
	found := false
	expectedMask := uint32(state.FWMaskVal)
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			found = true
			if r.Mark != fwMark {
				t.Errorf("Rule mark = %d, want %d", r.Mark, fwMark)
			}
			if r.Mask == nil || *r.Mask != expectedMask {
				got := uint32(0)
				if r.Mask != nil {
					got = *r.Mask
				}
				t.Errorf("Rule mask = 0x%x, want 0x%x", got, expectedMask)
			}
			break
		}
	}
	if !found {
		t.Error("Expected IPv6 FW mark rule to be created")
	}

	routes := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V6)
	if len(routes) == 0 {
		t.Fatal("Expected IPv6 routes to be created in route table")
	}

	hasDefaultRoute := false
	hasGWRoute := false
	expectedGWDst := &net.IPNet{IP: gwIP, Mask: net.CIDRMask(128, 128)}
	expectedDefaultDst := &net.IPNet{IP: net.IPv6zero, Mask: net.CIDRMask(0, 128)}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(expectedDefaultDst.IP) && bytes.Equal(r.Dst.Mask, expectedDefaultDst.Mask) {
			hasDefaultRoute = true
			if !r.Gw.Equal(gwIP) {
				t.Errorf("Default route Gw = %v, want %v", r.Gw, gwIP)
			}
		}
		if r.Dst != nil && r.Dst.IP.Equal(expectedGWDst.IP) && bytes.Equal(r.Dst.Mask, expectedGWDst.Mask) {
			hasGWRoute = true
		}
	}
	if !hasDefaultRoute {
		t.Error("Expected default route (::/0) in route table")
	}
	if !hasGWRoute {
		t.Errorf("Expected gateway host route (%v/128) in route table", gwIP)
	}
}

func TestReconcile_DeleteNode(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	routeTableID := state.RouteTableIDOff + 3
	fwMark := uint32(3) << state.FWMaskVal.Shift()
	nodeState := core.NodeState{
		Node:         core.Node{Name: "delete-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           3,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}

	// First, add the node
	state.NodeStates["delete-node"] = nodeState
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("delete-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile (add) failed: %v", err)
	}

	// Verify rule exists
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	found := false
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Expected rule to exist before deletion")
	}

	// Now delete the node
	delete(state.NodeStates, "delete-node")
	sc2 := core.NewStateChange()
	sc2.NodesDeleted["delete-node"] = nodeState
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Reconcile (delete) failed: %v", err)
	}

	// Verify rule was removed
	rules = listManagedRules(t, m, netlink.FAMILY_V4)
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			t.Error("Expected IPv4 rule to be deleted")
			break
		}
	}

	// Verify routes were removed
	routes := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	if len(routes) != 0 {
		t.Errorf("Expected routes to be deleted, found %d", len(routes))
	}
}

func TestReconcile_UpdateNodeGateway(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	routeTableID := state.RouteTableIDOff + 4
	fwMark := uint32(4) << state.FWMaskVal.Shift()
	state.NodeStates["update-node"] = core.NodeState{
		Node:         core.Node{Name: "update-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           4,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}

	sc := core.NewStateChange()
	sc.NodesUpdated.Add("update-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("First reconcile failed: %v", err)
	}

	// Reconcile again with the same data (idempotency)
	sc2 := core.NewStateChange()
	sc2.NodesUpdated.Add("update-node")
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Second reconcile (idempotent) failed: %v", err)
	}

	// Verify exactly one rule exists for this table with correct values
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	count := 0
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			count++
			if r.Mark != fwMark {
				t.Errorf("Rule mark = %d, want %d", r.Mark, fwMark)
			}
		}
	}
	if count != 1 {
		t.Errorf("Expected exactly 1 rule for table %d, got %d", routeTableID, count)
	}

	// Verify exactly one default route and one gw host route
	routes := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	defaultCount := 0
	gwCount := 0
	expectedGWDst := &net.IPNet{IP: gwIP, Mask: net.CIDRMask(32, 32)}
	expectedDefaultDst := &net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(expectedDefaultDst.IP) && bytes.Equal(r.Dst.Mask, expectedDefaultDst.Mask) {
			defaultCount++
		}
		if r.Dst != nil && r.Dst.IP.Equal(expectedGWDst.IP) && bytes.Equal(r.Dst.Mask, expectedGWDst.Mask) {
			gwCount++
		}
	}
	if defaultCount != 1 {
		t.Errorf("Expected exactly 1 default route after idempotent reconcile, got %d", defaultCount)
	}
	if gwCount != 1 {
		t.Errorf("Expected exactly 1 gw host route after idempotent reconcile, got %d", gwCount)
	}
}

func TestReconcile_NodeWithNoIPSkipsRuleCreation(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	routeTableID := state.RouteTableIDOff + 5
	fwMark := uint32(5) << state.FWMaskVal.Shift()
	// Node with no IPs set
	state.NodeStates["no-ip-node"] = core.NodeState{
		Node:         core.Node{Name: "no-ip-node"},
		IDAllocated:  true,
		ID:           5,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}

	sc := core.NewStateChange()
	sc.NodesUpdated.Add("no-ip-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Should not create any rules for a node without IPs
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			t.Error("Expected no IPv4 rule for node without IP")
			break
		}
	}
	rules6 := listManagedRules(t, m, netlink.FAMILY_V6)
	for _, r := range rules6 {
		if r.Table == int(routeTableID) {
			t.Error("Expected no IPv6 rule for node without IP")
			break
		}
	}
}

func TestReconcile_NodeWithoutAllocatedIDIsSkipped(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	routeTableID := state.RouteTableIDOff + 6
	state.NodeStates["unalloc-node"] = core.NodeState{
		Node:         core.Node{Name: "unalloc-node", IPv4: gwIP},
		IDAllocated:  false,
		RouteTableID: routeTableID,
	}

	sc := core.NewStateChange()
	sc.NodesUpdated.Add("unalloc-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			t.Error("Expected no rule for node without allocated ID")
			break
		}
	}
}

func TestReconcile_DeleteNodeWithoutAllocatedIDIsSkipped(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	sc := core.NewStateChange()
	sc.NodesDeleted["unalloc-deleted"] = core.NodeState{
		Node:        core.Node{Name: "unalloc-deleted"},
		IDAllocated: false,
	}

	// Should not error even though the node had no allocated ID
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
}

// --- Cleanup ---

func TestCleanup_RemovesStaleRules(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	// Manually add a rule in the managed range that is not tracked in state
	staleTableID := int(state.RouteTableIDOff + 7)
	staleFWMark := uint32(7) << state.FWMaskVal.Shift()
	rule := netlink.NewRule()
	rule.Mark = staleFWMark
	mask := uint32(state.FWMaskVal)
	rule.Mask = &mask
	rule.Table = staleTableID
	rule.Family = netlink.FAMILY_V4
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatalf("Failed to add stale rule: %v", err)
	}

	// Verify stale rule exists
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	found := false
	for _, r := range rules {
		if r.Table == staleTableID {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Stale rule was not created")
	}

	// Cleanup should remove the stale rule since no node tracks it
	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	rules = listManagedRules(t, m, netlink.FAMILY_V4)
	for _, r := range rules {
		if r.Table == staleTableID {
			t.Error("Expected stale rule to be cleaned up")
			break
		}
	}
}

func TestCleanup_PreservesActiveRules(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	routeTableID := state.RouteTableIDOff + 8
	fwMark := uint32(8) << state.FWMaskVal.Shift()
	state.NodeStates["active-node"] = core.NodeState{
		Node:         core.Node{Name: "active-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           8,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}

	// Add the rule via reconcile
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("active-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Cleanup should keep the active rule with correct values
	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	found := false
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			found = true
			if r.Mark != fwMark {
				t.Errorf("Preserved rule mark = %d, want %d", r.Mark, fwMark)
			}
			expectedMask := uint32(state.FWMaskVal)
			if r.Mask == nil || *r.Mask != expectedMask {
				got := uint32(0)
				if r.Mask != nil {
					got = *r.Mask
				}
				t.Errorf("Preserved rule mask = 0x%x, want 0x%x", got, expectedMask)
			}
			break
		}
	}
	if !found {
		t.Error("Expected active rule to be preserved after cleanup")
	}
}

// --- Purge ---

func TestPurge_RemovesAllManagedRules(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	// Add two nodes
	for i, name := range []string{"purge-node-1", "purge-node-2"} {
		idx := uint32(i + 9)
		routeTableID := state.RouteTableIDOff + idx
		fwMark := idx << state.FWMaskVal.Shift()
		state.NodeStates[name] = core.NodeState{
			Node:         core.Node{Name: name, IPv4: gwIP},
			IDAllocated:  true,
			ID:           idx,
			FWMark:       fwMark,
			RouteTableID: routeTableID,
		}
	}

	sc := core.NewStateChange()
	sc.NodesUpdated.Add("purge-node-1")
	sc.NodesUpdated.Add("purge-node-2")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify rules exist
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	if len(rules) < 2 {
		t.Fatalf("Expected at least 2 managed rules, got %d", len(rules))
	}

	// Purge should remove all managed rules
	if err := m.Purge(); err != nil {
		t.Fatalf("Purge failed: %v", err)
	}
	rules = listManagedRules(t, m, netlink.FAMILY_V4)
	if len(rules) != 0 {
		t.Errorf("Expected no managed rules after purge, got %d", len(rules))
	}
}

func TestPurge_IsIdempotent(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())

	// Purging with no rules should not error
	if err := m.Purge(); err != nil {
		t.Fatalf("First purge failed: %v", err)
	}
	if err := m.Purge(); err != nil {
		t.Fatalf("Second purge failed: %v", err)
	}
}

// --- Dual-stack ---

func TestReconcile_DualStackNode(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIPv4 := tn.GatewayIPv4
	gwIPv6 := tn.GatewayIPv6

	routeTableID := state.RouteTableIDOff + 11
	fwMark := uint32(11) << state.FWMaskVal.Shift()
	state.NodeStates["dual-node"] = core.NodeState{
		Node:         core.Node{Name: "dual-node", IPv4: gwIPv4, IPv6: gwIPv6},
		IDAllocated:  true,
		ID:           11,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}

	sc := core.NewStateChange()
	sc.NodesUpdated.Add("dual-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	expectedMask := uint32(state.FWMaskVal)

	// Verify IPv4
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	found := false
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			found = true
			if r.Mark != fwMark {
				t.Errorf("IPv4 rule mark = %d, want %d", r.Mark, fwMark)
			}
			if r.Mask == nil || *r.Mask != expectedMask {
				t.Errorf("IPv4 rule mask mismatch")
			}
			break
		}
	}
	if !found {
		t.Error("Expected IPv4 FW mark rule for dual-stack node")
	}

	routesV4 := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	hasDefault := false
	hasGW := false
	for _, r := range routesV4 {
		if r.Dst != nil && r.Dst.IP.Equal(net.IPv4zero) && bytes.Equal(r.Dst.Mask, net.CIDRMask(0, 32)) {
			hasDefault = true
			if !r.Gw.Equal(gwIPv4) {
				t.Errorf("IPv4 default route Gw = %v, want %v", r.Gw, gwIPv4)
			}
		}
		if r.Dst != nil && r.Dst.IP.Equal(gwIPv4) && bytes.Equal(r.Dst.Mask, net.CIDRMask(32, 32)) {
			hasGW = true
		}
	}
	if !hasDefault {
		t.Error("Expected IPv4 default route for dual-stack node")
	}
	if !hasGW {
		t.Error("Expected IPv4 gateway host route for dual-stack node")
	}

	// Verify IPv6
	rulesV6 := listManagedRules(t, m, netlink.FAMILY_V6)
	found = false
	for _, r := range rulesV6 {
		if r.Table == int(routeTableID) {
			found = true
			if r.Mark != fwMark {
				t.Errorf("IPv6 rule mark = %d, want %d", r.Mark, fwMark)
			}
			if r.Mask == nil || *r.Mask != expectedMask {
				t.Errorf("IPv6 rule mask mismatch")
			}
			break
		}
	}
	if !found {
		t.Error("Expected IPv6 FW mark rule for dual-stack node")
	}

	routesV6 := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V6)
	hasDefault = false
	hasGW = false
	for _, r := range routesV6 {
		if r.Dst != nil && r.Dst.IP.Equal(net.IPv6zero) && bytes.Equal(r.Dst.Mask, net.CIDRMask(0, 128)) {
			hasDefault = true
			if !r.Gw.Equal(gwIPv6) {
				t.Errorf("IPv6 default route Gw = %v, want %v", r.Gw, gwIPv6)
			}
		}
		if r.Dst != nil && r.Dst.IP.Equal(gwIPv6) && bytes.Equal(r.Dst.Mask, net.CIDRMask(128, 128)) {
			hasGW = true
		}
	}
	if !hasDefault {
		t.Error("Expected IPv6 default route for dual-stack node")
	}
	if !hasGW {
		t.Error("Expected IPv6 gateway host route for dual-stack node")
	}
}

// --- Duplicate / conflicting / stale cleanup ---

func TestReconcile_RemovesDuplicateRules(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4
	routeTableID := state.RouteTableIDOff + 12
	fwMark := uint32(12) << state.FWMaskVal.Shift()
	mask := uint32(state.FWMaskVal)

	// Manually insert two identical rules for the same table
	for i := 0; i < 2; i++ {
		rule := netlink.NewRule()
		rule.Mark = fwMark
		rule.Mask = &mask
		rule.Table = int(routeTableID)
		rule.Family = netlink.FAMILY_V4
		if err := netlink.RuleAdd(rule); err != nil {
			t.Fatalf("Failed to add duplicate rule %d: %v", i, err)
		}
	}

	// Reconcile should deduplicate, leaving exactly one
	state.NodeStates["dedup-node"] = core.NodeState{
		Node:         core.Node{Name: "dedup-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           12,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("dedup-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	count := 0
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			count++
		}
	}
	if count != 1 {
		t.Errorf("Expected exactly 1 rule after dedup, got %d", count)
	}
}

func TestReconcile_RemovesConflictingRule(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4
	routeTableID := state.RouteTableIDOff + 13
	correctMark := uint32(13) << state.FWMaskVal.Shift()
	wrongMark := uint32(99) << state.FWMaskVal.Shift()
	mask := uint32(state.FWMaskVal)

	// Insert a rule with the wrong mark
	rule := netlink.NewRule()
	rule.Mark = wrongMark
	rule.Mask = &mask
	rule.Table = int(routeTableID)
	rule.Family = netlink.FAMILY_V4
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatalf("Failed to add conflicting rule: %v", err)
	}

	state.NodeStates["conflict-node"] = core.NodeState{
		Node:         core.Node{Name: "conflict-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           13,
		FWMark:       correctMark,
		RouteTableID: routeTableID,
	}
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("conflict-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			if r.Mark != correctMark {
				t.Errorf("Expected rule mark %d, got %d (conflicting rule was not replaced)", correctMark, r.Mark)
			}
			return
		}
	}
	t.Error("Expected rule to exist after reconcile")
}

func TestReconcile_RemovesDuplicateDefaultRoute(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4
	routeTableID := state.RouteTableIDOff + 12
	fwMark := uint32(12) << state.FWMaskVal.Shift()

	// First, set up the node normally
	state.NodeStates["dup-route-node"] = core.NodeState{
		Node:         core.Node{Name: "dup-route-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           12,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("dup-route-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("First reconcile failed: %v", err)
	}

	// Manually append a second default route with a different priority to bypass
	// the kernel's "file exists" check while still creating a duplicate from
	// the manager's perspective (same dst, same gw).
	gwRoutes, _ := netlink.RouteGet(gwIP)
	if len(gwRoutes) == 0 {
		t.Fatal("No route to gateway")
	}
	dst := net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	dup := &netlink.Route{
		Dst:       &dst,
		Gw:        gwIP,
		LinkIndex: gwRoutes[0].LinkIndex,
		Table:     int(routeTableID),
		Family:    netlink.FAMILY_V4,
		Priority:  999,
	}
	if err := netlink.RouteAdd(dup); err != nil {
		t.Fatalf("Failed to add duplicate default route: %v", err)
	}

	// Reconcile again should remove the duplicate
	sc2 := core.NewStateChange()
	sc2.NodesUpdated.Add("dup-route-node")
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Second reconcile failed: %v", err)
	}

	routes := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	defaultCount := 0
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(net.IPv4zero) && bytes.Equal(r.Dst.Mask, net.CIDRMask(0, 32)) {
			defaultCount++
		}
	}
	if defaultCount != 1 {
		t.Errorf("Expected exactly 1 default route after dedup, got %d", defaultCount)
	}
}

func TestReconcile_RemovesConflictingDefaultRoute(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4
	wrongGW := net.ParseIP("192.168.249.3")
	routeTableID := state.RouteTableIDOff + 13
	fwMark := uint32(13) << state.FWMaskVal.Shift()

	// Pre-create routes with the wrong gateway
	gwRoutes, _ := netlink.RouteGet(gwIP)
	if len(gwRoutes) == 0 {
		t.Fatal("No route to gateway")
	}
	linkIndex := gwRoutes[0].LinkIndex

	gwDst := net.IPNet{IP: wrongGW, Mask: net.CIDRMask(32, 32)}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: &gwDst, LinkIndex: linkIndex,
		Table: int(routeTableID), Family: netlink.FAMILY_V4,
	}); err != nil {
		t.Fatalf("Failed to add wrong gw host route: %v", err)
	}
	defaultDst := net.IPNet{IP: net.IPv4zero, Mask: net.CIDRMask(0, 32)}
	if err := netlink.RouteAdd(&netlink.Route{
		Dst: &defaultDst, Gw: wrongGW, LinkIndex: linkIndex,
		Table: int(routeTableID), Family: netlink.FAMILY_V4,
	}); err != nil {
		t.Fatalf("Failed to add wrong default route: %v", err)
	}

	// Reconcile with the correct gateway should replace the wrong routes
	state.NodeStates["wrong-gw-node"] = core.NodeState{
		Node:         core.Node{Name: "wrong-gw-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           13,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("wrong-gw-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	routes := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(net.IPv4zero) && bytes.Equal(r.Dst.Mask, net.CIDRMask(0, 32)) {
			if !r.Gw.Equal(gwIP) {
				t.Errorf("Default route still points to wrong gw %v, want %v", r.Gw, gwIP)
			}
		}
	}
}

func TestReconcile_RemovesStaleRoutesFromTable(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4
	routeTableID := state.RouteTableIDOff + 14
	fwMark := uint32(14) << state.FWMaskVal.Shift()

	// First set up the node normally
	state.NodeStates["stale-route-node"] = core.NodeState{
		Node:         core.Node{Name: "stale-route-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           14,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("stale-route-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("First reconcile failed: %v", err)
	}

	// Manually add a stale route with an unrelated destination in the same table
	gwRoutes, _ := netlink.RouteGet(gwIP)
	if len(gwRoutes) == 0 {
		t.Fatal("No route to gateway")
	}
	staleDst := net.IPNet{IP: net.ParseIP("172.16.0.0"), Mask: net.CIDRMask(16, 32)}
	staleRoute := &netlink.Route{
		Dst:       &staleDst,
		LinkIndex: gwRoutes[0].LinkIndex,
		Table:     int(routeTableID),
		Family:    netlink.FAMILY_V4,
	}
	if err := netlink.RouteAdd(staleRoute); err != nil {
		t.Fatalf("Failed to add stale route: %v", err)
	}

	// Verify stale route exists
	routes := listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	foundStale := false
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(net.ParseIP("172.16.0.0")) {
			foundStale = true
			break
		}
	}
	if !foundStale {
		t.Fatal("Stale route was not created")
	}

	// Reconcile should remove the stale route
	sc2 := core.NewStateChange()
	sc2.NodesUpdated.Add("stale-route-node")
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Second reconcile failed: %v", err)
	}

	routes = listManagedRoutes(t, int(routeTableID), netlink.FAMILY_V4)
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(net.ParseIP("172.16.0.0")) {
			t.Error("Stale route was not removed by reconcile")
		}
	}

	// Verify legitimate routes still exist
	hasDefault := false
	hasGW := false
	for _, r := range routes {
		if r.Dst != nil && r.Dst.IP.Equal(net.IPv4zero) {
			hasDefault = true
		}
		if r.Dst != nil && r.Dst.IP.Equal(gwIP) {
			hasGW = true
		}
	}
	if !hasDefault {
		t.Error("Default route should still exist after stale removal")
	}
	if !hasGW {
		t.Error("Gateway host route should still exist after stale removal")
	}
}

// --- Unrelated rule safety guards ---

func TestReconcile_SkipsRulesOutsideManagedRange(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	// Create a rule that is outside the managed range
	// Managed range is [RouteTableIDOff, RouteTableIDOff + FWMask.Size() - 1]
	outsideTableID := int(state.RouteTableIDOff) - 1
	rule := netlink.NewRule()
	rule.Mark = 0xDEAD
	mask := uint32(0xFFFF)
	rule.Mask = &mask
	rule.Table = outsideTableID
	rule.Family = netlink.FAMILY_V4
	if err := netlink.RuleAdd(rule); err != nil {
		t.Fatalf("Failed to add outside-range rule: %v", err)
	}
	t.Cleanup(func() {
		netlink.RuleDel(rule)
	})

	// Set up a node inside the managed range and reconcile
	routeTableID := state.RouteTableIDOff + 15
	fwMark := uint32(15) << state.FWMaskVal.Shift()
	state.NodeStates["safe-node"] = core.NodeState{
		Node:         core.Node{Name: "safe-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           15,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("safe-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify the outside-range rule was NOT deleted
	allRules, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Fatalf("Failed to list rules: %v", err)
	}
	found := false
	for _, r := range allRules {
		if r.Table == outsideTableID && r.Mark == 0xDEAD {
			found = true
			break
		}
	}
	if !found {
		t.Error("Rule outside managed range was incorrectly deleted")
	}
}

func TestDeleteNode_SkipsRulesOutsideManagedRange(t *testing.T) {
	requireNetlinkTestsEnabled(t)
	tn := setupTestNet(t)
	state := mock.NewState()
	m := NewManager(state, logr.Discard())
	t.Cleanup(func() { cleanupRulesAndRoutes(t, m) })

	gwIP := tn.GatewayIPv4

	// Create a rule outside the managed range at the same table ID that
	// deleteNetlinkRule will target (by manipulating routeTableIDMin/Max)
	routeTableID := state.RouteTableIDOff + 15
	fwMark := uint32(15) << state.FWMaskVal.Shift()

	// First create a managed node + rule
	state.NodeStates["del-guard-node"] = core.NodeState{
		Node:         core.Node{Name: "del-guard-node", IPv4: gwIP},
		IDAllocated:  true,
		ID:           15,
		FWMark:       fwMark,
		RouteTableID: routeTableID,
	}
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("del-guard-node")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Verify rule exists
	rules := listManagedRules(t, m, netlink.FAMILY_V4)
	found := false
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("Expected rule to exist before deletion test")
	}

	// Delete the node and verify the rule is removed
	nodeState := state.NodeStates["del-guard-node"]
	delete(state.NodeStates, "del-guard-node")
	sc2 := core.NewStateChange()
	sc2.NodesDeleted["del-guard-node"] = nodeState
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Reconcile (delete) failed: %v", err)
	}

	rules = listManagedRules(t, m, netlink.FAMILY_V4)
	for _, r := range rules {
		if r.Table == int(routeTableID) {
			t.Error("Expected managed rule to be deleted")
			break
		}
	}
}
