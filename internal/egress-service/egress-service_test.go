package egress_service

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	fm "github.com/gerolf-vent/metaleg/internal/firewall-manager"
	rm "github.com/gerolf-vent/metaleg/internal/route-manager"
)

// Mock FirewallManager for testing
type mockFirewallManager struct {
	setupErr          error
	cleanupErr        error
	reconcileErr      error
	cleanupStaleErr   error
	setupCalls        int
	cleanupCalls      int
	reconcileCalls    []mockReconcileCall
	cleanupStaleCalls []map[string]*fm.EgressRule
}

type mockReconcileCall struct {
	rule    *fm.EgressRule
	present bool
}

func (m *mockFirewallManager) Setup() error {
	m.setupCalls++
	return m.setupErr
}

func (m *mockFirewallManager) Cleanup() error {
	m.cleanupCalls++
	return m.cleanupErr
}

func (m *mockFirewallManager) ReconcileEgressRule(rule *fm.EgressRule, present bool) error {
	if m.reconcileCalls == nil {
		m.reconcileCalls = []mockReconcileCall{}
	}
	m.reconcileCalls = append(m.reconcileCalls, mockReconcileCall{rule: rule, present: present})
	return m.reconcileErr
}

func (m *mockFirewallManager) CleanupStaleEgressRules(rules map[string]*fm.EgressRule) error {
	if m.cleanupStaleCalls == nil {
		m.cleanupStaleCalls = []map[string]*fm.EgressRule{}
	}
	m.cleanupStaleCalls = append(m.cleanupStaleCalls, rules)
	return m.cleanupStaleErr
}

// Mock RouteManager for testing
type mockRouteManager struct {
	setupErr               error
	cleanupErr             error
	reconcileErr           error
	cleanupNodeRoutesErr   error
	setupCalls             int
	cleanupCalls           int
	reconcileCalls         []mockNodeReconcileCall
	cleanupNodeRoutesCalls []map[string]*rm.NodeRoute
}

type mockNodeReconcileCall struct {
	route   *rm.NodeRoute
	present bool
}

func (m *mockRouteManager) Setup() error {
	m.setupCalls++
	return m.setupErr
}

func (m *mockRouteManager) Cleanup() error {
	m.cleanupCalls++
	return m.cleanupErr
}

func (m *mockRouteManager) ReconcileNodeRoute(route *rm.NodeRoute, present bool) error {
	if m.reconcileCalls == nil {
		m.reconcileCalls = []mockNodeReconcileCall{}
	}
	m.reconcileCalls = append(m.reconcileCalls, mockNodeReconcileCall{route: route, present: present})
	return m.reconcileErr
}

func (m *mockRouteManager) CleanupStaleNodeRoutes(routes map[string]*rm.NodeRoute) error {
	if m.cleanupNodeRoutesCalls == nil {
		m.cleanupNodeRoutesCalls = []map[string]*rm.NodeRoute{}
	}
	m.cleanupNodeRoutesCalls = append(m.cleanupNodeRoutesCalls, routes)
	return m.cleanupNodeRoutesErr
}

func createTestEgressService() (*EgressService, *mockFirewallManager, *mockRouteManager) {
	mockFW := &mockFirewallManager{}
	mockRM := &mockRouteManager{}

	es, _ := New("test-node", 100*time.Millisecond, mockFW, mockRM)
	return es, mockFW, mockRM
}

func TestNew(t *testing.T) {
	mockFW := &mockFirewallManager{}
	mockRM := &mockRouteManager{}

	es, err := New("test-node", 5*time.Second, mockFW, mockRM)

	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if es.nodeName != "test-node" {
		t.Errorf("expected node name 'test-node', got %v", es.nodeName)
	}
	if es.reconciliationInterval != 5*time.Second {
		t.Errorf("expected reconciliation interval 5s, got %v", es.reconciliationInterval)
	}
	if es.firewallManager != mockFW {
		t.Error("expected firewall manager to be set")
	}
	if es.routeManager != mockRM {
		t.Error("expected route manager to be set")
	}
	if es.rules == nil {
		t.Error("expected rules map to be initialized")
	}
	if es.nodes == nil {
		t.Error("expected nodes map to be initialized")
	}
	if es.isReady {
		t.Error("expected service to not be ready initially")
	}
}

func TestEgressService_IsReady(t *testing.T) {
	es, _, _ := createTestEgressService()

	// Initially not ready
	if es.IsReady() {
		t.Error("expected service to not be ready initially")
	}

	// Mark as ready
	es.isReady = true
	if !es.IsReady() {
		t.Error("expected service to be ready after marking")
	}
}

func TestEgressService_UpdateEgressRule(t *testing.T) {
	t.Run("creates new egress rule", func(t *testing.T) {
		es, mockFW, mockRM := createTestEgressService()

		lbIPv4 := net.ParseIP("192.168.1.100")
		lbIPv6 := net.ParseIP("2001:db8::100")
		srcIPv4 := []net.IP{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.2")}
		srcIPv6 := []net.IP{net.ParseIP("2001:db8::1"), net.ParseIP("2001:db8::2")}

		// Add a node route first
		nodeIPv4 := net.ParseIP("192.168.1.10")
		nodeIPv6 := net.ParseIP("2001:db8::10")
		err := es.UpdateNodeRoute("gateway-node", nodeIPv4, nodeIPv6)
		if err != nil {
			t.Fatalf("failed to add node route: %v", err)
		}

		err = es.UpdateEgressRule("test-rule", lbIPv4, lbIPv6, srcIPv4, srcIPv6, "gateway-node")

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify rule was created
		rule, exists := es.rules["test-rule"]
		if !exists {
			t.Fatal("expected rule to be created")
		}
		if rule.ID != "test-rule" {
			t.Errorf("expected rule ID 'test-rule', got %v", rule.ID)
		}
		if !rule.SNATIPv4.Equal(lbIPv4) {
			t.Errorf("expected SNAT IPv4 %v, got %v", lbIPv4, rule.SNATIPv4)
		}
		if !rule.SNATIPv6.Equal(lbIPv6) {
			t.Errorf("expected SNAT IPv6 %v, got %v", lbIPv6, rule.SNATIPv6)
		}
		if rule.GWNodeName != "gateway-node" {
			t.Errorf("expected gateway node 'gateway-node', got %v", rule.GWNodeName)
		}
		if rule.GWRoute == nil {
			t.Error("expected gateway route to be set")
		}

		// Verify node route rule count was incremented
		nodeRoute := es.nodes["gateway-node"]
		if nodeRoute.RuleCount != 1 {
			t.Errorf("expected node route rule count 1, got %d", nodeRoute.RuleCount)
		}

		// Verify reconciliation was called
		if len(mockRM.reconcileCalls) != 2 { // One for node creation, one for rule addition
			t.Errorf("expected 2 route manager reconcile calls, got %d", len(mockRM.reconcileCalls))
		}
		if len(mockFW.reconcileCalls) != 1 {
			t.Errorf("expected 1 firewall manager reconcile call, got %d", len(mockFW.reconcileCalls))
		}
		if !mockFW.reconcileCalls[0].present {
			t.Error("expected firewall reconcile to be called with present=true")
		}
	})

	t.Run("updates existing egress rule", func(t *testing.T) {
		es, mockFW, mockRM := createTestEgressService()

		// Create initial rule
		lbIPv4 := net.ParseIP("192.168.1.100")
		srcIPv4 := []net.IP{net.ParseIP("10.0.1.1")}

		// Add node routes
		es.UpdateNodeRoute("gateway-node-1", net.ParseIP("192.168.1.10"), nil)
		es.UpdateNodeRoute("gateway-node-2", net.ParseIP("192.168.1.20"), nil)

		es.UpdateEgressRule("test-rule", lbIPv4, nil, srcIPv4, nil, "gateway-node-1")

		// Reset mock call counts
		mockFW.reconcileCalls = nil
		mockRM.reconcileCalls = nil

		// Update the rule with new values
		newLbIPv4 := net.ParseIP("192.168.1.200")
		newSrcIPv4 := []net.IP{net.ParseIP("10.0.1.1"), net.ParseIP("10.0.1.3")}

		err := es.UpdateEgressRule("test-rule", newLbIPv4, nil, newSrcIPv4, nil, "gateway-node-2")

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify rule was updated
		rule := es.rules["test-rule"]
		if !rule.SNATIPv4.Equal(newLbIPv4) {
			t.Errorf("expected updated SNAT IPv4 %v, got %v", newLbIPv4, rule.SNATIPv4)
		}
		if len(rule.SrcIPv4s) != 2 {
			t.Errorf("expected 2 source IPs, got %d", len(rule.SrcIPv4s))
		}
		if rule.GWNodeName != "gateway-node-2" {
			t.Errorf("expected gateway node 'gateway-node-2', got %v", rule.GWNodeName)
		}
		// After bug fix, rule.GWRoute should now point to gateway-node-2
		if rule.GWRoute == nil || rule.GWRoute.Name != "gateway-node-2" {
			t.Errorf("expected gateway route to be gateway-node-2, got %v",
				func() string {
					if rule.GWRoute == nil {
						return "nil"
					}
					return rule.GWRoute.Name
				}())
		}

		// Verify node route counts
		node1 := es.nodes["gateway-node-1"]
		node2 := es.nodes["gateway-node-2"]
		if node1.RuleCount != 0 {
			t.Errorf("expected node1 rule count 0, got %d", node1.RuleCount)
		}
		// After bug fix, node2 count should be incremented correctly
		if node2.RuleCount != 1 {
			t.Errorf("expected node2 rule count 1, got %d", node2.RuleCount)
		}

		// Verify reconciliation calls - after bug fix, both nodes should be reconciled
		if len(mockRM.reconcileCalls) != 2 {
			t.Errorf("expected 2 route manager reconcile calls, got %d", len(mockRM.reconcileCalls))
		}
		if len(mockFW.reconcileCalls) != 1 {
			t.Errorf("expected 1 firewall manager reconcile call, got %d", len(mockFW.reconcileCalls))
		}
	})

	t.Run("returns error for empty rule ID", func(t *testing.T) {
		es, _, _ := createTestEgressService()

		err := es.UpdateEgressRule("", net.ParseIP("192.168.1.100"), nil, nil, nil, "gateway-node")

		if err == nil {
			t.Error("expected error for empty rule ID")
		}
		if err.Error() != "egress rule ID must not empty" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})

	t.Run("handles firewall manager error", func(t *testing.T) {
		es, mockFW, _ := createTestEgressService()
		mockFW.reconcileErr = errors.New("firewall reconcile error")

		es.UpdateNodeRoute("gateway-node", net.ParseIP("192.168.1.10"), nil)
		err := es.UpdateEgressRule("test-rule", net.ParseIP("192.168.1.100"), nil, nil, nil, "gateway-node")

		if err == nil {
			t.Error("expected error from firewall manager")
		}
		if err.Error() != "firewall reconcile error" {
			t.Errorf("expected firewall error, got %v", err)
		}
	})

	t.Run("handles route manager error", func(t *testing.T) {
		es, _, mockRM := createTestEgressService()
		mockRM.reconcileErr = errors.New("route reconcile error")

		es.UpdateNodeRoute("gateway-node", net.ParseIP("192.168.1.10"), nil)
		// Reset error for rule update
		mockRM.reconcileErr = nil

		// Set error again for the reconcile call during rule update
		mockRM.reconcileErr = errors.New("route reconcile error")
		err := es.UpdateEgressRule("test-rule", net.ParseIP("192.168.1.100"), nil, nil, nil, "gateway-node")

		if err == nil {
			t.Error("expected error from route manager")
		}
		if err.Error() != "route reconcile error" {
			t.Errorf("expected route error, got %v", err)
		}
	})
}

func TestEgressService_DeleteEgressRule(t *testing.T) {
	t.Run("deletes existing egress rule", func(t *testing.T) {
		es, mockFW, mockRM := createTestEgressService()

		// Create a rule first
		es.UpdateNodeRoute("gateway-node", net.ParseIP("192.168.1.10"), nil)
		es.UpdateEgressRule("test-rule", net.ParseIP("192.168.1.100"), nil, nil, nil, "gateway-node")

		// Reset mock calls
		mockFW.reconcileCalls = nil
		mockRM.reconcileCalls = nil

		err := es.DeleteEgressRule("test-rule")

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify rule was deleted
		if _, exists := es.rules["test-rule"]; exists {
			t.Error("expected rule to be deleted")
		}

		// Verify node route count was decremented
		nodeRoute := es.nodes["gateway-node"]
		if nodeRoute.RuleCount != 0 {
			t.Errorf("expected node route rule count 0, got %d", nodeRoute.RuleCount)
		}

		// Verify reconciliation was called
		if len(mockRM.reconcileCalls) != 1 {
			t.Errorf("expected 1 route manager reconcile call, got %d", len(mockRM.reconcileCalls))
		}
		if len(mockFW.reconcileCalls) != 1 {
			t.Errorf("expected 1 firewall manager reconcile call, got %d", len(mockFW.reconcileCalls))
		}
		if mockFW.reconcileCalls[0].present {
			t.Error("expected firewall reconcile to be called with present=false")
		}
	})

	t.Run("handles non-existent rule gracefully", func(t *testing.T) {
		es, mockFW, _ := createTestEgressService()

		err := es.DeleteEgressRule("non-existent-rule")

		if err != nil {
			t.Errorf("expected no error for non-existent rule, got %v", err)
		}

		// Verify cleanup was called
		if len(mockFW.cleanupStaleCalls) != 1 {
			t.Errorf("expected 1 cleanup stale call, got %d", len(mockFW.cleanupStaleCalls))
		}
	})

	t.Run("returns error for empty rule ID", func(t *testing.T) {
		es, _, _ := createTestEgressService()

		err := es.DeleteEgressRule("")

		if err == nil {
			t.Error("expected error for empty rule ID")
		}
		if err.Error() != "egress rule ID must not empty" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})
}

func TestEgressService_UpdateNodeRoute(t *testing.T) {
	t.Run("creates new node route", func(t *testing.T) {
		es, _, mockRM := createTestEgressService()

		nodeIPv4 := net.ParseIP("192.168.1.10")
		nodeIPv6 := net.ParseIP("2001:db8::10")

		err := es.UpdateNodeRoute("remote-node", nodeIPv4, nodeIPv6)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify node was created
		node, exists := es.nodes["remote-node"]
		if !exists {
			t.Fatal("expected node to be created")
		}
		if !node.IPv4.Equal(nodeIPv4) {
			t.Errorf("expected node IPv4 %v, got %v", nodeIPv4, node.IPv4)
		}
		if !node.IPv6.Equal(nodeIPv6) {
			t.Errorf("expected node IPv6 %v, got %v", nodeIPv6, node.IPv6)
		}
		if node.Name != "remote-node" {
			t.Errorf("expected node name 'remote-node', got %v", node.Name)
		}

		// Verify reconciliation was called
		if len(mockRM.reconcileCalls) != 1 {
			t.Errorf("expected 1 route manager reconcile call, got %d", len(mockRM.reconcileCalls))
		}
		if !mockRM.reconcileCalls[0].present {
			t.Error("expected route reconcile to be called with present=true")
		}
	})

	t.Run("updates existing node route", func(t *testing.T) {
		es, _, mockRM := createTestEgressService()

		// Create initial node
		es.UpdateNodeRoute("remote-node", net.ParseIP("192.168.1.10"), nil)

		// Reset mock calls
		mockRM.reconcileCalls = nil

		// Update the node
		newIPv4 := net.ParseIP("192.168.1.20")
		newIPv6 := net.ParseIP("2001:db8::20")

		err := es.UpdateNodeRoute("remote-node", newIPv4, newIPv6)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify node was updated
		node := es.nodes["remote-node"]
		if !node.IPv4.Equal(newIPv4) {
			t.Errorf("expected updated IPv4 %v, got %v", newIPv4, node.IPv4)
		}
		if !node.IPv6.Equal(newIPv6) {
			t.Errorf("expected updated IPv6 %v, got %v", newIPv6, node.IPv6)
		}

		// Verify reconciliation was called
		if len(mockRM.reconcileCalls) != 1 {
			t.Errorf("expected 1 route manager reconcile call, got %d", len(mockRM.reconcileCalls))
		}
	})

	t.Run("ignores local node updates", func(t *testing.T) {
		es, _, mockRM := createTestEgressService()

		err := es.UpdateNodeRoute("test-node", net.ParseIP("192.168.1.10"), nil) // test-node is the local node

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify no node was created
		if len(es.nodes) != 0 {
			t.Errorf("expected no nodes to be created, got %d", len(es.nodes))
		}

		// Verify no reconciliation was called
		if len(mockRM.reconcileCalls) != 0 {
			t.Errorf("expected 0 route manager reconcile calls, got %d", len(mockRM.reconcileCalls))
		}
	})

	t.Run("links existing rules to new node", func(t *testing.T) {
		es, mockFW, mockRM := createTestEgressService()

		// Create a rule with a gateway node that doesn't exist yet
		es.UpdateEgressRule("test-rule", net.ParseIP("192.168.1.100"), nil, nil, nil, "gateway-node")

		// Reset mock calls
		mockFW.reconcileCalls = nil
		mockRM.reconcileCalls = nil

		// Add the gateway node
		err := es.UpdateNodeRoute("gateway-node", net.ParseIP("192.168.1.10"), nil)

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify rule is now linked to the node
		rule := es.rules["test-rule"]
		if rule.GWRoute == nil {
			t.Error("expected rule to be linked to gateway route")
		}

		// Verify node route count
		node := es.nodes["gateway-node"]
		if node.RuleCount != 1 {
			t.Errorf("expected node rule count 1, got %d", node.RuleCount)
		}

		// Verify both route and firewall reconciliation were called
		if len(mockRM.reconcileCalls) != 1 {
			t.Errorf("expected 1 route manager reconcile call, got %d", len(mockRM.reconcileCalls))
		}
		if len(mockFW.reconcileCalls) != 1 {
			t.Errorf("expected 1 firewall manager reconcile call, got %d", len(mockFW.reconcileCalls))
		}
	})

	t.Run("returns error for empty node name", func(t *testing.T) {
		es, _, _ := createTestEgressService()

		err := es.UpdateNodeRoute("", net.ParseIP("192.168.1.10"), nil)

		if err == nil {
			t.Error("expected error for empty node name")
		}
		if err.Error() != "node name must not empty" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})
}

func TestEgressService_DeleteNodeRoute(t *testing.T) {
	t.Run("deletes existing node route", func(t *testing.T) {
		es, mockFW, mockRM := createTestEgressService()

		// Create node and rule
		es.UpdateNodeRoute("gateway-node", net.ParseIP("192.168.1.10"), nil)
		es.UpdateEgressRule("test-rule", net.ParseIP("192.168.1.100"), nil, nil, nil, "gateway-node")

		// Reset mock calls
		mockFW.reconcileCalls = nil
		mockRM.reconcileCalls = nil

		err := es.DeleteNodeRoute("gateway-node")

		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}

		// Verify node was deleted
		if _, exists := es.nodes["gateway-node"]; exists {
			t.Error("expected node to be deleted")
		}

		// Verify rule's gateway route was cleared
		rule := es.rules["test-rule"]
		if rule.GWRoute != nil {
			t.Error("expected rule's gateway route to be cleared")
		}

		// Verify reconciliation was called
		if len(mockFW.reconcileCalls) != 1 {
			t.Errorf("expected 1 firewall manager reconcile call, got %d", len(mockFW.reconcileCalls))
		}
		if len(mockRM.reconcileCalls) != 1 {
			t.Errorf("expected 1 route manager reconcile call, got %d", len(mockRM.reconcileCalls))
		}
		if mockRM.reconcileCalls[0].present {
			t.Error("expected route reconcile to be called with present=false")
		}
	})

	t.Run("handles non-existent node gracefully", func(t *testing.T) {
		es, _, mockRM := createTestEgressService()

		err := es.DeleteNodeRoute("non-existent-node")

		if err != nil {
			t.Errorf("expected no error for non-existent node, got %v", err)
		}

		// Verify cleanup was called
		if len(mockRM.cleanupNodeRoutesCalls) != 1 {
			t.Errorf("expected 1 cleanup node routes call, got %d", len(mockRM.cleanupNodeRoutesCalls))
		}
	})

	t.Run("returns error for empty node name", func(t *testing.T) {
		es, _, _ := createTestEgressService()

		err := es.DeleteNodeRoute("")

		if err == nil {
			t.Error("expected error for empty node name")
		}
		if err.Error() != "node name must not empty" {
			t.Errorf("expected specific error message, got %v", err)
		}
	})
}

func TestEgressService_RealWorldScenario(t *testing.T) {
	t.Run("complete service lifecycle", func(t *testing.T) {
		es, _, _ := createTestEgressService()

		// Start service
		ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
		defer cancel()

		go es.Start(ctx)

		// Wait for service to be ready
		time.Sleep(50 * time.Millisecond)

		if !es.IsReady() {
			t.Fatal("service should be ready")
		}

		// Add gateway nodes
		err := es.UpdateNodeRoute("gateway-1", net.ParseIP("10.0.1.10"), net.ParseIP("2001:db8::10"))
		if err != nil {
			t.Fatalf("failed to add gateway-1: %v", err)
		}

		err = es.UpdateNodeRoute("gateway-2", net.ParseIP("10.0.1.20"), net.ParseIP("2001:db8::20"))
		if err != nil {
			t.Fatalf("failed to add gateway-2: %v", err)
		}

		// Create egress rules
		err = es.UpdateEgressRule("service-a",
			net.ParseIP("192.168.100.10"), net.ParseIP("2001:db8:100::10"),
			[]net.IP{net.ParseIP("10.244.1.10")}, []net.IP{net.ParseIP("2001:db8:244::10")},
			"gateway-1")
		if err != nil {
			t.Fatalf("failed to create service-a rule: %v", err)
		}

		err = es.UpdateEgressRule("service-b",
			net.ParseIP("192.168.100.20"), net.ParseIP("2001:db8:100::20"),
			[]net.IP{net.ParseIP("10.244.1.20"), net.ParseIP("10.244.1.21")}, []net.IP{net.ParseIP("2001:db8:244::20")},
			"gateway-2")
		if err != nil {
			t.Fatalf("failed to create service-b rule: %v", err)
		}

		// Verify state
		if len(es.rules) != 2 {
			t.Errorf("expected 2 rules, got %d", len(es.rules))
		}
		if len(es.nodes) != 2 {
			t.Errorf("expected 2 nodes, got %d", len(es.nodes))
		}

		// Verify node rule counts
		if es.nodes["gateway-1"].RuleCount != 1 {
			t.Errorf("expected gateway-1 rule count 1, got %d", es.nodes["gateway-1"].RuleCount)
		}
		if es.nodes["gateway-2"].RuleCount != 1 {
			t.Errorf("expected gateway-2 rule count 1, got %d", es.nodes["gateway-2"].RuleCount)
		}

		// Update service-a to use gateway-2 (should move rule)
		err = es.UpdateEgressRule("service-a",
			net.ParseIP("192.168.100.10"), net.ParseIP("2001:db8:100::10"),
			[]net.IP{net.ParseIP("10.244.1.10")}, []net.IP{net.ParseIP("2001:db8:244::10")},
			"gateway-2")
		if err != nil {
			t.Fatalf("failed to update service-a rule: %v", err)
		}

		// Verify rule counts after move
		if es.nodes["gateway-1"].RuleCount != 0 {
			t.Errorf("expected gateway-1 rule count 0, got %d", es.nodes["gateway-1"].RuleCount)
		}
		if es.nodes["gateway-2"].RuleCount != 2 {
			t.Errorf("expected gateway-2 rule count 2, got %d", es.nodes["gateway-2"].RuleCount)
		}

		// Delete service-a
		err = es.DeleteEgressRule("service-a")
		if err != nil {
			t.Fatalf("failed to delete service-a: %v", err)
		}

		// Verify deletion
		if len(es.rules) != 1 {
			t.Errorf("expected 1 rule after deletion, got %d", len(es.rules))
		}
		if es.nodes["gateway-2"].RuleCount != 1 {
			t.Errorf("expected gateway-2 rule count 1 after deletion, got %d", es.nodes["gateway-2"].RuleCount)
		}

		// Delete gateway-2 (should unlink remaining rule)
		err = es.DeleteNodeRoute("gateway-2")
		if err != nil {
			t.Fatalf("failed to delete gateway-2: %v", err)
		}

		// Verify gateway deletion
		if len(es.nodes) != 1 { // gateway-1 should still exist
			t.Errorf("expected 1 node after gateway-2 deletion, got %d", len(es.nodes))
		}

		serviceB := es.rules["service-b"]
		if serviceB.GWRoute != nil {
			t.Error("expected service-b gateway route to be cleared")
		}
	})
}
