package controller

import (
	"net"
	"testing"
	"time"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/mock"
	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/go-logr/logr"
)

func newTestReconciler(t *testing.T, nodeName string, managers ...core.Manager) *reconciler {
	t.Helper()

	config := &core.Config{
		NodeName:               nodeName,
		FWMask:                 utils.FWMask(0xF00000),
		RouteTableIDOffset:     100000,
		ReconciliationInterval: time.Hour, // effectively disabled in tests
	}

	state, err := core.NewState(config, logr.Discard())
	if err != nil {
		t.Fatalf("Failed to create state: %v", err)
	}

	return &reconciler{
		state:                  state,
		reconciliationInterval: config.ReconciliationInterval,
		managers:               managers,
		logger:                 logr.Discard(),
	}
}

// --- Basic reconciler tests ---

func TestReconciler_UpdateNode(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	err := r.UpdateNode(core.Node{Name: "node-a", IPv4: net.ParseIP("10.0.0.1")})
	if err != nil {
		t.Fatalf("UpdateNode failed: %v", err)
	}

	if len(mgr.ReconcileCalls) != 1 {
		t.Fatalf("Expected 1 Reconcile call, got %d", len(mgr.ReconcileCalls))
	}
}

func TestReconciler_DeleteNode(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Add then delete
	r.UpdateNode(core.Node{Name: "node-a", IPv4: net.ParseIP("10.0.0.1")})
	mgr.ReconcileCalls = nil

	err := r.DeleteNode("node-a")
	if err != nil {
		t.Fatalf("DeleteNode failed: %v", err)
	}

	if len(mgr.ReconcileCalls) != 1 {
		t.Fatalf("Expected 1 Reconcile call, got %d", len(mgr.ReconcileCalls))
	}
}

func TestReconciler_UpdateEgressRule(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	rule := core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}

	err := r.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("UpdateEgressRule failed: %v", err)
	}

	if len(mgr.ReconcileCalls) != 1 {
		t.Fatalf("Expected 1 Reconcile call, got %d", len(mgr.ReconcileCalls))
	}

	changes := mgr.ReconcileCalls[0]
	if !changes.EgressRulesUpdated.Contains("ns/svc1") {
		t.Error("Expected ns/svc1 in EgressRulesUpdated")
	}
}

func TestReconciler_DeleteEgressRule(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	rule := core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}

	r.UpdateEgressRule(rule)
	mgr.ReconcileCalls = nil

	err := r.DeleteEgressRule("ns/svc1")
	if err != nil {
		t.Fatalf("DeleteEgressRule failed: %v", err)
	}

	if len(mgr.ReconcileCalls) != 1 {
		t.Fatalf("Expected 1 Reconcile call, got %d", len(mgr.ReconcileCalls))
	}

	changes := mgr.ReconcileCalls[0]
	if _, ok := changes.EgressRulesDeleted["ns/svc1"]; !ok {
		t.Error("Expected ns/svc1 in EgressRulesDeleted")
	}
}

func TestReconciler_MultipleManagers(t *testing.T) {
	mgr1 := mock.NewManager("fw")
	mgr2 := mock.NewManager("route")
	r := newTestReconciler(t, "local-node", mgr1, mgr2)

	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	if len(mgr1.ReconcileCalls) != 1 {
		t.Errorf("Expected fw manager to receive 1 call, got %d", len(mgr1.ReconcileCalls))
	}
	if len(mgr2.ReconcileCalls) != 1 {
		t.Errorf("Expected route manager to receive 1 call, got %d", len(mgr2.ReconcileCalls))
	}
}

func TestReconciler_Purge(t *testing.T) {
	purged := false
	mgr := mock.NewManager("test")
	mgr.PurgeFunc = func() error { purged = true; return nil }

	r := newTestReconciler(t, "local-node", mgr)

	if err := r.Purge(); err != nil {
		t.Fatalf("Purge failed: %v", err)
	}
	if !purged {
		t.Error("Expected manager Purge to be called")
	}
}

// --- Integration: node + egress rule interaction ---

func TestIntegration_AddRuleThenNode_AllocatesID(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Add an egress rule pointing to a node not yet known
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	// Node not yet known → rule should be in state but no node ID allocated
	ruleState, ok := r.state.GetEgressRuleState("ns/svc1")
	if !ok {
		t.Fatal("Expected egress rule to be in state")
	}
	if ruleState.FWMark != 0 {
		t.Error("Expected FWMark to be 0 before node is known")
	}

	// Now add the gateway node
	mgr.ReconcileCalls = nil
	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")})

	// The node should get an ID allocated, and the rule should be marked for reconciliation
	nodeState, ok := r.state.GetNodeState("gw-node")
	if !ok {
		t.Fatal("Expected gw-node to be in state")
	}
	if !nodeState.IDAllocated {
		t.Error("Expected gw-node to have an ID allocated")
	}
	if nodeState.FWMark == 0 {
		t.Error("Expected gw-node to have a non-zero FWMark")
	}

	// Rule state should now reflect the node's info
	ruleState, _ = r.state.GetEgressRuleState("ns/svc1")
	if ruleState.FWMark == 0 {
		t.Error("Expected rule FWMark to be set after node is known")
	}
	if !ruleState.GWIPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected rule GWIPv4 to be 192.168.1.1, got %v", ruleState.GWIPv4)
	}

	// Managers should have been called with both node and rule changes
	if len(mgr.ReconcileCalls) != 1 {
		t.Fatalf("Expected 1 Reconcile call after UpdateNode, got %d", len(mgr.ReconcileCalls))
	}
	changes := mgr.ReconcileCalls[0]
	if !changes.NodesUpdated.Contains("gw-node") {
		t.Error("Expected gw-node in NodesUpdated")
	}
	if !changes.EgressRulesUpdated.Contains("ns/svc1") {
		t.Error("Expected ns/svc1 in EgressRulesUpdated")
	}
}

func TestIntegration_AddNodeThenRule_AllocatesID(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Add node first
	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")})

	// Node exists but no rules reference it → no ID allocated
	nodeState, _ := r.state.GetNodeState("gw-node")
	if nodeState.IDAllocated {
		t.Error("Expected no ID allocated when no rules reference the node")
	}

	// Add rule pointing to the node
	mgr.ReconcileCalls = nil
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	// Now the node should have an ID
	nodeState, _ = r.state.GetNodeState("gw-node")
	if !nodeState.IDAllocated {
		t.Error("Expected ID to be allocated after rule references node")
	}

	// Rule should have the node's info
	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	if ruleState.FWMark == 0 {
		t.Error("Expected rule FWMark to be set")
	}
	if !ruleState.GWIPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected rule GWIPv4 to be 192.168.1.1, got %v", ruleState.GWIPv4)
	}
}

func TestIntegration_DeleteRule_DeallocatesNodeID(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Setup: node + rule
	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	// Verify ID is allocated
	nodeState, _ := r.state.GetNodeState("gw-node")
	if !nodeState.IDAllocated {
		t.Fatal("Expected node ID to be allocated")
	}

	// Delete the rule
	mgr.ReconcileCalls = nil
	r.DeleteEgressRule("ns/svc1")

	// Node should lose its ID (no more rules reference it)
	nodeState, _ = r.state.GetNodeState("gw-node")
	if nodeState.IDAllocated {
		t.Error("Expected node ID to be deallocated after last rule removed")
	}
	if nodeState.FWMark != 0 {
		t.Error("Expected FWMark to be 0 after deallocation")
	}
}

func TestIntegration_MultipleRulesSameNode_KeepsID(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc2",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.2")},
		SNATIPv4:   net.ParseIP("5.6.7.8"),
	})

	nodeState, _ := r.state.GetNodeState("gw-node")
	if !nodeState.IDAllocated {
		t.Fatal("Expected node ID to be allocated")
	}
	fwMark := nodeState.FWMark

	// Delete first rule, node should still have ID (second rule still references it)
	r.DeleteEgressRule("ns/svc1")
	nodeState, _ = r.state.GetNodeState("gw-node")
	if !nodeState.IDAllocated {
		t.Error("Expected node ID to remain allocated with remaining rule")
	}
	if nodeState.FWMark != fwMark {
		t.Error("Expected FWMark to be unchanged")
	}

	// Delete second rule, node should lose its ID
	r.DeleteEgressRule("ns/svc2")
	nodeState, _ = r.state.GetNodeState("gw-node")
	if nodeState.IDAllocated {
		t.Error("Expected node ID to be deallocated after all rules removed")
	}
}

func TestIntegration_DeleteNode_WithRules(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	// Delete the node while rules still reference it
	mgr.ReconcileCalls = nil
	r.DeleteNode("gw-node")

	// Node should be gone
	_, exists := r.state.GetNodeState("gw-node")
	if exists {
		t.Error("Expected gw-node to be removed from state")
	}

	// Rule should still exist but with cleared GW info
	ruleState, ok := r.state.GetEgressRuleState("ns/svc1")
	if !ok {
		t.Fatal("Expected rule to still exist")
	}
	if ruleState.FWMark != 0 {
		t.Error("Expected FWMark to be 0 after node deletion")
	}

	// Manager should have been notified
	if len(mgr.ReconcileCalls) != 1 {
		t.Fatalf("Expected 1 Reconcile call, got %d", len(mgr.ReconcileCalls))
	}
	changes := mgr.ReconcileCalls[0]
	if !changes.EgressRulesUpdated.Contains("ns/svc1") {
		t.Error("Expected ns/svc1 in EgressRulesUpdated after node deletion")
	}
}

func TestIntegration_MoveRuleToNewGateway(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Setup: two nodes and a rule
	r.UpdateNode(core.Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateNode(core.Node{Name: "node-b", IPv4: net.ParseIP("192.168.1.2")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	// node-a should have ID, node-b should not
	nodeA, _ := r.state.GetNodeState("node-a")
	nodeB, _ := r.state.GetNodeState("node-b")
	if !nodeA.IDAllocated {
		t.Fatal("Expected node-a to have ID")
	}
	if nodeB.IDAllocated {
		t.Error("Expected node-b to have no ID")
	}

	// Move rule to node-b
	mgr.ReconcileCalls = nil
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "node-b",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	// node-a should lose ID, node-b should gain ID
	nodeA, _ = r.state.GetNodeState("node-a")
	nodeB, _ = r.state.GetNodeState("node-b")
	if nodeA.IDAllocated {
		t.Error("Expected node-a to lose ID after rule moved away")
	}
	if !nodeB.IDAllocated {
		t.Error("Expected node-b to gain ID after rule moved to it")
	}

	// Rule should point to node-b's IP
	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	if !ruleState.GWIPv4.Equal(net.ParseIP("192.168.1.2")) {
		t.Errorf("Expected rule GWIPv4 to be 192.168.1.2, got %v", ruleState.GWIPv4)
	}
}

func TestIntegration_MoveRuleToLocalNode_SNAT(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Setup: remote node and local node, rule on remote
	r.UpdateNode(core.Node{Name: "remote-node", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateNode(core.Node{Name: "local-node", IPv4: net.ParseIP("192.168.1.2")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "remote-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	mode := ruleState.GetMode("local-node", false)
	if mode != core.EgressRuleModeRedirect {
		t.Errorf("Expected Redirect mode, got %v", mode)
	}

	// Move rule to local node (should become SNAT mode)
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "local-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	ruleState, _ = r.state.GetEgressRuleState("ns/svc1")
	mode = ruleState.GetMode("local-node", false)
	if mode != core.EgressRuleModeSNAT {
		t.Errorf("Expected SNAT mode after moving to local node, got %v", mode)
	}
}

func TestIntegration_LocalNodeRule_NoIDAllocation(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Add the local node and a rule pointing to it
	r.UpdateNode(core.Node{Name: "local-node", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "local-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	// Local node rules use SNAT, no routing ID needed
	nodeState, _ := r.state.GetNodeState("local-node")
	if nodeState.IDAllocated {
		t.Error("Expected no ID to be allocated for local gateway node (SNAT, not routing)")
	}
}

func TestIntegration_NodeIPUpdate_PropagatesToRules(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	if !ruleState.GWIPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Fatal("Expected initial GW IP 192.168.1.1")
	}

	// Update node IP
	mgr.ReconcileCalls = nil
	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.2.1")})

	// Rule should reflect the new node IP
	ruleState, _ = r.state.GetEgressRuleState("ns/svc1")
	if !ruleState.GWIPv4.Equal(net.ParseIP("192.168.2.1")) {
		t.Errorf("Expected GW IP to update to 192.168.2.1, got %v", ruleState.GWIPv4)
	}

	// When a node IP changes but ID is already allocated, syncNodeId returns
	// added=false, so the node goes into NodesDeleted (not NodesUpdated)
	if len(mgr.ReconcileCalls) != 1 {
		t.Fatalf("Expected 1 Reconcile call, got %d", len(mgr.ReconcileCalls))
	}
	changes := mgr.ReconcileCalls[0]
	if _, ok := changes.NodesDeleted["gw-node"]; !ok {
		t.Error("Expected gw-node in NodesDeleted (node IP update with existing ID)")
	}
}

func TestIntegration_DualStack_Node(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	r.UpdateNode(core.Node{
		Name: "gw-node",
		IPv4: net.ParseIP("192.168.1.1"),
		IPv6: net.ParseIP("fd00::1"),
	})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SrcIPv6s:   []net.IP{net.ParseIP("fd00::100")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
		SNATIPv6:   net.ParseIP("2001:db8::1"),
	})

	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	if !ruleState.GWIPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected GWIPv4 192.168.1.1, got %v", ruleState.GWIPv4)
	}
	if !ruleState.GWIPv6.Equal(net.ParseIP("fd00::1")) {
		t.Errorf("Expected GWIPv6 fd00::1, got %v", ruleState.GWIPv6)
	}

	// Both IPv4 and IPv6 should be in redirect mode
	modeV4 := ruleState.GetMode("local-node", false)
	modeV6 := ruleState.GetMode("local-node", true)
	if modeV4 != core.EgressRuleModeRedirect {
		t.Errorf("Expected IPv4 Redirect mode, got %v", modeV4)
	}
	if modeV6 != core.EgressRuleModeRedirect {
		t.Errorf("Expected IPv6 Redirect mode, got %v", modeV6)
	}
}

func TestIntegration_FullLifecycle(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// 1. Add nodes
	r.UpdateNode(core.Node{Name: "local-node", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.2")})

	// 2. Add egress rule → redirect to gw-node
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	if ruleState.GetMode("local-node", false) != core.EgressRuleModeRedirect {
		t.Error("Expected redirect mode")
	}

	// 3. MetalLB failover: rule moves to local-node → SNAT mode
	mgr.ReconcileCalls = nil
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "local-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	ruleState, _ = r.state.GetEgressRuleState("ns/svc1")
	// Local node rules should be in SNAT mode, even if they have a GW IP (which is ignored in this case)
	if ruleState.GetMode("local-node", false) != core.EgressRuleModeSNAT {
		t.Error("Expected SNAT mode after failover to local node")
	}

	// gw-node should have lost its ID
	gwNode, _ := r.state.GetNodeState("gw-node")
	if gwNode.IDAllocated {
		t.Error("Expected gw-node to lose ID after rule moved away")
	}

	// 4. Add a second rule to the same gw
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc2",
		GWNodeName: "local-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.3")},
		SNATIPv4:   net.ParseIP("5.6.7.8"),
	})

	// 5. Delete first rule
	r.DeleteEgressRule("ns/svc1")

	// Second rule should still work
	rule2, ok := r.state.GetEgressRuleState("ns/svc2")
	if !ok {
		t.Fatal("Expected ns/svc2 to still exist")
	}
	if rule2.GetMode("local-node", false) != core.EgressRuleModeSNAT {
		t.Error("Expected ns/svc2 to still be in SNAT mode")
	}

	// 6. Delete second rule
	r.DeleteEgressRule("ns/svc2")

	// 7. Delete nodes
	r.DeleteNode("gw-node")
	r.DeleteNode("local-node")

	// State should be empty
	if len(r.state.GetEgressRuleStates()) != 0 {
		t.Error("Expected no egress rules in state")
	}
	if len(r.state.GetNodeStates()) != 0 {
		t.Error("Expected no nodes in state")
	}
}

func TestIntegration_RuleWithoutSNATIP_Unconfigured(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	r.UpdateNode(core.Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")})

	// Rule without SNAT IP → unconfigured mode
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		// No SNATIPv4
	})

	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	mode := ruleState.GetMode("local-node", false)
	if mode != core.EgressRuleModeUnconfigured {
		t.Errorf("Expected Unconfigured mode, got %v", mode)
	}
}

func TestIntegration_RuleBlockMode_NoGWIP(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Add rule pointing to a node that doesn't exist yet → block mode
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "unknown-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	ruleState, _ := r.state.GetEgressRuleState("ns/svc1")
	// No node → no GW IP, no FWMark → block mode
	mode := ruleState.GetMode("local-node", false)
	if mode != core.EgressRuleModeBlock {
		t.Errorf("Expected Block mode for unknown gateway, got %v", mode)
	}

	// Once the node appears, mode should change to redirect
	r.UpdateNode(core.Node{Name: "unknown-node", IPv4: net.ParseIP("192.168.1.1")})
	ruleState, _ = r.state.GetEgressRuleState("ns/svc1")
	mode = ruleState.GetMode("local-node", false)
	if mode != core.EgressRuleModeRedirect {
		t.Errorf("Expected Redirect mode after node appears, got %v", mode)
	}
}

func TestIntegration_IDReuse_AfterDeallocation(t *testing.T) {
	mgr := mock.NewManager("test")
	r := newTestReconciler(t, "local-node", mgr)

	// Allocate: node-a gets first ID
	r.UpdateNode(core.Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")})
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	})

	nodeA, _ := r.state.GetNodeState("node-a")
	firstID := nodeA.ID

	// Deallocate: remove the rule → node-a loses ID
	r.DeleteEgressRule("ns/svc1")
	nodeA, _ = r.state.GetNodeState("node-a")
	if nodeA.IDAllocated {
		t.Fatal("Expected node-a to lose ID")
	}

	// Re-allocate: new rule to node-a should get an ID again (possibly reused)
	r.UpdateEgressRule(core.EgressRule{
		ID:         "ns/svc2",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.2")},
		SNATIPv4:   net.ParseIP("5.6.7.8"),
	})

	nodeA, _ = r.state.GetNodeState("node-a")
	if !nodeA.IDAllocated {
		t.Fatal("Expected node-a to have ID reallocated")
	}
	// The ID should be reused since it was the only one freed
	if nodeA.ID != firstID {
		t.Errorf("Expected ID %d to be reused, got %d", firstID, nodeA.ID)
	}
}
