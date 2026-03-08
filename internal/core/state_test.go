package core

import (
	"fmt"
	"net"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/go-logr/logr"
)

func testConfig() *Config {
	return &Config{
		NodeName:           "local-node",
		FWMask:             utils.FWMask(0xF00000), // Size=16, Shift=20
		RouteTableIDOffset: 100000,
	}
}

func newTestState(t *testing.T) State {
	t.Helper()
	s, err := NewState(testConfig(), logr.Discard())
	if err != nil {
		t.Fatalf("NewState failed: %v", err)
	}
	return s
}

// --- NewState ---

func TestNewState_ValidConfig(t *testing.T) {
	s := newTestState(t)
	if s == nil {
		t.Fatal("Expected non-nil state")
	}
	if s.NodeName() != "local-node" {
		t.Errorf("Expected NodeName 'local-node', got %q", s.NodeName())
	}
	if s.FWMask() != utils.FWMask(0xF00000) {
		t.Errorf("Expected FWMask 0xF00000, got 0x%x", s.FWMask())
	}
	if s.RouteTableIDOffset() != 100000 {
		t.Errorf("Expected RouteTableIDOffset 100000, got %d", s.RouteTableIDOffset())
	}
}

func TestNewState_InvalidConfig(t *testing.T) {
	cfg := &Config{
		FWMask: utils.FWMask(0x1), // Size=2, but IsContinuous -> valid, Size()-1=1 => ok
	}
	// A mask with size <= 1 is invalid
	cfg.FWMask = utils.FWMask(0x0) // Size=0
	_, err := NewState(cfg, logr.Discard())
	if err == nil {
		t.Fatal("Expected error for invalid config")
	}
}

func TestNewState_NonContinuousMask(t *testing.T) {
	cfg := &Config{
		FWMask: utils.FWMask(0xA00000), // Non-continuous: 1010...
	}
	_, err := NewState(cfg, logr.Discard())
	if err == nil {
		t.Fatal("Expected error for non-continuous mask")
	}
}

// --- ExcludeDstCIDRs ---

func TestExcludeDstCIDRs(t *testing.T) {
	cfg := testConfig()
	_, cidr, _ := net.ParseCIDR("10.0.0.0/8")
	cfg.FWExcludeDstCIDRs = []net.IPNet{*cidr}

	s, err := NewState(cfg, logr.Discard())
	if err != nil {
		t.Fatalf("NewState failed: %v", err)
	}
	cidrs := s.ExcludeDstCIDRs()
	if len(cidrs) != 1 {
		t.Fatalf("Expected 1 CIDR, got %d", len(cidrs))
	}
	if cidrs[0].String() != "10.0.0.0/8" {
		t.Errorf("Expected 10.0.0.0/8, got %s", cidrs[0].String())
	}
}

// --- Egress Rule CRUD ---

func TestUpdateEgressRule_NewRule(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}

	sc, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("UpdateEgressRule failed: %v", err)
	}
	if !sc.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated")
	}

	// Verify rule was stored
	rs, ok := s.GetEgressRuleState("rule1")
	if !ok {
		t.Fatal("Expected to find rule1")
	}
	if rs.GWNodeName != "gw-node" {
		t.Errorf("Expected GWNodeName 'gw-node', got %q", rs.GWNodeName)
	}
}

func TestUpdateEgressRule_UnchangedRule(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}

	_, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("first UpdateEgressRule failed: %v", err)
	}

	// Update with the same data
	sc, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("second UpdateEgressRule failed: %v", err)
	}
	if !sc.IsEmpty() {
		t.Error("Expected empty state change for unchanged rule")
	}
}

func TestUpdateEgressRule_ModifyRule(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	_, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("first UpdateEgressRule failed: %v", err)
	}

	// Change SNAT IP
	rule.SNATIPv4 = net.ParseIP("5.6.7.8")
	sc, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("second UpdateEgressRule failed: %v", err)
	}
	if !sc.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated")
	}

	rs, _ := s.GetEgressRuleState("rule1")
	if !rs.SNATIPv4.Equal(net.ParseIP("5.6.7.8")) {
		t.Errorf("Expected SNATIPv4 5.6.7.8, got %v", rs.SNATIPv4)
	}
}

func TestUpdateEgressRule_ChangeGWNode(t *testing.T) {
	s := newTestState(t)

	// Add nodes so IDs can be allocated
	if _, err := s.UpdateNode(Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}); err != nil {
		t.Fatalf("UpdateNode node-a: %v", err)
	}
	if _, err := s.UpdateNode(Node{Name: "node-b", IPv4: net.ParseIP("192.168.1.2")}); err != nil {
		t.Fatalf("UpdateNode node-b: %v", err)
	}

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	_, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("first UpdateEgressRule failed: %v", err)
	}

	// Verify node-a got an ID
	nsA, _ := s.GetNodeState("node-a")
	if !nsA.IDAllocated {
		t.Fatal("Expected node-a to have ID allocated")
	}

	// Change gateway node
	rule.GWNodeName = "node-b"
	sc, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("second UpdateEgressRule failed: %v", err)
	}
	if !sc.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated")
	}
	// Old node should be deleted since no rules reference it
	if _, deleted := sc.NodesDeleted["node-a"]; !deleted {
		t.Error("Expected node-a in NodesDeleted")
	}
	// New node should get an ID allocated
	if !sc.NodesUpdated.Contains("node-b") {
		t.Error("Expected node-b in NodesUpdated")
	}

	// Verify node-a ID was deallocated
	nsA, _ = s.GetNodeState("node-a")
	if nsA.IDAllocated {
		t.Error("Expected node-a to have ID deallocated")
	}

	// Verify node-b got an ID
	nsB, _ := s.GetNodeState("node-b")
	if !nsB.IDAllocated {
		t.Error("Expected node-b to have ID allocated")
	}
}

func TestUpdateEgressRule_ChangeGWNode_OldNodeStillReferenced(t *testing.T) {
	s := newTestState(t)

	// Two rules using node-a
	rule1 := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	rule2 := EgressRule{
		ID:         "rule2",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.2")},
		SNATIPv4:   net.ParseIP("1.2.3.5"),
	}
	if _, err := s.UpdateEgressRule(rule1); err != nil {
		t.Fatalf("UpdateEgressRule rule1: %v", err)
	}
	if _, err := s.UpdateEgressRule(rule2); err != nil {
		t.Fatalf("UpdateEgressRule rule2: %v", err)
	}

	// Move rule1 to node-b; node-a still has rule2
	rule1.GWNodeName = "node-b"
	sc, err := s.UpdateEgressRule(rule1)
	if err != nil {
		t.Fatalf("UpdateEgressRule rule1 (move): %v", err)
	}
	if _, deleted := sc.NodesDeleted["node-a"]; deleted {
		t.Error("node-a should NOT be deleted since rule2 still uses it")
	}
}

func TestDeleteEgressRule_Existing(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule failed: %v", err)
	}

	sc, err := s.DeleteEgressRule("rule1")
	if err != nil {
		t.Fatalf("DeleteEgressRule failed: %v", err)
	}
	if _, exists := sc.EgressRulesDeleted["rule1"]; !exists {
		t.Error("Expected rule1 in EgressRulesDeleted")
	}

	// Verify rule was removed
	_, ok := s.GetEgressRuleState("rule1")
	if ok {
		t.Error("Expected rule1 to be deleted")
	}
}

func TestDeleteEgressRule_NonExisting(t *testing.T) {
	s := newTestState(t)

	sc, err := s.DeleteEgressRule("nonexistent")
	if err != nil {
		t.Fatalf("DeleteEgressRule failed: %v", err)
	}
	if !sc.IsEmpty() {
		t.Error("Expected empty state change for non-existing rule")
	}
}

func TestDeleteEgressRule_FreesNodeId(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule failed: %v", err)
	}

	// Add a node for gw-node
	node := Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode failed: %v", err)
	}

	// Delete the rule — gw-node should be cleaned up
	sc, err := s.DeleteEgressRule("rule1")
	if err != nil {
		t.Fatalf("DeleteEgressRule failed: %v", err)
	}
	if _, deleted := sc.NodesDeleted["gw-node"]; !deleted {
		t.Error("Expected gw-node in NodesDeleted")
	}
}

func TestDeleteEgressRule_NodeStillUsedByOtherRule(t *testing.T) {
	s := newTestState(t)

	rule1 := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	rule2 := EgressRule{
		ID:         "rule2",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.2")},
		SNATIPv4:   net.ParseIP("1.2.3.5"),
	}
	if _, err := s.UpdateEgressRule(rule1); err != nil {
		t.Fatalf("UpdateEgressRule rule1: %v", err)
	}
	if _, err := s.UpdateEgressRule(rule2); err != nil {
		t.Fatalf("UpdateEgressRule rule2: %v", err)
	}

	sc, err := s.DeleteEgressRule("rule1")
	if err != nil {
		t.Fatalf("DeleteEgressRule rule1: %v", err)
	}
	if _, deleted := sc.NodesDeleted["gw-node"]; deleted {
		t.Error("gw-node should NOT be deleted since rule2 still uses it")
	}
}

// --- GetEgressRuleStates ---

func TestGetEgressRuleStates_Empty(t *testing.T) {
	s := newTestState(t)
	rules := s.GetEgressRuleStates()
	if len(rules) != 0 {
		t.Errorf("Expected 0 rules, got %d", len(rules))
	}
}

func TestGetEgressRuleStates_Multiple(t *testing.T) {
	s := newTestState(t)

	for _, id := range []string{"rule1", "rule2", "rule3"} {
		rule := EgressRule{
			ID:         id,
			GWNodeName: "gw-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		}
		if _, err := s.UpdateEgressRule(rule); err != nil {
			t.Fatalf("UpdateEgressRule %s: %v", id, err)
		}
	}

	rules := s.GetEgressRuleStates()
	if len(rules) != 3 {
		t.Errorf("Expected 3 rules, got %d", len(rules))
	}
}

func TestGetEgressRuleStates_FillsNodeInfo(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}

	node := Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1"), IPv6: net.ParseIP("fd00::1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	rules := s.GetEgressRuleStates()
	if len(rules) != 1 {
		t.Fatalf("Expected 1 rule, got %d", len(rules))
	}
	if !rules[0].GWIPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected GWIPv4 192.168.1.1, got %v", rules[0].GWIPv4)
	}
	if !rules[0].GWIPv6.Equal(net.ParseIP("fd00::1")) {
		t.Errorf("Expected GWIPv6 fd00::1, got %v", rules[0].GWIPv6)
	}
	if rules[0].FWMark == 0 {
		t.Error("Expected non-zero FWMark")
	}
}

func TestGetEgressRuleState_NotFound(t *testing.T) {
	s := newTestState(t)
	_, ok := s.GetEgressRuleState("nonexistent")
	if ok {
		t.Error("Expected false for nonexistent rule")
	}
}

func TestGetEgressRuleState_FillsNodeInfo(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}

	node := Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	rs, ok := s.GetEgressRuleState("rule1")
	if !ok {
		t.Fatal("Expected to find rule1")
	}
	if !rs.GWIPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected GWIPv4 192.168.1.1, got %v", rs.GWIPv4)
	}
}

// --- Node CRUD ---

func TestUpdateNode_New(t *testing.T) {
	s := newTestState(t)

	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	sc, err := s.UpdateNode(node)
	if err != nil {
		t.Fatalf("UpdateNode failed: %v", err)
	}

	// Without egress rules referencing this node, the node should be "deleted" (no ID allocated)
	if _, deleted := sc.NodesDeleted["node-a"]; !deleted {
		t.Error("Expected node-a in NodesDeleted when no egress rules reference it")
	}

	ns, ok := s.GetNodeState("node-a")
	if !ok {
		t.Fatal("Expected to find node-a")
	}
	if !ns.IPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected IPv4 192.168.1.1, got %v", ns.IPv4)
	}
}

func TestUpdateNode_WithEgressRuleReference(t *testing.T) {
	s := newTestState(t)

	// First add an egress rule pointing to node-a
	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}

	// Now add the node
	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	sc, err := s.UpdateNode(node)
	if err != nil {
		t.Fatalf("UpdateNode failed: %v", err)
	}

	if !sc.NodesUpdated.Contains("node-a") {
		t.Error("Expected node-a in NodesUpdated")
	}
	// The egress rule should also be marked for update
	if !sc.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated")
	}

	ns, ok := s.GetNodeState("node-a")
	if !ok {
		t.Fatal("Expected to find node-a")
	}
	if !ns.IDAllocated {
		t.Error("Expected node-a to have ID allocated")
	}
	if ns.FWMark == 0 {
		t.Error("Expected non-zero FWMark")
	}
	if ns.RouteTableID == 0 {
		t.Error("Expected non-zero RouteTableID")
	}
}

func TestUpdateNode_Unchanged(t *testing.T) {
	s := newTestState(t)

	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("first UpdateNode: %v", err)
	}

	sc, err := s.UpdateNode(node)
	if err != nil {
		t.Fatalf("second UpdateNode: %v", err)
	}
	if !sc.IsEmpty() {
		t.Error("Expected empty state change for unchanged node")
	}
}

func TestUpdateNode_ModifyIP(t *testing.T) {
	s := newTestState(t)

	// Add rule first so node gets an ID
	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}

	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("first UpdateNode: %v", err)
	}

	// Change IP
	node.IPv4 = net.ParseIP("192.168.1.2")
	sc, err := s.UpdateNode(node)
	if err != nil {
		t.Fatalf("second UpdateNode: %v", err)
	}
	if sc.IsEmpty() {
		t.Error("Expected non-empty state change when IP changes")
	}
}

func TestDeleteNode_Existing(t *testing.T) {
	s := newTestState(t)

	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	sc, err := s.DeleteNode("node-a")
	if err != nil {
		t.Fatalf("DeleteNode failed: %v", err)
	}
	if _, deleted := sc.NodesDeleted["node-a"]; !deleted {
		t.Error("Expected node-a in NodesDeleted")
	}

	_, ok := s.GetNodeState("node-a")
	if ok {
		t.Error("Expected node-a to be deleted")
	}
}

func TestDeleteNode_NonExisting(t *testing.T) {
	s := newTestState(t)

	sc, err := s.DeleteNode("nonexistent")
	if err != nil {
		t.Fatalf("DeleteNode failed: %v", err)
	}
	if !sc.IsEmpty() {
		t.Error("Expected empty state change for non-existing node")
	}
}

func TestDeleteNode_WithEgressRules(t *testing.T) {
	s := newTestState(t)

	// Add rule pointing to node-a
	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}

	// Add the node
	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	// Delete the node — egress rules using it should be marked for update
	sc, err := s.DeleteNode("node-a")
	if err != nil {
		t.Fatalf("DeleteNode failed: %v", err)
	}
	if _, deleted := sc.NodesDeleted["node-a"]; !deleted {
		t.Error("Expected node-a in NodesDeleted")
	}
	if !sc.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated after node deletion")
	}

	// Node should be removed from state
	_, ok := s.GetNodeState("node-a")
	if ok {
		t.Error("Expected node-a to be removed from state")
	}

	// Egress rule still exists but now has no node info
	rs, ok := s.GetEgressRuleState("rule1")
	if !ok {
		t.Fatal("Expected rule1 to still exist")
	}
	if rs.GWIPv4 != nil {
		t.Error("Expected nil GWIPv4 after node deletion")
	}
}

// --- GetNodeStates ---

func TestGetNodeStates_Empty(t *testing.T) {
	s := newTestState(t)
	nodes := s.GetNodeStates()
	if len(nodes) != 0 {
		t.Errorf("Expected 0 nodes, got %d", len(nodes))
	}
}

func TestGetNodeStates_Multiple(t *testing.T) {
	s := newTestState(t)

	for _, name := range []string{"node-a", "node-b", "node-c"} {
		node := Node{Name: name, IPv4: net.ParseIP("192.168.1.1")}
		if _, err := s.UpdateNode(node); err != nil {
			t.Fatalf("UpdateNode %s: %v", name, err)
		}
	}

	nodes := s.GetNodeStates()
	if len(nodes) != 3 {
		t.Errorf("Expected 3 nodes, got %d", len(nodes))
	}
}

func TestGetNodeState_NotFound(t *testing.T) {
	s := newTestState(t)
	_, ok := s.GetNodeState("nonexistent")
	if ok {
		t.Error("Expected false for nonexistent node")
	}
}

// --- ID allocation / FW Mark ---

func TestNodeIDAllocation_FWMarkAndRouteTableID(t *testing.T) {
	s := newTestState(t)

	// Add rule first so the node gets an ID
	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}

	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	ns, ok := s.GetNodeState("node-a")
	if !ok {
		t.Fatal("Expected to find node-a")
	}

	// ID should be 0 (first allocation)
	if ns.ID != 0 {
		t.Errorf("Expected ID 0, got %d", ns.ID)
	}

	// FWMark = (ID + 1) << Shift = (0 + 1) << 20 = 1048576 = 0x100000
	expectedFWMark := uint32(1) << 20
	if ns.FWMark != expectedFWMark {
		t.Errorf("Expected FWMark %d (0x%x), got %d (0x%x)", expectedFWMark, expectedFWMark, ns.FWMark, ns.FWMark)
	}

	// RouteTableID = offset + ID = 100000 + 0 = 100000
	if ns.RouteTableID != 100000 {
		t.Errorf("Expected RouteTableID 100000, got %d", ns.RouteTableID)
	}
}

func TestNodeIDAllocation_MultipleNodes(t *testing.T) {
	s := newTestState(t)

	// Add two rules for two different nodes
	rule1 := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	rule2 := EgressRule{
		ID:         "rule2",
		GWNodeName: "node-b",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.2")},
		SNATIPv4:   net.ParseIP("1.2.3.5"),
	}
	if _, err := s.UpdateEgressRule(rule1); err != nil {
		t.Fatalf("UpdateEgressRule rule1: %v", err)
	}
	if _, err := s.UpdateEgressRule(rule2); err != nil {
		t.Fatalf("UpdateEgressRule rule2: %v", err)
	}

	nodeA := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	nodeB := Node{Name: "node-b", IPv4: net.ParseIP("192.168.1.2")}
	if _, err := s.UpdateNode(nodeA); err != nil {
		t.Fatalf("UpdateNode node-a: %v", err)
	}
	if _, err := s.UpdateNode(nodeB); err != nil {
		t.Fatalf("UpdateNode node-b: %v", err)
	}

	nsA, _ := s.GetNodeState("node-a")
	nsB, _ := s.GetNodeState("node-b")

	if nsA.ID == nsB.ID {
		t.Error("Expected different IDs for different nodes")
	}
	if nsA.FWMark == nsB.FWMark {
		t.Error("Expected different FWMarks for different nodes")
	}
	if nsA.RouteTableID == nsB.RouteTableID {
		t.Error("Expected different RouteTableIDs for different nodes")
	}
}

func TestNodeIDDeallocation_AfterRuleDeletion(t *testing.T) {
	s := newTestState(t)

	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "node-a",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}
	node := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	// Verify node has ID
	ns, _ := s.GetNodeState("node-a")
	if !ns.IDAllocated {
		t.Fatal("Expected node-a to have ID allocated")
	}

	// Delete the rule
	if _, err := s.DeleteEgressRule("rule1"); err != nil {
		t.Fatalf("DeleteEgressRule: %v", err)
	}

	// Node should still exist but ID should be deallocated
	ns, ok := s.GetNodeState("node-a")
	if !ok {
		t.Fatal("Expected node-a to still exist")
	}
	if ns.IDAllocated {
		t.Error("Expected node-a ID to be deallocated")
	}
	if ns.FWMark != 0 {
		t.Errorf("Expected FWMark 0, got %d", ns.FWMark)
	}
	if ns.RouteTableID != 0 {
		t.Errorf("Expected RouteTableID 0, got %d", ns.RouteTableID)
	}
}

func TestNodeIDReuse_AfterDeallocation(t *testing.T) {
	s := newTestState(t)

	// Add two rules for two nodes
	rule1 := EgressRule{ID: "rule1", GWNodeName: "node-a", SrcIPv4s: []net.IP{net.ParseIP("10.0.0.1")}, SNATIPv4: net.ParseIP("1.2.3.4")}
	rule2 := EgressRule{ID: "rule2", GWNodeName: "node-b", SrcIPv4s: []net.IP{net.ParseIP("10.0.0.2")}, SNATIPv4: net.ParseIP("1.2.3.5")}
	if _, err := s.UpdateEgressRule(rule1); err != nil {
		t.Fatalf("UpdateEgressRule rule1: %v", err)
	}
	if _, err := s.UpdateEgressRule(rule2); err != nil {
		t.Fatalf("UpdateEgressRule rule2: %v", err)
	}
	if _, err := s.UpdateNode(Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1")}); err != nil {
		t.Fatalf("UpdateNode node-a: %v", err)
	}
	if _, err := s.UpdateNode(Node{Name: "node-b", IPv4: net.ParseIP("192.168.1.2")}); err != nil {
		t.Fatalf("UpdateNode node-b: %v", err)
	}

	nsA, _ := s.GetNodeState("node-a")
	oldIdA := nsA.ID

	// Delete rule1 to free node-a's ID
	if _, err := s.DeleteEgressRule("rule1"); err != nil {
		t.Fatalf("DeleteEgressRule: %v", err)
	}

	// Add a new rule pointing to node-c
	rule3 := EgressRule{ID: "rule3", GWNodeName: "node-c", SrcIPv4s: []net.IP{net.ParseIP("10.0.0.3")}, SNATIPv4: net.ParseIP("1.2.3.6")}
	if _, err := s.UpdateEgressRule(rule3); err != nil {
		t.Fatalf("UpdateEgressRule rule3: %v", err)
	}
	if _, err := s.UpdateNode(Node{Name: "node-c", IPv4: net.ParseIP("192.168.1.3")}); err != nil {
		t.Fatalf("UpdateNode node-c: %v", err)
	}

	nsC, _ := s.GetNodeState("node-c")
	// node-c should reuse the freed ID
	if nsC.ID != oldIdA {
		t.Errorf("Expected node-c to reuse ID %d, got %d", oldIdA, nsC.ID)
	}
}

// --- SNAT-only rules should NOT count as node references ---

func TestSNATOnlyRule_DoesNotAllocateNodeID(t *testing.T) {
	s := newTestState(t)

	// A rule where GWNodeName == local node name and both SNAT IPs are set
	// means GetMode returns EgressRuleModeSNAT for both IPv4 and IPv6.
	// syncNodeId filters out these pure-SNAT rules.
	rule := EgressRule{
		ID:         "snat-rule",
		GWNodeName: "local-node", // same as state's NodeName
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SrcIPv6s:   []net.IP{net.ParseIP("fd00::1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
		SNATIPv6:   net.ParseIP("2001:db8::1"),
	}
	if _, err := s.UpdateEgressRule(rule); err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}

	// Add the node
	node := Node{Name: "local-node", IPv4: net.ParseIP("192.168.1.1"), IPv6: net.ParseIP("fd00::99")}
	sc, err := s.UpdateNode(node)
	if err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	// Node should NOT have an ID allocated since the only rule is SNAT-only
	ns, _ := s.GetNodeState("local-node")
	if ns.IDAllocated {
		t.Error("Expected no ID allocation for SNAT-only rule")
	}

	// Node should be in NodesDeleted (because no ID was allocated)
	if _, deleted := sc.NodesDeleted["local-node"]; !deleted {
		t.Error("Expected local-node in NodesDeleted since SNAT-only rules don't count")
	}
}

// --- EgressRule with node added first, then rule ---

func TestAddEgressRule_NodeAlreadyExists(t *testing.T) {
	s := newTestState(t)

	// Add node first
	node := Node{Name: "gw-node", IPv4: net.ParseIP("192.168.1.1")}
	if _, err := s.UpdateNode(node); err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}

	// Now add a rule pointing to that node
	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "gw-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	sc, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}
	if !sc.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated")
	}
	// Node should get an ID now
	if !sc.NodesUpdated.Contains("gw-node") {
		t.Error("Expected gw-node in NodesUpdated")
	}

	ns, _ := s.GetNodeState("gw-node")
	if !ns.IDAllocated {
		t.Error("Expected gw-node to have ID allocated")
	}
}

// --- StateChange helpers ---

func TestStateChange_IsEmpty(t *testing.T) {
	sc := NewStateChange()
	if !sc.IsEmpty() {
		t.Error("Expected new StateChange to be empty")
	}

	sc.EgressRulesUpdated.Add("rule1")
	if sc.IsEmpty() {
		t.Error("Expected StateChange with updated rule to not be empty")
	}
}

func TestStateChange_HasEgressRuleChanges(t *testing.T) {
	sc := NewStateChange()
	if sc.HasEgressRuleChanges() {
		t.Error("Expected no egress rule changes")
	}

	sc.EgressRulesUpdated.Add("rule1")
	if !sc.HasEgressRuleChanges() {
		t.Error("Expected egress rule changes")
	}

	sc2 := NewStateChange()
	sc2.EgressRulesDeleted["rule1"] = EgressRuleState{}
	if !sc2.HasEgressRuleChanges() {
		t.Error("Expected egress rule changes from deletion")
	}
}

func TestStateChange_HasNodeChanges(t *testing.T) {
	sc := NewStateChange()
	if sc.HasNodeChanges() {
		t.Error("Expected no node changes")
	}

	sc.NodesUpdated.Add("node-a")
	if !sc.HasNodeChanges() {
		t.Error("Expected node changes from update")
	}

	sc2 := NewStateChange()
	sc2.NodesDeleted["node-a"] = NodeState{}
	if !sc2.HasNodeChanges() {
		t.Error("Expected node changes from deletion")
	}
}

// --- Integration-style scenarios ---

func TestScenario_FullLifecycle(t *testing.T) {
	s := newTestState(t)

	// 1. Add nodes
	nodeA := Node{Name: "node-a", IPv4: net.ParseIP("192.168.1.1"), IPv6: net.ParseIP("fd00::1")}
	nodeB := Node{Name: "node-b", IPv4: net.ParseIP("192.168.1.2"), IPv6: net.ParseIP("fd00::2")}
	if _, err := s.UpdateNode(nodeA); err != nil {
		t.Fatalf("UpdateNode node-a: %v", err)
	}
	if _, err := s.UpdateNode(nodeB); err != nil {
		t.Fatalf("UpdateNode node-b: %v", err)
	}

	// 2. Add egress rules
	rule1 := EgressRule{ID: "svc/rule1", GWNodeName: "node-a", SrcIPv4s: []net.IP{net.ParseIP("10.0.0.1")}, SNATIPv4: net.ParseIP("1.2.3.4")}
	rule2 := EgressRule{ID: "svc/rule2", GWNodeName: "node-b", SrcIPv4s: []net.IP{net.ParseIP("10.0.0.2")}, SNATIPv4: net.ParseIP("5.6.7.8")}

	sc1, err := s.UpdateEgressRule(rule1)
	if err != nil {
		t.Fatalf("UpdateEgressRule rule1: %v", err)
	}
	if !sc1.EgressRulesUpdated.Contains("svc/rule1") {
		t.Error("Expected svc/rule1 in EgressRulesUpdated")
	}

	sc2, err := s.UpdateEgressRule(rule2)
	if err != nil {
		t.Fatalf("UpdateEgressRule rule2: %v", err)
	}
	if !sc2.EgressRulesUpdated.Contains("svc/rule2") {
		t.Error("Expected svc/rule2 in EgressRulesUpdated")
	}

	// 3. Verify state
	rules := s.GetEgressRuleStates()
	if len(rules) != 2 {
		t.Errorf("Expected 2 egress rules, got %d", len(rules))
	}

	nsA, _ := s.GetNodeState("node-a")
	nsB, _ := s.GetNodeState("node-b")
	if !nsA.IDAllocated || !nsB.IDAllocated {
		t.Error("Expected both nodes to have IDs allocated")
	}

	// 4. Move rule1 to node-b
	rule1.GWNodeName = "node-b"
	sc3, err := s.UpdateEgressRule(rule1)
	if err != nil {
		t.Fatalf("UpdateEgressRule rule1 (move): %v", err)
	}
	if !sc3.EgressRulesUpdated.Contains("svc/rule1") {
		t.Error("Expected svc/rule1 in EgressRulesUpdated after move")
	}
	// node-a should lose its ID since no rules reference it
	if _, deleted := sc3.NodesDeleted["node-a"]; !deleted {
		t.Error("Expected node-a in NodesDeleted after moving last rule away")
	}

	nsA, _ = s.GetNodeState("node-a")
	if nsA.IDAllocated {
		t.Error("Expected node-a to have ID deallocated after move")
	}

	// 5. Delete rule2
	sc4, err := s.DeleteEgressRule("svc/rule2")
	if err != nil {
		t.Fatalf("DeleteEgressRule rule2: %v", err)
	}
	if _, deleted := sc4.EgressRulesDeleted["svc/rule2"]; !deleted {
		t.Error("Expected svc/rule2 in EgressRulesDeleted")
	}

	// 6. Delete rule1 — node-b should lose its ID
	sc5, err := s.DeleteEgressRule("svc/rule1")
	if err != nil {
		t.Fatalf("DeleteEgressRule rule1: %v", err)
	}
	if _, deleted := sc5.NodesDeleted["node-b"]; !deleted {
		t.Error("Expected node-b in NodesDeleted after deleting last rule")
	}

	// 7. Final state should be empty of egress rules
	finalRules := s.GetEgressRuleStates()
	if len(finalRules) != 0 {
		t.Errorf("Expected 0 egress rules, got %d", len(finalRules))
	}
}

func TestScenario_RuleBeforeNode(t *testing.T) {
	s := newTestState(t)

	// Add a rule before the node exists
	rule := EgressRule{
		ID:         "rule1",
		GWNodeName: "future-node",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	sc1, err := s.UpdateEgressRule(rule)
	if err != nil {
		t.Fatalf("UpdateEgressRule: %v", err)
	}
	if !sc1.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated")
	}

	// Rule state should exist but have no GW IP filled in
	rs, ok := s.GetEgressRuleState("rule1")
	if !ok {
		t.Fatal("Expected to find rule1")
	}
	if rs.GWIPv4 != nil {
		t.Error("Expected nil GWIPv4 before node is added")
	}

	// Now add the node
	node := Node{Name: "future-node", IPv4: net.ParseIP("192.168.1.1")}
	sc2, err := s.UpdateNode(node)
	if err != nil {
		t.Fatalf("UpdateNode: %v", err)
	}
	if !sc2.NodesUpdated.Contains("future-node") {
		t.Error("Expected future-node in NodesUpdated")
	}
	if !sc2.EgressRulesUpdated.Contains("rule1") {
		t.Error("Expected rule1 in EgressRulesUpdated after node added")
	}

	// Now rule should have GW info
	rs, _ = s.GetEgressRuleState("rule1")
	if !rs.GWIPv4.Equal(net.ParseIP("192.168.1.1")) {
		t.Errorf("Expected GWIPv4 192.168.1.1, got %v", rs.GWIPv4)
	}
}

func TestScenario_ManyRulesExhaustPool(t *testing.T) {
	cfg := &Config{
		NodeName:           "local-node",
		FWMask:             utils.FWMask(0x300000), // Size=4, usable=3
		RouteTableIDOffset: 100000,
	}
	s, err := NewState(cfg, logr.Discard())
	if err != nil {
		t.Fatalf("NewState: %v", err)
	}

	// Add nodes first so IDs get allocated when rules are added
	for i := 0; i < 4; i++ {
		node := Node{Name: fmt.Sprintf("node-%d", i), IPv4: net.ParseIP(fmt.Sprintf("192.168.1.%d", i+1))}
		if _, err := s.UpdateNode(node); err != nil {
			t.Fatalf("UpdateNode node-%d: %v", i, err)
		}
	}

	// Allocate 3 rules pointing to 3 different nodes (fills the pool)
	for i := 0; i < 3; i++ {
		rule := EgressRule{
			ID:         fmt.Sprintf("rule%d", i),
			GWNodeName: fmt.Sprintf("node-%d", i),
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		}
		if _, err := s.UpdateEgressRule(rule); err != nil {
			t.Fatalf("UpdateEgressRule rule%d: %v", i, err)
		}
	}

	// The 4th rule to a new node should fail (pool exhausted)
	rule := EgressRule{
		ID:         "rule3",
		GWNodeName: "node-3",
		SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
		SNATIPv4:   net.ParseIP("1.2.3.4"),
	}
	_, err = s.UpdateEgressRule(rule)
	if err == nil {
		t.Error("Expected pool exhaustion error")
	}
}
