package core

import (
	"fmt"
	"net"
	"sync"

	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/go-logr/logr"
)

type State interface {
	NodeName() string
	FWMask() utils.FWMask
	RouteTableIDOffset() uint32
	ExcludeDstCIDRs() []net.IPNet

	GetEgressRuleStates() []EgressRuleState
	GetEgressRuleState(id string) (EgressRuleState, bool)
	UpdateEgressRule(rule EgressRule) (StateChange, error)
	DeleteEgressRule(id string) (StateChange, error)
	GetNodeStates() []NodeState
	GetNodeState(name string) (NodeState, bool)
	UpdateNode(node Node) (StateChange, error)
	DeleteNode(name string) (StateChange, error)
}

type state struct {
	egressRuleStates map[string]EgressRuleState
	nodeStates       map[string]NodeState

	nodeName           string       // Name of the node
	fwMask             utils.FWMask // Firewall mask for egress rules
	fwExcludeDstCIDRs  []net.IPNet  // CIDRs to exclude from egress routing
	routeTableIDOffset uint32       // Offset for route table IDs
	idAllocator        *utils.IDRangeAllocator

	logger logr.Logger
	mu     sync.RWMutex
}

func NewState(config *Config, logger logr.Logger) (State, error) {
	if err := config.Validate(); err != nil {
		return nil, fmt.Errorf("invalid egress state config: %w", err)
	}

	return &state{
		egressRuleStates: make(map[string]EgressRuleState),
		nodeStates:       make(map[string]NodeState),

		nodeName:           config.NodeName,
		fwMask:             config.FWMask,
		fwExcludeDstCIDRs:  config.FWExcludeDstCIDRs,
		routeTableIDOffset: config.RouteTableIDOffset,
		// We can't use the first element (0) in the range, because a fw mask with that
		// value would cause all traffic to be matched, so we start allocating from 1
		// and the id allocator must be created with a size reduced by 1
		idAllocator: utils.NewIDRangeAllocator(config.FWMask.Size() - 1),

		logger: logger.WithName("State"),
	}, nil
}

func (s *state) NodeName() string {
	return s.nodeName
}

func (s *state) FWMask() utils.FWMask {
	return s.fwMask
}

func (s *state) RouteTableIDOffset() uint32 {
	return s.routeTableIDOffset
}

func (s *state) ExcludeDstCIDRs() []net.IPNet {
	return s.fwExcludeDstCIDRs
}

func (s *state) GetEgressRuleStates() []EgressRuleState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.logger.V(3).Info("GetEgressRuleStates called", "count", len(s.egressRuleStates))

	rules := make([]EgressRuleState, 0, len(s.egressRuleStates))
	for _, rule := range s.egressRuleStates {
		// Fill in the gw info and fw mark from the node state
		nodeState, _ := s.nodeStates[rule.GWNodeName]
		rule = rule.WithNodeState(nodeState)

		rules = append(rules, rule)
	}

	return rules
}

func (s *state) GetEgressRuleState(id string) (EgressRuleState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	state, exists := s.egressRuleStates[id]
	if !exists {
		s.logger.V(3).Info("GetEgressRuleState: not found", "id", id)
		return EgressRuleState{}, false
	}

	s.logger.V(3).Info("GetEgressRuleState: found", "id", id, "gwNodeName", state.GWNodeName)

	// Fill in the gw info and fw mark from the node state
	nodeState, _ := s.nodeStates[state.GWNodeName]
	state = state.WithNodeState(nodeState)

	return state, true
}

func (s *state) UpdateEgressRule(rule EgressRule) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.V(2).Info("UpdateEgressRule called", "id", rule.ID, "gwNodeName", rule.GWNodeName)

	stateChange := NewStateChange()

	existingState, exists := s.egressRuleStates[rule.ID]
	if exists && existingState.Equals(&rule) {
		s.logger.V(2).Info("Egress rule unchanged", "id", rule.ID)
		return stateChange, nil
	}

	// Allocate lazy Id for possible node Id assignment
	// This is done beforehand to not apply any changes if allocation fails
	lazyIdConsumed := false
	lazyId, err := s.idAllocator.Allocate()
	if err != nil {
		return stateChange, err
	}
	defer func() {
		if !lazyIdConsumed {
			s.idAllocator.Release(uint(lazyId))
		}
	}()

	// Update the egress rule
	existingState.EgressRule = rule
	s.egressRuleStates[rule.ID] = existingState
	stateChange.EgressRulesUpdated.Add(rule.ID)

	s.logger.V(2).Info("Egress rule updated in state", "id", rule.ID, "gwNodeName", rule.GWNodeName, "existed", exists)

	// If the gw node name changed, we need to sync the old node Id assignment
	if exists && existingState.GWNodeName != rule.GWNodeName {
		s.logger.V(2).Info("Egress rule changing gateway node", "id", rule.ID, "oldGwNode", existingState.GWNodeName, "newGwNode", rule.GWNodeName)

		// Changing the gw node name might cause the node to have no egress rules attached
		// anymore. The lazyId is -1 here, because this should NEVER allocate a new Id, only
		// possibly free an existing one.
		_, removed := s.syncNodeId(existingState.GWNodeName, -1)

		// If this was the last rule using the node, the rule must be reconciled
		// to remove the route
		if removed {
			s.logger.V(2).Info("Old gateway node removed after GW change", "nodeName", existingState.GWNodeName)

			nodeState, nodeExists := s.nodeStates[existingState.GWNodeName]
			if nodeExists {
				stateChange.NodesDeleted[existingState.GWNodeName] = nodeState
			} else {
				stateChange.NodesDeleted[existingState.GWNodeName] = NodeState{
					Node: Node{
						Name: existingState.GWNodeName,
					},
				}
			}
		}
	}

	// Ensure that the current gw node has an Id assigned
	lazyIdConsumed, _ = s.syncNodeId(rule.GWNodeName, int64(lazyId))
	// If a node id was allocated, this is the first rule using this node,
	// so the rule must be reconciled to add the route
	if lazyIdConsumed {
		s.logger.V(2).Info("Gateway node now has allocated ID", "nodeName", rule.GWNodeName)
		stateChange.NodesUpdated.Add(rule.GWNodeName)
	}

	s.logger.V(2).Info("UpdateEgressRule completed", "id", rule.ID, "stateChange", stateChange)

	return stateChange, nil
}

func (s *state) DeleteEgressRule(id string) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.V(2).Info("DeleteEgressRule called", "id", id)

	stateChange := NewStateChange()

	existingRule, exists := s.egressRuleStates[id]
	if exists {
		s.logger.V(2).Info("Deleting egress rule from state", "id", id, "gwNodeName", existingRule.GWNodeName)
		delete(s.egressRuleStates, id)
		stateChange.EgressRulesDeleted[id] = existingRule

		// Deleting an egress rule might free up a node Id. The lazyId is -1 here,
		// because this should NEVER allocate a new Id, only possibly free an existing one.
		_, removed := s.syncNodeId(existingRule.GWNodeName, -1)

		// If this was the last rule using the existing node, the rule must
		// be reconciled to remove the route
		if removed {
			s.logger.V(2).Info("Gateway node removed after deleting last egress rule", "nodeName", existingRule.GWNodeName)

			nodeState, nodeExists := s.nodeStates[existingRule.GWNodeName]
			if nodeExists {
				stateChange.NodesDeleted[existingRule.GWNodeName] = nodeState
			} else {
				stateChange.NodesDeleted[existingRule.GWNodeName] = NodeState{
					Node: Node{
						Name: existingRule.GWNodeName,
					},
				}
			}
		}
	} else {
		s.logger.V(2).Info("DeleteEgressRule: rule not found", "id", id)
	}

	s.logger.V(2).Info("DeleteEgressRule completed", "id", id, "stateChange", stateChange)

	return stateChange, nil
}

func (s *state) GetNodeStates() []NodeState {
	s.mu.RLock()
	defer s.mu.RUnlock()

	s.logger.V(3).Info("GetNodeStates called", "count", len(s.nodeStates))

	nodes := make([]NodeState, 0, len(s.nodeStates))
	for _, node := range s.nodeStates {
		nodes = append(nodes, node)
	}

	return nodes
}

func (s *state) GetNodeState(name string) (NodeState, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	nodeState, exists := s.nodeStates[name]
	if !exists {
		s.logger.V(3).Info("GetNodeState: not found", "name", name)
		return NodeState{}, false
	}

	s.logger.V(3).Info("GetNodeState: found", "name", name, "idAllocated", nodeState.IDAllocated, "routeTableID", nodeState.RouteTableID)

	return nodeState, true
}

func (s *state) UpdateNode(node Node) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.V(2).Info("UpdateNode called", "name", node.Name, "ipv4", node.IPv4, "ipv6", node.IPv6)

	stateChange := NewStateChange()

	existingState, exists := s.nodeStates[node.Name]
	if exists && existingState.Equals(&node) {
		s.logger.V(2).Info("Node unchanged", "name", node.Name)
		return stateChange, nil
	}

	// Allocate lazy Id for possible node Id assignment
	// This is done beforehand to not apply any changes if allocation fails
	lazyIdConsumed := false
	lazyId, err := s.idAllocator.Allocate()
	if err != nil {
		s.logger.Error(err, "Failed to allocate lazy ID for node", "name", node.Name)
		return stateChange, err
	}
	s.logger.V(3).Info("Allocated lazy ID for node", "name", node.Name, "lazyId", lazyId)
	defer func() {
		if !lazyIdConsumed {
			s.logger.V(3).Info("Releasing unused lazy ID for node", "lazyId", lazyId)
			s.idAllocator.Release(uint(lazyId))
		}
	}()

	// Update the node
	existingState.Node = node
	s.nodeStates[node.Name] = existingState

	s.logger.V(2).Info("Node updated in state", "name", node.Name, "existed", exists)

	// Sync node Id assignment
	lazyIdConsumed, _ = s.syncNodeId(node.Name, int64(lazyId))

	// If a node id was allocated, ensure that all egress rules using this node
	// are reconciled (the node is new, but may have rules assigned already)
	if lazyIdConsumed {
		nodeState := s.nodeStates[node.Name]
		s.logger.V(2).Info("Node ID allocated", "name", node.Name, "id", nodeState.ID, "fwMark", nodeState.FWMark, "routeTableID", nodeState.RouteTableID)

		stateChange.NodesUpdated.Add(node.Name)
		for _, rule := range s.egressRuleStates {
			if rule.GWNodeName == node.Name {
				s.logger.V(3).Info("Adding egress rule to state change", "ruleId", rule.ID, "nodeName", node.Name)
				stateChange.EgressRulesUpdated.Add(rule.ID)
			}
		}
	} else {
		nodeState := s.nodeStates[node.Name]
		s.logger.V(2).Info("Node ID deallocated (no egress rules)", "name", node.Name, "routeTableID", nodeState.RouteTableID)

		stateChange.NodesDeleted[node.Name] = existingState
	}

	s.logger.V(2).Info("UpdateNode completed", "name", node.Name, "stateChange", stateChange)

	return stateChange, nil
}

func (s *state) DeleteNode(name string) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.logger.V(2).Info("DeleteNode called", "name", name)

	stateChange := NewStateChange()

	existingState, exists := s.nodeStates[name]
	if exists {
		s.logger.V(2).Info("Deleting node from state", "name", name)
		delete(s.nodeStates, name)
		stateChange.NodesDeleted[name] = existingState
		// Deleting a node might free up a node Id. The lazyId is -1 here, because this
		// should NEVER allocate a new Id, only possibly free an existing one.
		_, removed := s.syncNodeId(name, -1)
		// If this was the last rule using the existing node, all rules using
		// this node must be reconciled to remove the routes
		if removed {
			s.logger.V(2).Info("Node ID removed after deleting node", "name", name)
			for _, rule := range s.egressRuleStates {
				if rule.GWNodeName == name {
					s.logger.V(3).Info("Adding egress rule to state change after node deletion", "ruleId", rule.ID, "nodeName", name)
					stateChange.EgressRulesUpdated.Add(rule.ID)
				}
			}
		}
	} else {
		s.logger.V(2).Info("DeleteNode: node not found", "name", name)
	}

	s.logger.V(2).Info("DeleteNode completed", "name", name, "stateChange", stateChange)

	return stateChange, nil
}

func (s *state) syncNodeId(name string, lazyId int64) (added, removed bool) {
	// No locking here, must be done by caller

	nodeState, nodeExists := s.nodeStates[name]
	if !nodeExists {
		s.logger.V(2).Info("syncNodeId: node does not exist", "name", name)
		return
	}

	// Count how many rules are using the given node as gateway. This will
	// determine whether an Id will be allocated for it.
	var refCount uint
	for _, ruleState := range s.egressRuleStates {
		// Filter out rules that only perform SNAT on the given node, those don't
		// need a route
		if ruleState.GWNodeName == name && (ruleState.GetMode(s.nodeName, false) != EgressRuleModeSNAT || ruleState.GetMode(s.nodeName, true) != EgressRuleModeSNAT) {
			refCount++
		}
	}

	s.logger.V(2).Info("syncNodeId", "name", name, "refCount", refCount, "idAllocated", nodeState.IDAllocated, "currentID", nodeState.ID, "currentRouteTableID", nodeState.RouteTableID, "lazyId", lazyId)

	if refCount == 0 {
		if nodeState.IDAllocated {
			s.logger.V(2).Info("syncNodeId: deallocating ID (no egress rules)", "name", name, "id", nodeState.ID, "routeTableID", nodeState.RouteTableID)
			s.idAllocator.Release(uint(nodeState.ID))
			nodeState.IDAllocated = false
			nodeState.ID = 0
			nodeState.FWMark = 0
			nodeState.RouteTableID = 0
			s.nodeStates[name] = nodeState
			removed = true
		}
	} else {
		if !nodeState.IDAllocated {
			if lazyId < 0 {
				panic("syncNodeId called with lazyId < 0 for new node Id assignment")
			}

			nodeState.IDAllocated = true
			nodeState.ID = uint32(lazyId)
			// We add 1 to the ID here, because fw mark with 0 would match all traffic
			nodeState.FWMark = (nodeState.ID + 1) << uint32(s.fwMask.Shift())
			nodeState.RouteTableID = s.routeTableIDOffset + nodeState.ID
			s.nodeStates[name] = nodeState
			added = true
			s.logger.V(2).Info("syncNodeId: allocated new ID", "name", name, "id", nodeState.ID, "fwMark", nodeState.FWMark, "routeTableID", nodeState.RouteTableID)
		}
	}

	return
}
