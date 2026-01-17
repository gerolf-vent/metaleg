package core

import (
	"fmt"
	"net"
	"sync"

	"github.com/gerolf-vent/metaleg/internal/utils"
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

	mu sync.RWMutex
}

func NewState(config *Config) (State, error) {
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
		return EgressRuleState{}, false
	}

	// Fill in the gw info and fw mark from the node state
	nodeState, _ := s.nodeStates[state.GWNodeName]
	state = state.WithNodeState(nodeState)

	return state, true
}

func (s *state) UpdateEgressRule(rule EgressRule) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stateChange := NewStateChange()

	existingState, exists := s.egressRuleStates[rule.ID]
	if exists && existingState.Equals(&rule) {
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

	// Sync node Id assignments
	if exists && existingState.GWNodeName != rule.GWNodeName {
		// Changing the gw node name, might cause the node to have no egress rules attached
		// anymore. The lazyId is 0 here, because this should NEVER allocate a new Id, only
		// possibly free an existing one.
		_, removed := s.syncNodeId(existingState.GWNodeName, 0)
		// If this was the last rule using the node, the rule must be reconciled
		// to remove the route
		if removed {
			stateChange.NodesUpdated.Add(existingState.GWNodeName)
		}
	}
	lazyIdConsumed, _ = s.syncNodeId(rule.GWNodeName, uint32(lazyId))
	// If a node id was allocated, this is the first rule using this node,
	// so the rule must be reconciled to add the route
	if lazyIdConsumed {
		stateChange.NodesUpdated.Add(rule.GWNodeName)
	}

	return stateChange, nil
}

func (s *state) DeleteEgressRule(id string) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stateChange := NewStateChange()

	existingRule, exists := s.egressRuleStates[id]
	if exists {
		delete(s.egressRuleStates, id)
		stateChange.EgressRulesDeleted[id] = existingRule
		// Deleting an egress rule might free up a node Id. The lazyId is 0 here,
		// because this should NEVER allocate a new Id, only possibly free an existing one.
		_, removed := s.syncNodeId(existingRule.GWNodeName, 0)
		// If this was the last rule using the existing node, the rule must
		// be reconciled to remove the route
		if removed {
			stateChange.NodesUpdated.Add(existingRule.GWNodeName)
		}
	}

	return stateChange, nil
}

func (s *state) GetNodeStates() []NodeState {
	s.mu.RLock()
	defer s.mu.RUnlock()

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
		return NodeState{}, false
	}

	return nodeState, true
}

func (s *state) UpdateNode(node Node) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stateChange := NewStateChange()

	existingState, exists := s.nodeStates[node.Name]
	if exists && existingState.Equals(&node) {
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

	// Update the node
	existingState.Node = node
	s.nodeStates[node.Name] = existingState
	stateChange.NodesUpdated.Add(node.Name)

	// Sync node Id assignment
	lazyIdConsumed, _ = s.syncNodeId(node.Name, uint32(lazyId))

	// If a node id was allocated, ensure that all egress rules using this node
	// are reconciled (the node is new, but may have rules assigned already)
	if lazyIdConsumed {
		for _, rule := range s.egressRuleStates {
			if rule.GWNodeName == node.Name {
				stateChange.EgressRulesUpdated.Add(rule.ID)
			}
		}
	}

	return stateChange, nil
}

func (s *state) DeleteNode(name string) (StateChange, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	stateChange := NewStateChange()

	existingState, exists := s.nodeStates[name]
	if exists {
		delete(s.nodeStates, name)
		stateChange.NodesDeleted[name] = existingState
		// Deleting a node might free up a node Id. The lazyId is 0 here,
		// because this should NEVER allocate a new Id, only possibly free an existing one.
		_, removed := s.syncNodeId(name, 0)
		// If this was the last rule using the existing node, all rules using
		// this node must be reconciled to remove the routes
		if removed {
			for _, rule := range s.egressRuleStates {
				if rule.GWNodeName == name {
					stateChange.EgressRulesUpdated.Add(rule.ID)
				}
			}
		}
	}

	return stateChange, nil
}

func (s *state) syncNodeId(name string, lazyId uint32) (added, removed bool) {
	// No locking here, must be done by caller

	nodeState, nodeExists := s.nodeStates[name]
	if !nodeExists {
		return
	}

	var refCount uint
	for _, rule := range s.egressRuleStates {
		if rule.GWNodeName == name {
			refCount++
		}
	}

	if refCount == 0 {
		if nodeState.IDAllocated {
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
			if lazyId == 0 {
				panic("syncNodeId called with lazyId == 0 for new node Id assignment")
			}

			nodeState.IDAllocated = true
			nodeState.ID = lazyId
			// We add 1 to the ID here, because fw mark with 0 would match all traffic
			nodeState.FWMark = (lazyId + 1) << uint32(s.fwMask.Shift())
			nodeState.RouteTableID = s.routeTableIDOffset + lazyId
			s.nodeStates[name] = nodeState
			added = true
		}
	}

	return
}
