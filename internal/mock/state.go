package mock

import (
	"net"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/utils"
)

type State struct {
	NodeNameVal        string
	FWMaskVal          utils.FWMask
	RouteTableIDOff    uint32
	ExcludeDstCIDRsVal []net.IPNet
	EgressRuleStates   map[string]core.EgressRuleState
	NodeStates         map[string]core.NodeState
}

func NewState() *State {
	_, cidr4, _ := net.ParseCIDR("10.0.0.0/8")
	_, cidr6, _ := net.ParseCIDR("fc00::/7")
	return &State{
		NodeNameVal:        "local-node",
		FWMaskVal:          utils.FWMask(0xF00000),
		RouteTableIDOff:    100000,
		ExcludeDstCIDRsVal: []net.IPNet{*cidr4, *cidr6},
		EgressRuleStates:   make(map[string]core.EgressRuleState),
		NodeStates:         make(map[string]core.NodeState),
	}
}

func (s *State) NodeName() string             { return s.NodeNameVal }
func (s *State) FWMask() utils.FWMask         { return s.FWMaskVal }
func (s *State) RouteTableIDOffset() uint32   { return s.RouteTableIDOff }
func (s *State) ExcludeDstCIDRs() []net.IPNet { return s.ExcludeDstCIDRsVal }

func (s *State) GetEgressRuleStates() []core.EgressRuleState {
	rules := make([]core.EgressRuleState, 0, len(s.EgressRuleStates))
	for _, r := range s.EgressRuleStates {
		rules = append(rules, r)
	}
	return rules
}

func (s *State) GetEgressRuleState(id string) (core.EgressRuleState, bool) {
	r, ok := s.EgressRuleStates[id]
	return r, ok
}

func (s *State) UpdateEgressRule(rule core.EgressRule) (core.StateChange, error) {
	return core.NewStateChange(), nil
}

func (s *State) DeleteEgressRule(id string) (core.StateChange, error) {
	return core.NewStateChange(), nil
}

func (s *State) GetNodeStates() []core.NodeState {
	states := make([]core.NodeState, 0, len(s.NodeStates))
	for _, ns := range s.NodeStates {
		states = append(states, ns)
	}
	return states
}

func (s *State) GetNodeState(name string) (core.NodeState, bool) {
	ns, ok := s.NodeStates[name]
	return ns, ok
}

func (s *State) UpdateNode(node core.Node) (core.StateChange, error) {
	return core.NewStateChange(), nil
}

func (s *State) DeleteNode(name string) (core.StateChange, error) {
	return core.NewStateChange(), nil
}
