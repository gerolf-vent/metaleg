package core

import "github.com/gerolf-vent/metaleg/internal/utils/set"

type StateChange struct {
	EgressRulesUpdated set.Set[string]
	EgressRulesDeleted map[string]EgressRuleState
	NodesUpdated       set.Set[string]
	NodesDeleted       map[string]NodeState
}

func NewStateChange() StateChange {
	return StateChange{
		EgressRulesUpdated: set.New[string](),
		EgressRulesDeleted: make(map[string]EgressRuleState),
		NodesUpdated:       set.New[string](),
		NodesDeleted:       make(map[string]NodeState),
	}
}

func (sr StateChange) IsEmpty() bool {
	return len(sr.EgressRulesUpdated) == 0 && len(sr.EgressRulesDeleted) == 0 &&
		len(sr.NodesUpdated) == 0 && len(sr.NodesDeleted) == 0
}

func (sc StateChange) HasEgressRuleChanges() bool {
	return len(sc.EgressRulesUpdated) > 0 || len(sc.EgressRulesDeleted) > 0
}

func (sc StateChange) HasNodeChanges() bool {
	return len(sc.NodesUpdated) > 0 || len(sc.NodesDeleted) > 0
}

// MarshalLog implements logr.Marshaler for structured logging
func (sc StateChange) MarshalLog() interface{} {
	return map[string]int{
		"egressRulesUpdated": len(sc.EgressRulesUpdated),
		"egressRulesDeleted": len(sc.EgressRulesDeleted),
		"nodesUpdated":       len(sc.NodesUpdated),
		"nodesDeleted":       len(sc.NodesDeleted),
	}
}
