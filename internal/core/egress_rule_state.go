package core

import "net"

type EgressRuleMode uint8

const (
	// Traffic should be untouched
	EgressRuleModeUnconfigured EgressRuleMode = iota
	// Traffic should be blocked
	EgressRuleModeBlock
	// Traffic should be redirected to the gateway node
	EgressRuleModeRedirect
	// Traffic is on the gateway node and should be SNATed
	EgressRuleModeSNAT
)

func (m EgressRuleMode) String() string {
	switch m {
	case EgressRuleModeBlock:
		return "block"
	case EgressRuleModeRedirect:
		return "redirect"
	case EgressRuleModeSNAT:
		return "SNAT"
	default:
		return "unknown"
	}
}

type EgressRuleState struct {
	EgressRule
	GWIPv4 net.IP
	GWIPv6 net.IP
	FWMark uint32
}

func (s EgressRuleState) GetMode(nodeName string, ipv6 bool) EgressRuleMode {
	if (ipv6 && (s.SNATIPv6 == nil || s.SNATIPv6.IsUnspecified())) || (!ipv6 && (s.SNATIPv4 == nil || s.SNATIPv4.IsUnspecified())) {
		return EgressRuleModeUnconfigured
	}
	if s.GWNodeName == nodeName {
		return EgressRuleModeSNAT
	}
	if s.FWMark == 0 || (ipv6 && (s.GWIPv6 == nil || s.GWIPv6.IsUnspecified())) || (!ipv6 && (s.GWIPv4 == nil || s.GWIPv4.IsUnspecified())) {
		return EgressRuleModeBlock
	}
	return EgressRuleModeRedirect
}

func (s EgressRuleState) WithNodeState(nodeState NodeState) EgressRuleState {
	s.GWIPv4 = nodeState.IPv4
	s.GWIPv6 = nodeState.IPv6
	s.FWMark = nodeState.FWMark
	return s
}
