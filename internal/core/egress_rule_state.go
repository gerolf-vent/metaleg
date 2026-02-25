package core

import "net"

type EgressRuleMode uint8

const (
	// Traffic should be blocked
	EgressRuleModeBlock EgressRuleMode = iota
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
	if (ipv6 && (s.SNATIPv6.IsUnspecified() || s.GWIPv6.IsUnspecified())) || (!ipv6 && (s.SNATIPv4.IsUnspecified() || s.GWIPv4.IsUnspecified())) {
		return EgressRuleModeBlock
	}
	if s.GWNodeName != nodeName {
		return EgressRuleModeRedirect
	}
	return EgressRuleModeSNAT
}

func (s EgressRuleState) WithNodeState(nodeState NodeState) EgressRuleState {
	s.GWIPv4 = nodeState.IPv4
	s.GWIPv6 = nodeState.IPv6
	s.FWMark = nodeState.FWMark
	return s
}
