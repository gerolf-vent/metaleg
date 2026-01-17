package core

import "net"

type EgressRuleState struct {
	EgressRule
	GWIPv4 net.IP
	GWIPv6 net.IP
	FWMark uint32
}

// Determines whether traffic should be blocked
func (s EgressRuleState) ShouldBlockTraffic(ipv6 bool) bool {
	return (ipv6 && (s.SNATIPv6.IsUnspecified() || s.GWIPv6.IsUnspecified())) || (!ipv6 && (s.SNATIPv4.IsUnspecified() || s.GWIPv4.IsUnspecified()))
}

// Determines whether traffic should be redirected to the gateway node
func (s EgressRuleState) NeedTrafficRedirection(nodeName string, ipv6 bool) bool {
	return s.GWNodeName != nodeName && !s.ShouldBlockTraffic(ipv6)
}

// Determines whether the gateway node is the local node and has a valid SNAT IP
func (s EgressRuleState) IsGWLocal(nodeName string, ipv6 bool) bool {
	return s.GWNodeName == nodeName && !s.ShouldBlockTraffic(ipv6)
}

func (s EgressRuleState) WithNodeState(nodeState NodeState) EgressRuleState {
	s.GWIPv4 = nodeState.IPv4
	s.GWIPv6 = nodeState.IPv6
	s.FWMark = nodeState.FWMark
	return s
}
