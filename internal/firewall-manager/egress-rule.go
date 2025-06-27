package firewall_manager

import (
	"crypto/sha256"
	"encoding/base32"
	"net"
	"strings"

	rm "github.com/gerolf-vent/metaleg/internal/route-manager"
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

type EgressRule struct {
	ID          string          // Unique identifier for the egress rule (namespaced service name)
	SrcIPv4s    []net.IP        // Source IPv4 addresses from Pods
	SrcIPv6s    []net.IP        // Source IPv6 addresses from Pods
	SrcTCPPorts set.Set[uint16] // List of source tcp ports to match for egress traffic
	SrcUDPPorts set.Set[uint16] // List of source udp ports to match for egress traffic
	SNATIPv4    net.IP          // SNAT IPv4 address for egress traffic
	SNATIPv6    net.IP          // SNAT IPv6 address for egress traffic
	GWNodeName  string          // Name of the gateway node for egress traffic
	GWRoute     *rm.NodeRoute   // Gateway route for egress traffic
}

func NewEgressRule(id string) *EgressRule {
	return &EgressRule{
		ID:          id,
		SrcTCPPorts: set.New[uint16](),
		SrcUDPPorts: set.New[uint16](),
	}
}

func (r *EgressRule) CalcIDHash(isIPv6 bool) string {
	var protoPrefix string
	if isIPv6 {
		protoPrefix = "ipv6:"
	}
	hash := sha256.Sum256([]byte(protoPrefix + r.ID))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return strings.ToUpper(encoded[:12])
}

func (r *EgressRule) MatchesIPTablesSNATRule(iptRule *IPTablesSNATRule) bool {
	if r == nil || iptRule == nil {
		return false // Invalid rule
	}

	// Determine the rule's hash ID and SNAT IP based on the protocol
	var ruleHashID string
	var snatIP net.IP
	switch iptRule.Protocol {
	case iptables.IPv4:
		ruleHashID = r.CalcIDHash(false)
		snatIP = r.SNATIPv4
	case iptables.IPv6:
		ruleHashID = r.CalcIDHash(true)
		snatIP = r.SNATIPv6
	default:
		return false // Unsupported protocol
	}

	// Check whether the rule targets the correct IP set
	if !strings.Contains(iptRule.SrcIPSetName, ruleHashID) {
		return false
	}

	// Determine src ports to consider
	var srcPorts set.Set[uint16]
	switch iptRule.TransportProtocol {
	case iptables.TCP:
		srcPorts = r.SrcTCPPorts
	case iptables.UDP:
		srcPorts = r.SrcUDPPorts
	default:
		return false // Unsupported transport protocol
	}

	// An empty list of src ports can't match any rule
	if len(srcPorts) == 0 {
		return false
	}

	// Check if the source ports match
	if !iptRule.SrcPorts.Equals(srcPorts) {
		return false
	}

	// Check if the SNAT IP matches the rule's SNAT IP
	if !snatIP.Equal(iptRule.SNATIP) {
		return false
	}

	return true
}

func (r *EgressRule) MatchesIPSetName(ipSetName string) bool {
	if r == nil {
		return false // Invalid rule
	}

	ruleHashID := r.CalcIDHash(false)
	if strings.Contains(ipSetName, ruleHashID) {
		return true
	}

	ruleHashID = r.CalcIDHash(true)
	return strings.Contains(ipSetName, ruleHashID)
}

func (r *EgressRule) MatchesIPTablesMarkRule(iptRule *IPTablesMarkRule, fwMask uint32) bool {
	// Ensure the rule is valid and has a gateway set
	if r.GWRoute == nil {
		return false
	}

	// Check if the rule's FWMark and FWMask match the gateway's FWMark and provided mask
	if iptRule.FWMark != r.GWRoute.FWMark || iptRule.FWMask != fwMask {
		return false
	}

	// Determine the rule's hash ID based on the protocol
	var ruleHashID string
	switch iptRule.Protocol {
	case iptables.IPv4:
		ruleHashID = r.CalcIDHash(false)
	case iptables.IPv6:
		ruleHashID = r.CalcIDHash(true)
	default:
		return false // Unsupported protocol
	}

	// Check whether the rule targets the correct IP set
	if !strings.Contains(iptRule.SrcIPSetName, ruleHashID) {
		return false
	}

	// Determine src ports to consider
	var srcPorts set.Set[uint16]
	switch iptRule.TransportProtocol {
	case iptables.TCP:
		srcPorts = r.SrcTCPPorts
	case iptables.UDP:
		srcPorts = r.SrcUDPPorts
	default:
		return false // Unsupported transport protocol
	}

	// An empty list of src ports can't match any rule
	if len(srcPorts) == 0 {
		return false
	}

	// Check if the source ports match
	if !iptRule.SrcPorts.Equals(srcPorts) {
		return false
	}

	return true
}

func (r *EgressRule) MatchesIPTablesRejectRule(iptRule *IPTablesRejectRule) bool {
	if r.GWRoute != nil {
		return false // Reject rules are not applicable when a gateway route is set
	}

	// Determine the rule's hash ID based on the protocol
	var ruleHashID string
	switch iptRule.Protocol {
	case iptables.IPv4:
		ruleHashID = r.CalcIDHash(false)
	case iptables.IPv6:
		ruleHashID = r.CalcIDHash(true)
	default:
		return false // Unsupported protocol
	}

	// Check whether the rule targets the correct IP set
	if !strings.Contains(iptRule.SrcIPSetName, ruleHashID) {
		return false
	}

	// Determine src ports to consider
	var srcPorts set.Set[uint16]
	switch iptRule.TransportProtocol {
	case iptables.TCP:
		srcPorts = r.SrcTCPPorts
	case iptables.UDP:
		srcPorts = r.SrcUDPPorts
	default:
		return false // Unsupported transport protocol
	}

	// An empty list of src ports can't match any rule
	if len(srcPorts) == 0 {
		return false
	}

	// Check if the source ports match
	if !iptRule.SrcPorts.Equals(srcPorts) {
		return false
	}

	return true
}
