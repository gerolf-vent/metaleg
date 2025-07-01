package firewall_manager

import (
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type IPTablesRejectRule struct {
	SrcIPSetName string
	Protocol     iptables.Protocol
}

func ParseIPTablesRejectRule(spec []string, protocol iptables.Protocol) (*IPTablesRejectRule, bool) {
	parsedRule := &IPTablesRejectRule{
		Protocol: protocol,
	}

	if len(spec) != 9 {
		return nil, false // Expected format is 9 parts
	}

	var module string
	for i := 0; i < len(spec); i++ {
		switch spec[i] {
		case "-m":
			if len(spec) < i+2 { // -m requires one argument
				return nil, false
			}
			module = spec[i+1]
			i += 1
		case "--match-set":
			if module != "set" {
				return nil, false // Only valid for set module
			}
			if len(spec) < i+3 { // --match-set requires two arguments
				return nil, false
			}
			if spec[i+2] != "src" {
				return nil, false // Only interested in source IP sets
			}
			parsedRule.SrcIPSetName = spec[i+1]
			i += 2
		case "-j":
			if len(spec) < i+4 { // -j MARK requires at least two further arguments
				return nil, false
			}
			if spec[i+1] != "REJECT" || spec[i+2] != "--reject-with" ||
				(protocol == iptables.IPv4 && spec[i+3] != "icmp-port-unreachable") ||
				(protocol == iptables.IPv6 && spec[i+3] != "icmp6-port-unreachable") {
				return nil, false // Only interested in MARK rules
			}
			i += 3
		default:
			return nil, false // Unrecognized part of the spec
		}
	}

	return parsedRule, true
}

func (r *IPTablesRejectRule) Spec() []string {
	var rejectWith string
	switch r.Protocol {
	case iptables.IPv4:
		rejectWith = "icmp-port-unreachable"
	case iptables.IPv6:
		rejectWith = "icmp6-port-unreachable"
	}

	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-j", "REJECT", "--reject-with", rejectWith}
}
