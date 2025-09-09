package firewall_manager

import (
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type IPTablesExcludeCIDRsRule struct {
	IPSetName string
	Protocol  iptables.Protocol
}

func ParseIPTablesExcludeCIDRsRule(spec []string, protocol iptables.Protocol) (*IPTablesExcludeCIDRsRule, bool) {
	parsedRule := &IPTablesExcludeCIDRsRule{
		Protocol: protocol,
	}

	if len(spec) != 7 {
		return nil, false // Expected format is 7 parts
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
			if spec[i+2] != "dst" {
				return nil, false // Only interested in destination IP sets
			}
			parsedRule.IPSetName = spec[i+1]
			i += 2
		case "-j":
			if len(spec) < i+2 {
				return nil, false
			}
			if spec[i+1] != "RETURN" {
				return nil, false // Only interested in RETURN rules
			}
			i += 1
		default:
			return nil, false // Unrecognized part of the spec
		}
	}

	return parsedRule, true
}

func (r *IPTablesExcludeCIDRsRule) Spec() []string {
	return []string{"-m", "set", "--match-set", r.IPSetName, "dst", "-j", "RETURN"}
}
