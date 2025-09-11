package firewall_manager

import (
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type IPTablesExcludeCIDRsRule struct {
	IPSetName string
	Protocol  iptables.Protocol
}

func ParseIPTablesExcludeCIDRsRule(spec []string, protocol iptables.Protocol) (*IPTablesExcludeCIDRsRule, bool) {
	r := &IPTablesExcludeCIDRsRule{
		Protocol: protocol,
	}

	ruleParser := iptables.NewIPTablesSpecParser([][]string{
		{"-m", "set"},
		{"--match-set", "{setName}", "dst"},
		{"-j", "RETURN"},
	})

	values, ok := ruleParser.Parse(spec)
	if !ok {
		return nil, false
	}

	r.IPSetName = values["setName"]

	return r, true
}

func (r *IPTablesExcludeCIDRsRule) Spec() []string {
	if r == nil {
		return []string{"<nil>"}
	}
	return []string{"-m", "set", "--match-set", r.IPSetName, "dst", "-j", "RETURN"}
}
