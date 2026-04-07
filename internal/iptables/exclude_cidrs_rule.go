package iptables

import (
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type ExcludeCIDRsRule struct {
	IPSetName string
	Protocol  iptables.Protocol
}

func ParseExcludeCIDRsRule(spec []string, protocol iptables.Protocol) (*ExcludeCIDRsRule, bool) {
	r := &ExcludeCIDRsRule{
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

func (r *ExcludeCIDRsRule) Spec() []string {
	if r == nil {
		return []string{"<nil>"}
	}
	return []string{"-m", "set", "--match-set", r.IPSetName, "dst", "-j", "RETURN"}
}

func (r *ExcludeCIDRsRule) String() string {
	if r == nil {
		return "<nil>"
	}
	return strings.Join(r.Spec(), " ")
}
