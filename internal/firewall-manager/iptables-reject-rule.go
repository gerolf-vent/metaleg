package firewall_manager

import (
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type IPTablesRejectRule struct {
	SrcIPSetName string
	Protocol     iptables.Protocol
}

func ParseIPTablesRejectRule(spec []string, protocol iptables.Protocol) (*IPTablesRejectRule, bool) {
	r := &IPTablesRejectRule{
		Protocol: protocol,
	}

	ruleParser := iptables.NewIPTablesSpecParser([][]string{
		{"-m", "set"},
		{"--match-set", "{setName}", "src"},
		{"-j", "REJECT", "--reject-with", r.rejectWith()},
	})

	values, ok := ruleParser.Parse(spec)
	if !ok {
		return nil, false
	}

	r.SrcIPSetName = values["setName"]

	return r, true
}

func (r *IPTablesRejectRule) Spec() []string {
	if r == nil {
		return []string{"<nil>"}
	}
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-j", "REJECT", "--reject-with", r.rejectWith()}
}

func (r *IPTablesRejectRule) rejectWith() string {
	switch r.Protocol {
	case iptables.IPv6:
		return "icmp6-port-unreachable"
	default:
		return "icmp-port-unreachable" // Default to IPv4 if unknown
	}
}
