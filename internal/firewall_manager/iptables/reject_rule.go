package iptables

import (
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type RejectRule struct {
	SrcIPSetName string
	Protocol     iptables.Protocol
}

func ParseRejectRule(spec []string, protocol iptables.Protocol) (*RejectRule, bool) {
	r := &RejectRule{
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

func (r *RejectRule) Spec() []string {
	if r == nil {
		return []string{"<nil>"}
	}
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-j", "REJECT", "--reject-with", r.rejectWith()}
}

func (r *RejectRule) String() string {
	if r == nil {
		return "<nil>"
	}
	return strings.Join(r.Spec(), " ")
}

func (r *RejectRule) RuleID() string {
	if r == nil {
		return "<nil>"
	}
	return r.SrcIPSetName
}

func (r *RejectRule) rejectWith() string {
	switch r.Protocol {
	case iptables.IPv6:
		return "icmp6-port-unreachable"
	default:
		return "icmp-port-unreachable" // Default to IPv4 if unknown
	}
}
