package iptables

import (
	"net"
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type SNATRule struct {
	SrcIPSetName string
	SNATIP       net.IP
	Protocol     iptables.Protocol
}

func ParseSNATRule(spec []string, protocol iptables.Protocol) (Rule, bool) {
	r := &SNATRule{
		Protocol: protocol,
	}

	ruleParser := iptables.NewIPTablesSpecParser([][]string{
		{"-m", "set"},
		{"--match-set", "{setName}", "src"},
		{"-j", "SNAT", "--to", "{snatIP}"},
	})

	values, ok := ruleParser.Parse(spec)
	if !ok {
		return nil, false
	}

	r.SrcIPSetName = values["setName"]

	snatIP := net.ParseIP(values["snatIP"])
	if snatIP == nil {
		return nil, false
	}
	r.SNATIP = snatIP

	return r, true
}

func (r *SNATRule) Spec() []string {
	if r == nil {
		return []string{"<nil>"}
	}
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-j", "SNAT", "--to", r.SNATIP.String()}
}

func (r *SNATRule) String() string {
	if r == nil {
		return "<nil>"
	}
	return strings.Join(r.Spec(), " ")
}

func (r *SNATRule) RuleID() string {
	if r == nil {
		return "<nil>"
	}
	return r.SrcIPSetName
}
