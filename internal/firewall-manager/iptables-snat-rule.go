package firewall_manager

import (
	"net"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type IPTablesSNATRule struct {
	SrcIPSetName string
	SNATIP       net.IP
	Protocol     iptables.Protocol
}

func ParseIPTablesSNATRule(spec []string, protocol iptables.Protocol) (*IPTablesSNATRule, bool) {
	r := &IPTablesSNATRule{
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

func (r *IPTablesSNATRule) Spec() []string {
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-j", "SNAT", "--to", r.SNATIP.String()}
}
