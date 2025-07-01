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
	parsedRule := &IPTablesSNATRule{
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
			if len(spec) < i+4 { // -j SNAT requires at least two further arguments
				return nil, false
			}
			if spec[i+1] != "SNAT" || spec[i+2] != "--to" {
				return nil, false // Only interested in SNAT rules
			}
			snatIP := net.ParseIP(spec[i+3])
			if snatIP == nil {
				return nil, false // Invalid SNAT IP address
			}
			parsedRule.SNATIP = snatIP
			i += 3
		default:
			return nil, false // Unrecognized part of the spec
		}
	}

	return parsedRule, true
}

func (r *IPTablesSNATRule) Spec() []string {
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-j", "SNAT", "--to", r.SNATIP.String()}
}
