package firewall_manager

import (
	"strconv"
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

type IPTablesRejectRule struct {
	SrcIPSetName      string
	SrcPorts          set.Set[uint16]
	Protocol          iptables.Protocol
	TransportProtocol iptables.TransportProtocol
}

func ParseIPTablesRejectRule(spec []string, protocol iptables.Protocol) (*IPTablesRejectRule, bool) {
	parsedRule := &IPTablesRejectRule{
		Protocol: protocol,
		SrcPorts: set.New[uint16](),
	}

	if len(spec) != 15 {
		return nil, false // Expected format is 15 parts
	}

	var module string
	for i := 0; i < len(spec); i++ {
		switch spec[i] {
		case "-p":
			if len(spec) < i+2 { // -p requires one argument
				return nil, false
			}
			switch spec[i+1] {
			case "tcp":
				parsedRule.TransportProtocol = iptables.TCP
			case "udp":
				parsedRule.TransportProtocol = iptables.UDP
			default:
				return nil, false // Unknown transport protocol
			}
			i += 1
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
		case "--sports":
			if module != "multiport" {
				return nil, false // Only valid for multiport module
			}
			if len(spec) < i+2 { // --sports requires one argument
				return nil, false
			}
			ports := strings.Split(spec[i+1], ",")
			for _, port := range ports {
				port = strings.TrimSpace(port)
				p, err := strconv.ParseUint(port, 10, 16)
				if err != nil {
					return nil, false // Invalid port format
				}
				parsedRule.SrcPorts.Add(uint16(p))
			}
			i += 1
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
	sports := make([]string, 0, len(r.SrcPorts))
	for port := range r.SrcPorts {
		sports = append(sports, strconv.Itoa(int(port)))
	}
	var rejectWith string
	switch r.Protocol {
	case iptables.IPv4:
		rejectWith = "icmp-port-unreachable"
	case iptables.IPv6:
		rejectWith = "icmp6-port-unreachable"
	}
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-p", r.TransportProtocol.String(), "-m", "multiport", "--sports", strings.Join(sports, ","), "-j", "REJECT", "--reject-with", rejectWith}
}
