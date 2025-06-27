package firewall_manager

import (
	"strconv"
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

type IPTablesMarkRule struct {
	SrcIPSetName      string
	SrcPorts          set.Set[uint16]
	FWMark            uint32
	FWMask            uint32
	Protocol          iptables.Protocol
	TransportProtocol iptables.TransportProtocol
}

func ParseIPTablesMarkRule(spec []string, protocol iptables.Protocol) (*IPTablesMarkRule, bool) {
	parsedRule := &IPTablesMarkRule{
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
			if spec[i+1] != "MARK" || spec[i+2] != "--set-xmark" {
				return nil, false // Only interested in MARK rules
			}

			mark := strings.SplitN(spec[i+3], "/", 2)
			if len(mark) != 2 {
				return nil, false // Expected format is "0x<mark>/0x<mask>"
			}

			fwMark, err := strconv.ParseUint(strings.TrimPrefix(mark[0], "0x"), 16, 32)
			if err != nil {
				return nil, false // Invalid hex format for fw mark
			}
			parsedRule.FWMark = uint32(fwMark)

			fwMask, err := strconv.ParseUint(strings.TrimPrefix(mark[1], "0x"), 16, 32)
			if err != nil {
				return nil, false // Invalid hex format for fw mask
			}
			parsedRule.FWMask = uint32(fwMask)
			i += 3
		default:
			return nil, false // Unrecognized part of the spec
		}
	}

	return parsedRule, true
}

func (r *IPTablesMarkRule) Spec() []string {
	sports := make([]string, 0, len(r.SrcPorts))
	for port, _ := range r.SrcPorts {
		sports = append(sports, strconv.Itoa(int(port)))
	}
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-p", r.TransportProtocol.String(), "-m", "multiport", "--sports", strings.Join(sports, ","), "-j", "MARK", "--set-xmark", "0x" + strconv.FormatUint(uint64(r.FWMark), 16) + "/0x" + strconv.FormatUint(uint64(r.FWMask), 16)}
}
