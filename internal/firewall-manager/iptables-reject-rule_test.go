package firewall_manager

import (
	"reflect"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

func TestParseIPTablesRejectRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
		expected *IPTablesRejectRule
	}{
		{
			name:     "TCP rule with single port IPv4",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
			expected: &IPTablesRejectRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80)),
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
		},
		{
			name:     "UDP rule with multiple ports IPv4",
			spec:     []string{"-m", "set", "--match-set", "my-ipset", "src", "-p", "udp", "-m", "multiport", "--sports", "53,123,161", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
			expected: &IPTablesRejectRule{
				SrcIPSetName:      "my-ipset",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(123), uint16(161)),
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.UDP,
			},
		},
		{
			name:     "TCP rule with IPv6",
			spec:     []string{"-m", "set", "--match-set", "ipv6-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "443,8080", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv6,
			expected: &IPTablesRejectRule{
				SrcIPSetName:      "ipv6-set",
				SrcPorts:          set.NewWithItems(uint16(443), uint16(8080)),
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.TCP,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesRejectRule(tt.spec, tt.protocol)
			if !ok {
				t.Fatalf("ParseIPTablesRejectRule() failed, expected success")
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIPTablesRejectRule() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseIPTablesRejectRule_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
	}{
		{
			name:     "Wrong number of arguments",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid transport protocol",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "icmp", "-m", "multiport", "--sports", "80", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing module for match-set",
			spec:     []string{"--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "REJECT", "--reject-with", "icmp-port-unreachable", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong match-set direction",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Sports without multiport module",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "--sports", "80", "-j", "REJECT", "--reject-with", "icmp-port-unreachable", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid port number",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "invalid", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Port number too large",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "70000", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong jump target",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong reject-with option",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "REJECT", "--reject-with", "tcp-reset"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing --reject-with argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "REJECT", "icmp-port-unreachable", "extra", "arg"},
			protocol: iptables.IPv4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesRejectRule(tt.spec, tt.protocol)
			if ok {
				t.Errorf("ParseIPTablesRejectRule() succeeded with %+v, expected failure", result)
			}
		})
	}
}

func TestIPTablesRejectRule_Spec(t *testing.T) {
	tests := []struct {
		name     string
		rule     *IPTablesRejectRule
		expected []string
	}{
		{
			name: "TCP rule with single port IPv4",
			rule: &IPTablesRejectRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80)),
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
			expected: []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		},
		{
			name: "UDP rule with multiple ports IPv4",
			rule: &IPTablesRejectRule{
				SrcIPSetName:      "my-ipset",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(123), uint16(161)),
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.UDP,
			},
			expected: []string{"-m", "set", "--match-set", "my-ipset", "src", "-p", "udp", "-m", "multiport", "--sports", "53,123,161", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		},
		{
			name: "TCP rule with IPv6",
			rule: &IPTablesRejectRule{
				SrcIPSetName:      "ipv6-set",
				SrcPorts:          set.NewWithItems(uint16(443), uint16(8080)),
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.TCP,
			},
			expected: []string{"-m", "set", "--match-set", "ipv6-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "443,8080", "-j", "REJECT", "--reject-with", "icmp6-port-unreachable"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Spec()

			// Since the port order in the set might vary, we need to check the spec more carefully
			if len(result) != len(tt.expected) {
				t.Errorf("Spec() length = %d, want %d", len(result), len(tt.expected))
				return
			}

			// Check all parts except the sports (which might be in different order)
			for i, part := range result {
				if i == 10 { // --sports value index
					// Check that all expected ports are present
					expectedPorts := tt.expected[i]
					if !containsSamePorts(part, expectedPorts) {
						t.Errorf("Spec() sports = %s, want %s", part, expectedPorts)
					}
				} else if part != tt.expected[i] {
					t.Errorf("Spec()[%d] = %s, want %s", i, part, tt.expected[i])
				}
			}
		})
	}
}

func TestIPTablesRejectRule_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rule *IPTablesRejectRule
	}{
		{
			name: "IPv4 TCP rule",
			rule: &IPTablesRejectRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80), uint16(443), uint16(8080)),
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
		},
		{
			name: "IPv6 UDP rule",
			rule: &IPTablesRejectRule{
				SrcIPSetName:      "ipv6-set",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(5353)),
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.UDP,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate spec from original rule
			spec := tt.rule.Spec()

			// Parse the generated spec back
			parsed, ok := ParseIPTablesRejectRule(spec, tt.rule.Protocol)
			if !ok {
				t.Fatalf("Failed to parse generated spec")
			}

			// Compare the parsed rule with the original
			if parsed.SrcIPSetName != tt.rule.SrcIPSetName {
				t.Errorf("SrcIPSetName mismatch: got %s, want %s", parsed.SrcIPSetName, tt.rule.SrcIPSetName)
			}
			if parsed.Protocol != tt.rule.Protocol {
				t.Errorf("Protocol mismatch: got %s, want %s", parsed.Protocol, tt.rule.Protocol)
			}
			if parsed.TransportProtocol != tt.rule.TransportProtocol {
				t.Errorf("TransportProtocol mismatch: got %s, want %s", parsed.TransportProtocol, tt.rule.TransportProtocol)
			}
			if !parsed.SrcPorts.Equals(tt.rule.SrcPorts) {
				t.Errorf("SrcPorts mismatch: got %v, want %v", parsed.SrcPorts, tt.rule.SrcPorts)
			}
		})
	}
}
