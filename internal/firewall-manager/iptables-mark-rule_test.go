package firewall_manager

import (
	"reflect"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

func TestParseIPTablesMarkRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
		expected *IPTablesMarkRule
	}{
		{
			name:     "TCP rule with single port",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
			expected: &IPTablesMarkRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80)),
				FWMark:            0x1,
				FWMask:            0xff,
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
		},
		{
			name:     "UDP rule with multiple ports",
			spec:     []string{"-m", "set", "--match-set", "my-ipset", "src", "-p", "udp", "-m", "multiport", "--sports", "53,123,161", "-j", "MARK", "--set-xmark", "0xab/0xffff"},
			protocol: iptables.IPv6,
			expected: &IPTablesMarkRule{
				SrcIPSetName:      "my-ipset",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(123), uint16(161)),
				FWMark:            0xab,
				FWMask:            0xffff,
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.UDP,
			},
		},
		{
			name:     "TCP rule with high mark values",
			spec:     []string{"-m", "set", "--match-set", "high-mark", "src", "-p", "tcp", "-m", "multiport", "--sports", "443,8080", "-j", "MARK", "--set-xmark", "0xdeadbeef/0xffffffff"},
			protocol: iptables.IPv4,
			expected: &IPTablesMarkRule{
				SrcIPSetName:      "high-mark",
				SrcPorts:          set.NewWithItems(uint16(443), uint16(8080)),
				FWMark:            0xdeadbeef,
				FWMask:            0xffffffff,
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesMarkRule(tt.spec, tt.protocol)
			if !ok {
				t.Fatalf("ParseIPTablesMarkRule() failed, expected success")
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIPTablesMarkRule() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseIPTablesMarkRule_Invalid(t *testing.T) {
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
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "icmp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing module for match-set",
			spec:     []string{"--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1/0xff", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong match-set direction",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Sports without multiport module",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1/0xff", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid port number",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "invalid", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Port number too large",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "70000", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong jump target",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong mark option",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-mark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid mark format - no slash",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid mark format - invalid hex mark",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0xzz/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid mark format - invalid hex mask",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1/0xzz"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing --set-xmark argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "0x1/0xff", "extra", "arg"},
			protocol: iptables.IPv4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesMarkRule(tt.spec, tt.protocol)
			if ok {
				t.Errorf("ParseIPTablesMarkRule() succeeded with %+v, expected failure", result)
			}
		})
	}
}

func TestIPTablesMarkRule_Spec(t *testing.T) {
	tests := []struct {
		name     string
		rule     *IPTablesMarkRule
		expected []string
	}{
		{
			name: "TCP rule with single port",
			rule: &IPTablesMarkRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80)),
				FWMark:            0x1,
				FWMask:            0xff,
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
			expected: []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "MARK", "--set-xmark", "0x1/0xff"},
		},
		{
			name: "UDP rule with multiple ports",
			rule: &IPTablesMarkRule{
				SrcIPSetName:      "my-ipset",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(123), uint16(161)),
				FWMark:            0xab,
				FWMask:            0xffff,
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.UDP,
			},
			expected: []string{"-m", "set", "--match-set", "my-ipset", "src", "-p", "udp", "-m", "multiport", "--sports", "53,123,161", "-j", "MARK", "--set-xmark", "0xab/0xffff"},
		},
		{
			name: "TCP rule with high mark values",
			rule: &IPTablesMarkRule{
				SrcIPSetName:      "high-mark",
				SrcPorts:          set.NewWithItems(uint16(443), uint16(8080)),
				FWMark:            0xdeadbeef,
				FWMask:            0xffffffff,
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
			expected: []string{"-m", "set", "--match-set", "high-mark", "src", "-p", "tcp", "-m", "multiport", "--sports", "443,8080", "-j", "MARK", "--set-xmark", "0xdeadbeef/0xffffffff"},
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

func TestIPTablesMarkRule_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rule *IPTablesMarkRule
	}{
		{
			name: "IPv4 TCP rule with low mark",
			rule: &IPTablesMarkRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80), uint16(443), uint16(8080)),
				FWMark:            0x1,
				FWMask:            0xff,
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
		},
		{
			name: "IPv6 UDP rule with high mark",
			rule: &IPTablesMarkRule{
				SrcIPSetName:      "ipv6-set",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(5353)),
				FWMark:            0xdeadbeef,
				FWMask:            0xffffffff,
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
			parsed, ok := ParseIPTablesMarkRule(spec, tt.rule.Protocol)
			if !ok {
				t.Fatalf("Failed to parse generated spec")
			}

			// Compare the parsed rule with the original
			if parsed.SrcIPSetName != tt.rule.SrcIPSetName {
				t.Errorf("SrcIPSetName mismatch: got %s, want %s", parsed.SrcIPSetName, tt.rule.SrcIPSetName)
			}
			if parsed.FWMark != tt.rule.FWMark {
				t.Errorf("FWMark mismatch: got 0x%x, want 0x%x", parsed.FWMark, tt.rule.FWMark)
			}
			if parsed.FWMask != tt.rule.FWMask {
				t.Errorf("FWMask mismatch: got 0x%x, want 0x%x", parsed.FWMask, tt.rule.FWMask)
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
