package firewall_manager

import (
	"net"
	"reflect"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
)

func TestParseIPTablesSNATRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
		expected *IPTablesSNATRule
	}{
		{
			name:     "TCP rule with single port",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
			expected: &IPTablesSNATRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80)),
				SNATIP:            net.ParseIP("192.168.1.1"),
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
		},
		{
			name:     "UDP rule with multiple ports",
			spec:     []string{"-m", "set", "--match-set", "my-ipset", "src", "-p", "udp", "-m", "multiport", "--sports", "53,123,161", "-j", "SNAT", "--to", "10.0.0.1"},
			protocol: iptables.IPv6,
			expected: &IPTablesSNATRule{
				SrcIPSetName:      "my-ipset",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(123), uint16(161)),
				SNATIP:            net.ParseIP("10.0.0.1"),
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.UDP,
			},
		},
		{
			name:     "TCP rule with IPv6 SNAT",
			spec:     []string{"-m", "set", "--match-set", "ipv6-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "443,8080", "-j", "SNAT", "--to", "2001:db8::1"},
			protocol: iptables.IPv6,
			expected: &IPTablesSNATRule{
				SrcIPSetName:      "ipv6-set",
				SrcPorts:          set.NewWithItems(uint16(443), uint16(8080)),
				SNATIP:            net.ParseIP("2001:db8::1"),
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.TCP,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesSNATRule(tt.spec, tt.protocol)
			if !ok {
				t.Fatalf("ParseIPTablesSNATRule() failed, expected success")
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIPTablesSNATRule() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseIPTablesSNATRule_Invalid(t *testing.T) {
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
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "icmp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing module for match-set",
			spec:     []string{"--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--to", "192.168.1.1", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong match-set direction",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Sports without multiport module",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "--sports", "80", "-j", "SNAT", "--to", "192.168.1.1", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid port number",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "invalid", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Port number too large",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "70000", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid SNAT IP",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--to", "invalid-ip"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong jump target",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "DNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing --to argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "192.168.1.1", "extra", "arg"},
			protocol: iptables.IPv4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesSNATRule(tt.spec, tt.protocol)
			if ok {
				t.Errorf("ParseIPTablesSNATRule() succeeded with %+v, expected failure", result)
			}
		})
	}
}

func TestIPTablesSNATRule_Spec(t *testing.T) {
	tests := []struct {
		name     string
		rule     *IPTablesSNATRule
		expected []string
	}{
		{
			name: "TCP rule with single port",
			rule: &IPTablesSNATRule{
				SrcIPSetName:      "test-set",
				SrcPorts:          set.NewWithItems(uint16(80)),
				SNATIP:            net.ParseIP("192.168.1.1"),
				Protocol:          iptables.IPv4,
				TransportProtocol: iptables.TCP,
			},
			expected: []string{"-m", "set", "--match-set", "test-set", "src", "-p", "tcp", "-m", "multiport", "--sports", "80", "-j", "SNAT", "--to", "192.168.1.1"},
		},
		{
			name: "UDP rule with multiple ports",
			rule: &IPTablesSNATRule{
				SrcIPSetName:      "my-ipset",
				SrcPorts:          set.NewWithItems(uint16(53), uint16(123), uint16(161)),
				SNATIP:            net.ParseIP("10.0.0.1"),
				Protocol:          iptables.IPv6,
				TransportProtocol: iptables.UDP,
			},
			expected: []string{"-m", "set", "--match-set", "my-ipset", "src", "-p", "udp", "-m", "multiport", "--sports", "53,123,161", "-j", "SNAT", "--to", "10.0.0.1"},
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

func TestIPTablesSNATRule_RoundTrip(t *testing.T) {
	original := &IPTablesSNATRule{
		SrcIPSetName:      "test-set",
		SrcPorts:          set.NewWithItems(uint16(80), uint16(443), uint16(8080)),
		SNATIP:            net.ParseIP("192.168.1.100"),
		Protocol:          iptables.IPv4,
		TransportProtocol: iptables.TCP,
	}

	// Generate spec from original rule
	spec := original.Spec()

	// Parse the generated spec back
	parsed, ok := ParseIPTablesSNATRule(spec, original.Protocol)
	if !ok {
		t.Fatalf("Failed to parse generated spec")
	}

	// Compare the parsed rule with the original
	if parsed.SrcIPSetName != original.SrcIPSetName {
		t.Errorf("SrcIPSetName mismatch: got %s, want %s", parsed.SrcIPSetName, original.SrcIPSetName)
	}
	if !parsed.SNATIP.Equal(original.SNATIP) {
		t.Errorf("SNATIP mismatch: got %s, want %s", parsed.SNATIP, original.SNATIP)
	}
	if parsed.Protocol != original.Protocol {
		t.Errorf("Protocol mismatch: got %s, want %s", parsed.Protocol, original.Protocol)
	}
	if parsed.TransportProtocol != original.TransportProtocol {
		t.Errorf("TransportProtocol mismatch: got %s, want %s", parsed.TransportProtocol, original.TransportProtocol)
	}
	if !parsed.SrcPorts.Equals(original.SrcPorts) {
		t.Errorf("SrcPorts mismatch: got %v, want %v", parsed.SrcPorts, original.SrcPorts)
	}
}
