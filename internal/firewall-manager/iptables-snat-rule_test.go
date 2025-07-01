package firewall_manager

import (
	"net"
	"reflect"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

func TestParseIPTablesSNATRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
		expected *IPTablesSNATRule
	}{
		{
			name:     "Simple SNAT rule IPv4",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
			expected: &IPTablesSNATRule{
				SrcIPSetName: "test-set",
				SNATIP:       net.ParseIP("192.168.1.1"),
				Protocol:     iptables.IPv4,
			},
		},
		{
			name:     "SNAT rule with different IPv4",
			spec:     []string{"-m", "set", "--match-set", "my-ipset", "src", "-j", "SNAT", "--to", "10.0.0.1"},
			protocol: iptables.IPv4,
			expected: &IPTablesSNATRule{
				SrcIPSetName: "my-ipset",
				SNATIP:       net.ParseIP("10.0.0.1"),
				Protocol:     iptables.IPv4,
			},
		},
		{
			name:     "SNAT rule with IPv6",
			spec:     []string{"-m", "set", "--match-set", "ipv6-set", "src", "-j", "SNAT", "--to", "2001:db8::1"},
			protocol: iptables.IPv6,
			expected: &IPTablesSNATRule{
				SrcIPSetName: "ipv6-set",
				SNATIP:       net.ParseIP("2001:db8::1"),
				Protocol:     iptables.IPv6,
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
			name:     "Wrong number of arguments - too few",
			spec:     []string{"-m", "set", "--match-set", "test-set"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong number of arguments - too many",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--to", "192.168.1.1", "extra", "arg"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing module for match-set",
			spec:     []string{"--match-set", "test-set", "src", "-j", "SNAT", "--to", "192.168.1.1", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong match-set direction",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong module type",
			spec:     []string{"-m", "state", "--match-set", "test-set", "src", "-j", "SNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid SNAT IP",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--to", "invalid-ip"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong jump target",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "DNAT", "--to", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong SNAT option",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--to-source", "192.168.1.1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing --to argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--to"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing SNAT IP address",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "192.168.1.1", "extra"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Unrecognized argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "--unknown", "-j", "SNAT", "--to", "192.168.1.1"},
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
			name: "Simple IPv4 SNAT rule",
			rule: &IPTablesSNATRule{
				SrcIPSetName: "test-set",
				SNATIP:       net.ParseIP("192.168.1.1"),
				Protocol:     iptables.IPv4,
			},
			expected: []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--to", "192.168.1.1"},
		},
		{
			name: "IPv4 SNAT rule with different IP",
			rule: &IPTablesSNATRule{
				SrcIPSetName: "my-ipset",
				SNATIP:       net.ParseIP("10.0.0.1"),
				Protocol:     iptables.IPv4,
			},
			expected: []string{"-m", "set", "--match-set", "my-ipset", "src", "-j", "SNAT", "--to", "10.0.0.1"},
		},
		{
			name: "IPv6 SNAT rule",
			rule: &IPTablesSNATRule{
				SrcIPSetName: "ipv6-set",
				SNATIP:       net.ParseIP("2001:db8::1"),
				Protocol:     iptables.IPv6,
			},
			expected: []string{"-m", "set", "--match-set", "ipv6-set", "src", "-j", "SNAT", "--to", "2001:db8::1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.rule.Spec()
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("Spec() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestIPTablesSNATRule_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rule *IPTablesSNATRule
	}{
		{
			name: "IPv4 SNAT rule",
			rule: &IPTablesSNATRule{
				SrcIPSetName: "test-set",
				SNATIP:       net.ParseIP("192.168.1.100"),
				Protocol:     iptables.IPv4,
			},
		},
		{
			name: "IPv6 SNAT rule",
			rule: &IPTablesSNATRule{
				SrcIPSetName: "ipv6-set",
				SNATIP:       net.ParseIP("2001:db8::42"),
				Protocol:     iptables.IPv6,
			},
		},
		{
			name: "Another IPv4 rule",
			rule: &IPTablesSNATRule{
				SrcIPSetName: "nat-set",
				SNATIP:       net.ParseIP("203.0.113.1"),
				Protocol:     iptables.IPv4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate spec from original rule
			spec := tt.rule.Spec()

			// Parse the generated spec back
			parsed, ok := ParseIPTablesSNATRule(spec, tt.rule.Protocol)
			if !ok {
				t.Fatalf("Failed to parse generated spec")
			}

			// Compare the parsed rule with the original
			if !reflect.DeepEqual(parsed, tt.rule) {
				t.Errorf("Round trip failed: got %+v, want %+v", parsed, tt.rule)
			}
		})
	}
}
