package iptables

import (
	"reflect"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

func TestParseRejectRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
		expected *RejectRule
	}{
		{
			name:     "Simple reject rule IPv4",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
			expected: &RejectRule{
				SrcIPSetName: "test-set",
				Protocol:     iptables.IPv4,
			},
		},
		{
			name:     "Simple reject rule IPv6",
			spec:     []string{"-m", "set", "--match-set", "my-ipset", "src", "-j", "REJECT", "--reject-with", "icmp6-port-unreachable"},
			protocol: iptables.IPv6,
			expected: &RejectRule{
				SrcIPSetName: "my-ipset",
				Protocol:     iptables.IPv6,
			},
		},
		{
			name:     "Another IPv4 reject rule",
			spec:     []string{"-m", "set", "--match-set", "block-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
			expected: &RejectRule{
				SrcIPSetName: "block-set",
				Protocol:     iptables.IPv4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseRejectRule(tt.spec, tt.protocol)
			if !ok {
				t.Fatalf("ParseRejectRule() failed, expected success")
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseRejectRule() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseRejectRule_Invalid(t *testing.T) {
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
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable", "extra", "arg"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing module for match-set",
			spec:     []string{"--match-set", "test-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong match-set direction",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong module type",
			spec:     []string{"-m", "state", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong jump target",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong reject-with option for IPv4",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-with", "tcp-reset"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong reject-with option for IPv6",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv6,
		},
		{
			name:     "Missing --reject-with argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-with"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong reject option",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-type", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Unrecognized argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "--unknown", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
			protocol: iptables.IPv4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseRejectRule(tt.spec, tt.protocol)
			if ok {
				t.Errorf("ParseRejectRule() succeeded with %+v, expected failure", result)
			}
		})
	}
}

func TestRejectRule_Spec(t *testing.T) {
	tests := []struct {
		name     string
		rule     *RejectRule
		expected []string
	}{
		{
			name: "Simple IPv4 reject rule",
			rule: &RejectRule{
				SrcIPSetName: "test-set",
				Protocol:     iptables.IPv4,
			},
			expected: []string{"-m", "set", "--match-set", "test-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
		},
		{
			name: "Simple IPv6 reject rule",
			rule: &RejectRule{
				SrcIPSetName: "my-ipset",
				Protocol:     iptables.IPv6,
			},
			expected: []string{"-m", "set", "--match-set", "my-ipset", "src", "-j", "REJECT", "--reject-with", "icmp6-port-unreachable"},
		},
		{
			name: "Another IPv4 reject rule",
			rule: &RejectRule{
				SrcIPSetName: "block-set",
				Protocol:     iptables.IPv4,
			},
			expected: []string{"-m", "set", "--match-set", "block-set", "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"},
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

func TestRejectRule_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rule *RejectRule
	}{
		{
			name: "IPv4 reject rule",
			rule: &RejectRule{
				SrcIPSetName: "test-set",
				Protocol:     iptables.IPv4,
			},
		},
		{
			name: "IPv6 reject rule",
			rule: &RejectRule{
				SrcIPSetName: "ipv6-set",
				Protocol:     iptables.IPv6,
			},
		},
		{
			name: "Another IPv4 rule",
			rule: &RejectRule{
				SrcIPSetName: "block-list",
				Protocol:     iptables.IPv4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate spec from original rule
			spec := tt.rule.Spec()

			// Parse the generated spec back
			parsed, ok := ParseRejectRule(spec, tt.rule.Protocol)
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
