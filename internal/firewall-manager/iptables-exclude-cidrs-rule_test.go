package firewall_manager

import (
	"reflect"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

func TestParseIPTablesExcludeCIDRsRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
		expected *IPTablesExcludeCIDRsRule
	}{
		{
			name:     "Simple exclude rule",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-j", "RETURN"},
			protocol: iptables.IPv4,
			expected: &IPTablesExcludeCIDRsRule{
				IPSetName: "test-set",
				Protocol:  iptables.IPv4,
			},
		},
		{
			name:     "IPv6 exclude rule",
			spec:     []string{"-m", "set", "--match-set", "ipv6-set", "dst", "-j", "RETURN"},
			protocol: iptables.IPv6,
			expected: &IPTablesExcludeCIDRsRule{
				IPSetName: "ipv6-set",
				Protocol:  iptables.IPv6,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesExcludeCIDRsRule(tt.spec, tt.protocol)
			if !ok {
				t.Fatalf("ParseIPTablesExcludeCIDRsRule() failed, expected success")
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIPTablesExcludeCIDRsRule() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseIPTablesExcludeCIDRsRule_Invalid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
	}{
		{
			name:     "Wrong number of arguments",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-j"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong module",
			spec:     []string{"-m", "state", "--match-set", "test-set", "dst", "-j", "RETURN"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong match-set direction",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "RETURN"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong jump target",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-j", "DROP"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Unrecognized argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-j", "RETURN", "extra"},
			protocol: iptables.IPv4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesExcludeCIDRsRule(tt.spec, tt.protocol)
			if ok {
				t.Errorf("ParseIPTablesExcludeCIDRsRule() succeeded with %+v, expected failure", result)
			}
		})
	}
}

func TestIPTablesExcludeCIDRsRule_Spec(t *testing.T) {
	tests := []struct {
		name     string
		rule     *IPTablesExcludeCIDRsRule
		expected []string
	}{
		{
			name: "Simple rule",
			rule: &IPTablesExcludeCIDRsRule{
				IPSetName: "test-set",
				Protocol:  iptables.IPv4,
			},
			expected: []string{"-m", "set", "--match-set", "test-set", "dst", "-j", "RETURN"},
		},
		{
			name: "IPv6 rule",
			rule: &IPTablesExcludeCIDRsRule{
				IPSetName: "ipv6-set",
				Protocol:  iptables.IPv6,
			},
			expected: []string{"-m", "set", "--match-set", "ipv6-set", "dst", "-j", "RETURN"},
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

func TestIPTablesExcludeCIDRsRule_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rule *IPTablesExcludeCIDRsRule
	}{
		{
			name: "IPv4 rule",
			rule: &IPTablesExcludeCIDRsRule{
				IPSetName: "test-set",
				Protocol:  iptables.IPv4,
			},
		},
		{
			name: "IPv6 rule",
			rule: &IPTablesExcludeCIDRsRule{
				IPSetName: "ipv6-set",
				Protocol:  iptables.IPv6,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := tt.rule.Spec()
			parsed, ok := ParseIPTablesExcludeCIDRsRule(spec, tt.rule.Protocol)
			if !ok {
				t.Fatalf("Failed to parse generated spec")
			}
			if !reflect.DeepEqual(parsed, tt.rule) {
				t.Errorf("Round trip failed: got %+v, want %+v", parsed, tt.rule)
			}
		})
	}
}
