package iptables

import (
	"reflect"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

func TestParseMarkRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		protocol iptables.Protocol
		expected *MarkRule
	}{
		{
			name:     "Simple mark rule",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
			expected: &MarkRule{
				SrcIPSetName: "test-set",
				FWMark:       0x1,
				FWMask:       0xff,
				Protocol:     iptables.IPv4,
			},
		},
		{
			name:     "IPv6 rule with different mark",
			spec:     []string{"-m", "set", "--match-set", "my-ipset", "src", "-j", "MARK", "--set-xmark", "0xab/0xffff"},
			protocol: iptables.IPv6,
			expected: &MarkRule{
				SrcIPSetName: "my-ipset",
				FWMark:       0xab,
				FWMask:       0xffff,
				Protocol:     iptables.IPv6,
			},
		},
		{
			name:     "High mark values",
			spec:     []string{"-m", "set", "--match-set", "high-mark", "src", "-j", "MARK", "--set-xmark", "0xdeadbeef/0xffffffff"},
			protocol: iptables.IPv4,
			expected: &MarkRule{
				SrcIPSetName: "high-mark",
				FWMark:       0xdeadbeef,
				FWMask:       0xffffffff,
				Protocol:     iptables.IPv4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseMarkRule(tt.spec, tt.protocol)
			if !ok {
				t.Fatalf("ParseMarkRule() failed, expected success")
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseMarkRule() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseMarkRule_Invalid(t *testing.T) {
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
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0x1/0xff", "extra", "arg"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing module for match-set",
			spec:     []string{"--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0x1/0xff", "extra", "args"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong match-set direction",
			spec:     []string{"-m", "set", "--match-set", "test-set", "dst", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong module type",
			spec:     []string{"-m", "state", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong jump target",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "SNAT", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Wrong mark option",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-mark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid mark format - no slash",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0x1"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid mark format - invalid hex mark",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0xzz/0xff"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Invalid mark format - invalid hex mask",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0x1/0xzz"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Missing --set-xmark argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark"},
			protocol: iptables.IPv4,
		},
		{
			name:     "Unrecognized argument",
			spec:     []string{"-m", "set", "--match-set", "test-set", "src", "--unknown", "-j", "MARK", "--set-xmark", "0x1/0xff"},
			protocol: iptables.IPv4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseMarkRule(tt.spec, tt.protocol)
			if ok {
				t.Errorf("ParseMarkRule() succeeded with %+v, expected failure", result)
			}
		})
	}
}

func TestMarkRule_Spec(t *testing.T) {
	tests := []struct {
		name     string
		rule     *MarkRule
		expected []string
	}{
		{
			name: "Simple rule with low mark",
			rule: &MarkRule{
				SrcIPSetName: "test-set",
				FWMark:       0x1,
				FWMask:       0xff,
				Protocol:     iptables.IPv4,
			},
			expected: []string{"-m", "set", "--match-set", "test-set", "src", "-j", "MARK", "--set-xmark", "0x1/0xff"},
		},
		{
			name: "IPv6 rule with different mark",
			rule: &MarkRule{
				SrcIPSetName: "my-ipset",
				FWMark:       0xab,
				FWMask:       0xffff,
				Protocol:     iptables.IPv6,
			},
			expected: []string{"-m", "set", "--match-set", "my-ipset", "src", "-j", "MARK", "--set-xmark", "0xab/0xffff"},
		},
		{
			name: "High mark values",
			rule: &MarkRule{
				SrcIPSetName: "high-mark",
				FWMark:       0xdeadbeef,
				FWMask:       0xffffffff,
				Protocol:     iptables.IPv4,
			},
			expected: []string{"-m", "set", "--match-set", "high-mark", "src", "-j", "MARK", "--set-xmark", "0xdeadbeef/0xffffffff"},
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

func TestMarkRule_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rule *MarkRule
	}{
		{
			name: "IPv4 rule with low mark",
			rule: &MarkRule{
				SrcIPSetName: "test-set",
				FWMark:       0x1,
				FWMask:       0xff,
				Protocol:     iptables.IPv4,
			},
		},
		{
			name: "IPv6 rule with high mark",
			rule: &MarkRule{
				SrcIPSetName: "ipv6-set",
				FWMark:       0xdeadbeef,
				FWMask:       0xffffffff,
				Protocol:     iptables.IPv6,
			},
		},
		{
			name: "Rule with zero mark",
			rule: &MarkRule{
				SrcIPSetName: "zero-mark",
				FWMark:       0x0,
				FWMask:       0xff,
				Protocol:     iptables.IPv4,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate spec from original rule
			spec := tt.rule.Spec()

			// Parse the generated spec back
			parsed, ok := ParseMarkRule(spec, tt.rule.Protocol)
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
