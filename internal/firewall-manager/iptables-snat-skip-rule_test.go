package firewall_manager

import (
	"reflect"
	"testing"
)

func TestParseIPTablesSNATSkipRule_Valid(t *testing.T) {
	tests := []struct {
		name     string
		spec     []string
		expected *IPTablesSNATSkipRule
	}{
		{
			name: "Simple skip rule with low mask",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xff", "-j", "RETURN"},
			expected: &IPTablesSNATSkipRule{
				FWMask: 0xff,
			},
		},
		{
			name: "Skip rule with high mask",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xffff", "-j", "RETURN"},
			expected: &IPTablesSNATSkipRule{
				FWMask: 0xffff,
			},
		},
		{
			name: "Skip rule with full mask",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xffffffff", "-j", "RETURN"},
			expected: &IPTablesSNATSkipRule{
				FWMask: 0xffffffff,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesSNATSkipRule(tt.spec)
			if !ok {
				t.Fatalf("ParseIPTablesSNATSkipRule() failed, expected success")
			}
			if !reflect.DeepEqual(result, tt.expected) {
				t.Errorf("ParseIPTablesSNATSkipRule() = %+v, want %+v", result, tt.expected)
			}
		})
	}
}

func TestParseIPTablesSNATSkipRule_Invalid(t *testing.T) {
	tests := []struct {
		name string
		spec []string
	}{
		{
			name: "Wrong number of arguments - too few",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xff"},
		},
		{
			name: "Wrong number of arguments - too many",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xff", "-j", "RETURN", "extra"},
		},
		{
			name: "Missing negation",
			spec: []string{"-m", "mark", "--mark", "0x0/0xff", "-j", "RETURN", "extra"},
		},
		{
			name: "Wrong module type",
			spec: []string{"-m", "state", "!", "--mark", "0x0/0xff", "-j", "RETURN"},
		},
		{
			name: "Wrong mark option without module",
			spec: []string{"!", "--mark", "0x0/0xff", "-j", "RETURN", "extra", "args"},
		},
		{
			name: "Non-zero mark value",
			spec: []string{"-m", "mark", "!", "--mark", "0x1/0xff", "-j", "RETURN"},
		},
		{
			name: "Invalid mark format - no slash",
			spec: []string{"-m", "mark", "!", "--mark", "0x0", "-j", "RETURN"},
		},
		{
			name: "Invalid mark format - invalid hex mark",
			spec: []string{"-m", "mark", "!", "--mark", "0xzz/0xff", "-j", "RETURN"},
		},
		{
			name: "Invalid mark format - invalid hex mask",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xzz", "-j", "RETURN"},
		},
		{
			name: "Wrong jump target",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xff", "-j", "ACCEPT"},
		},
		{
			name: "Missing jump target",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xff", "-j"},
		},
		{
			name: "Negation in wrong position",
			spec: []string{"-m", "mark", "--mark", "!", "0x0/0xff", "-j", "RETURN"},
		},
		{
			name: "Unrecognized argument",
			spec: []string{"-m", "mark", "!", "--mark", "0x0/0xff", "--unknown", "RETURN"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, ok := ParseIPTablesSNATSkipRule(tt.spec)
			if ok {
				t.Errorf("ParseIPTablesSNATSkipRule() succeeded with %+v, expected failure", result)
			}
		})
	}
}

func TestIPTablesSNATSkipRule_Spec(t *testing.T) {
	tests := []struct {
		name     string
		rule     *IPTablesSNATSkipRule
		expected []string
	}{
		{
			name: "Skip rule with low mask",
			rule: &IPTablesSNATSkipRule{
				FWMask: 0xff,
			},
			expected: []string{"-m", "mark", "!", "--mark", "0x0/0xff", "-j", "RETURN"},
		},
		{
			name: "Skip rule with high mask",
			rule: &IPTablesSNATSkipRule{
				FWMask: 0xffff,
			},
			expected: []string{"-m", "mark", "!", "--mark", "0x0/0xffff", "-j", "RETURN"},
		},
		{
			name: "Skip rule with full mask",
			rule: &IPTablesSNATSkipRule{
				FWMask: 0xffffffff,
			},
			expected: []string{"-m", "mark", "!", "--mark", "0x0/0xffffffff", "-j", "RETURN"},
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

func TestIPTablesSNATSkipRule_RoundTrip(t *testing.T) {
	tests := []struct {
		name string
		rule *IPTablesSNATSkipRule
	}{
		{
			name: "Skip rule with 8-bit mask",
			rule: &IPTablesSNATSkipRule{
				FWMask: 0xff,
			},
		},
		{
			name: "Skip rule with 16-bit mask",
			rule: &IPTablesSNATSkipRule{
				FWMask: 0xffff,
			},
		},
		{
			name: "Skip rule with 32-bit mask",
			rule: &IPTablesSNATSkipRule{
				FWMask: 0xffffffff,
			},
		},
		{
			name: "Skip rule with custom mask",
			rule: &IPTablesSNATSkipRule{
				FWMask: 0xdeadbeef,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Generate spec from original rule
			spec := tt.rule.Spec()

			// Parse the generated spec back
			parsed, ok := ParseIPTablesSNATSkipRule(spec)
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
