package iptables

import (
	"reflect"
	"testing"
)

func TestIPTablesSpecParser_Comprehensive(t *testing.T) {
	tests := []struct {
		name       string
		args       [][]string
		spec       []string
		expectOk   bool
		expectVals map[string]string
	}{
		{
			name: "simple match",
			args: [][]string{
				{"-p", "tcp"},
				{"-j", "ACCEPT"},
			},
			spec:       []string{"-p", "tcp", "-j", "ACCEPT"},
			expectOk:   true,
			expectVals: map[string]string{},
		},
		{
			name: "with placeholder",
			args: [][]string{
				{"-p", "{protocol}"},
				{"--dport", "{port}"},
				{"-j", "ACCEPT"},
			},
			spec:       []string{"-p", "tcp", "--dport", "8080", "-j", "ACCEPT"},
			expectOk:   true,
			expectVals: map[string]string{"protocol": "tcp", "port": "8080"},
		},
		{
			name: "multiple placeholders in one arg",
			args: [][]string{
				{"-s", "{source_ip}", "-d", "{dest_ip}"},
				{"-j", "ACCEPT"},
			},
			spec:       []string{"-s", "192.168.1.1", "-d", "10.0.0.1", "-j", "ACCEPT"},
			expectOk:   true,
			expectVals: map[string]string{"source_ip": "192.168.1.1", "dest_ip": "10.0.0.1"},
		},
		{
			name: "spec too short",
			args: [][]string{
				{"-p", "tcp"},
				{"--dport", "{port}"},
			},
			spec:     []string{"-p", "tcp"},
			expectOk: false,
		},
		{
			name: "wrong first argument",
			args: [][]string{
				{"-p", "tcp"},
				{"-j", "ACCEPT"},
			},
			spec:     []string{"-p", "udp", "-j", "ACCEPT"},
			expectOk: false,
		},
		{
			name: "wrong non-placeholder value",
			args: [][]string{
				{"-p", "{protocol}"},
				{"-j", "ACCEPT"},
			},
			spec:     []string{"-p", "tcp", "-j", "DROP"},
			expectOk: false,
		},
		{
			name: "empty arg definition",
			args: [][]string{
				{},
				{"-p", "tcp"},
				{"-j", "ACCEPT"},
			},
			spec:     []string{"-p", "tcp", "-j", "ACCEPT"},
			expectOk: false,
		},
		{
			name: "unmatched spec argument",
			args: [][]string{
				{"-p", "tcp"},
			},
			spec:     []string{"-p", "tcp", "-j", "ACCEPT"},
			expectOk: false,
		},
		{
			name: "not all args matched",
			args: [][]string{
				{"-p", "tcp"},
				{"-j", "ACCEPT"},
				{"--dport", "{port}"},
			},
			spec:     []string{"-p", "tcp", "-j", "ACCEPT"},
			expectOk: false,
		},
		{
			name: "insufficient values for arg",
			args: [][]string{
				{"-p", "tcp", "--sport", "{sport}"},
			},
			spec:     []string{"-p", "tcp", "--sport"},
			expectOk: false,
		},
		{
			name: "complex realistic rule",
			args: [][]string{
				{"-p", "{protocol}"},
				{"-m", "{protocol}"},
				{"--dport", "{port}"},
				{"-s", "{source}"},
				{"-j", "ACCEPT"},
			},
			spec:       []string{"-p", "tcp", "-m", "tcp", "--dport", "443", "-s", "192.168.1.0/24", "-j", "ACCEPT"},
			expectOk:   true,
			expectVals: map[string]string{"protocol": "tcp", "port": "443", "source": "192.168.1.0/24"},
		},
		{
			name: "arguments out of order",
			args: [][]string{
				{"-p", "tcp"},
				{"-j", "ACCEPT"},
			},
			spec:       []string{"-j", "ACCEPT", "-p", "tcp"},
			expectOk:   true,
			expectVals: map[string]string{},
		},
		{
			name: "single argument with multiple values",
			args: [][]string{
				{"-m", "multiport", "--dports", "{ports}"},
				{"-j", "ACCEPT"},
			},
			spec:       []string{"-m", "multiport", "--dports", "80,443,8080", "-j", "ACCEPT"},
			expectOk:   true,
			expectVals: map[string]string{"ports": "80,443,8080"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewIPTablesSpecParser(tt.args)
			if parser == nil {
				t.Fatal("Expected non-nil parser")
			}

			vals, ok := parser.Parse(tt.spec)

			if ok != tt.expectOk {
				t.Errorf("Expected ok=%v, got ok=%v", tt.expectOk, ok)
				return
			}

			if tt.expectOk {
				if !reflect.DeepEqual(vals, tt.expectVals) {
					t.Errorf("Expected values %v, got %v", tt.expectVals, vals)
				}
			}
		})
	}
}

func TestIPTablesSpecParser_EdgeCases(t *testing.T) {
	t.Run("nil args", func(t *testing.T) {
		parser := NewIPTablesSpecParser(nil)
		if parser == nil {
			t.Fatal("Expected non-nil parser even with nil args")
		}

		vals, ok := parser.Parse([]string{"-p", "tcp"})
		if ok {
			t.Error("Expected parsing to fail with nil args")
		}
		if vals != nil {
			t.Error("Expected nil values when parsing fails")
		}
	})

	t.Run("empty spec", func(t *testing.T) {
		args := [][]string{
			{"-p", "tcp"},
		}
		parser := NewIPTablesSpecParser(args)

		vals, ok := parser.Parse([]string{})
		if ok {
			t.Error("Expected parsing to fail with empty spec")
		}
		if vals != nil {
			t.Error("Expected nil values when parsing fails")
		}
	})

	t.Run("empty args list", func(t *testing.T) {
		parser := NewIPTablesSpecParser([][]string{})

		vals, ok := parser.Parse([]string{"-p", "tcp"})
		if ok {
			t.Error("Expected parsing to fail with empty args list")
		}
		if vals != nil {
			t.Error("Expected nil values when parsing fails")
		}
	})

	t.Run("placeholder edge cases", func(t *testing.T) {
		args := [][]string{
			{"{", "}"},      // invalid placeholder format
			{"{}", "value"}, // empty placeholder
			{"{valid_placeholder}", "fixed_value"},
		}
		parser := NewIPTablesSpecParser(args)

		// This should not match because "{" and "}" are not valid placeholders
		vals, ok := parser.Parse([]string{"{", "}", "{}", "value", "anything", "fixed_value"})
		if ok {
			t.Error("Expected parsing to fail with invalid placeholder format")
		}
		if vals != nil {
			t.Error("Expected nil values when parsing fails")
		}
	})

	t.Run("complex placeholders", func(t *testing.T) {
		args := [][]string{
			{"-s", "{source_address}"},
			{"--dport", "{destination_port}"},
			{"-j", "ACCEPT"},
		}
		parser := NewIPTablesSpecParser(args)

		// This tests placeholders with underscores and descriptive names
		vals, ok := parser.Parse([]string{"-s", "192.168.1.1", "--dport", "8080", "-j", "ACCEPT"})
		if !ok {
			t.Error("Expected parsing to succeed with complex placeholders")
		}
		if vals["source_address"] != "192.168.1.1" {
			t.Errorf("Expected source_address to be '192.168.1.1', got '%s'", vals["source_address"])
		}
		if vals["destination_port"] != "8080" {
			t.Errorf("Expected destination_port to be '8080', got '%s'", vals["destination_port"])
		}
	})
}

func TestIPTablesSpecParser_RealWorldExamples(t *testing.T) {
	t.Run("SNAT rule", func(t *testing.T) {
		args := [][]string{
			{"-o", "{interface}"},
			{"-j", "SNAT"},
			{"--to-source", "{source_ip}"},
		}
		parser := NewIPTablesSpecParser(args)

		spec := []string{"-o", "eth0", "-j", "SNAT", "--to-source", "10.0.0.1"}
		vals, ok := parser.Parse(spec)

		if !ok {
			t.Error("Expected SNAT rule parsing to succeed")
		}

		expectedVals := map[string]string{
			"interface": "eth0",
			"source_ip": "10.0.0.1",
		}

		if !reflect.DeepEqual(vals, expectedVals) {
			t.Errorf("Expected values %v, got %v", expectedVals, vals)
		}
	})

	t.Run("DNAT rule", func(t *testing.T) {
		args := [][]string{
			{"-i", "{interface}"},
			{"-p", "{protocol}"},
			{"--dport", "{port}"},
			{"-j", "DNAT"},
			{"--to-destination", "{dest}"},
		}
		parser := NewIPTablesSpecParser(args)

		spec := []string{"-i", "eth1", "-p", "tcp", "--dport", "80", "-j", "DNAT", "--to-destination", "192.168.1.10:8080"}
		vals, ok := parser.Parse(spec)

		if !ok {
			t.Error("Expected DNAT rule parsing to succeed")
		}

		expectedVals := map[string]string{
			"interface": "eth1",
			"protocol":  "tcp",
			"port":      "80",
			"dest":      "192.168.1.10:8080",
		}

		if !reflect.DeepEqual(vals, expectedVals) {
			t.Errorf("Expected values %v, got %v", expectedVals, vals)
		}
	})

	t.Run("MARK rule", func(t *testing.T) {
		args := [][]string{
			{"-p", "{protocol}"},
			{"-m", "{protocol}"},
			{"--dport", "{port}"},
			{"-j", "MARK"},
			{"--set-xmark", "{mark}"},
		}
		parser := NewIPTablesSpecParser(args)

		spec := []string{"-p", "tcp", "-m", "tcp", "--dport", "443", "-j", "MARK", "--set-xmark", "0x1/0xffffffff"}
		vals, ok := parser.Parse(spec)

		if !ok {
			t.Error("Expected MARK rule parsing to succeed")
		}

		expectedVals := map[string]string{
			"protocol": "tcp",
			"port":     "443",
			"mark":     "0x1/0xffffffff",
		}

		if !reflect.DeepEqual(vals, expectedVals) {
			t.Errorf("Expected values %v, got %v", expectedVals, vals)
		}
	})
}
