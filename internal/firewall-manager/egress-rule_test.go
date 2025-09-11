package firewall_manager

import (
	"net"
	"testing"

	rm "github.com/gerolf-vent/metaleg/internal/route-manager"
)

func TestNewEgressRule(t *testing.T) {
	rule := NewEgressRule("test-rule")
	
	if rule == nil {
		t.Fatal("expected non-nil egress rule")
	}
	if rule.ID != "test-rule" {
		t.Errorf("expected ID 'test-rule', got %v", rule.ID)
	}
	if rule.SrcIPv4s != nil {
		t.Error("expected SrcIPv4s to be nil by default")
	}
	if rule.SrcIPv6s != nil {
		t.Error("expected SrcIPv6s to be nil by default")
	}
	if rule.SNATIPv4 != nil {
		t.Error("expected SNATIPv4 to be nil by default")
	}
	if rule.SNATIPv6 != nil {
		t.Error("expected SNATIPv6 to be nil by default")
	}
	if rule.GWNodeName != "" {
		t.Error("expected GWNodeName to be empty by default")
	}
	if rule.GWRoute != nil {
		t.Error("expected GWRoute to be nil by default")
	}
}

func TestEgressRule_CalcIDHash(t *testing.T) {
	rule := NewEgressRule("test-rule-id")
	
	t.Run("IPv4 hash", func(t *testing.T) {
		hash := rule.CalcIDHash(false)
		
		if len(hash) != 12 {
			t.Errorf("expected hash length 12, got %d", len(hash))
		}
		
		// Hash should be uppercase
		for _, char := range hash {
			if char >= 'a' && char <= 'z' {
				t.Error("expected hash to be uppercase")
				break
			}
		}
		
		// Same input should produce same hash
		hash2 := rule.CalcIDHash(false)
		if hash != hash2 {
			t.Error("expected consistent hash for same input")
		}
	})
	
	t.Run("IPv6 hash", func(t *testing.T) {
		hash := rule.CalcIDHash(true)
		
		if len(hash) != 12 {
			t.Errorf("expected hash length 12, got %d", len(hash))
		}
		
		// IPv6 hash should be different from IPv4 hash
		ipv4Hash := rule.CalcIDHash(false)
		if hash == ipv4Hash {
			t.Error("expected IPv6 hash to be different from IPv4 hash")
		}
	})
	
	t.Run("different IDs produce different hashes", func(t *testing.T) {
		rule1 := NewEgressRule("rule-1")
		rule2 := NewEgressRule("rule-2")
		
		hash1 := rule1.CalcIDHash(false)
		hash2 := rule2.CalcIDHash(false)
		
		if hash1 == hash2 {
			t.Error("expected different rules to produce different hashes")
		}
	})
}

func TestEgressRule_FieldAssignment(t *testing.T) {
	rule := NewEgressRule("test-rule")
	
	// Test IPv4 addresses
	srcIPv4s := []net.IP{
		net.ParseIP("10.0.1.1"),
		net.ParseIP("10.0.1.2"),
	}
	rule.SrcIPv4s = srcIPv4s
	
	if len(rule.SrcIPv4s) != 2 {
		t.Errorf("expected 2 source IPv4 addresses, got %d", len(rule.SrcIPv4s))
	}
	if !rule.SrcIPv4s[0].Equal(net.ParseIP("10.0.1.1")) {
		t.Errorf("expected first IPv4 to be 10.0.1.1, got %v", rule.SrcIPv4s[0])
	}
	
	// Test IPv6 addresses
	srcIPv6s := []net.IP{
		net.ParseIP("2001:db8::1"),
		net.ParseIP("2001:db8::2"),
	}
	rule.SrcIPv6s = srcIPv6s
	
	if len(rule.SrcIPv6s) != 2 {
		t.Errorf("expected 2 source IPv6 addresses, got %d", len(rule.SrcIPv6s))
	}
	if !rule.SrcIPv6s[0].Equal(net.ParseIP("2001:db8::1")) {
		t.Errorf("expected first IPv6 to be 2001:db8::1, got %v", rule.SrcIPv6s[0])
	}
	
	// Test SNAT addresses
	rule.SNATIPv4 = net.ParseIP("192.168.1.100")
	rule.SNATIPv6 = net.ParseIP("2001:db8:100::1")
	
	if !rule.SNATIPv4.Equal(net.ParseIP("192.168.1.100")) {
		t.Errorf("expected SNAT IPv4 to be 192.168.1.100, got %v", rule.SNATIPv4)
	}
	if !rule.SNATIPv6.Equal(net.ParseIP("2001:db8:100::1")) {
		t.Errorf("expected SNAT IPv6 to be 2001:db8:100::1, got %v", rule.SNATIPv6)
	}
	
	// Test gateway node name
	rule.GWNodeName = "gateway-node-1"
	if rule.GWNodeName != "gateway-node-1" {
		t.Errorf("expected gateway node name 'gateway-node-1', got %v", rule.GWNodeName)
	}
	
	// Test gateway route
	gwRoute := &rm.NodeRoute{
		Name:  "gateway-node-1",
		IPv4:  net.ParseIP("10.0.1.10"),
		IPv6:  net.ParseIP("2001:db8::10"),
	}
	rule.GWRoute = gwRoute
	
	if rule.GWRoute == nil {
		t.Fatal("expected gateway route to be set")
	}
	if rule.GWRoute.Name != "gateway-node-1" {
		t.Errorf("expected gateway route name 'gateway-node-1', got %v", rule.GWRoute.Name)
	}
}

func TestEgressRule_HashConsistency(t *testing.T) {
	// Test that the hash algorithm is deterministic and consistent
	testCases := []struct {
		id     string
		isIPv6 bool
		expected string // We'll calculate this from the first run
	}{
		{"simple-rule", false, ""},
		{"simple-rule", true, ""},
		{"namespace/service-name", false, ""},
		{"very-long-rule-id-with-many-characters", false, ""},
		{"rule-with-numbers-123", false, ""},
	}
	
	for i, tc := range testCases {
		rule := NewEgressRule(tc.id)
		hash := rule.CalcIDHash(tc.isIPv6)
		
		// Verify hash properties
		if len(hash) != 12 {
			t.Errorf("test case %d: expected hash length 12, got %d", i, len(hash))
		}
		
		// Verify consistency - same input should always produce same output
		for j := 0; j < 5; j++ {
			newHash := rule.CalcIDHash(tc.isIPv6)
			if hash != newHash {
				t.Errorf("test case %d: hash not consistent, got %s and %s", i, hash, newHash)
			}
		}
	}
}

func TestEgressRule_EdgeCases(t *testing.T) {
	t.Run("empty ID", func(t *testing.T) {
		rule := NewEgressRule("")
		hash := rule.CalcIDHash(false)
		
		// Should still produce a valid hash
		if len(hash) != 12 {
			t.Errorf("expected hash length 12 for empty ID, got %d", len(hash))
		}
	})
	
	t.Run("special characters in ID", func(t *testing.T) {
		rule := NewEgressRule("rule/with@special#characters$%^&*()")
		hash := rule.CalcIDHash(false)
		
		if len(hash) != 12 {
			t.Errorf("expected hash length 12 for special characters, got %d", len(hash))
		}
	})
	
	t.Run("unicode characters in ID", func(t *testing.T) {
		rule := NewEgressRule("规则-名称-🚀")
		hash := rule.CalcIDHash(false)
		
		if len(hash) != 12 {
			t.Errorf("expected hash length 12 for unicode characters, got %d", len(hash))
		}
	})
}