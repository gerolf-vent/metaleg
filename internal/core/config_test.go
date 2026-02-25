package core

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/utils"
)

func TestCIDRList_UnmarshalText(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		want      []string
		wantErr   bool
		errString string
	}{
		{
			name:  "single valid CIDR",
			input: "192.168.1.0/24",
			want:  []string{"192.168.1.0/24"},
		},
		{
			name:  "multiple valid CIDRs",
			input: "192.168.1.0/24,10.0.0.0/8,172.16.0.0/12",
			want:  []string{"192.168.1.0/24", "10.0.0.0/8", "172.16.0.0/12"},
		},
		{
			name:  "CIDRs with whitespace",
			input: " 192.168.1.0/24 , 10.0.0.0/8 ",
			want:  []string{"192.168.1.0/24", "10.0.0.0/8"},
		},
		{
			name:  "IPv6 CIDRs",
			input: "2001:db8::/32,fe80::/10",
			want:  []string{"2001:db8::/32", "fe80::/10"},
		},
		{
			name:  "empty string",
			input: "",
			want:  []string{},
		},
		{
			name:  "only whitespace and commas",
			input: " , , ",
			want:  []string{},
		},
		{
			name:      "invalid CIDR format",
			input:     "192.168.1.0",
			wantErr:   true,
			errString: "invalid CIDR",
		},
		{
			name:      "invalid IP in CIDR",
			input:     "999.999.999.999/24",
			wantErr:   true,
			errString: "invalid CIDR",
		},
		{
			name:      "unspecified IPv4 CIDR",
			input:     "0.0.0.0/0",
			wantErr:   true,
			errString: "unspecified CIDR",
		},
		{
			name:      "unspecified IPv6 CIDR",
			input:     "::/0",
			wantErr:   true,
			errString: "unspecified CIDR",
		},
		{
			name:      "mixed valid and invalid",
			input:     "192.168.1.0/24,invalid,10.0.0.0/8",
			wantErr:   true,
			errString: "invalid CIDR",
		},
		{
			name:      "host IP without mask",
			input:     "192.168.1.5/24,10.0.0.5",
			wantErr:   true,
			errString: "invalid CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CIDRList
			err := c.UnmarshalText([]byte(tt.input))

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				if tt.errString != "" && err != nil {
					if !strings.Contains(err.Error(), tt.errString) {
						t.Errorf("expected error to contain %q, got %q", tt.errString, err.Error())
					}
				}
				return
			}

			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if len(c) != len(tt.want) {
				t.Fatalf("expected %d CIDRs, got %d", len(tt.want), len(c))
			}

			for i, wantCIDR := range tt.want {
				_, expectedNet, err := net.ParseCIDR(wantCIDR)
				if err != nil {
					t.Fatalf("failed to parse expected CIDR %q: %v", wantCIDR, err)
				}
				if expectedNet.String() != c[i].String() {
					t.Errorf("CIDR at index %d: expected %s, got %s", i, expectedNet.String(), c[i].String())
				}
			}
		})
	}
}

func TestLoadConfig_Defaults(t *testing.T) {
	ctx := context.Background()
	t.Setenv("NODE_NAME", "test-node")

	cfg, err := LoadConfig(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if cfg.NodeName != "test-node" {
		t.Errorf("expected NodeName %q, got %q", "test-node", cfg.NodeName)
	}
	if cfg.FWBackend != "iptables" {
		t.Errorf("expected FWBackend %q, got %q", "iptables", cfg.FWBackend)
	}
	if cfg.FWMask != utils.FWMask(0xF00000) {
		t.Errorf("expected FWMask %v, got %v", utils.FWMask(0xF00000), cfg.FWMask)
	}
	if cfg.RouteBackend != "netlink" {
		t.Errorf("expected RouteBackend %q, got %q", "netlink", cfg.RouteBackend)
	}
	if cfg.RouteTableIDOffset != 100000 {
		t.Errorf("expected RouteTableIDOffset %d, got %d", 100000, cfg.RouteTableIDOffset)
	}

	// Check default exclude CIDRs
	if len(cfg.FWExcludeDstCIDRs) == 0 {
		t.Error("expected at least one default CIDR")
	}

	// All defaults should be present (some might be filtered if unspecified)
	for i, cidr := range cfg.FWExcludeDstCIDRs {
		if cidr.IP == nil {
			t.Errorf("CIDR at index %d should not have nil IP (got: %+v)", i, cidr)
		}
		if cidr.Mask == nil {
			t.Errorf("CIDR at index %d should not have nil Mask (got: %+v)", i, cidr)
		}
		if cidr.IP != nil && cidr.IP.IsUnspecified() {
			t.Errorf("CIDR at index %d should not be unspecified (got: %s)", i, cidr.String())
		}
	}

	// Verify expected defaults based on actual DefaultFWExcludeDstCIDRs
	expectedCIDRs := DefaultFWExcludeDstCIDRs

	if len(cfg.FWExcludeDstCIDRs) != len(expectedCIDRs) {
		t.Errorf("expected %d default CIDRs, got %d", len(expectedCIDRs), len(cfg.FWExcludeDstCIDRs))
	}

	for i, expected := range expectedCIDRs {
		if i >= len(cfg.FWExcludeDstCIDRs) {
			break
		}
		if cfg.FWExcludeDstCIDRs[i].String() != expected {
			t.Errorf("CIDR at index %d: expected %s, got %s", i, expected, cfg.FWExcludeDstCIDRs[i].String())
		}
	}
}

func TestLoadConfig_CustomCIDRs(t *testing.T) {
	ctx := context.Background()
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("FIREWALL_EXCLUDE_DST_CIDRS", "192.168.0.0/16,10.0.0.0/8")

	cfg, err := LoadConfig(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg == nil {
		t.Fatal("expected non-nil config")
	}

	if len(cfg.FWExcludeDstCIDRs) != 2 {
		t.Fatalf("expected 2 CIDRs, got %d", len(cfg.FWExcludeDstCIDRs))
	}
	if cfg.FWExcludeDstCIDRs[0].String() != "192.168.0.0/16" {
		t.Errorf("expected CIDR[0] %q, got %q", "192.168.0.0/16", cfg.FWExcludeDstCIDRs[0].String())
	}
	if cfg.FWExcludeDstCIDRs[1].String() != "10.0.0.0/8" {
		t.Errorf("expected CIDR[1] %q, got %q", "10.0.0.0/8", cfg.FWExcludeDstCIDRs[1].String())
	}
}

func TestLoadConfig_InvalidCIDRs(t *testing.T) {
	ctx := context.Background()
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("FIREWALL_EXCLUDE_DST_CIDRS", "invalid-cidr")

	cfg, err := LoadConfig(ctx)
	if err == nil {
		t.Error("expected error but got nil")
	}
	if cfg != nil {
		t.Error("expected nil config")
	}
}

func TestLoadConfig_UnspecifiedCIDRs(t *testing.T) {
	ctx := context.Background()
	t.Setenv("NODE_NAME", "test-node")
	t.Setenv("FIREWALL_EXCLUDE_DST_CIDRS", "0.0.0.0/0")

	cfg, err := LoadConfig(ctx)
	if err == nil {
		t.Error("expected error but got nil")
	}
	if cfg != nil {
		t.Error("expected nil config")
	}
	if err != nil && !strings.Contains(err.Error(), "unspecified CIDR") {
		t.Errorf("expected error to contain %q, got %q", "unspecified CIDR", err.Error())
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name      string
		config    Config
		wantErr   bool
		errString string
	}{
		{
			name: "valid config",
			config: Config{
				NodeName:           "test-node",
				FWBackend:          "iptables",
				FWMask:             utils.FWMask(0xF00000),
				RouteBackend:       "netlink",
				RouteTableIDOffset: 100000,
			},
			wantErr: false,
		},
		{
			name: "firewall mask too small (size 0)",
			config: Config{
				NodeName:           "test-node",
				FWMask:             utils.FWMask(0x0),
				RouteTableIDOffset: 100000,
			},
			wantErr:   true,
			errString: "firewall mask too small",
		},
		{
			name: "firewall mask not continuous",
			config: Config{
				NodeName:           "test-node",
				FWMask:             utils.FWMask(0x101010), // Non-continuous bits
				RouteTableIDOffset: 100000,
			},
			wantErr:   true,
			errString: "firewall mask not continous",
		},
		{
			name: "route table ID offset too large",
			config: Config{
				NodeName:           "test-node",
				FWMask:             utils.FWMask(0xF00000), // Size 16
				RouteTableIDOffset: 4294967280,             // MaxUint32 - 15, will overflow
			},
			wantErr:   true,
			errString: "route table ID offset is too large",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()

			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got nil")
				}
				if tt.errString != "" && err != nil {
					if !strings.Contains(err.Error(), tt.errString) {
						t.Errorf("expected error to contain %q, got %q", tt.errString, err.Error())
					}
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestCIDRList_NoNilEntries(t *testing.T) {
	// This test ensures that even after unmarshaling, we don't have nil IPs
	var c CIDRList
	err := c.UnmarshalText([]byte("192.168.1.0/24,10.0.0.0/8"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	for i, cidr := range c {
		if cidr.IP == nil {
			t.Errorf("CIDR at index %d should not have nil IP", i)
		}
		if cidr.Mask == nil {
			t.Errorf("CIDR at index %d should not have nil Mask", i)
		}
		if cidr.IP.IsUnspecified() {
			t.Errorf("CIDR at index %d should not be unspecified", i)
		}
	}
}

func TestCIDRList_EmptyInput(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"empty string", ""},
		{"only spaces", "   "},
		{"only commas", ",,,"},
		{"commas and spaces", " , , , "},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var c CIDRList
			err := c.UnmarshalText([]byte(tt.input))
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(c) != 0 {
				t.Errorf("Empty input should result in zero-length CIDRList, got %d", len(c))
			}
		})
	}
}
