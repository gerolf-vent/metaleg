package core

import (
	"context"
	"fmt"
	"math"
	"net"
	"strings"
	"time"

	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/sethvargo/go-envconfig"
)

var (
	DefaultFWExcludeDstCIDRs = []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"fc00::/7",
		"fe80::/10",
	}
)

type CIDRList []net.IPNet

func (c *CIDRList) UnmarshalText(text []byte) error {
	for cidrStr := range strings.SplitSeq(string(text), ",") {
		cidrStr = strings.TrimSpace(cidrStr)
		if cidrStr == "" {
			continue
		}

		_, cidr, err := net.ParseCIDR(cidrStr)
		if err != nil {
			return fmt.Errorf("invalid CIDR %q: %w", cidrStr, err)
		}
		if cidr == nil || cidr.IP.IsUnspecified() || cidr.Mask == nil {
			return fmt.Errorf("unspecified CIDR %q", cidrStr)
		}

		*c = append(*c, *cidr)
	}

	return nil
}

func (c *CIDRList) String() string {
	var cidrStrs []string
	for _, cidr := range *c {
		cidrStrs = append(cidrStrs, cidr.String())
	}
	return strings.Join(cidrStrs, ",")
}

type Config struct {
	NodeName string `env:"NODE_NAME"`

	FWBackend         string       `env:"FIREWALL_BACKEND,default=iptables"`
	FWMask            utils.FWMask `env:"FIREWALL_MASK,default=0xF000"`
	FWExcludeDstCIDRs CIDRList     `env:"FIREWALL_EXCLUDE_DST_CIDRS"`

	RouteBackend       string `env:"ROUTE_BACKEND,default=netlink"`
	RouteTableIDOffset uint32 `env:"ROUTE_TABLE_ID_OFFSET,default=100000"`

	ReconciliationInterval time.Duration `env:"RECONCILIATION_INTERVAL,default=5m"`
}

func LoadConfig(ctx context.Context) (*Config, error) {
	var cfg Config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return nil, err
	}

	if len(cfg.FWExcludeDstCIDRs) == 0 {
		for _, cidrStr := range DefaultFWExcludeDstCIDRs {
			_, cidr, err := net.ParseCIDR(cidrStr)
			if err != nil || cidr.IP.IsUnspecified() || cidr.Mask == nil {
				panic(fmt.Sprintf("invalid default CIDR %q: %v", cidrStr, err))
			}
			cfg.FWExcludeDstCIDRs = append(cfg.FWExcludeDstCIDRs, *cidr)
		}
	}

	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	return &cfg, nil
}

func (c *Config) Validate() error {
	if c.FWMask.Size() <= 1 {
		return fmt.Errorf("firewall mask too small")
	}

	if !c.FWMask.IsContinous() {
		return fmt.Errorf("firewall mask not continous")
	}

	if c.RouteTableIDOffset > math.MaxUint32-uint32(c.FWMask.Size()) {
		return fmt.Errorf("route table ID offset is too large")
	}

	return nil
}
