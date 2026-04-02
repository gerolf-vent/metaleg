package controller

import (
	"context"
	"fmt"

	"github.com/sethvargo/go-envconfig"
)

type NodeAddressType string

const (
	NodeAddressTypeAny      NodeAddressType = "any"
	NodeAddressTypeInternal NodeAddressType = "internal"
	NodeAddressTypeExternal NodeAddressType = "external"
)

func (m *NodeAddressType) UnmarshalText(text []byte) error {
	switch string(text) {
	case "any":
		*m = NodeAddressTypeAny
	case "internal":
		*m = NodeAddressTypeInternal
	case "external":
		*m = NodeAddressTypeExternal
	default:
		return fmt.Errorf("invalid node ip type: %s", string(text))
	}
	return nil
}

type Config struct {
	NodeName               string          `env:"NODE_NAME"`
	MLBNamespace           string          `env:"METALLB_NAMESPACE"`
	FilterEndpointsForNode bool            `env:"FILTER_ENDPOINTS_FOR_NODE,default=true"`
	NodeAddressType        NodeAddressType `env:"NODE_ADDRESS_TYPE,default=internal"`

	MetricsBindAddress     string `env:"METRICS_BIND_ADDRESS,default=:21793"`
	HealthProbeBindAddress string `env:"HEALTH_PROBE_BIND_ADDRESS,default=:21794"`
}

func LoadConfig(ctx context.Context) (*Config, error) {
	var cfg Config
	if err := envconfig.Process(ctx, &cfg); err != nil {
		return nil, err
	}

	return &cfg, nil
}
