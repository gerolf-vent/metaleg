package controller

import (
	"context"

	"github.com/sethvargo/go-envconfig"
)

type Config struct {
	NodeName               string `env:"NODE_NAME"`
	MLBNamespace           string `env:"METALLB_NAMESPACE"`
	FilterEndpointsForNode bool   `env:"FILTER_ENDPOINTS_FOR_NODE,default=true"`

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
