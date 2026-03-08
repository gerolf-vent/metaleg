package main

import (
	"context"
	"errors"
	"flag"
	"net/http"
	"os"
	"strconv"

	"github.com/gerolf-vent/metaleg/internal/controller"
	"github.com/gerolf-vent/metaleg/internal/core"
	"go.uber.org/zap/zapcore"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	"k8s.io/apimachinery/pkg/runtime"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	metallbv1beta1 "go.universe.tf/metallb/api/v1beta1"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/log/zap"
)

func main() {
	runCleanup := flag.Bool("cleanup", false, "Cleanup any left-over rules and exit")
	flag.Parse()

	devMode := false
	devModeEnv := os.Getenv("DEV_MODE")
	if devModeEnv == "true" {
		devMode = true
	}

	// Setup structured logging
	zapOpts := zap.Options{
		Development: devMode,
	}
	if devMode {
		logLevelEnv := os.Getenv("LOG_LEVEL")
		var logLevel int
		var err error
		if logLevelEnv == "" {
			logLevel = -10 // Default to Debug level in development mode
		} else {
			logLevel, err = strconv.Atoi(logLevelEnv)
			if err != nil {
				panic("invalid LOG_LEVEL value, must be an integer")
			}
		}
		zapOpts.Level = zapcore.Level(logLevel)
	}
	logger := zap.New(zap.UseFlagOptions(&zapOpts)).WithName("metaleg-agent")
	ctrl.SetLogger(logger)

	// Load main configuration from environment variables
	config, err := core.LoadConfig(context.Background())
	if err != nil {
		logger.Error(err, "Failed to load configuration from environment variables")
		os.Exit(1)
	}

	// Load additional controller configuration
	ctrlConfig, err := controller.LoadConfig(context.Background())
	if err != nil {
		logger.Error(err, "Failed to load controller configuration from environment variables")
		os.Exit(1)
	}

	reconciler, err := controller.NewReconciler(config, logger)
	if err != nil {
		logger.Error(err, "Failed to create egress service")
		os.Exit(1)
	}

	if *runCleanup {
		logger.Info("Running in purge mode")

		exitCode := 0

		if err := reconciler.Purge(); err != nil {
			logger.Error(err, "Purge encountered errors")
			exitCode = 1
		} else {
			logger.Info("Successfully completed purge")
		}

		os.Exit(exitCode)
	}

	cfg := ctrl.GetConfigOrDie()

	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		logger.Error(err, "Failed to add corev1 to scheme")
		os.Exit(1)
	}
	if err := discoveryv1.AddToScheme(scheme); err != nil {
		logger.Error(err, "Failed to add discoveryv1 to scheme")
		os.Exit(1)
	}
	if err := metallbv1beta1.AddToScheme(scheme); err != nil {
		logger.Error(err, "Failed to add metallbv1beta1 to scheme")
		os.Exit(1)
	}

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false, // this is a node agent, no leader election needed
		Logger:         logger,
		Metrics: metricsserver.Options{
			BindAddress: ctrlConfig.MetricsBindAddress,
		},
		HealthProbeBindAddress: ctrlConfig.HealthProbeBindAddress,
	})
	if err != nil {
		logger.Error(err, "Failed to create controller manager")
		os.Exit(1)
	}

	if err := mgr.Add(reconciler); err != nil {
		logger.Error(err, "Failed to add egress service to manager")
		os.Exit(1)
	}

	if err := controller.AttachNodeController(mgr, reconciler); err != nil {
		logger.Error(err, "Failed to attach node controller")
		os.Exit(1)
	}

	if err := controller.AttachServiceController(mgr, reconciler, ctrlConfig); err != nil {
		logger.Error(err, "Failed to attach service controller")
		os.Exit(1)
	}

	if err := mgr.AddReadyzCheck("egress-service", func(req *http.Request) error {
		if !reconciler.IsReady() {
			return errors.New("egress service not ready")
		}
		return nil
	}); err != nil {
		logger.Error(err, "Failed to add readiness check")
		os.Exit(1)
	}

	if err := mgr.AddHealthzCheck("egress-service", func(req *http.Request) error {
		return nil
	}); err != nil {
		logger.Error(err, "Failed to add health check")
		os.Exit(1)
	}

	logger.Info("Starting agent",
		"nodeName", config.NodeName,
		"fwBackend", config.FWBackend,
		"fwMask", config.FWMask,
		"fwExcludeDstCIDRs", config.FWExcludeDstCIDRs.String(),
		"routeBackend", config.RouteBackend,
		"routeTableIDOffset", config.RouteTableIDOffset,
		"reconciliationInterval", config.ReconciliationInterval,
		"filterEndpointsForNode", ctrlConfig.FilterEndpointsForNode,
	)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "Agent stopped unexpectedly")
		os.Exit(1)
	} else {
		logger.Info("Agent stopped gracefully")
	}
}
