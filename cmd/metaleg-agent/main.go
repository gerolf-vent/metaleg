package main

import (
	"flag"
	"os"
	"strconv"
	"time"

	metaleg "github.com/gerolf-vent/metaleg/internal"
	es "github.com/gerolf-vent/metaleg/internal/egress-service"
	fm "github.com/gerolf-vent/metaleg/internal/firewall-manager"
	rm "github.com/gerolf-vent/metaleg/internal/route-manager"
	utils "github.com/gerolf-vent/metaleg/internal/utils"
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
	logger := zap.New(zap.UseFlagOptions(&zapOpts)).WithName("metaleg-agent")
	ctrl.SetLogger(logger)

	var err error

	nodeName := os.Getenv("NODE_NAME")
	if nodeName == "" {
		logger.Error(nil, "NODE_NAME env var not set")
	}

	mlbNamespace := os.Getenv("METALLB_NAMESPACE")
	if mlbNamespace == "" {
		mlbNamespace = "metallb-system" // Default namespace for MetalLB
	}

	fwMask := utils.FWMask(0x00F00000) // Default FW mask
	fwMaskEnv := os.Getenv("FIREWALL_MASK")
	if fwMaskEnv != "" {
		fwMask, err = utils.ParseFWMask(fwMaskEnv)
		if err != nil {
			logger.Error(err, "Failed to parse env var FIREWALL_MASK", "value", fwMaskEnv)
			os.Exit(1)
		}
	} else {
		logger.Info("FIREWALL_MASK env var not set, using default value", "value", fwMask)
	}

	fmBackend := os.Getenv("FIREWALL_BACKEND")
	if fmBackend == "" {
		fmBackend = "iptables" // Default firewall backend
	}

	var firewallManager fm.FirewallManager
	switch fmBackend {
	case "iptables":
		firewallManager, err = fm.NewIPTablesManager(nodeName, uint32(fwMask))
		if err != nil {
			logger.Error(err, "Failed to create iptables manager")
			os.Exit(1)
		}
	default:
		logger.Error(nil, "Unsupported firewall manager backend", "backend", fmBackend)
		os.Exit(1)
	}

	routeTableIDOffset := uint64(100000) // Default route table ID offset
	routeTableIDOffsetRaw := os.Getenv("ROUTE_TABLE_ID_OFFSET")
	if routeTableIDOffsetRaw != "" {
		routeTableIDOffset, err = strconv.ParseUint(routeTableIDOffsetRaw, 10, 32)
		if err != nil {
			logger.Error(err, "Invalid ROUTE_TABLE_ID_OFFSET")
			os.Exit(1)
		}
	}

	rmBackend := os.Getenv("ROUTE_BACKEND")
	if rmBackend == "" {
		rmBackend = "netlink" // Default route backend
	}

	var routeManager rm.RouteManager
	switch rmBackend {
	case "netlink":
		routeManager, err = rm.NewNetlinkManager(fwMask, uint32(routeTableIDOffset))
		if err != nil {
			logger.Error(err, "Failed to create netlink manager")
			os.Exit(1)
		}
	default:
		logger.Error(nil, "Unsupported route manager backend", "backend", rmBackend)
		os.Exit(1)
	}

	reconciliationInterval := time.Minute * 5 // Default reconciliation interval
	reconciliationIntervalRaw := os.Getenv("RECONCILIATION_INTERVAL")
	if reconciliationIntervalRaw != "" {
		reconciliationInterval, err = time.ParseDuration(reconciliationIntervalRaw)
		if err != nil {
			logger.Error(err, "Invalid GC_INTERVAL")
			os.Exit(1)
		}
	}

	if *runCleanup {
		logger.Info("Running in cleanup mode")

		exitCode := 0

		if err := firewallManager.Cleanup(); err != nil {
			logger.Error(err, "Failed to cleanup firewall rules")
			exitCode = 1
		}

		if err := routeManager.Cleanup(); err != nil {
			logger.Error(err, "Failed to cleanup route rules")
			exitCode = 1
		}

		logger.Info("Cleanup finished, exiting")
		os.Exit(exitCode)
	}

	metricsBindAddress := os.Getenv("METRICS_BIND_ADDRESS")
	if metricsBindAddress == "" {
		metricsBindAddress = ":21793" // Default metrics bind address
	}

	healthProbeBindAddress := os.Getenv("HEALTH_PROBE_BIND_ADDRESS")
	if healthProbeBindAddress == "" {
		healthProbeBindAddress = ":21794" // Default health probe bind address
	}

	cfg := ctrl.GetConfigOrDie()

	scheme := runtime.NewScheme()
	corev1.AddToScheme(scheme)
	discoveryv1.AddToScheme(scheme)
	metallbv1beta1.AddToScheme(scheme)

	mgr, err := ctrl.NewManager(cfg, ctrl.Options{
		Scheme:         scheme,
		LeaderElection: false, // this is a node agent, no leader election needed
		Logger:         logger,
		Metrics: metricsserver.Options{
			BindAddress: metricsBindAddress,
		},
		HealthProbeBindAddress: healthProbeBindAddress,
	})
	if err != nil {
		logger.Error(err, "Failed to create controller manager")
		os.Exit(1)
	}

	es, err := es.New(nodeName, reconciliationInterval, firewallManager, routeManager)
	if err != nil {
		logger.Error(err, "Failed to create egress service")
		os.Exit(1)
	}

	if err := mgr.Add(es); err != nil {
		logger.Error(err, "Failed to add egress service to manager")
		os.Exit(1)
	}

	if err := metaleg.AttachNodeController(mgr, es); err != nil {
		logger.Error(err, "Failed to attach node controller")
		os.Exit(1)
	}

	if err := metaleg.AttachServiceController(mgr, es, mlbNamespace); err != nil {
		logger.Error(err, "Failed to attach service controller")
		os.Exit(1)
	}

	logger.Info("Starting agent", "nodeName", nodeName, "firewallMask", fwMask, "routeTableIDOffset", routeTableIDOffset, "firewallBackend", fmBackend, "routeBackend", rmBackend, "reconciliationInterval", reconciliationInterval)
	if err := mgr.Start(ctrl.SetupSignalHandler()); err != nil {
		logger.Error(err, "Agent stopped unexpectedly")
		os.Exit(1)
	} else {
		logger.Info("Agent stopped gracefully")
	}
}
