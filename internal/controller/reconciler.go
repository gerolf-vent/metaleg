package controller

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/iptables"
	"github.com/gerolf-vent/metaleg/internal/netlink"
	ctrl "sigs.k8s.io/controller-runtime"
)

type Reconciler struct {
	sync.RWMutex

	state                  core.State
	reconciliationInterval time.Duration // Interval for garbage collection and reconciliation
	managers               []core.Manager
	isReady                bool // Indicates if the service is ready to process requests
}

func NewReconciler(config *core.Config) (*Reconciler, error) {
	state, err := core.NewState(config)
	if err != nil {
		return nil, err
	}

	var managers []core.Manager

	// Firewall backend
	switch config.FWBackend {
	case "iptables":
		fwManager, err := iptables.NewManager(state)
		if err != nil {
			return nil, fmt.Errorf("failed to create iptables manager: %w", err)
		}
		managers = append(managers, fwManager)
	default:
		return nil, fmt.Errorf("unsupported firewall backend: %q", config.FWBackend)
	}

	// Route backend
	switch config.RouteBackend {
	case "netlink":
		routeBackend := netlink.NewManager(state)
		managers = append(managers, routeBackend)
	default:
		return nil, fmt.Errorf("unsupported route backend: %q", config.RouteBackend)
	}

	return &Reconciler{
		state:                  state,
		reconciliationInterval: config.ReconciliationInterval,
		managers:               managers,
	}, nil
}

func (r *Reconciler) Start(ctx context.Context) error {
	r.Lock()

	logger := ctrl.LoggerFrom(ctx)
	logger.Info("Starting egress reconciler")

	// Setup all managers
	for _, manager := range r.managers {
		if err := manager.Setup(); err != nil {
			return fmt.Errorf("failed to setup manager %q: %w", manager.Name(), err)
		}
	}

	// Cleanup any left-over stuff
	for _, manager := range r.managers {
		if err := manager.Cleanup(); err != nil {
			logger.Error(err, "Failed to run cleanup on manager", "manager", manager.Name())
		}
	}

	r.isReady = true // Mark the service as ready to process requests

	r.Unlock()

	// Periodically run reconciliation to ensure the egress rules and node routes are up-to-date
	ticker := time.NewTicker(r.reconciliationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopping egress reconciler")
			return nil
		case <-ticker.C:
			r.Lock()
			logger.Info("Running reconciliation for egress service")

			// Run setup again to ensure everything is in place
			for _, manager := range r.managers {
				if err := manager.Setup(); err != nil {
					logger.Error(err, "Failed to setup manager", "manager", manager.Name())
				}
			}

			// Cleanup any left-over stuff
			for _, manager := range r.managers {
				if err := manager.Cleanup(); err != nil {
					logger.Error(err, "Failed to run cleanup on manager", "manager", manager.Name())
				}
			}

			// Ensure all managers are fully reconciled
			changes := core.NewStateChange()
			for _, ruleState := range r.state.GetEgressRuleStates() {
				changes.EgressRulesUpdated.Add(ruleState.ID)
			}
			for _, manager := range r.managers {
				if err := manager.Reconcile(changes); err != nil {
					logger.Error(err, "Failed to reconcile manager", "manager", manager.Name())
				}
			}

			r.Unlock()
		}
	}
}

func (r *Reconciler) Purge() error {
	r.Lock()
	defer r.Unlock()

	var errs []error

	for _, manager := range r.managers {
		if err := manager.Purge(); err != nil {
			errs = append(errs, fmt.Errorf("failed to purge manager %q: %w", manager.Name(), err))
		}
	}

	return errors.Join(errs...)
}

func (r *Reconciler) IsReady() bool {
	r.RLock()
	defer r.RUnlock()

	return r.isReady
}

func (r *Reconciler) UpdateEgressRule(egressRule core.EgressRule) error {
	r.Lock()
	defer r.Unlock()

	changes, err := r.state.UpdateEgressRule(egressRule)
	if err != nil {
		return err
	}

	return r.reconcile(changes)
}

func (r *Reconciler) DeleteEgressRule(id string) error {
	r.Lock()
	defer r.Unlock()

	changes, err := r.state.DeleteEgressRule(id)
	if err != nil {
		return err
	}

	return r.reconcile(changes)
}

func (r *Reconciler) UpdateNode(node core.Node) error {
	r.Lock()
	defer r.Unlock()

	changes, err := r.state.UpdateNode(node)
	if err != nil {
		return err
	}

	return r.reconcile(changes)
}

func (r *Reconciler) DeleteNode(nodeName string) error {
	r.Lock()
	defer r.Unlock()

	changes, err := r.state.DeleteNode(nodeName)
	if err != nil {
		return err
	}

	return r.reconcile(changes)
}

func (r *Reconciler) reconcile(changes core.StateChange) error {
	var errs []error

	for _, manager := range r.managers {
		if err := manager.Reconcile(changes); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
