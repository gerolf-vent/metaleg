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
	"github.com/go-logr/logr"
)

type Reconciler struct {
	sync.RWMutex

	state                  core.State
	reconciliationInterval time.Duration // Interval for garbage collection and reconciliation
	managers               []core.Manager
	isReady                bool // Indicates if the service is ready to process requests
	logger                 logr.Logger
}

func NewReconciler(config *core.Config, logger logr.Logger) (*Reconciler, error) {
	state, err := core.NewState(config, logger)
	if err != nil {
		return nil, err
	}

	var managers []core.Manager

	// Firewall backend
	switch config.FWBackend {
	case "iptables":
		fwManager, err := iptables.NewManager(state, logger)
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
		routeBackend := netlink.NewManager(state, logger)
		managers = append(managers, routeBackend)
	default:
		return nil, fmt.Errorf("unsupported route backend: %q", config.RouteBackend)
	}

	return &Reconciler{
		state:                  state,
		reconciliationInterval: config.ReconciliationInterval,
		managers:               managers,
		logger:                 logger,
	}, nil
}

func (r *Reconciler) Start(ctx context.Context) error {
	r.Lock()

	r.logger.Info("Starting egress reconciler")

	// Setup all managers
	for _, manager := range r.managers {
		if err := manager.Setup(); err != nil {
			r.Unlock()
			return fmt.Errorf("failed to setup manager %q: %w", manager.Name(), err)
		}
	}

	// Cleanup any left-over stuff
	for _, manager := range r.managers {
		if err := manager.Cleanup(); err != nil {
			r.logger.Error(err, "Failed to run cleanup on manager", "manager", manager.Name())
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
			r.logger.Info("Stopping egress reconciler")
			return nil
		case <-ticker.C:
			r.Lock()
			r.logger.Info("Running reconciliation for egress service")

			// Run setup again to ensure everything is in place
			for _, manager := range r.managers {
				if err := manager.Setup(); err != nil {
					r.logger.Error(err, "Failed to setup manager", "manager", manager.Name())
				}
			}

			// Cleanup any left-over stuff
			for _, manager := range r.managers {
				if err := manager.Cleanup(); err != nil {
					r.logger.Error(err, "Failed to run cleanup on manager", "manager", manager.Name())
				}
			}

			// Ensure all managers are fully reconciled
			changes := core.NewStateChange()
			for _, ruleState := range r.state.GetEgressRuleStates() {
				changes.EgressRulesUpdated.Add(ruleState.ID)
			}
			for _, manager := range r.managers {
				if err := manager.Reconcile(changes); err != nil {
					r.logger.Error(err, "Failed to reconcile manager", "manager", manager.Name())
				}
			}

			r.Unlock()
		}
	}
}

func (r *Reconciler) Purge() error {
	r.Lock()
	defer r.Unlock()

	r.logger.Info("Purging all managers")

	var errs []error

	for _, manager := range r.managers {
		r.logger.V(1).Info("Purging manager", "manager", manager.Name())
		if err := manager.Purge(); err != nil {
			r.logger.Error(err, "Failed to purge manager", "manager", manager.Name())
			errs = append(errs, fmt.Errorf("failed to purge manager %q: %w", manager.Name(), err))
		}
	}

	if len(errs) > 0 {
		r.logger.Info("Purge completed with errors", "errorCount", len(errs))
	} else {
		r.logger.Info("Purge completed successfully")
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

	r.logger.V(1).Info("Updating egress rule", "id", egressRule.ID, "gwNode", egressRule.GWNodeName, "srcIPv4Count", len(egressRule.SrcIPv4s), "srcIPv6Count", len(egressRule.SrcIPv6s))

	changes, err := r.state.UpdateEgressRule(egressRule)
	if err != nil {
		r.logger.Error(err, "Failed to update egress rule in state", "id", egressRule.ID)
		return err
	}

	if err := r.reconcile(changes); err != nil {
		r.logger.Error(err, "Failed to reconcile after egress rule update", "id", egressRule.ID)
		return err
	}

	r.logger.V(1).Info("Successfully updated egress rule", "id", egressRule.ID, "stateChange", changes)

	return nil
}

func (r *Reconciler) DeleteEgressRule(id string) error {
	r.Lock()
	defer r.Unlock()

	r.logger.V(1).Info("Deleting egress rule", "id", id)

	changes, err := r.state.DeleteEgressRule(id)
	if err != nil {
		r.logger.Error(err, "Failed to delete egress rule from state", "id", id)
		return err
	}

	if err := r.reconcile(changes); err != nil {
		r.logger.Error(err, "Failed to reconcile after egress rule deletion", "id", id)
		return err
	}

	r.logger.V(1).Info("Successfully deleted egress rule", "id", id, "stateChange", changes)

	return nil
}

func (r *Reconciler) UpdateNode(node core.Node) error {
	r.Lock()
	defer r.Unlock()

	r.logger.V(1).Info("Updating node", "name", node.Name, "ipv4", node.IPv4, "ipv6", node.IPv6)

	changes, err := r.state.UpdateNode(node)
	if err != nil {
		r.logger.Error(err, "Failed to update node in state", "name", node.Name)
		return err
	}

	if err := r.reconcile(changes); err != nil {
		r.logger.Error(err, "Failed to reconcile after node update", "name", node.Name)
		return err
	}

	r.logger.V(1).Info("Successfully updated node", "name", node.Name, "stateChange", changes)

	return nil
}

func (r *Reconciler) DeleteNode(nodeName string) error {
	r.Lock()
	defer r.Unlock()

	r.logger.V(1).Info("Deleting node", "name", nodeName)

	changes, err := r.state.DeleteNode(nodeName)
	if err != nil {
		r.logger.Error(err, "Failed to delete node from state", "name", nodeName)
		return err
	}

	if err := r.reconcile(changes); err != nil {
		r.logger.Error(err, "Failed to reconcile after node deletion", "name", nodeName)
		return err
	}

	r.logger.V(1).Info("Successfully deleted node", "name", nodeName, "stateChange", changes)

	return nil
}

func (r *Reconciler) reconcile(changes core.StateChange) error {
	if !changes.IsEmpty() {
		r.logger.V(2).Info("Reconciling state changes", "stateChange", changes)
	}

	var errs []error

	for _, manager := range r.managers {
		r.logger.V(2).Info("Reconciling manager", "manager", manager.Name())
		if err := manager.Reconcile(changes); err != nil {
			r.logger.Error(err, "Manager reconciliation failed", "manager", manager.Name())
			errs = append(errs, err)
		}
	}

	if len(errs) > 0 {
		r.logger.Info("Reconciliation completed with errors", "errorCount", len(errs))
	}

	return errors.Join(errs...)
}
