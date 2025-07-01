package egress_service

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	fm "github.com/gerolf-vent/metaleg/internal/firewall-manager"
	rm "github.com/gerolf-vent/metaleg/internal/route-manager"
	ctrl "sigs.k8s.io/controller-runtime"
)

type EgressService struct {
	sync.RWMutex
	nodeName string

	// Map to hold all SNAT rules by their namespace/svcName as the key
	rules map[string]*fm.EgressRule

	// Map to hold all node ips, their route table IDs and fw marks by node name
	nodes map[string]*rm.NodeRoute

	reconciliationInterval time.Duration // Interval for garbage collection and reconciliation

	firewallManager fm.FirewallManager // Interface to manage firewall rules
	routeManager    rm.RouteManager    // Interface to manage node routes
}

func New(nodeName string, reconciliationInterval time.Duration, firewallManager fm.FirewallManager, routeManager rm.RouteManager) (*EgressService, error) {
	return &EgressService{
		nodeName:               nodeName,
		rules:                  make(map[string]*fm.EgressRule),
		nodes:                  make(map[string]*rm.NodeRoute),
		reconciliationInterval: reconciliationInterval,
		firewallManager:        firewallManager,
		routeManager:           routeManager,
	}, nil
}

func (es *EgressService) Start(ctx context.Context) error {
	logger := ctrl.LoggerFrom(ctx)
	logger.Info("Starting egress service")

	// Setup the firewall manager
	if err := es.firewallManager.Setup(); err != nil {
		return fmt.Errorf("failed to setup firewall manager: %w", err)
	}

	// Setup the route manager
	if err := es.routeManager.Setup(); err != nil {
		return fmt.Errorf("failed to setup route manager: %w", err)
	}

	// Periodically run reconciliation to ensure the egress rules and node routes are up-to-date
	ticker := time.NewTicker(es.reconciliationInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			logger.Info("Stopping egress service")
			return nil
		case <-ticker.C:
			es.Lock()
			logger.Info("Running reconciliation for egress service")

			// Setup route manager again
			if err := es.routeManager.Setup(); err != nil {
				logger.Error(err, "Failed to setup route manager")
			}

			// Garbage collect node routes that are no longer present
			if err := es.routeManager.CleanupNodeRoutes(es.nodes); err != nil {
				logger.Error(err, "Failed to cleanup node routes")
			}

			// Reconcile all node routes
			for _, nodeRoute := range es.nodes {
				if err := es.routeManager.ReconcileNodeRoute(nodeRoute, true); err != nil {
					logger.Error(err, "Failed to reconcile node route", "nodeName", nodeRoute.Name)
				}
			}

			// Setup firewall manager again
			if err := es.firewallManager.Setup(); err != nil {
				logger.Error(err, "Failed to setup firewall manager")
			}

			// Garbage collect egress rules that are no longer present
			if err := es.firewallManager.CleanupEgressRules(es.rules); err != nil {
				logger.Error(err, "Failed to cleanup egress rules")
			}

			// Reconcile all egress rules
			for _, rule := range es.rules {
				if err := es.firewallManager.ReconcileEgressRule(rule, true); err != nil {
					logger.Error(err, "Failed to reconcile egress rule", "ruleID", rule.ID)
				}
			}

			es.Unlock()
		}
	}
}

func (es *EgressService) UpdateEgressRule(id string, lbIPv4, lbIPv6 net.IP, srcIPv4, srcIPv6 []net.IP, gwNodeName string) error {
	es.Lock()
	defer es.Unlock()

	if id == "" {
		return errors.New("egress rule ID must not empty")
	}

	rule, exists := es.rules[id]
	oldRule := rule // Keep a reference to the old rule for comparison

	nodesUpdated := make(map[string]*rm.NodeRoute)

	if exists {
		// If the rule already existed, we need to decrement the link count for the old
		// gateway node route, if it is different from the new one.
		if oldRule.GWNodeName != "" && oldRule.GWNodeName != gwNodeName {
			if gwRoute, ok := es.nodes[oldRule.GWNodeName]; ok && gwRoute.RuleCount > 0 {
				gwRoute.RuleCount-- // Decrement the link count for the old node route
				if gwRoute.RuleCount == 0 {
					// If the link count reaches zero, we need to reconcile the node route,
					// because it will be removed from the routing table
					nodesUpdated[oldRule.GWNodeName] = gwRoute
				}
			}
		}

		// Update the existing rule with the new values
		rule.SNATIPv4 = lbIPv4
		rule.SNATIPv6 = lbIPv6
		rule.SrcIPv4s = srcIPv4
		rule.SrcIPv6s = srcIPv6
		rule.GWNodeName = gwNodeName
	} else {
		// Create a new rule if it does not exist
		rule = &fm.EgressRule{
			ID:         id,
			SNATIPv4:   lbIPv4,
			SNATIPv6:   lbIPv6,
			SrcIPv4s:   srcIPv4,
			SrcIPv6s:   srcIPv6,
			GWNodeName: gwNodeName,
		}
		es.rules[id] = rule
	}

	// If the updated rule is new or the gateway node name has changed, the gateway
	// route and it's link counter needs to be updated.
	if gwNodeName != "" && (!exists || gwNodeName != oldRule.GWNodeName) {
		if gwRoute, ok := es.nodes[gwNodeName]; ok {
			rule.GWRoute = gwRoute // Set the gateway route to the node route
			gwRoute.RuleCount++
			if gwRoute.RuleCount == 1 {
				// If this is the first link to the node route, we need to reconcile it,
				// because it will be added to the routing table
				nodesUpdated[gwNodeName] = gwRoute
			}
		}
	}

	var errs []error

	// Reconcile the node routes for all nodes that were updated
	// This must happen before reconciling the egress rule, because the reconciliation
	// function also lazy allocates the fw mark, which will be used in the egress rule
	// reconciliation.
	for _, nodeRoute := range nodesUpdated {
		// Reconcile the node route for each node that was updated
		if err := es.routeManager.ReconcileNodeRoute(nodeRoute, true); err != nil {
			errs = append(errs, err)
		}
	}

	// Reconcile the egress rule
	if err := es.firewallManager.ReconcileEgressRule(rule, true); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (es *EgressService) DeleteEgressRule(id string) error {
	es.Lock()
	defer es.Unlock()

	if id == "" {
		return errors.New("egress rule ID must not empty")
	}

	rule, exists := es.rules[id]

	if !exists {
		// Maybe the last attempt to delete the rule was not reconciled successfully,
		// but we can catch a left-over rule by a general cleanup.
		if err := es.firewallManager.CleanupEgressRules(es.rules); err != nil {
			return err
		}
		return nil
	}

	delete(es.rules, id)

	nodesUpdated := make(map[string]*rm.NodeRoute)

	if rule.GWRoute != nil {
		if rule.GWRoute.RuleCount > 0 {
			rule.GWRoute.RuleCount-- // Decrement the link count for the node route
			if rule.GWRoute.RuleCount == 0 {
				// If the link count reaches zero, we need to reconcile the node route,
				// because it will be removed from the routing table
				nodesUpdated[rule.GWNodeName] = rule.GWRoute
			}
		}
		rule.GWRoute = nil // Clear the gateway route for this rule
	}

	var errs []error

	for _, nodeRoute := range nodesUpdated {
		// Reconcile the node route for each node that was updated
		if err := es.routeManager.ReconcileNodeRoute(nodeRoute, true); err != nil {
			errs = append(errs, err)
		}
	}

	// Reconcile the egress rule to remove it from iptables and ipset
	if err := es.firewallManager.ReconcileEgressRule(rule, false); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}

func (es *EgressService) UpdateNodeRoute(nodeName string, nodeIPv4 net.IP, nodeIPv6 net.IP) error {
	es.Lock()
	defer es.Unlock()

	if nodeName == "" {
		return errors.New("node name must not empty")
	}

	if nodeName == es.nodeName {
		return nil // Ignore updates for the local node
	}

	node, exists := es.nodes[nodeName]

	rulesUpdated := make(map[string]*fm.EgressRule)

	if exists {
		node.IPv4 = nodeIPv4
		node.IPv6 = nodeIPv6
	} else {
		node = &rm.NodeRoute{
			Name: nodeName,
			IPv4: nodeIPv4,
			IPv6: nodeIPv6,
		}

		for _, rule := range es.rules {
			if rule.GWNodeName == nodeName && rule.GWRoute == nil {
				// Set the gateway route for this rule to the new node
				rule.GWRoute = node
				node.RuleCount++

				rulesUpdated[rule.ID] = rule // Add the rule to the reconciliation map
			}
		}

		es.nodes[nodeName] = node
	}

	var errs []error

	if err := es.routeManager.ReconcileNodeRoute(node, true); err != nil {
		errs = append(errs, err)
	}

	// Reconcile each egress rule that was updated
	for _, rule := range rulesUpdated {
		if err := es.firewallManager.ReconcileEgressRule(rule, true); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func (es *EgressService) DeleteNodeRoute(nodeName string) error {
	es.Lock()
	defer es.Unlock()

	if nodeName == "" {
		return errors.New("node name must not empty")
	}

	node, exists := es.nodes[nodeName]

	if !exists {
		var errs []error

		// Maybe the last attempt to delete the node route was not reconciled successfully,
		// but we can catch a left-over node route by a general cleanup.
		if err := es.routeManager.CleanupNodeRoutes(es.nodes); err != nil {
			errs = append(errs, err)
		}

		// Also reconcile all egress rules that are associated with this node, just in case
		for _, rule := range es.rules {
			if rule.GWNodeName == nodeName {
				if err := es.firewallManager.ReconcileEgressRule(rule, true); err != nil {
					errs = append(errs, err)
				}
			}
		}

		return errors.Join(errs...)
	}

	rulesToReconcile := make(map[string]*fm.EgressRule)

	// Remove any route rules associated with this node
	for _, rule := range es.rules {
		if rule.GWRoute != nil && rule.GWNodeName == nodeName {
			rule.GWRoute = nil               // Clear the gateway node route for this rule
			rulesToReconcile[rule.ID] = rule // Add the rule to the reconciliation map
		}
	}

	node.RuleCount = 0 // Reset the link count for the node route

	delete(es.nodes, nodeName)

	var errs []error

	// Reconcile the egress rules for all rules that were updated
	for _, rule := range rulesToReconcile {
		// Reconcile the egress rule for each rule that was updated
		if err := es.firewallManager.ReconcileEgressRule(rule, true); err != nil {
			errs = append(errs, err)
		}
	}

	// Reconcile the node route to remove it from the routing table
	if err := es.routeManager.ReconcileNodeRoute(node, false); err != nil {
		errs = append(errs, err)
	}

	return errors.Join(errs...)
}
