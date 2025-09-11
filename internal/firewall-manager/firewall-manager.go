package firewall_manager

type FirewallManager interface {
	Setup() error
	Cleanup() error
	ReconcileEgressRule(rule *EgressRule, present bool) error
	CleanupStaleEgressRules(rules map[string]*EgressRule) error
}
