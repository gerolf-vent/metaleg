package firewall_manager

type IPTablesRule interface {
	Spec() []string
	RuleID() string
	String() string
}
