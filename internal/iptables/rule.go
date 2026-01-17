package iptables

type Rule interface {
	Spec() []string
	RuleID() string
	String() string
}
