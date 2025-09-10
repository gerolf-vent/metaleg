package iptables

import (
	"os/exec"
	"reflect"
	"testing"
)

func TestProtocolString(t *testing.T) {
	if IPv4.String() != "IPv4" {
		t.Errorf("Expected IPv4.String() to be 'IPv4', got '%s'", IPv4.String())
	}
	if IPv6.String() != "IPv6" {
		t.Errorf("Expected IPv6.String() to be 'IPv6', got '%s'", IPv6.String())
	}
}

func TestTransportProtocolString(t *testing.T) {
	if TCP.String() != "tcp" {
		t.Errorf("Expected TCP.String() to be 'tcp', got '%s'", TCP.String())
	}
	if UDP.String() != "udp" {
		t.Errorf("Expected UDP.String() to be 'udp', got '%s'", UDP.String())
	}
}

func TestCmdError_Error(t *testing.T) {
	exitErr := &exec.ExitError{}
	e := &CmdError{ExitError: exitErr, cmd: "iptables -A foo", msg: "fail"}
	_ = e.Error() // Just ensure it doesn't panic
}

func TestNew_InvalidProto(t *testing.T) {
	_, err := New(Protocol("invalid"))
	if err == nil {
		t.Error("Expected error for invalid protocol")
	}
}

func TestNew_Integration(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	if ipt == nil {
		t.Error("Expected non-nil IPTables")
	}
}

func TestIsIPv6(t *testing.T) {
	ipt, err := New(IPv6)
	if err != nil {
		t.Skip("ip6tables not found, skipping integration test")
	}

	if !ipt.IsIPv6() {
		t.Error("Expected IsIPv6 to be true for IPv6")
	}
}

func TestProtocolMethod(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	if ipt.Protocol() != IPv4 {
		t.Errorf("Expected Protocol() to be IPv4, got %v", ipt.Protocol())
	}
}

func TestChainLifecycle(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	table := TableFilter
	chain := Chain("TESTCHAIN1234")
	_, _ = ipt.DeleteChain(table, chain) // Clean up before

	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		t.Errorf("ChainExists failed: %v", err)
	}
	if exists {
		t.Error("Expected chain to not exist before EnsureChain")
	}
	_, err = ipt.EnsureChain(table, chain)
	if err != nil {
		t.Errorf("EnsureChain failed: %v", err)
	}
	exists, err = ipt.ChainExists(table, chain)
	if err != nil {
		t.Errorf("ChainExists failed: %v", err)
	}
	if !exists {
		t.Error("Expected chain to exist after EnsureChain")
	}
	err = ipt.FlushChain(table, chain)
	if err != nil {
		t.Errorf("FlushChain failed: %v", err)
	}
	_, err = ipt.DeleteChain(table, chain)
	if err != nil {
		t.Errorf("DeleteChain failed: %v", err)
	}
}

func TestRuleLifecycle(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	table := TableFilter
	chain := Chain("TESTCHAIN1234")
	_, _ = ipt.DeleteChain(table, chain) // Clean up before

	_, _ = ipt.EnsureChain(table, chain)
	rule := []string{"-p", "tcp", "--dport", "12345", "-j", "ACCEPT"}
	_, _ = ipt.DeleteRule(table, chain, rule...)
	exists, err := ipt.RuleExists(table, chain, rule...)
	if err != nil {
		t.Errorf("RuleExists failed: %v", err)
	}
	if exists {
		t.Error("Expected rule to not exist before EnsureRule")
	}
	_, err = ipt.EnsureRule(Prepend, table, chain, rule...)
	if err != nil {
		t.Errorf("EnsureRule failed: %v", err)
	}
	exists, err = ipt.RuleExists(table, chain, rule...)
	if err != nil {
		t.Errorf("RuleExists failed: %v", err)
	}
	if !exists {
		t.Error("Expected rule to exist after EnsureRule")
	}
	_, err = ipt.DeleteRule(table, chain, rule...)
	if err != nil {
		t.Errorf("DeleteRule failed: %v", err)
	}
	_, _ = ipt.DeleteChain(table, chain)
}

func TestListRules(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	table := TableFilter
	chain := Chain("TESTCHAIN1234")
	_, _ = ipt.DeleteChain(table, chain)
	_, _ = ipt.EnsureChain(table, chain)
	rule := []string{"-p", "tcp", "-m", "tcp", "--dport", "12345", "-j", "ACCEPT"}
	_, _ = ipt.EnsureRule(Prepend, table, chain, rule...)
	rules, err := ipt.ListRules(table, chain)
	if err != nil {
		t.Errorf("ListRules failed: %v", err)
	}
	found := false
	for _, r := range rules {
		if reflect.DeepEqual(r[2:], rule) {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected to find rule in ListRules")
	}
	_, _ = ipt.DeleteRule(table, chain, rule...)
	_, _ = ipt.DeleteChain(table, chain)
}

func TestCheckVersion(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	err = ipt.checkVersion()
	if err != nil {
		t.Errorf("checkVersion failed: %v", err)
	}
}

func TestRunWithOutput_Error(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	err = ipt.runWithOutput([]string{"notarealcommand"}, nil)
	if err == nil {
		t.Error("Expected error for invalid command")
	}
}

func TestRun_Error(t *testing.T) {
	ipt, err := New(IPv4)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	err = ipt.run([]string{"notarealcommand"})
	if err == nil {
		t.Error("Expected error for invalid command")
	}
}

func TestTableString(t *testing.T) {
	if TableNAT != "nat" || TableFilter != "filter" || TableMangle != "mangle" {
		t.Error("Table string values incorrect")
	}
}

func TestChainString(t *testing.T) {
	if ChainPostrouting != "POSTROUTING" || ChainPrerouting != "PREROUTING" || ChainOutput != "OUTPUT" || ChainInput != "INPUT" || ChainForward != "FORWARD" {
		t.Error("Chain string values incorrect")
	}
}

func TestRulePositionString(t *testing.T) {
	if Prepend != "-I" || Append != "-A" {
		t.Error("RulePosition string values incorrect")
	}
}
