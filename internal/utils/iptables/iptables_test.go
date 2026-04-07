package iptables

import (
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func requireIPTablePrivileges(t *testing.T, ipt IPTables) {
	t.Helper()

	// Check if we have enough privileges by attempting a harmless ChainExists call.
	_, err := ipt.ChainExists(TableFilter, ChainInput)
	if err != nil && strings.Contains(strings.ToLower(err.Error()), "permission denied") {
		t.Skipf("Insufficient privileges to manage iptables: %v", err)
	}
}

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
	_, err := New(Protocol("invalid"), false)
	if err == nil {
		t.Error("Expected error for invalid protocol")
	}
}

func TestNew(t *testing.T) {
	for _, proto := range []Protocol{IPv4, IPv6} {
		t.Run(proto.String(), func(t *testing.T) {
			ipt, err := New(proto, false)
			if err != nil {
				t.Skipf("%s not found, skipping integration test", proto)
			}
			if ipt == nil {
				t.Errorf("Expected non-nil IPTables for %s", proto)
			}
			if ipt.Protocol() != proto {
				t.Errorf("Expected Protocol() to be %s, got %v", proto, ipt.Protocol())
			}
		})
	}
}

func TestIsIPv6(t *testing.T) {
	ipt, err := New(IPv6, false)
	if err != nil {
		t.Skip("ip6tables not found, skipping integration test")
	}

	if !ipt.IsIPv6() {
		t.Error("Expected IsIPv6 to be true for IPv6")
	}
}

func TestChainLifecycle(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

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
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

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
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

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

func TestEnsureRule_InsertAtOrdering(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

	table := TableFilter
	chain := Chain("TESTCHAIN_INSERTAT")
	_, _ = ipt.DeleteChain(table, chain)
	_, _ = ipt.EnsureChain(table, chain)

	rule1 := []string{"-m", "comment", "--comment", "rule-1", "-j", "ACCEPT"}
	rule2 := []string{"-m", "comment", "--comment", "rule-2", "-j", "ACCEPT"}
	rule3 := []string{"-m", "comment", "--comment", "rule-3", "-j", "ACCEPT"}
	rule4 := []string{"-m", "comment", "--comment", "rule-4", "-j", "ACCEPT"}
	rule5 := []string{"-m", "comment", "--comment", "rule-5", "-j", "ACCEPT"}

	_, _ = ipt.DeleteRule(table, chain, rule1...)
	_, _ = ipt.DeleteRule(table, chain, rule2...)
	_, _ = ipt.DeleteRule(table, chain, rule3...)
	_, _ = ipt.DeleteRule(table, chain, rule4...)
	_, _ = ipt.DeleteRule(table, chain, rule5...)

	if _, err := ipt.EnsureRule(Append, table, chain, rule1...); err != nil {
		t.Fatalf("failed to append rule1: %v", err)
	}
	if _, err := ipt.EnsureRule(Append, table, chain, rule3...); err != nil {
		t.Fatalf("failed to append rule3: %v", err)
	}
	if _, err := ipt.EnsureRule(Append, table, chain, rule5...); err != nil {
		t.Fatalf("failed to append rule5: %v", err)
	}
	if _, err := ipt.EnsureRule(InsertAt(2), table, chain, rule2...); err != nil {
		t.Fatalf("failed to insert rule2 at index 2: %v", err)
	}
	if _, err := ipt.EnsureRule(InsertAt(4), table, chain, rule4...); err != nil {
		t.Fatalf("failed to insert rule4 at index 4: %v", err)
	}

	rules, err := ipt.ListRules(table, chain)
	if err != nil {
		t.Fatalf("ListRules failed: %v", err)
	}

	if len(rules) != 5 {
		t.Fatalf("expected 5 rules, got %d", len(rules))
	}
	if !reflect.DeepEqual(rules[0][2:], rule1) {
		t.Errorf("expected first rule to be rule1, got %v", rules[0][2:])
	}
	if !reflect.DeepEqual(rules[1][2:], rule2) {
		t.Errorf("expected second rule to be rule2, got %v", rules[1][2:])
	}
	if !reflect.DeepEqual(rules[2][2:], rule3) {
		t.Errorf("expected third rule to be rule3, got %v", rules[2][2:])
	}
	if !reflect.DeepEqual(rules[3][2:], rule4) {
		t.Errorf("expected fourth rule to be rule4, got %v", rules[3][2:])
	}
	if !reflect.DeepEqual(rules[4][2:], rule5) {
		t.Errorf("expected fifth rule to be rule5, got %v", rules[4][2:])
	}

	_, _ = ipt.DeleteRule(table, chain, rule1...)
	_, _ = ipt.DeleteRule(table, chain, rule2...)
	_, _ = ipt.DeleteRule(table, chain, rule3...)
	_, _ = ipt.DeleteRule(table, chain, rule4...)
	_, _ = ipt.DeleteRule(table, chain, rule5...)
	_, _ = ipt.DeleteChain(table, chain)
}

func TestEnsureRule_InsertAtInvalidPositions(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

	table := TableFilter
	chain := Chain("TESTCHAIN_INSERTAT_INVALID")
	_, _ = ipt.DeleteChain(table, chain)
	_, _ = ipt.EnsureChain(table, chain)

	rule0 := []string{"-m", "comment", "--comment", "invalid-insert-0", "-j", "ACCEPT"}
	ruleNeg := []string{"-m", "comment", "--comment", "invalid-insert-neg", "-j", "ACCEPT"}

	_, _ = ipt.DeleteRule(table, chain, rule0...)
	_, _ = ipt.DeleteRule(table, chain, ruleNeg...)

	if _, err := ipt.EnsureRule(InsertAt(0), table, chain, rule0...); err == nil {
		t.Fatal("expected EnsureRule with InsertAt(0) to fail")
	}

	if _, err := ipt.EnsureRule(InsertAt(-1), table, chain, ruleNeg...); err == nil {
		t.Fatal("expected EnsureRule with InsertAt(-1) to fail")
	}

	exists0, err := ipt.RuleExists(table, chain, rule0...)
	if err != nil {
		t.Fatalf("RuleExists failed for InsertAt(0) rule: %v", err)
	}
	if exists0 {
		t.Error("did not expect rule from InsertAt(0) to exist")
	}

	existsNeg, err := ipt.RuleExists(table, chain, ruleNeg...)
	if err != nil {
		t.Fatalf("RuleExists failed for InsertAt(-1) rule: %v", err)
	}
	if existsNeg {
		t.Error("did not expect rule from InsertAt(-1) to exist")
	}

	_, _ = ipt.DeleteRule(table, chain, rule0...)
	_, _ = ipt.DeleteRule(table, chain, ruleNeg...)
	_, _ = ipt.DeleteChain(table, chain)
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

func TestNew_ExecutableNotFound(t *testing.T) {
	// Save original PATH and restore it after test
	originalPath := os.Getenv("PATH")
	defer func() {
		os.Setenv("PATH", originalPath)
	}()

	// Set PATH to empty to simulate executable not found
	os.Setenv("PATH", "")

	_, err := New(IPv4, false)
	if err == nil {
		t.Error("Expected error when iptables executable not found")
	}
	if !strings.Contains(err.Error(), "iptables executable not found") {
		t.Errorf("Expected error message about iptables executable not found, got: %v", err)
	}

	_, err = New(IPv6, false)
	if err == nil {
		t.Error("Expected error when ip6tables executable not found")
	}
	if !strings.Contains(err.Error(), "ip6tables executable not found") {
		t.Errorf("Expected error message about ip6tables executable not found, got: %v", err)
	}
}

func TestEnsureChain_ChainAlreadyExists(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

	table := TableFilter
	chain := Chain("TESTCHAIN_EXISTS")

	// Clean up before test
	_, _ = ipt.DeleteChain(table, chain)

	// Create the chain first
	created, err := ipt.EnsureChain(table, chain)
	if err != nil {
		t.Errorf("First EnsureChain failed: %v", err)
	}
	if created {
		t.Error("Expected first EnsureChain to return false (chain was created)")
	}

	// Try to ensure the same chain again - should return true (already exists)
	exists, err := ipt.EnsureChain(table, chain)
	if err != nil {
		t.Errorf("Second EnsureChain failed: %v", err)
	}
	if !exists {
		t.Error("Expected second EnsureChain to return true (chain already exists)")
	}

	// Clean up
	_, _ = ipt.DeleteChain(table, chain)
}

func TestDeleteChain_ChainDoesNotExist(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

	table := TableFilter
	chain := Chain("TESTCHAIN_NONEXISTENT")

	// Make sure the chain doesn't exist
	_, _ = ipt.DeleteChain(table, chain)

	// Verify chain doesn't exist
	exists, err := ipt.ChainExists(table, chain)
	if err != nil {
		t.Errorf("ChainExists failed: %v", err)
	}
	if exists {
		t.Error("Expected chain to not exist before test")
	}

	// Try to delete non-existent chain - should return true (nothing to delete)
	deleted, err := ipt.DeleteChain(table, chain)
	if err != nil {
		t.Errorf("DeleteChain failed: %v", err)
	}
	if !deleted {
		t.Error("Expected DeleteChain to return true when chain doesn't exist")
	}
}

// Test IPTablesSpecParser
func TestIPTablesSpecParser_NewIPTablesSpecParser(t *testing.T) {
	args := [][]string{
		{"-p", "tcp"},
		{"--dport", "{port}"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)
	if parser == nil {
		t.Fatal("Expected non-nil parser")
	}
	if len(parser.args) != 3 {
		t.Errorf("Expected 3 args, got %d", len(parser.args))
	}
}

func TestIPTablesSpecParser_Parse_Success(t *testing.T) {
	args := [][]string{
		{"-p", "tcp"},
		{"--dport", "{port}"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)

	spec := []string{"-p", "tcp", "--dport", "8080", "-j", "ACCEPT"}
	values, ok := parser.Parse(spec)
	if !ok {
		t.Error("Expected Parse to succeed")
	}
	if values["port"] != "8080" {
		t.Errorf("Expected port to be '8080', got '%s'", values["port"])
	}
}

func TestIPTablesSpecParser_Parse_Mismatch(t *testing.T) {
	args := [][]string{
		{"-p", "tcp"},
		{"--dport", "{port}"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)

	// Test with wrong protocol
	spec := []string{"-p", "udp", "--dport", "8080", "-j", "ACCEPT"}
	_, ok := parser.Parse(spec)
	if ok {
		t.Error("Expected Parse to fail with wrong protocol")
	}
}

func TestIPTablesSpecParser_Parse_InsufficientValues(t *testing.T) {
	args := [][]string{
		{"-p", "tcp"},
		{"--dport", "{port}"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)

	// Test with insufficient values
	spec := []string{"-p", "tcp", "--dport"}
	_, ok := parser.Parse(spec)
	if ok {
		t.Error("Expected Parse to fail with insufficient values")
	}
}

func TestIPTablesSpecParser_Parse_ValueMismatch(t *testing.T) {
	args := [][]string{
		{"-p", "tcp"},
		{"--dport", "8080"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)

	// Test with wrong port value
	spec := []string{"-p", "tcp", "--dport", "9090", "-j", "ACCEPT"}
	_, ok := parser.Parse(spec)
	if ok {
		t.Error("Expected Parse to fail with wrong port value")
	}
}

func TestIPTablesSpecParser_Parse_EmptyArg(t *testing.T) {
	args := [][]string{
		{}, // empty arg
		{"-p", "tcp"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)

	spec := []string{"-p", "tcp", "-j", "ACCEPT"}
	_, ok := parser.Parse(spec)
	if ok {
		t.Error("Expected Parse to fail when not all args are matched")
	}
}

func TestIPTablesSpecParser_Parse_UnmatchedArg(t *testing.T) {
	args := [][]string{
		{"-p", "tcp"},
		{"--dport", "{port}"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)

	// Test with spec that doesn't match all args (missing -j ACCEPT)
	spec := []string{"-p", "tcp", "--dport", "8080"}
	_, ok := parser.Parse(spec)
	if ok {
		t.Error("Expected Parse to fail when spec doesn't match all args")
	}
}

func TestIPTablesSpecParser_Parse_NoMatchingArg(t *testing.T) {
	args := [][]string{
		{"-p", "tcp"},
		{"-j", "ACCEPT"},
	}
	parser := NewIPTablesSpecParser(args)

	// Test with spec that has unrecognized option
	spec := []string{"-p", "tcp", "--unknown-option", "value", "-j", "ACCEPT"}
	_, ok := parser.Parse(spec)
	if ok {
		t.Error("Expected Parse to fail with unrecognized option")
	}
}

// Test additional error scenarios for main iptables functionality
func TestEnsureRule_DeleteRule_NonExistent(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

	table := TableFilter
	chain := Chain("TESTCHAIN_RULES")
	_, _ = ipt.DeleteChain(table, chain)
	_, _ = ipt.EnsureChain(table, chain)

	// Test deleting a non-existent rule
	rule := []string{"-p", "tcp", "--dport", "99999", "-j", "DROP"}
	deleted, err := ipt.DeleteRule(table, chain, rule...)
	if err != nil {
		t.Errorf("DeleteRule failed: %v", err)
	}
	if deleted {
		t.Error("Expected DeleteRule to return false when rule doesn't exist")
	}

	// Clean up
	_, _ = ipt.DeleteChain(table, chain)
}

func TestEnsureRule_RuleAlreadyExists(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

	table := TableFilter
	chain := Chain("TESTCHAIN_EXISTING_RULE")
	_, _ = ipt.DeleteChain(table, chain)
	_, _ = ipt.EnsureChain(table, chain)

	rule := []string{"-p", "tcp", "--dport", "54321", "-j", "ACCEPT"}

	// Create the rule first
	existed, err := ipt.EnsureRule(Append, table, chain, rule...)
	if err != nil {
		t.Errorf("First EnsureRule failed: %v", err)
	}
	if existed {
		t.Error("Expected first EnsureRule to return false (rule was created)")
	}

	// Try to ensure the same rule again - should return true (already exists)
	existed, err = ipt.EnsureRule(Append, table, chain, rule...)
	if err != nil {
		t.Errorf("Second EnsureRule failed: %v", err)
	}
	if !existed {
		t.Error("Expected second EnsureRule to return true (rule already exists)")
	}

	// Clean up
	_, _ = ipt.DeleteRule(table, chain, rule...)
	_, _ = ipt.DeleteChain(table, chain)
}

func TestListRules_EmptyChain(t *testing.T) {
	ipt, err := New(IPv4, false)
	if err != nil {
		t.Skip("iptables not found, skipping integration test")
	}

	requireIPTablePrivileges(t, ipt)

	table := TableFilter
	chain := Chain("TESTCHAIN_EMPTY")
	_, _ = ipt.DeleteChain(table, chain)
	_, _ = ipt.EnsureChain(table, chain)

	rules, err := ipt.ListRules(table, chain)
	if err != nil {
		t.Errorf("ListRules failed: %v", err)
	}

	if len(rules) != 0 {
		t.Error("Expected no rules in empty chain")
	}

	// Clean up
	_, _ = ipt.DeleteChain(table, chain)
}

// Test constants and string methods
func TestConstants(t *testing.T) {
	// Test that all constants have expected values
	tests := []struct {
		name     string
		actual   interface{}
		expected interface{}
	}{
		{"TableNAT", TableNAT, Table("nat")},
		{"TableFilter", TableFilter, Table("filter")},
		{"TableMangle", TableMangle, Table("mangle")},
		{"ChainPostrouting", ChainPostrouting, Chain("POSTROUTING")},
		{"ChainPrerouting", ChainPrerouting, Chain("PREROUTING")},
		{"ChainOutput", ChainOutput, Chain("OUTPUT")},
		{"ChainInput", ChainInput, Chain("INPUT")},
		{"ChainForward", ChainForward, Chain("FORWARD")},
		{"Prepend", Prepend, RulePosition([]string{"-I"})},
		{"Append", Append, RulePosition([]string{"-A"})},
		{"InsertAt(1)", InsertAt(1), RulePosition([]string{"-I", "1"})},
		{"IPv4", IPv4, Protocol("IPv4")},
		{"IPv6", IPv6, Protocol("IPv6")},
		{"TCP", TCP, TransportProtocol("tcp")},
		{"UDP", UDP, TransportProtocol("udp")},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if !reflect.DeepEqual(test.expected, test.actual) {
				t.Errorf("Expected %s to be %v, got %v", test.name, test.expected, test.actual)
			}
		})
	}
}

func TestInsertAt(t *testing.T) {
	tests := []struct {
		name     string
		index    int
		expected RulePosition
	}{
		{name: "first", index: 1, expected: RulePosition([]string{"-I", "1"})},
		{name: "middle", index: 7, expected: RulePosition([]string{"-I", "7"})},
		{name: "zero", index: 0, expected: RulePosition([]string{"-I", "0"})},
		{name: "negative", index: -3, expected: RulePosition([]string{"-I", "-3"})},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			actual := InsertAt(tt.index)
			if !reflect.DeepEqual(tt.expected, actual) {
				t.Errorf("InsertAt(%d): expected %v, got %v", tt.index, tt.expected, actual)
			}
		})
	}
}

func TestCmdError_ExitCode(t *testing.T) {
	// Create a mock ExitError
	exitErr := &exec.ExitError{}

	cmdErr := &CmdError{
		ExitError: exitErr,
		cmd:       "test-command",
		msg:       "test message",
	}

	// Test Error() method formatting
	errorStr := cmdErr.Error()
	if !strings.Contains(errorStr, "test-command") {
		t.Error("Expected error message to contain command")
	}
	if !strings.Contains(errorStr, "test message") {
		t.Error("Expected error message to contain message")
	}
}
