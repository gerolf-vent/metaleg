package iptables

import (
	"net"
	"strings"
	"testing"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/mock"
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/go-logr/logr"
)

func ruleSpecToString(spec []string) string {
	return strings.Join(spec, " ")
}

func isSNATSkipRuleWithMask(spec []string, mask uint32) bool {
	rule, ok := ParseSNATSkipRule(spec)
	return ok && rule.FWMask == mask
}

// --- Test helpers ---

func newTestManager(state *mock.State) *Manager {
	return &Manager{
		state:           state,
		logger:          logr.Discard(),
		nodeName:        state.NodeNameVal,
		fwMask:          state.FWMaskVal,
		excludeDstCIDRs: state.ExcludeDstCIDRsVal,
		ipt4:            mock.NewIPTables(false),
		ipt6:            mock.NewIPTables(true),
		ips:             mock.NewIPSet(),
	}
}

func getIPT4(m *Manager) *mock.IPTables { return m.ipt4.(*mock.IPTables) }
func getIPT6(m *Manager) *mock.IPTables { return m.ipt6.(*mock.IPTables) }
func getIPS(m *Manager) *mock.IPSet     { return m.ips.(*mock.IPSet) }

// --- Tests ---

func TestManager_Name(t *testing.T) {
	m := newTestManager(mock.NewState())
	if m.Name() != "iptables" {
		t.Errorf("Expected name 'iptables', got %q", m.Name())
	}
}

// --- Setup ---

func TestSetup_CreatesChains(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ipt4 := getIPT4(m)
	ipt6 := getIPT6(m)

	for _, ipt := range []*mock.IPTables{ipt4, ipt6} {
		proto := "IPv4"
		if ipt.IPv6 {
			proto = "IPv6"
		}

		// Mangle chain
		if !ipt.Chains[string(iptables.TableMangle)+":"+iptablesRTMarkChainName] {
			t.Errorf("%s: Expected mangle chain %s to exist", proto, iptablesRTMarkChainName)
		}
		// Filter chain
		if !ipt.Chains[string(iptables.TableFilter)+":"+iptablesRejectChainName] {
			t.Errorf("%s: Expected filter chain %s to exist", proto, iptablesRejectChainName)
		}
		// NAT chain
		if !ipt.Chains[string(iptables.TableNAT)+":"+iptablesSNATChainName] {
			t.Errorf("%s: Expected NAT chain %s to exist", proto, iptablesSNATChainName)
		}
	}
}

func TestSetup_CreatesExcludeDstIPSets(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ips := getIPS(m)

	if !ips.NetworkSets[ipsetExcludeDstPrefix+"4"] {
		t.Error("Expected IPv4 exclude dst ipset to exist")
	}
	if !ips.NetworkSets[ipsetExcludeDstPrefix+"6"] {
		t.Error("Expected IPv6 exclude dst ipset to exist")
	}

	// Check IPv4 exclude CIDRs were added
	entries4 := ips.NetworkEntries[ipsetExcludeDstPrefix+"4"]
	found4 := false
	for _, e := range entries4 {
		if e.String() == "10.0.0.0/8" {
			found4 = true
		}
	}
	if !found4 {
		t.Error("Expected 10.0.0.0/8 in IPv4 exclude dst ipset")
	}

	// Check IPv6 exclude CIDRs were added
	entries6 := ips.NetworkEntries[ipsetExcludeDstPrefix+"6"]
	found6 := false
	for _, e := range entries6 {
		if e.String() == "fc00::/7" {
			found6 = true
		}
	}
	if !found6 {
		t.Error("Expected fc00::/7 in IPv6 exclude dst ipset")
	}
}

func TestSetup_JumpRules(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ipt4 := getIPT4(m)

	// PREROUTING -> METALEG-RT-MARK
	preroutingRules := ipt4.GetRules(iptables.TableMangle, iptables.ChainPrerouting)
	found := false
	for _, r := range preroutingRules {
		if ruleSpecToString(r) == "-j "+iptablesRTMarkChainName {
			found = true
		}
	}
	if !found {
		t.Error("Expected PREROUTING -> METALEG-RT-MARK jump rule")
	}

	// FORWARD -> METALEG-REJECT
	forwardRules := ipt4.GetRules(iptables.TableFilter, iptables.ChainForward)
	found = false
	for _, r := range forwardRules {
		if ruleSpecToString(r) == "-j "+iptablesRejectChainName {
			found = true
		}
	}
	if !found {
		t.Error("Expected FORWARD -> METALEG-REJECT jump rule")
	}

	// POSTROUTING -> METALEG-SNAT
	postroutingRules := ipt4.GetRules(iptables.TableNAT, iptables.ChainPostrouting)
	found = false
	for _, r := range postroutingRules {
		if ruleSpecToString(r) == "-j "+iptablesSNATChainName {
			found = true
		}
	}
	if !found {
		t.Error("Expected POSTROUTING -> METALEG-SNAT jump rule")
	}
}

func TestSetup_BuiltInChainRulePositions(t *testing.T) {
	m := newTestManager(mock.NewState())
	ipt4 := getIPT4(m)

	// Simulate pre-existing network plugin rules (Calico/kube-router style) in built-in chains.
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableMangle, iptables.ChainPrerouting, "-m", "comment", "--comment", "cali: accepted established", "-j", "ACCEPT")
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableMangle, iptables.ChainPrerouting, "-j", "cali-PREROUTING")
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableMangle, iptables.ChainPrerouting, "-j", "KUBE-ROUTER-PREROUTING")

	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableFilter, iptables.ChainForward, "-j", "KUBE-ROUTER-FORWARD")
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableFilter, iptables.ChainForward, "-j", "cali-FORWARD")

	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableNAT, iptables.ChainPostrouting, "-j", "cali-POSTROUTING")
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableNAT, iptables.ChainPostrouting, "-j", "KUBE-ROUTER-POSTROUTING")

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	manglePrerouting := ipt4.GetRules(iptables.TableMangle, iptables.ChainPrerouting)
	if len(manglePrerouting) < 4 {
		t.Fatalf("Expected at least 4 rules in mangle PREROUTING, got %d", len(manglePrerouting))
	}
	if got := ruleSpecToString(manglePrerouting[0]); got != "-j "+iptablesRTMarkChainName {
		t.Errorf("Expected first mangle PREROUTING rule to be jump to %s, got %q", iptablesRTMarkChainName, got)
	}
	if !isSNATSkipRuleWithMask(manglePrerouting[1], uint32(m.fwMask)) {
		t.Errorf("Expected second mangle PREROUTING rule to be SNAT-skip with mask %#x, got %q", uint32(m.fwMask), ruleSpecToString(manglePrerouting[1]))
	}
	if got := ruleSpecToString(manglePrerouting[2]); got != "-j cali-PREROUTING" {
		t.Errorf("Expected third mangle PREROUTING rule to remain cali-PREROUTING, got %q", got)
	}
	if got := ruleSpecToString(manglePrerouting[3]); got != "-j KUBE-ROUTER-PREROUTING" {
		t.Errorf("Expected fourth mangle PREROUTING rule to remain KUBE-ROUTER-PREROUTING, got %q", got)
	}

	filterForward := ipt4.GetRules(iptables.TableFilter, iptables.ChainForward)
	if len(filterForward) < 4 {
		t.Fatalf("Expected at least 4 rules in filter FORWARD, got %d", len(filterForward))
	}
	if !isSNATSkipRuleWithMask(filterForward[0], uint32(m.fwMask)) {
		t.Errorf("Expected first filter FORWARD rule to be SNAT-skip with mask %#x, got %q", uint32(m.fwMask), ruleSpecToString(filterForward[0]))
	}
	if got := ruleSpecToString(filterForward[1]); got != "-j "+iptablesRejectChainName {
		t.Errorf("Expected second filter FORWARD rule to be jump to %s, got %q", iptablesRejectChainName, got)
	}
	if got := ruleSpecToString(filterForward[2]); got != "-j KUBE-ROUTER-FORWARD" {
		t.Errorf("Expected third filter FORWARD rule to remain KUBE-ROUTER-FORWARD, got %q", got)
	}
	if got := ruleSpecToString(filterForward[3]); got != "-j cali-FORWARD" {
		t.Errorf("Expected fourth filter FORWARD rule to remain cali-FORWARD, got %q", got)
	}

	natPostrouting := ipt4.GetRules(iptables.TableNAT, iptables.ChainPostrouting)
	if len(natPostrouting) < 4 {
		t.Fatalf("Expected at least 4 rules in nat POSTROUTING, got %d", len(natPostrouting))
	}
	if !isSNATSkipRuleWithMask(natPostrouting[0], uint32(m.fwMask)) {
		t.Errorf("Expected first nat POSTROUTING rule to be SNAT-skip with mask %#x, got %q", uint32(m.fwMask), ruleSpecToString(natPostrouting[0]))
	}
	if got := ruleSpecToString(natPostrouting[1]); got != "-j "+iptablesSNATChainName {
		t.Errorf("Expected second nat POSTROUTING rule to be jump to %s, got %q", iptablesSNATChainName, got)
	}
	if got := ruleSpecToString(natPostrouting[2]); got != "-j cali-POSTROUTING" {
		t.Errorf("Expected third nat POSTROUTING rule to remain cali-POSTROUTING, got %q", got)
	}
	if got := ruleSpecToString(natPostrouting[3]); got != "-j KUBE-ROUTER-POSTROUTING" {
		t.Errorf("Expected fourth nat POSTROUTING rule to remain KUBE-ROUTER-POSTROUTING, got %q", got)
	}
}

func TestSetup_CustomChainExcludeRulePosition(t *testing.T) {
	m := newTestManager(mock.NewState())
	ipt4 := getIPT4(m)

	_, _ = ipt4.EnsureChain(iptables.TableMangle, iptablesRTMarkChainName)
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableMangle, iptablesRTMarkChainName, "-j", "EXISTING-MANGLE")

	_, _ = ipt4.EnsureChain(iptables.TableFilter, iptablesRejectChainName)
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableFilter, iptablesRejectChainName, "-j", "EXISTING-FILTER")

	_, _ = ipt4.EnsureChain(iptables.TableNAT, iptablesSNATChainName)
	_, _ = ipt4.EnsureRule(iptables.Append, iptables.TableNAT, iptablesSNATChainName, "-j", "EXISTING-NAT")

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mangleRules := ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName)
	if len(mangleRules) == 0 {
		t.Fatal("Expected mangle chain to contain rules after setup")
	}
	if !strings.Contains(ruleSpecToString(mangleRules[0]), ipsetExcludeDstPrefix) {
		t.Errorf("Expected first mangle chain rule to be exclude-dst, got %q", ruleSpecToString(mangleRules[0]))
	}

	filterRules := ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName)
	if len(filterRules) == 0 {
		t.Fatal("Expected filter chain to contain rules after setup")
	}
	if !strings.Contains(ruleSpecToString(filterRules[0]), ipsetExcludeDstPrefix) {
		t.Errorf("Expected first filter chain rule to be exclude-dst, got %q", ruleSpecToString(filterRules[0]))
	}

	natRules := ipt4.GetRules(iptables.TableNAT, iptablesSNATChainName)
	if len(natRules) == 0 {
		t.Fatal("Expected nat chain to contain rules after setup")
	}
	if !strings.Contains(ruleSpecToString(natRules[0]), ipsetExcludeDstPrefix) {
		t.Errorf("Expected first nat chain rule to be exclude-dst, got %q", ruleSpecToString(natRules[0]))
	}
}

func TestSetup_ExcludeDstRulesInChains(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ipt4 := getIPT4(m)

	// Check exclude dst rule in mangle chain
	mangleRules := ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName)
	hasExclude := false
	for _, r := range mangleRules {
		if strings.Contains(ruleSpecToString(r), ipsetExcludeDstPrefix) {
			hasExclude = true
		}
	}
	if !hasExclude {
		t.Error("Expected exclude dst rule in mangle chain")
	}

	// Check exclude dst rule in filter chain
	filterRules := ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName)
	hasExclude = false
	for _, r := range filterRules {
		if strings.Contains(ruleSpecToString(r), ipsetExcludeDstPrefix) {
			hasExclude = true
		}
	}
	if !hasExclude {
		t.Error("Expected exclude dst rule in filter chain")
	}

	// Check exclude dst rule in NAT chain
	natRules := ipt4.GetRules(iptables.TableNAT, iptablesSNATChainName)
	hasExclude = false
	for _, r := range natRules {
		if strings.Contains(ruleSpecToString(r), ipsetExcludeDstPrefix) {
			hasExclude = true
		}
	}
	if !hasExclude {
		t.Error("Expected exclude dst rule in NAT chain")
	}
}

func TestSetup_SNATSkipRule(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ipt4 := getIPT4(m)

	postroutingRules := ipt4.GetRules(iptables.TableNAT, iptables.ChainPostrouting)
	hasSNATSkip := false
	for _, r := range postroutingRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, "--mark") && strings.Contains(spec, "RETURN") {
			hasSNATSkip = true
		}
	}
	if !hasSNATSkip {
		t.Error("Expected SNAT-skip rule in POSTROUTING")
	}
}

func TestSetup_Idempotent(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("First Setup failed: %v", err)
	}

	// Count rules
	ipt4 := getIPT4(m)
	mangleCount := len(ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName))
	filterCount := len(ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName))

	if err := m.Setup(); err != nil {
		t.Fatalf("Second Setup failed: %v", err)
	}

	// Rule counts should be the same (no duplicates)
	if len(ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName)) != mangleCount {
		t.Error("Setup is not idempotent: mangle chain rule count changed")
	}
	if len(ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName)) != filterCount {
		t.Error("Setup is not idempotent: filter chain rule count changed")
	}
}

func TestSetup_RemovesStaleExcludeCIDRs(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)
	ips := getIPS(m)

	// Pre-populate ipset with a stale CIDR
	_, staleCIDR, _ := net.ParseCIDR("172.16.0.0/12")
	ips.NetworkSets[ipsetExcludeDstPrefix+"4"] = true
	ips.NetworkEntries[ipsetExcludeDstPrefix+"4"] = []net.IPNet{*staleCIDR}

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// The stale CIDR should be removed, and the configured one should be present
	entries := ips.NetworkEntries[ipsetExcludeDstPrefix+"4"]
	for _, e := range entries {
		if e.String() == "172.16.0.0/12" {
			t.Error("Expected stale CIDR 172.16.0.0/12 to be removed")
		}
	}

	found := false
	for _, e := range entries {
		if e.String() == "10.0.0.0/8" {
			found = true
		}
	}
	if !found {
		t.Error("Expected configured CIDR 10.0.0.0/8 to be present")
	}
}

// --- Purge ---

func TestPurge_CleansUpChains(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if err := m.Purge(); err != nil {
		t.Fatalf("Purge failed: %v", err)
	}

	ipt4 := getIPT4(m)

	// Custom chains should be deleted
	if ipt4.Chains[string(iptables.TableMangle)+":"+iptablesRTMarkChainName] {
		t.Error("Expected mangle chain to be deleted after purge")
	}
	if ipt4.Chains[string(iptables.TableFilter)+":"+iptablesRejectChainName] {
		t.Error("Expected filter chain to be deleted after purge")
	}
	if ipt4.Chains[string(iptables.TableNAT)+":"+iptablesSNATChainName] {
		t.Error("Expected NAT chain to be deleted after purge")
	}
}

func TestPurge_RemovesJumpRules(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if err := m.Purge(); err != nil {
		t.Fatalf("Purge failed: %v", err)
	}

	ipt4 := getIPT4(m)

	// Check that jump rules are removed from built-in chains
	for _, r := range ipt4.GetRules(iptables.TableMangle, iptables.ChainPrerouting) {
		if ruleSpecToString(r) == "-j "+iptablesRTMarkChainName {
			t.Error("Expected PREROUTING -> METALEG-RT-MARK jump rule to be removed")
		}
	}
	for _, r := range ipt4.GetRules(iptables.TableFilter, iptables.ChainForward) {
		if ruleSpecToString(r) == "-j "+iptablesRejectChainName {
			t.Error("Expected FORWARD -> METALEG-REJECT jump rule to be removed")
		}
	}
	for _, r := range ipt4.GetRules(iptables.TableNAT, iptables.ChainPostrouting) {
		if ruleSpecToString(r) == "-j "+iptablesSNATChainName {
			t.Error("Expected POSTROUTING -> METALEG-SNAT jump rule to be removed")
		}
	}
}

func TestPurge_RemovesMETALEGIPSets(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ips := getIPS(m)
	// Add a METALEG ipset that should be cleaned up
	ips.Sets["METALEG-SRC-TEST123"] = true
	ips.Entries["METALEG-SRC-TEST123"] = nil

	if err := m.Purge(); err != nil {
		t.Fatalf("Purge failed: %v", err)
	}

	sets, _ := ips.ListSets()
	for _, s := range sets {
		if strings.HasPrefix(s, "METALEG-") {
			t.Errorf("Expected all METALEG- ipsets to be purged, found %q", s)
		}
	}
}

func TestPurge_RemovesSNATSkipRule(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if err := m.Purge(); err != nil {
		t.Fatalf("Purge failed: %v", err)
	}

	ipt4 := getIPT4(m)
	for _, r := range ipt4.GetRules(iptables.TableNAT, iptables.ChainPostrouting) {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, "--mark") && strings.Contains(spec, "RETURN") {
			t.Error("Expected SNAT-skip rule to be removed after purge")
		}
	}
}

// --- Reconcile ---

func TestReconcile_NoChanges(t *testing.T) {
	m := newTestManager(mock.NewState())

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	sc := core.NewStateChange()
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
}

func TestReconcile_AddRedirectRule(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set up a rule in redirect mode (GW != local node, with FWMark and GW IPs)
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	ipt4 := getIPT4(m)
	ips := getIPS(m)

	// Should create source IP ipset
	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash
	if !ips.Sets[srcSetName] {
		t.Errorf("Expected source ipset %s to exist", srcSetName)
	}

	// Should contain the source IP
	srcEntries := ips.Entries[srcSetName]
	if len(srcEntries) != 1 || !srcEntries[0].Equal(net.ParseIP("10.0.0.1")) {
		t.Error("Expected source IP 10.0.0.1 in ipset")
	}

	// Should have a mark rule in mangle chain (redirect mode)
	mangleRules := ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName)
	hasMarkRule := false
	for _, r := range mangleRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, srcSetName) && strings.Contains(spec, "MARK") {
			hasMarkRule = true
		}
	}
	if !hasMarkRule {
		t.Error("Expected mark rule in mangle chain for redirect mode")
	}

	// Should NOT have a reject rule
	filterRules := ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName)
	for _, r := range filterRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, srcSetName) {
			t.Error("Should not have reject rule for redirect mode")
		}
	}

	// Should NOT have a SNAT rule
	natRules := ipt4.GetRules(iptables.TableNAT, iptablesSNATChainName)
	for _, r := range natRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, srcSetName) {
			t.Error("Should not have SNAT rule for redirect mode")
		}
	}
}

func TestReconcile_AddSNATRule(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set up a rule in SNAT mode (GW == local node)
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "local-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	ipt4 := getIPT4(m)
	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash

	// Should have a SNAT rule in NAT chain
	natRules := ipt4.GetRules(iptables.TableNAT, iptablesSNATChainName)
	hasSNATRule := false
	for _, r := range natRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, srcSetName) && strings.Contains(spec, "SNAT") {
			hasSNATRule = true
		}
	}
	if !hasSNATRule {
		t.Error("Expected SNAT rule in NAT chain for SNAT mode")
	}

	// Should NOT have a mark rule
	mangleRules := ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName)
	for _, r := range mangleRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, srcSetName) && strings.Contains(spec, "MARK") {
			t.Error("Should not have mark rule for SNAT mode")
		}
	}
}

func TestReconcile_AddBlockRule(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set up a rule in block mode (has SNAT IP but no GW IP → block)
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: nil, // No GW IP → block mode
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	ipt4 := getIPT4(m)
	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash

	// Should have a reject rule in filter chain
	filterRules := ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName)
	hasRejectRule := false
	for _, r := range filterRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, srcSetName) && strings.Contains(spec, "REJECT") {
			hasRejectRule = true
		}
	}
	if !hasRejectRule {
		t.Error("Expected reject rule in filter chain for block mode")
	}
}

func TestReconcile_DeleteEgressRule(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// First add a rule
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("First Reconcile failed: %v", err)
	}

	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash

	// Verify rule was created
	ips := getIPS(m)
	if !ips.Sets[srcSetName] {
		t.Fatal("Expected source ipset to exist before deletion")
	}

	// Now delete the rule
	delete(state.EgressRuleStates, "ns/svc1")
	sc2 := core.NewStateChange()
	sc2.EgressRulesDeleted["ns/svc1"] = ruleState

	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Delete Reconcile failed: %v", err)
	}

	// Source ipset should be removed
	if ips.Sets[srcSetName] {
		t.Error("Expected source ipset to be deleted")
	}

	// Iptables rules should be removed
	ipt4 := getIPT4(m)
	for _, r := range ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName) {
		if strings.Contains(ruleSpecToString(r), srcSetName) {
			t.Error("Expected mark rule to be removed after deletion")
		}
	}
	for _, r := range ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName) {
		if strings.Contains(ruleSpecToString(r), srcSetName) {
			t.Error("Expected reject rule to be removed after deletion")
		}
	}
	for _, r := range ipt4.GetRules(iptables.TableNAT, iptablesSNATChainName) {
		if strings.Contains(ruleSpecToString(r), srcSetName) {
			t.Error("Expected SNAT rule to be removed after deletion")
		}
	}
}

func TestReconcile_UpdateRuleModeChange(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Start with redirect mode
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("First Reconcile failed: %v", err)
	}

	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash
	ipt4 := getIPT4(m)

	// Verify redirect mode: has mark rule
	hasMarkRule := false
	for _, r := range ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName) {
		if strings.Contains(ruleSpecToString(r), srcSetName) {
			hasMarkRule = true
		}
	}
	if !hasMarkRule {
		t.Fatal("Expected mark rule after redirect mode reconcile")
	}

	// Switch to SNAT mode (GW becomes local node)
	ruleState.GWNodeName = "local-node"
	ruleState.GWIPv4 = net.ParseIP("192.168.1.99")
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc2 := core.NewStateChange()
	sc2.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Second Reconcile failed: %v", err)
	}

	// Mark rule should be gone
	for _, r := range ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName) {
		if strings.Contains(ruleSpecToString(r), srcSetName) && strings.Contains(ruleSpecToString(r), "MARK") {
			t.Error("Expected mark rule to be removed after switching to SNAT mode")
		}
	}

	// SNAT rule should exist
	hasSNATRule := false
	for _, r := range ipt4.GetRules(iptables.TableNAT, iptablesSNATChainName) {
		if strings.Contains(ruleSpecToString(r), srcSetName) && strings.Contains(ruleSpecToString(r), "SNAT") {
			hasSNATRule = true
		}
	}
	if !hasSNATRule {
		t.Error("Expected SNAT rule after switching to SNAT mode")
	}
}

func TestReconcile_UpdateSourceIPs(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.2")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("First Reconcile failed: %v", err)
	}

	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash
	ips := getIPS(m)

	if len(ips.Entries[srcSetName]) != 2 {
		t.Fatalf("Expected 2 source IPs, got %d", len(ips.Entries[srcSetName]))
	}

	// Update: remove 10.0.0.2, add 10.0.0.3
	ruleState.SrcIPv4s = []net.IP{net.ParseIP("10.0.0.1"), net.ParseIP("10.0.0.3")}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc2 := core.NewStateChange()
	sc2.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Second Reconcile failed: %v", err)
	}

	entries := ips.Entries[srcSetName]
	if len(entries) != 2 {
		t.Fatalf("Expected 2 source IPs after update, got %d", len(entries))
	}

	has1 := false
	has3 := false
	has2 := false
	for _, ip := range entries {
		if ip.Equal(net.ParseIP("10.0.0.1")) {
			has1 = true
		}
		if ip.Equal(net.ParseIP("10.0.0.2")) {
			has2 = true
		}
		if ip.Equal(net.ParseIP("10.0.0.3")) {
			has3 = true
		}
	}
	if !has1 {
		t.Error("Expected 10.0.0.1 to remain in ipset")
	}
	if has2 {
		t.Error("Expected 10.0.0.2 to be removed from ipset")
	}
	if !has3 {
		t.Error("Expected 10.0.0.3 to be added to ipset")
	}
}

func TestReconcile_UnconfiguredRuleDeletesIPTablesRules(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Set up a rule without SNAT IP → unconfigured mode
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			// No SNATIPv4 → unconfigured
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash

	// In unconfigured mode, any existing iptables rules and ipsets should be deleted
	ips := getIPS(m)
	if ips.Sets[srcSetName] {
		t.Error("Expected ipset to be deleted for unconfigured rule")
	}
}

func TestReconcile_IPv6Rule(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv6s:   []net.IP{net.ParseIP("fd00::1")},
			SNATIPv6:   net.ParseIP("2001:db8::1"),
		},
		GWIPv6: net.ParseIP("fd00::99"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	ipt6 := getIPT6(m)
	ips := getIPS(m)

	ruleHash := ruleState.CalcIDHash(true)
	srcSetName := "inet6:" + ipsetSrcPrefix + ruleHash

	if !ips.Sets[srcSetName] {
		t.Errorf("Expected IPv6 source ipset %s to exist", srcSetName)
	}

	// Should have a mark rule in IPv6 mangle chain
	mangleRules := ipt6.GetRules(iptables.TableMangle, iptablesRTMarkChainName)
	hasMarkRule := false
	for _, r := range mangleRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, srcSetName) && strings.Contains(spec, "MARK") {
			hasMarkRule = true
		}
	}
	if !hasMarkRule {
		t.Error("Expected mark rule in IPv6 mangle chain for redirect mode")
	}
}

func TestReconcile_SkipsNonExistentUpdatedRule(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Reference a rule ID that doesn't exist in state
	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("nonexistent")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile should not fail for non-existent rule: %v", err)
	}
}

func TestReconcile_NoEgressRuleChanges_Noop(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Only node changes, no egress rule changes
	sc := core.NewStateChange()
	sc.NodesUpdated.Add("some-node")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}
}

// --- Cleanup ---

func TestCleanup_RemovesStaleRules(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Add a legit rule
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	// Now inject a stale rule (a rule whose hash is no longer in state)
	ipt4 := getIPT4(m)
	staleSetName := ipsetSrcPrefix + "STALEHASH1234"
	staleRule := []string{"-m", "set", "--match-set", staleSetName, "src", "-j", "REJECT", "--reject-with", "icmp-port-unreachable"}
	ipt4.EnsureRule(iptables.Append, iptables.TableFilter, iptablesRejectChainName, staleRule...)

	// Run cleanup
	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	// The stale rule should be removed
	filterRules := ipt4.GetRules(iptables.TableFilter, iptablesRejectChainName)
	for _, r := range filterRules {
		if strings.Contains(ruleSpecToString(r), "STALEHASH1234") {
			t.Error("Expected stale rule to be removed by cleanup")
		}
	}

	// The legit rule should remain
	ruleHash := ruleState.CalcIDHash(false)
	srcSetName := ipsetSrcPrefix + ruleHash
	hasLegitRule := false
	for _, r := range ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName) {
		if strings.Contains(ruleSpecToString(r), srcSetName) {
			hasLegitRule = true
		}
	}
	if !hasLegitRule {
		t.Error("Expected legitimate rule to be preserved by cleanup")
	}
}

func TestCleanup_PreservesExcludeDstRules(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Run cleanup
	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup failed: %v", err)
	}

	ipt4 := getIPT4(m)

	// Exclude dst rules should still be present
	mangleRules := ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName)
	hasExclude := false
	for _, r := range mangleRules {
		if strings.Contains(ruleSpecToString(r), ipsetExcludeDstPrefix) {
			hasExclude = true
		}
	}
	if !hasExclude {
		t.Error("Expected exclude dst rule to be preserved in mangle chain after cleanup")
	}
}

func TestCleanup_NoActiveRules_NoError(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup with no active rules failed: %v", err)
	}
}

// --- Integration-style scenarios ---

func TestScenario_FullLifecycle(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	// 1. Setup
	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 2. Add a redirect rule
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc1 := core.NewStateChange()
	sc1.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc1); err != nil {
		t.Fatalf("Reconcile add: %v", err)
	}

	// 3. Update rule (change SNAT IP)
	ruleState.SNATIPv4 = net.ParseIP("5.6.7.8")
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc2 := core.NewStateChange()
	sc2.EgressRulesUpdated.Add("ns/svc1")
	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Reconcile update: %v", err)
	}

	// 4. Delete rule
	delete(state.EgressRuleStates, "ns/svc1")
	sc3 := core.NewStateChange()
	sc3.EgressRulesDeleted["ns/svc1"] = ruleState

	if err := m.Reconcile(sc3); err != nil {
		t.Fatalf("Reconcile delete: %v", err)
	}

	// 5. Cleanup
	if err := m.Cleanup(); err != nil {
		t.Fatalf("Cleanup: %v", err)
	}

	// 6. Purge
	if err := m.Purge(); err != nil {
		t.Fatalf("Purge: %v", err)
	}

	// After purge, all METALEG chains should be gone
	ipt4 := getIPT4(m)
	if ipt4.Chains[string(iptables.TableMangle)+":"+iptablesRTMarkChainName] {
		t.Error("Expected mangle chain to be purged")
	}
}

func TestScenario_MultipleRulesDifferentNodes(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Add two redirect rules to different nodes
	rule1 := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "node-a",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		FWMark: 0x100000,
	}
	rule2 := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc2",
			GWNodeName: "node-b",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.2")},
			SNATIPv4:   net.ParseIP("5.6.7.8"),
		},
		GWIPv4: net.ParseIP("192.168.1.2"),
		FWMark: 0x200000,
	}
	state.EgressRuleStates["ns/svc1"] = rule1
	state.EgressRuleStates["ns/svc2"] = rule2

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")
	sc.EgressRulesUpdated.Add("ns/svc2")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	ipt4 := getIPT4(m)
	ips := getIPS(m)

	hash1 := rule1.CalcIDHash(false)
	hash2 := rule2.CalcIDHash(false)
	set1 := ipsetSrcPrefix + hash1
	set2 := ipsetSrcPrefix + hash2

	// Both ipsets should exist
	if !ips.Sets[set1] {
		t.Errorf("Expected ipset %s to exist", set1)
	}
	if !ips.Sets[set2] {
		t.Errorf("Expected ipset %s to exist", set2)
	}

	// Both should have mark rules
	mangleRules := ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName)
	foundMarks := set.New[string]()
	for _, r := range mangleRules {
		spec := ruleSpecToString(r)
		if strings.Contains(spec, set1) && strings.Contains(spec, "MARK") {
			foundMarks.Add(set1)
		}
		if strings.Contains(spec, set2) && strings.Contains(spec, "MARK") {
			foundMarks.Add(set2)
		}
	}
	if !foundMarks.Contains(set1) {
		t.Error("Expected mark rule for rule1")
	}
	if !foundMarks.Contains(set2) {
		t.Error("Expected mark rule for rule2")
	}

	// Delete rule1, keep rule2
	delete(state.EgressRuleStates, "ns/svc1")
	sc2 := core.NewStateChange()
	sc2.EgressRulesDeleted["ns/svc1"] = rule1

	if err := m.Reconcile(sc2); err != nil {
		t.Fatalf("Reconcile delete: %v", err)
	}

	// rule1 ipset should be gone, rule2 ipset should remain
	if ips.Sets[set1] {
		t.Error("Expected rule1 ipset to be deleted")
	}
	if !ips.Sets[set2] {
		t.Error("Expected rule2 ipset to remain")
	}
}

func TestScenario_DualStack(t *testing.T) {
	state := mock.NewState()
	m := newTestManager(state)

	if err := m.Setup(); err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// Add a dual-stack rule
	ruleState := core.EgressRuleState{
		EgressRule: core.EgressRule{
			ID:         "ns/svc1",
			GWNodeName: "remote-node",
			SrcIPv4s:   []net.IP{net.ParseIP("10.0.0.1")},
			SrcIPv6s:   []net.IP{net.ParseIP("fd00::1")},
			SNATIPv4:   net.ParseIP("1.2.3.4"),
			SNATIPv6:   net.ParseIP("2001:db8::1"),
		},
		GWIPv4: net.ParseIP("192.168.1.1"),
		GWIPv6: net.ParseIP("fd00::99"),
		FWMark: 0x100000,
	}
	state.EgressRuleStates["ns/svc1"] = ruleState

	sc := core.NewStateChange()
	sc.EgressRulesUpdated.Add("ns/svc1")

	if err := m.Reconcile(sc); err != nil {
		t.Fatalf("Reconcile failed: %v", err)
	}

	ips := getIPS(m)
	ipt4 := getIPT4(m)
	ipt6 := getIPT6(m)

	hash4 := ruleState.CalcIDHash(false)
	hash6 := ruleState.CalcIDHash(true)
	set4 := ipsetSrcPrefix + hash4
	set6 := "inet6:" + ipsetSrcPrefix + hash6

	// Both IPv4 and IPv6 ipsets should exist
	if !ips.Sets[set4] {
		t.Errorf("Expected IPv4 ipset %s to exist", set4)
	}
	if !ips.Sets[set6] {
		t.Errorf("Expected IPv6 ipset %s to exist", set6)
	}

	// IPv4 mark rule
	hasIPv4Mark := false
	for _, r := range ipt4.GetRules(iptables.TableMangle, iptablesRTMarkChainName) {
		if strings.Contains(ruleSpecToString(r), set4) {
			hasIPv4Mark = true
		}
	}
	if !hasIPv4Mark {
		t.Error("Expected IPv4 mark rule")
	}

	// IPv6 mark rule
	hasIPv6Mark := false
	for _, r := range ipt6.GetRules(iptables.TableMangle, iptablesRTMarkChainName) {
		if strings.Contains(ruleSpecToString(r), set6) {
			hasIPv6Mark = true
		}
	}
	if !hasIPv6Mark {
		t.Error("Expected IPv6 mark rule")
	}
}
