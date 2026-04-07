package iptables

import (
	"errors"
	"fmt"
	"net"
	"slices"
	"strings"

	"github.com/gerolf-vent/metaleg/internal/core"
	"github.com/gerolf-vent/metaleg/internal/utils"
	"github.com/gerolf-vent/metaleg/internal/utils/ipset"
	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
	"github.com/gerolf-vent/metaleg/internal/utils/set"
	"github.com/go-logr/logr"
)

const (
	iptablesRTMarkChainName = "METALEG-RT-MARK"
	iptablesRejectChainName = "METALEG-REJECT"
	iptablesSNATChainName   = "METALEG-SNAT"
	ipsetSrcPrefix          = "METALEG-SRC-"
	ipsetExcludeDstPrefix   = "METALEG-EXCLUDE-DST-"
)

type Manager struct {
	state  core.State
	logger logr.Logger

	nodeName        string            // Name of the node this manager is running on
	fwMask          utils.FWMask      // Firewall mask for egress rules
	excludeDstCIDRs []net.IPNet       // CIDRs to exclude from firewall rules (and therefore traffic redirection)
	ipt4            iptables.IPTables // IPv4 iptables interface
	ipt6            iptables.IPTables // IPv6 iptables interface
	ips             ipset.IPSet       // IPSet interface
}

func NewManager(state core.State, logger logr.Logger, legacy bool) (*Manager, error) {
	var err error

	m := &Manager{
		state:           state,
		logger:          logger.WithName("iptables-manager"),
		nodeName:        state.NodeName(),
		fwMask:          state.FWMask(),
		excludeDstCIDRs: state.ExcludeDstCIDRs(),
	}

	m.ipt4, err = iptables.New(iptables.IPv4, legacy)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv4 iptables interface: %w", err)
	}

	m.ipt6, err = iptables.New(iptables.IPv6, legacy)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv6 iptables interface: %w", err)
	}

	m.ips, err = ipset.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset interface: %w", err)
	}

	return m, nil
}

func (m *Manager) Name() string {
	return "iptables"
}

func (m *Manager) Setup() error {
	for _, ipt := range []iptables.IPTables{m.ipt4, m.ipt6} {
		ipsetProtocol := ipset.IPv4
		ipsetExcludeDstName := ipsetExcludeDstPrefix + "4"
		if ipt.IsIPv6() {
			ipsetProtocol = ipset.IPv6
			ipsetExcludeDstName = ipsetExcludeDstPrefix + "6"
		}

		//
		// Setup exclude dst ipset and rules
		//

		var excludeCIDRs []net.IPNet
		for _, cidr := range m.excludeDstCIDRs {
			if (ipt.IsIPv6() && cidr.IP.To4() == nil) || (!ipt.IsIPv6() && cidr.IP.To4() != nil) {
				excludeCIDRs = append(excludeCIDRs, cidr)
			}
		}

		if _, err := m.ips.EnsureNetworkSet(ipsetExcludeDstName, ipsetProtocol); err != nil {
			return fmt.Errorf("failed to ensure %s exclude dst ipset: %w", ipsetProtocol, err)
		}

		existingCIDRs, err := m.ips.ListNetworkEntries(ipsetExcludeDstName)
		if err != nil {
			return fmt.Errorf("failed to list ipset entries: %w", err)
		}

		cidrsToAdd := slices.DeleteFunc(slices.Clone(excludeCIDRs), func(cidr net.IPNet) bool {
			return slices.ContainsFunc(existingCIDRs, func(other net.IPNet) bool {
				return cidr.IP.Equal(other.IP) && cidr.Mask.String() == other.Mask.String()
			})
		})

		cidrsToRemove := slices.DeleteFunc(slices.Clone(existingCIDRs), func(cidr net.IPNet) bool {
			return slices.ContainsFunc(excludeCIDRs, func(other net.IPNet) bool {
				return cidr.IP.Equal(other.IP) && cidr.Mask.String() == other.Mask.String()
			})
		})

		for _, cidr := range cidrsToAdd {
			if _, err := m.ips.EnsureNetworkEntry(ipsetExcludeDstName, &cidr); err != nil {
				return fmt.Errorf("failed to add ip %s to ipset %s: %w", cidr.String(), ipsetExcludeDstName, err)
			}
		}

		for _, cidr := range cidrsToRemove {
			if _, err := m.ips.DeleteNetworkEntry(ipsetExcludeDstName, &cidr); err != nil {
				return fmt.Errorf("failed to remove ip %s from ipset %s: %w", cidr.String(), ipsetExcludeDstName, err)
			}
		}

		excludeCIDRsRule := &ExcludeCIDRsRule{
			IPSetName: ipsetExcludeDstName,
			Protocol:  ipt.Protocol(),
		}

		//
		// Setup mangle chain
		//

		if _, err := ipt.EnsureChain(iptables.TableMangle, iptablesRTMarkChainName); err != nil {
			return fmt.Errorf("failed to ensure %s mangle chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableMangle, iptablesRTMarkChainName, excludeCIDRsRule.Spec()...); err != nil {
			return fmt.Errorf("failed to ensure %s exclude dst rule in mangle chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableMangle, iptables.ChainPrerouting, "-j", iptablesRTMarkChainName); err != nil {
			return fmt.Errorf("failed to ensure %s mangle PREROUTING rule: %w", ipt.Protocol(), err)
		}

		//
		// Setup filter chain
		//

		if _, err := ipt.EnsureChain(iptables.TableFilter, iptablesRejectChainName); err != nil {
			return fmt.Errorf("failed to ensure %s filter chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableFilter, iptablesRejectChainName, excludeCIDRsRule.Spec()...); err != nil {
			return fmt.Errorf("failed to ensure %s exclude dst rule in filter chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableFilter, iptables.ChainForward, "-j", iptablesRejectChainName); err != nil {
			return fmt.Errorf("failed to ensure %s filter FORWARD rule: %w", ipt.Protocol(), err)
		}

		//
		// Setup NAT chain
		//

		if _, err := ipt.EnsureChain(iptables.TableNAT, iptablesSNATChainName); err != nil {
			return fmt.Errorf("failed to ensure %s NAT chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableNAT, iptablesSNATChainName, excludeCIDRsRule.Spec()...); err != nil {
			return fmt.Errorf("failed to ensure %s exclude dst rule in NAT chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableNAT, iptables.ChainPostrouting, "-j", iptablesSNATChainName); err != nil {
			return fmt.Errorf("failed to ensure %s NAT POSTROUTING rule: %w", ipt.Protocol(), err)
		}

		if err := m.ensureSNATSKipRule(ipt, iptables.TableNAT, iptables.ChainPostrouting); err != nil {
			return err
		}
	}

	return nil
}

func (m *Manager) Purge() error {
	var errs []error

	for _, ipt := range []iptables.IPTables{m.ipt4, m.ipt6} {
		if _, err := ipt.DeleteRule(iptables.TableMangle, iptables.ChainPrerouting, "-j", iptablesRTMarkChainName); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %s mangle PREROUTING rule: %w", ipt.Protocol(), err))
		}

		if _, err := ipt.DeleteChain(iptables.TableMangle, iptablesRTMarkChainName); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %s mangle chain: %w", ipt.Protocol(), err))
		}

		if _, err := ipt.DeleteRule(iptables.TableFilter, iptables.ChainForward, "-j", iptablesRejectChainName); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %s filter FORWARD rule: %w", ipt.Protocol(), err))
		}

		if _, err := ipt.DeleteChain(iptables.TableFilter, iptablesRejectChainName); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %s filter chain: %w", ipt.Protocol(), err))
		}

		if _, err := ipt.DeleteRule(iptables.TableNAT, iptables.ChainPostrouting, "-j", iptablesSNATChainName); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %s NAT POSTROUTING rule: %w", ipt.Protocol(), err))
		}

		if _, err := ipt.DeleteChain(iptables.TableNAT, iptablesSNATChainName); err != nil {
			errs = append(errs, fmt.Errorf("failed to delete %s NAT chain: %w", ipt.Protocol(), err))
		}

		for _, target := range []struct {
			Table iptables.Table
			Chain iptables.Chain
		}{
			{
				Table: iptables.TableNAT,
				Chain: iptables.ChainPostrouting,
			},
		} {
			rules, err := ipt.ListRules(target.Table, target.Chain)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to list %s %s rules: %w", ipt.Protocol(), target.Chain, err))
			} else {
				// Cleanup any SNAT-skip rules that are left over in the table/chain.
				for _, rule := range rules {
					_, ok := ParseSNATSkipRule(rule[2:])
					if ok {
						if _, err := ipt.DeleteRule(target.Table, target.Chain, rule[2:]...); err != nil {
							errs = append(errs, fmt.Errorf("failed to delete %s %s %s SNAT-skip rule: %w", ipt.Protocol(), strings.ToUpper(string(target.Table)), strings.ToUpper(string(target.Chain)), err))
						}
					}
				}
			}
		}

		ipsetNames, err := m.ips.ListSets()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list ip sets: %w", err))
		} else {
			// Cleanup any ip sets that start with METALEG- or inet6:METALEG-
			for _, ipsetName := range ipsetNames {
				if strings.HasPrefix(ipsetName, "METALEG-") || strings.HasPrefix(ipsetName, "inet6:METALEG-") {
					if _, err := m.ips.DeleteSet(ipsetName); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete ip set %q: %w", ipsetName, err))
					}
				}
			}
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) Reconcile(change core.StateChange) error {
	if !change.HasEgressRuleChanges() {
		return nil
	}

	var errs []error

	// Reconcile updated egress rules
	for ruleId := range change.EgressRulesUpdated {
		ruleState, exists := m.state.GetEgressRuleState(ruleId)
		if !exists {
			// Egress rule no longer exists, skip
			continue
		}

		for _, protocol := range []iptables.Protocol{iptables.IPv4, iptables.IPv6} {
			ruleHash := ruleState.CalcIDHash(protocol == iptables.IPv6)
			ipsetSrcName := ipsetSrcPrefix + ruleHash
			var ipsetProto ipset.Protocol
			var snatIP net.IP
			var srcIPs []net.IP

			if protocol == iptables.IPv6 {
				ipsetSrcName = "inet6:" + ipsetSrcName
				ipsetProto = ipset.IPv6
				snatIP = ruleState.SNATIPv6
				srcIPs = ruleState.SrcIPv6s
			} else {
				ipsetProto = ipset.IPv4
				snatIP = ruleState.SNATIPv4
				srcIPs = ruleState.SrcIPv4s
			}

			ruleMode := ruleState.GetMode(m.nodeName, protocol == iptables.IPv6)

			if ruleMode != core.EgressRuleModeUnconfigured {
				m.logger.V(1).Info("Reconciling egress rule", "ruleID", ruleId, "mode", ruleMode.String(), "protocol", protocol, "gwNode", ruleState.GWNodeName, "fwMark", ruleState.FWMark)

				// Ensure the source IP ipset
				if err := m.ensureIPSet(ipsetSrcName, ipsetProto, srcIPs); err != nil {
					errs = append(errs, err)
					continue
				}

				// Ensure iptable rules
				if err := m.ensureIPTableRules(ruleMode, ipsetSrcName, ruleState.FWMark, snatIP, protocol); err != nil {
					errs = append(errs, err)
				}
			} else {
				m.logger.V(1).Info("Deleting egress rule", "ruleID", ruleState.ID, "gwNode", ruleState.GWNodeName)

				if err := m.deleteIPTableRules(ipsetSrcName, protocol); err != nil {
					errs = append(errs, err)
				}

				if _, err := m.ips.DeleteSet(ipsetSrcName); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete ipset: %w", err))
				}
			}
		}
	}

	// Reconcile deleted egress rules
	for _, ruleState := range change.EgressRulesDeleted {
		m.logger.V(1).Info("Deleting egress rule", "ruleID", ruleState.ID, "gwNode", ruleState.GWNodeName)
		for _, protocol := range []iptables.Protocol{iptables.IPv4, iptables.IPv6} {
			ruleHash := ruleState.CalcIDHash(protocol == iptables.IPv6)
			ipsetSrcName := ipsetSrcPrefix + ruleHash
			if protocol == iptables.IPv6 {
				ipsetSrcName = "inet6:" + ipsetSrcName
			}

			if err := m.deleteIPTableRules(ipsetSrcName, protocol); err != nil {
				errs = append(errs, err)
			}

			if _, err := m.ips.DeleteSet(ipsetSrcName); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete ipset: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) Cleanup() error {
	egressRuleStates := m.state.GetEgressRuleStates()

	var errs []error

	for _, ipt := range []iptables.IPTables{m.ipt4, m.ipt6} {
		expectedRuleHashes := make(set.Set[string], len(egressRuleStates))
		for _, ruleState := range egressRuleStates {
			expectedRuleHashes.Add(ruleState.CalcIDHash(ipt.IsIPv6()))
		}

		iptablesChains := []struct {
			Table iptables.Table
			Chain iptables.Chain
		}{
			{
				Table: iptables.TableFilter,
				Chain: iptablesRejectChainName,
			},
			{
				Table: iptables.TableMangle,
				Chain: iptablesRTMarkChainName,
			},
			{
				Table: iptables.TableNAT,
				Chain: iptablesSNATChainName,
			},
		}

		//
		// Cleanup stale iptables rules
		//

		for _, chain := range iptablesChains {
			ruleSpecs, err := ipt.ListRules(chain.Table, chain.Chain)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
				continue
			}

			for _, ruleSpec := range ruleSpecs {
				if strings.Contains(strings.Join(ruleSpec, " "), ipsetExcludeDstPrefix) {
					// Skip exclude dst rules
					continue
				}
				for _, ruleSpecPart := range ruleSpec {
					if strings.HasPrefix(ruleSpecPart, ipsetSrcPrefix) || strings.HasPrefix(ruleSpecPart, "inet6:"+ipsetSrcPrefix) {
						ruleHash := strings.TrimPrefix(strings.TrimPrefix(ruleSpecPart, "inet6:"), ipsetSrcPrefix)
						if !expectedRuleHashes.Contains(ruleHash) {
							if _, err := ipt.DeleteRule(chain.Table, chain.Chain, ruleSpec[2:]...); err != nil {
								errs = append(errs, fmt.Errorf("failed to delete stale iptables rule: %w", err))
							}
						}
					}
				}
			}
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) ensureSNATSKipRule(ipt iptables.IPTables, table iptables.Table, chain iptables.Chain) error {
	snatSkipRule := &SNATSkipRule{
		FWMask: uint32(m.fwMask),
	}

	rules, err := ipt.ListRules(table, chain)
	if err != nil {
		return fmt.Errorf("failed to list %s %s %s rules: %w", ipt.Protocol(), strings.ToUpper(string(table)), strings.ToUpper(string(chain)), err)
	}

	// Ignore the policy rule if present
	if len(rules) > 0 && rules[0][0] == "-P" {
		rules = rules[1:]
	}

	// Check if the our SNAT-skip rule is at desired index in the chain, otherwise cleanup existing duplicates,
	// so we can create a new one at the index.
	if len(rules) > 0 {
		parsedSNATSkipRule, ok := ParseSNATSkipRule(rules[0][2:])
		if !ok || parsedSNATSkipRule.FWMask != snatSkipRule.FWMask {
			for _, rule := range rules {
				parsedSkipRule, ok := ParseSNATSkipRule(rule[2:])
				if ok {
					m.logger.V(3).Info("Deleting conflicting SNAT-skip rule", "protocol", ipt.Protocol(), "table", table, "chain", chain, "mask", parsedSkipRule.FWMask)
					if _, err := ipt.DeleteRule(table, chain, rule[2:]...); err != nil {
						return fmt.Errorf("failed to delete conflicting %s %s %s rule: %w", ipt.Protocol(), strings.ToUpper(string(table)), strings.ToUpper(string(chain)), err)
					}
				}
			}
		}
	}

	if _, err := ipt.EnsureRule(iptables.Prepend, table, chain, snatSkipRule.Spec()...); err != nil {
		return fmt.Errorf("failed to ensure %s %s %s rule: %w", ipt.Protocol(), strings.ToUpper(string(table)), strings.ToUpper(string(chain)), err)
	}

	return nil
}

func (m *Manager) ensureIPSet(setName string, protocol ipset.Protocol, ips []net.IP) error {
	var errs []error

	if _, err := m.ips.EnsureSet(setName, protocol); err != nil {
		errs = append(errs, fmt.Errorf("failed to ensure ipset exists: %w", err))
	}

	existingIPs, err := m.ips.ListEntries(setName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to list ipset entries: %w", err))
		return errors.Join(errs...)
	}

	ipsToAdd := slices.DeleteFunc(slices.Clone(ips), func(ip net.IP) bool {
		return slices.ContainsFunc(existingIPs, func(other net.IP) bool {
			return ip.Equal(other)
		})
	})

	ipsToRemove := slices.DeleteFunc(slices.Clone(existingIPs), func(ip net.IP) bool {
		return slices.ContainsFunc(ips, func(other net.IP) bool {
			return ip.Equal(other)
		})
	})

	for _, ip := range ipsToAdd {
		if _, err := m.ips.EnsureEntry(setName, ip); err != nil {
			errs = append(errs, fmt.Errorf("failed to add ip %s to ipset %s: %w", ip.String(), setName, err))
		}
	}

	for _, ip := range ipsToRemove {
		if _, err := m.ips.DeleteEntry(setName, ip); err != nil {
			errs = append(errs, fmt.Errorf("failed to remove ip %s from ipset %s: %w", ip.String(), setName, err))
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) ensureIPTableRules(ruleMode core.EgressRuleMode, ipsetSrcName string, fwMark uint32, snatIP net.IP, protocol iptables.Protocol) error {
	var ipt iptables.IPTables
	if protocol == iptables.IPv6 {
		ipt = m.ipt6
	} else {
		ipt = m.ipt4
	}

	m.logger.V(2).Info("Ensuring iptables rules", "mode", ruleMode.String(), "protocol", protocol, "ipset", ipsetSrcName, "fwMark", fwMark, "snatIP", snatIP.String())

	var errs []error

	iptablesRules := []struct {
		Table    iptables.Table
		Chain    iptables.Chain
		Rule     Rule
		Parser   func([]string, iptables.Protocol) (Rule, bool)
		Presence bool
	}{
		// Used to reject traffic, if the gateway node is not local and the
		// route to the gateway is unknown.
		{
			Table: iptables.TableFilter,
			Chain: iptablesRejectChainName,
			Rule: &RejectRule{
				SrcIPSetName: ipsetSrcName,
				Protocol:     protocol,
			},
			Parser:   ParseRejectRule,
			Presence: ruleMode == core.EgressRuleModeBlock,
		},
		// Used to mark packets for routing to the gateway node.
		{
			Table: iptables.TableMangle,
			Chain: iptablesRTMarkChainName,
			Rule: &MarkRule{
				SrcIPSetName: ipsetSrcName,
				FWMark:       fwMark,
				FWMask:       uint32(m.fwMask),
				Protocol:     protocol,
			},
			Parser:   ParseMarkRule,
			Presence: ruleMode == core.EgressRuleModeRedirect,
		},
		// Used to SNAT traffic if the local node is the gateway node.
		{
			Table: iptables.TableNAT,
			Chain: iptablesSNATChainName,
			Rule: &SNATRule{
				SrcIPSetName: ipsetSrcName,
				SNATIP:       snatIP,
				Protocol:     protocol,
			},
			Parser:   ParseSNATRule,
			Presence: ruleMode == core.EgressRuleModeSNAT,
		},
	}

	for _, iptablesRule := range iptablesRules {
		existingRules, err := ipt.ListRules(iptablesRule.Table, iptablesRule.Chain)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
			continue
		}

		present := false
		for _, ruleSpec := range existingRules {
			parsedRule, ok := iptablesRule.Parser(ruleSpec[2:], ipt.Protocol())
			if !ok {
				continue
			}
			// Only consider rules with the same RuleID (ipset name) as related
			if parsedRule.RuleID() != iptablesRule.Rule.RuleID() {
				continue
			}
			if !iptablesRule.Presence || present == true || parsedRule.String() != iptablesRule.Rule.String() {
				// Remove duplicate or conflicting rules
				m.logger.V(3).Info("Deleting conflicting iptables rule", "table", iptablesRule.Table, "chain", iptablesRule.Chain, "rule", parsedRule.String())
				if _, err := ipt.DeleteRule(iptablesRule.Table, iptablesRule.Chain, ruleSpec[2:]...); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete conflicting iptables rule: %w", err))
				}
			} else {
				present = true
			}
		}

		if !present && iptablesRule.Presence {
			if _, err := ipt.EnsureRule(iptables.Append, iptablesRule.Table, iptablesRule.Chain, iptablesRule.Rule.Spec()...); err != nil {
				errs = append(errs, fmt.Errorf("failed to add iptables rule: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}

func (m *Manager) deleteIPTableRules(ipsetSrcName string, protocol iptables.Protocol) error {
	var ipt iptables.IPTables
	if protocol == iptables.IPv6 {
		ipt = m.ipt6
	} else {
		ipt = m.ipt4
	}

	var errs []error

	iptablesChains := []struct {
		Table iptables.Table
		Chain iptables.Chain
	}{
		{
			Table: iptables.TableFilter,
			Chain: iptablesRejectChainName,
		},
		{
			Table: iptables.TableMangle,
			Chain: iptablesRTMarkChainName,
		},
		{
			Table: iptables.TableNAT,
			Chain: iptablesSNATChainName,
		},
	}

	for _, chain := range iptablesChains {
		ruleSpecs, err := ipt.ListRules(chain.Table, chain.Chain)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
			continue
		}

		for _, ruleSpec := range ruleSpecs {
			if strings.Contains(strings.Join(ruleSpec, " "), ipsetSrcName) {
				if _, err := ipt.DeleteRule(chain.Table, chain.Chain, ruleSpec[2:]...); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete iptables rule: %w", err))
				}
			}
		}
	}

	return errors.Join(errs...)
}
