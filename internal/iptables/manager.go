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
)

const (
	iptablesRTMarkChainName = "METALEG-RT-MARK"
	iptablesRejectChainName = "METALEG-REJECT"
	iptablesSNATChainName   = "METALEG-SNAT"
	ipsetSrcPrefix          = "METALEG-SRC-"
	ipsetExcludeDstPrefix   = "METALEG-EXCLUDE-DST-"
)

type Manager struct {
	state core.State

	nodeName        string            // Name of the node this manager is running on
	fwMask          utils.FWMask      // Firewall mask for egress rules
	excludeDstCIDRs []net.IPNet       // CIDRs to exclude from firewall rules (and therefore traffic redirection)
	ipt4            iptables.IPTables // IPv4 iptables interface
	ipt6            iptables.IPTables // IPv6 iptables interface
	ips             ipset.IPSet       // IPSet interface
}

func NewManager(state core.State) (*Manager, error) {
	var err error

	m := &Manager{
		nodeName:        state.NodeName(),
		fwMask:          state.FWMask(),
		excludeDstCIDRs: state.ExcludeDstCIDRs(),
	}

	m.ipt4, err = iptables.New(iptables.IPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv4 iptables interface: %w", err)
	}

	m.ipt6, err = iptables.New(iptables.IPv6)
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

		if _, err := ipt.EnsureRule(iptables.Append, iptables.TableMangle, iptables.ChainPrerouting, "-j", iptablesRTMarkChainName); err != nil {
			return fmt.Errorf("failed to ensure %s mangle PREROUTING rule: %w", ipt.Protocol(), err)
		}

		//
		// Setup filter chain
		//

		if _, err := ipt.EnsureChain(iptables.TableFilter, iptablesRejectChainName); err != nil {
			return fmt.Errorf("failed to ensure %s filter chain: %w", ipt.Protocol(), err)
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

		snatSkipRule := &SNATSkipRule{
			FWMask: uint32(m.fwMask),
		}

		postroutingRules, err := ipt.ListRules(iptables.TableNAT, iptables.ChainPostrouting)
		if err != nil {
			return fmt.Errorf("failed to list %s NAT POSTROUTING rules: %w", ipt.Protocol(), err)
		}

		// If the first rule in the postrouting chain is not our SNAT-skip rule,
		// then cleanup any existing SNAT-skip rules, so we can insert it as the first rule.
		if len(postroutingRules) > 0 {
			parsedSNATSkipRule, ok := ParseSNATSkipRule(postroutingRules[0][2:])
			if !ok || parsedSNATSkipRule.FWMask != snatSkipRule.FWMask {
				for _, rule := range postroutingRules {
					_, ok := ParseSNATSkipRule(rule[2:])
					if ok {
						if _, err := ipt.DeleteRule(iptables.TableNAT, iptables.ChainPostrouting, rule[2:]...); err != nil {
							return fmt.Errorf("failed to delete conflicting %s NAT SNAP-skip rule: %w", ipt.Protocol(), err)
						}
					}
				}
			}
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableNAT, iptables.ChainPostrouting, snatSkipRule.Spec()...); err != nil {
			return fmt.Errorf("failed to ensure %s NAT SNAT-skip rule: %w", ipt.Protocol(), err)
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

		postroutingRules, err := ipt.ListRules(iptables.TableNAT, iptables.ChainPostrouting)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list %s NAT POSTROUTING rules: %w", ipt.Protocol(), err))
		} else {
			// Cleanup any SNAT-skip rules that are left over in the POSTROUTING chain.
			for _, rule := range postroutingRules {
				_, ok := ParseSNATSkipRule(rule[2:])
				if ok {
					if _, err := ipt.DeleteRule(iptables.TableNAT, iptables.ChainPostrouting, rule[2:]...); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete %s NAT SNAT-skip rule: %w", ipt.Protocol(), err))
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

		for _, ipt := range []iptables.IPTables{m.ipt4, m.ipt6} {
			ruleHash := ruleState.CalcIDHash(ipt.IsIPv6())
			ipsetSrcName := ipsetSrcPrefix + ruleHash
			var ipsetProto ipset.Protocol
			var snatIP net.IP
			var srcIPs []net.IP

			if ipt.IsIPv6() {
				ipsetSrcName = "inet6:" + ipsetSrcName
				ipsetProto = ipset.IPv6
				snatIP = ruleState.SNATIPv6
				srcIPs = ruleState.SrcIPv6s
			} else {
				ipsetProto = ipset.IPv4
				snatIP = ruleState.SNATIPv4
				srcIPs = ruleState.SrcIPv4s
			}

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
						Protocol:     ipt.Protocol(),
					},
					Parser:   ParseRejectRule,
					Presence: ruleState.ShouldBlockTraffic(ipt.IsIPv6()),
				},
				// Used to mark packets for routing to the gateway node.
				{
					Table: iptables.TableMangle,
					Chain: iptablesRTMarkChainName,
					Rule: &MarkRule{
						SrcIPSetName: ipsetSrcName,
						FWMark:       ruleState.FWMark,
						FWMask:       uint32(m.fwMask),
						Protocol:     ipt.Protocol(),
					},
					Parser:   ParseMarkRule,
					Presence: ruleState.NeedTrafficRedirection(m.nodeName, ipt.IsIPv6()),
				},
				// Used to SNAT traffic if the local node is the gateway node.
				{
					Table: iptables.TableNAT,
					Chain: iptablesSNATChainName,
					Rule: &SNATRule{
						SrcIPSetName: ipsetSrcName,
						SNATIP:       snatIP,
						Protocol:     ipt.Protocol(),
					},
					Parser:   ParseSNATRule,
					Presence: ruleState.IsGWLocal(m.nodeName, ipt.IsIPv6()),
				},
			}

			//
			// Sync src ips set (1/2)
			//

			// Ensure the ipset before any rules, so they don't throw errors, because the set
			// is missing.
			if _, err := m.ips.EnsureSet(ipsetSrcName, ipsetProto); err != nil {
				errs = append(errs, fmt.Errorf("failed to ensure ipset exists: %w", err))
			}

			//
			// Sync iptables rules
			//

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
					if !iptablesRule.Presence || present == true || parsedRule.String() != iptablesRule.Rule.String() {
						// Remove duplicate or conflicting rules
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

			//
			// Sync src ip set (2/2)
			//

			existingIPs, err := m.ips.ListEntries(ipsetSrcName)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to list ipset entries: %w", err))
				continue
			}

			ipsToAdd := slices.DeleteFunc(slices.Clone(srcIPs), func(ip net.IP) bool {
				return slices.ContainsFunc(existingIPs, func(other net.IP) bool {
					return ip.Equal(other)
				})
			})

			ipsToRemove := slices.DeleteFunc(slices.Clone(existingIPs), func(ip net.IP) bool {
				return slices.ContainsFunc(srcIPs, func(other net.IP) bool {
					return ip.Equal(other)
				})
			})

			for _, ip := range ipsToAdd {
				if _, err := m.ips.EnsureEntry(ipsetSrcName, ip); err != nil {
					errs = append(errs, fmt.Errorf("failed to add ip %s to ipset %s: %w", ip.String(), ipsetSrcName, err))
				}
			}

			for _, ip := range ipsToRemove {
				if _, err := m.ips.DeleteEntry(ipsetSrcName, ip); err != nil {
					errs = append(errs, fmt.Errorf("failed to remove ip %s from ipset %s: %w", ip.String(), ipsetSrcName, err))
				}
			}
		}
	}

	// Reconcile deleted egress rules
	for _, ruleState := range change.EgressRulesDeleted {
		for _, ipt := range []iptables.IPTables{m.ipt4, m.ipt6} {
			ruleHash := ruleState.CalcIDHash(ipt.IsIPv6())
			ipsetSrcName := ipsetSrcPrefix + ruleHash
			if ipt.IsIPv6() {
				ipsetSrcName = "inet6:" + ipsetSrcName
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
			// Delete iptables rules
			//

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

			//
			// Delete the ipset
			//

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
