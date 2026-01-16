package firewall_manager

import (
	"errors"
	"fmt"
	"net"
	"strings"

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

type IPTablesManager struct {
	nodeName        string            // Name of the node this manager is running on
	fwMask          uint32            // Firewall mask for egress rules
	excludeDstCIDRs []net.IPNet       // CIDRs to exclude from firewall rules (and therefore traffic redirection)
	ipt4            iptables.IPTables // IPv4 iptables interface
	ipt6            iptables.IPTables // IPv6 iptables interface
	ips             ipset.IPSet       // IPSet interface
}

func NewIPTablesManager(nodeName string, fwMask uint32, excludeDstCIDRs []net.IPNet) (*IPTablesManager, error) {
	var err error

	iptm := &IPTablesManager{
		nodeName:        nodeName,
		fwMask:          fwMask,
		excludeDstCIDRs: excludeDstCIDRs,
	}

	iptm.ipt4, err = iptables.New(iptables.IPv4)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv4 iptables interface: %w", err)
	}

	iptm.ipt6, err = iptables.New(iptables.IPv6)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv6 iptables interface: %w", err)
	}

	iptm.ips, err = ipset.New()
	if err != nil {
		return nil, fmt.Errorf("failed to create ipset interface: %w", err)
	}

	return iptm, nil
}

func (iptm *IPTablesManager) Setup() error {
	for _, ipt := range []iptables.IPTables{iptm.ipt4, iptm.ipt6} {
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
		for _, cidr := range iptm.excludeDstCIDRs {
			if (ipt.IsIPv6() && cidr.IP.To4() == nil) || (!ipt.IsIPv6() && cidr.IP.To4() != nil) {
				excludeCIDRs = append(excludeCIDRs, cidr)
			}
		}

		if _, err := iptm.ips.EnsureNetworkSet(ipsetExcludeDstName, ipsetProtocol); err != nil {
			return fmt.Errorf("failed to ensure %s exclude dst ipset: %w", ipsetProtocol, err)
		}

		excludeCIDRsSynchronizer := &IPSetIPNetsSynchronizer{
			ips:     iptm.ips,
			SetName: ipsetExcludeDstName,
			Entries: excludeCIDRs,
		}
		err := excludeCIDRsSynchronizer.Sync()
		if err != nil {
			return fmt.Errorf("failed to sync %s exclude dst ipset entries: %w", ipsetProtocol, err)
		}

		excludeCIDRsRule := IPTablesExcludeCIDRsRule{
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

		snatSkipRule := &IPTablesSNATSkipRule{
			FWMask: iptm.fwMask,
		}

		postroutingRules, err := ipt.ListRules(iptables.TableNAT, iptables.ChainPostrouting)
		if err != nil {
			return fmt.Errorf("failed to list %s NAT POSTROUTING rules: %w", ipt.Protocol(), err)
		}

		// If the first rule in the postrouting chain is not our SNAT-skip rule,
		// then cleanup any existing SNAT-skip rules, so we can insert it as the first rule.
		if len(postroutingRules) > 0 {
			parsedSNATSkipRule, ok := ParseIPTablesSNATSkipRule(postroutingRules[0][2:])
			if !ok || parsedSNATSkipRule.FWMask != snatSkipRule.FWMask {
				for _, rule := range postroutingRules {
					_, ok := ParseIPTablesSNATSkipRule(rule[2:])
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

func (iptm *IPTablesManager) Cleanup() error {
	var errs []error

	for _, ipt := range []iptables.IPTables{iptm.ipt4, iptm.ipt6} {
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
				_, ok := ParseIPTablesSNATSkipRule(rule[2:])
				if ok {
					if _, err := ipt.DeleteRule(iptables.TableNAT, iptables.ChainPostrouting, rule[2:]...); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete %s NAT SNAT-skip rule: %w", ipt.Protocol(), err))
					}
				}
			}
		}

		ipsetNames, err := iptm.ips.ListSets()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list ip sets: %w", err))
		} else {
			// Cleanup any ip sets that start with METALEG- or inet6:METALEG-
			for _, ipsetName := range ipsetNames {
				if strings.HasPrefix(ipsetName, "METALEG-") || strings.HasPrefix(ipsetName, "inet6:METALEG-") {
					if _, err := iptm.ips.DeleteSet(ipsetName); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete ip set %q: %w", ipsetName, err))
					}
				}
			}
		}
	}

	return errors.Join(errs...)
}

func (iptm *IPTablesManager) ReconcileEgressRule(rule *EgressRule, present bool) error {
	if rule == nil {
		return nil
	}

	var errs []error

	isGWLocal := rule.GWNodeName != "" && rule.GWNodeName == iptm.nodeName
	isGWRouteKnown := rule.GWRoute != nil
	isGWRouteAllocated := isGWRouteKnown && rule.GWRoute.IDAllocated

	for _, ipt := range []iptables.IPTables{iptm.ipt4, iptm.ipt6} {
		ruleHash := rule.CalcIDHash(ipt.IsIPv6())
		ipsetSrcName := ipsetSrcPrefix + ruleHash
		var ipsetProto ipset.Protocol
		var snatIP net.IP
		var srcIPs []net.IP

		if ipt.IsIPv6() {
			ipsetSrcName = "inet6:" + ipsetSrcName
			ipsetProto = ipset.IPv6
			snatIP = rule.SNATIPv6
			srcIPs = rule.SrcIPv6s
		} else {
			ipsetProto = ipset.IPv4
			snatIP = rule.SNATIPv4
			srcIPs = rule.SrcIPv4s
		}

		presentForIPFamily := present && snatIP != nil

		//
		// Sync rule ip set (1/2)
		//

		// Ensure the ipset exists if there are any rules to apply, so they don't throw errors,
		// because the set is missing.
		if presentForIPFamily {
			if _, err := iptm.ips.EnsureSet(ipsetSrcName, ipsetProto); err != nil {
				errs = append(errs, fmt.Errorf("failed to ensure ipset exists: %w", err))
			}
		}

		//
		// Sync Reject rules
		// These are used to reject traffic, if the gateway node is not local and the
		// route to the gateway is unknown.
		//

		rejectRule := &IPTablesRejectRule{
			SrcIPSetName: ipsetSrcName,
			Protocol:     ipt.Protocol(),
		}

		rejectRuleSynchronizer := &IPTablesRuleSynchronizer[*IPTablesRejectRule]{
			ipt:     ipt,
			Parser:  ParseIPTablesRejectRule,
			Table:   iptables.TableFilter,
			Chain:   iptablesRejectChainName,
			Rule:    rejectRule,
			Present: presentForIPFamily && !isGWLocal && (!isGWRouteKnown || !isGWRouteAllocated),
		}
		err := rejectRuleSynchronizer.Sync()
		if err != nil {
			errs = append(errs, err)
		}

		//
		// Sync RT Mark rules
		// These are used to mark packets for routing to the gateway node.
		//

		rtMarkRule := &IPTablesMarkRule{
			SrcIPSetName: ipsetSrcName,
			FWMark:       0,
			FWMask:       uint32(iptm.fwMask),
			Protocol:     ipt.Protocol(),
		}
		if rule.GWRoute != nil {
			rtMarkRule.FWMark = rule.GWRoute.FWMark
		}

		rtMarkRuleSynchronizer := &IPTablesRuleSynchronizer[*IPTablesMarkRule]{
			ipt:     ipt,
			Parser:  ParseIPTablesMarkRule,
			Table:   iptables.TableMangle,
			Chain:   iptablesRTMarkChainName,
			Rule:    rtMarkRule,
			Present: presentForIPFamily && !isGWLocal && (isGWRouteKnown && isGWRouteAllocated),
		}
		err = rtMarkRuleSynchronizer.Sync()
		if err != nil {
			errs = append(errs, err)
		}

		//
		// Sync SNAT rules
		// These are used to SNAT traffic if the local node is the gateway node.
		//

		snatRule := &IPTablesSNATRule{
			SrcIPSetName: ipsetSrcName,
			SNATIP:       snatIP,
			Protocol:     ipt.Protocol(),
		}

		snatRuleSynchronizer := &IPTablesRuleSynchronizer[*IPTablesSNATRule]{
			ipt:     ipt,
			Parser:  ParseIPTablesSNATRule,
			Table:   iptables.TableNAT,
			Chain:   iptablesSNATChainName,
			Rule:    snatRule,
			Present: presentForIPFamily && isGWLocal,
		}
		err = snatRuleSynchronizer.Sync()
		if err != nil {
			errs = append(errs, err)
		}

		//
		// Sync rule ip set (2/2)
		//

		ipsetSynchronizer := &IPSetIPsSynchronizer{
			ips:     iptm.ips,
			SetName: ipsetSrcName,
			Entries: srcIPs,
		}
		err = ipsetSynchronizer.Sync()
		if err != nil {
			errs = append(errs, err)
		}

		// Delete the ipset, if rule is absent
		if !presentForIPFamily {
			if _, err := iptm.ips.DeleteSet(ipsetSrcName); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete ipset: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}

func (iptm *IPTablesManager) CleanupStaleEgressRules(rules map[string]*EgressRule) error {
	if len(rules) == 0 {
		return nil
	}

	var errs []error

	for _, ipt := range []iptables.IPTables{iptm.ipt4, iptm.ipt6} {
		expectedRuleIDs := make(set.Set[string], len(rules))
		for _, rule := range rules {
			if (ipt.IsIPv6() && rule.SNATIPv6 == nil) || (!ipt.IsIPv6() && rule.SNATIPv4 == nil) {
				continue // No rule for this IP family
			}

			expectedRuleIDs.Add(ipsetSrcPrefix + rule.CalcIDHash(ipt.IsIPv6()))
		}

		//
		// Cleanup Reject rules
		//

		rejectRuleCleaner := &IPTablesRuleCleaner[*IPTablesRejectRule]{
			ipt:             ipt,
			Parser:          ParseIPTablesRejectRule,
			Table:           iptables.TableFilter,
			Chain:           iptablesRejectChainName,
			ExpectedRuleIDs: expectedRuleIDs,
			IgnoreRulePredicate: func(ruleSpec []string) bool {
				_, ok := ParseIPTablesExcludeCIDRsRule(ruleSpec, ipt.Protocol())
				return ok // Ignore the exclude CIDRs rule
			},
		}
		err := rejectRuleCleaner.Clean()
		if err != nil {
			errs = append(errs, err)
		}

		//
		// Cleanup RT Mark rules
		//

		rtMarkRuleCleaner := &IPTablesRuleCleaner[*IPTablesMarkRule]{
			ipt:             ipt,
			Parser:          ParseIPTablesMarkRule,
			Table:           iptables.TableMangle,
			Chain:           iptablesRTMarkChainName,
			ExpectedRuleIDs: expectedRuleIDs,
			IgnoreRulePredicate: func(ruleSpec []string) bool {
				_, ok := ParseIPTablesExcludeCIDRsRule(ruleSpec, ipt.Protocol())
				return ok // Ignore the exclude CIDRs rule
			},
		}
		err = rtMarkRuleCleaner.Clean()
		if err != nil {
			errs = append(errs, err)
		}

		//
		// Cleanup SNAT rules
		//

		snatRuleCleaner := &IPTablesRuleCleaner[*IPTablesSNATRule]{
			ipt:             ipt,
			Parser:          ParseIPTablesSNATRule,
			Table:           iptables.TableNAT,
			Chain:           iptablesSNATChainName,
			ExpectedRuleIDs: expectedRuleIDs,
			IgnoreRulePredicate: func(ruleSpec []string) bool {
				_, ok := ParseIPTablesExcludeCIDRsRule(ruleSpec, ipt.Protocol())
				return ok // Ignore the exclude CIDRs rule
			},
		}
		err = snatRuleCleaner.Clean()
		if err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}
