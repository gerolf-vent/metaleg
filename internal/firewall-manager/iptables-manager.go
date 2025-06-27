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
	iptablesRuleIDPrefix    = "METALEG-SVC-"
)

type IPTablesManager struct {
	nodeName string             // Name of the node this manager is running on
	fwMask   uint32             // Firewall mask for egress rules
	ipt4     *iptables.IPTables // IPv4 iptables interface
	ipt6     *iptables.IPTables // IPv6 iptables interface
	ips      *ipset.IPSet       // IPSet interface
}

func NewIPTablesManager(nodeName string, fwMask uint32) (*IPTablesManager, error) {
	var err error

	iptm := &IPTablesManager{
		nodeName: nodeName,
		fwMask:   fwMask,
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
	for _, ipt := range []*iptables.IPTables{iptm.ipt4, iptm.ipt6} {
		if _, err := ipt.EnsureChain(iptables.TableMangle, iptablesRTMarkChainName); err != nil {
			return fmt.Errorf("failed to ensure %s mangle chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Append, iptables.TableMangle, iptables.ChainPrerouting, "-j", iptablesRTMarkChainName); err != nil {
			return fmt.Errorf("failed to ensure %s mangle PREROUTING rule: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureChain(iptables.TableFilter, iptablesRejectChainName); err != nil {
			return fmt.Errorf("failed to ensure %s filter chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Append, iptables.TableFilter, iptables.ChainForward, "-j", iptablesRejectChainName); err != nil {
			return fmt.Errorf("failed to ensure %s filter FORWARD rule: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureChain(iptables.TableNAT, iptablesSNATChainName); err != nil {
			return fmt.Errorf("failed to ensure %s NAT chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Append, iptables.TableNAT, iptables.ChainPostrouting, "-j", iptablesSNATChainName); err != nil {
			return fmt.Errorf("failed to ensure %s NAT POSTROUTING rule: %w", ipt.Protocol(), err)
		}
	}

	return nil
}

func (iptm *IPTablesManager) ReconcileEgressRule(rule *EgressRule, present bool) error {
	if rule == nil {
		return nil
	}

	var errs []error

	isGWLocal := rule.GWNodeName != "" && rule.GWNodeName == iptm.nodeName
	isGWRouteKnown := rule.GWRoute != nil
	isGWRouteAllocated := isGWRouteKnown && rule.GWRoute.IDAllocated

	for _, ipt := range []*iptables.IPTables{iptm.ipt4, iptm.ipt6} {
		ruleHash := rule.CalcIDHash(ipt.IsIPv6())
		ipsetSrcName := ipsetSrcPrefix + ruleHash
		var ipsetProto ipset.Protocol
		var snatIP net.IP

		if ipt.IsIPv6() {
			ipsetSrcName = "inet6:" + ipsetSrcName
			ipsetProto = ipset.IPv6
			snatIP = rule.SNATIPv6
		} else {
			ipsetProto = ipset.IPv4
			snatIP = rule.SNATIPv4
		}

		//
		// Sync FW ip set (first half)
		//

		// Ensure the ipset exists if there are any rules to apply, so they don't throw errors,
		// because the set is missing.
		if present {
			if _, err := iptm.ips.EnsureSet(ipsetSrcName, ipsetProto); err != nil {
				errs = append(errs, fmt.Errorf("failed to ensure ipset exists: %w", err))
			}
		}

		for _, tp := range []iptables.TransportProtocol{iptables.TCP, iptables.UDP} {
			var srcPorts set.Set[uint16]
			if tp == iptables.UDP {
				srcPorts = rule.SrcUDPPorts
			} else {
				srcPorts = rule.SrcTCPPorts
			}

			//
			// Sync FW Reject rules
			// These are used to reject traffic, if the gateway node is not local and the
			// route to the gateway is unknown.
			//

			// Query all existing reject rules in the filter table
			rejectRules, err := ipt.ListRules(iptables.TableFilter, iptablesRejectChainName)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
			}

			// Cleanup any conflicting or left-over reject rules for the current rule
			for _, rejectRule := range rejectRules {
				parsedRejectRule, ok := ParseIPTablesRejectRule(rejectRule[2:], ipt.Protocol())
				if ok && strings.Contains(parsedRejectRule.SrcIPSetName, ruleHash) &&
					parsedRejectRule.TransportProtocol == tp && // Only consider rules that match the rule hash and transport protocol
					(!present || len(srcPorts) == 0 ||
						isGWLocal || // If the gw node is local, it's always reachable, so no reject rule should exist
						(isGWRouteKnown && isGWRouteAllocated) || // If the gw route is known and allocated, no reject rule should exist
						!rule.MatchesIPTablesRejectRule(parsedRejectRule)) {
					if _, err := ipt.DeleteRule(iptables.TableFilter, iptablesRejectChainName, rejectRule...); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete conflicting iptables rule: %w", err))
					}
				}
			}

			// Create a reject rule, if the gateway is not local and the route to it is unknown or not allocated
			if present && len(srcPorts) > 0 && !isGWLocal && (!isGWRouteKnown || !isGWRouteAllocated) {
				rejectRule := IPTablesRejectRule{
					SrcIPSetName:      ipsetSrcName,
					SrcPorts:          srcPorts,
					Protocol:          ipt.Protocol(),
					TransportProtocol: tp,
				}
				if _, err := ipt.EnsureRule(iptables.Append, iptables.TableFilter, iptablesRejectChainName, rejectRule.Spec()...); err != nil {
					errs = append(errs, fmt.Errorf("failed to ensure iptables rule: %w", err))
				}
			}

			//
			// Sync RT Mark rules
			// These are used to mark packets for routing to the gateway node.
			//

			// Query all existing rt mark rules in the mangle table
			rtMarkRules, err := ipt.ListRules(iptables.TableMangle, iptablesRTMarkChainName)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
			}

			// Cleanup any conflicting or left-over rt mark rules for the current rule
			for _, rtMarkRule := range rtMarkRules {
				parsedRTMarkRule, ok := ParseIPTablesMarkRule(rtMarkRule[2:], ipt.Protocol())
				if ok && strings.Contains(parsedRTMarkRule.SrcIPSetName, ruleHash) &&
					parsedRTMarkRule.TransportProtocol == tp && // Only consider rules that match the rule hash and transport protocol
					(!present || len(srcPorts) == 0 ||
						isGWLocal || // If the gw node is local, there is no need to mark packets for routing
						(!isGWRouteKnown || !isGWRouteAllocated) || // If the gw route is unknown or unallocated, the traffic should be rejected, not marked
						!rule.MatchesIPTablesMarkRule(parsedRTMarkRule, uint32(iptm.fwMask))) {
					if _, err := ipt.DeleteRule(iptables.TableMangle, iptablesRTMarkChainName, rtMarkRule...); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete conflicting iptables rule: %w", err))
					}
				}
			}

			// Create a new rt mark rule, if the gateway is not local and the route to it is known and allocated
			if present && len(srcPorts) > 0 && !isGWLocal && isGWRouteKnown && isGWRouteAllocated {
				rtMarkRule := IPTablesMarkRule{
					SrcIPSetName:      ipsetSrcName,
					SrcPorts:          srcPorts,
					FWMark:            rule.GWRoute.FWMark,
					FWMask:            uint32(iptm.fwMask),
					Protocol:          ipt.Protocol(),
					TransportProtocol: tp,
				}
				if _, err := ipt.EnsureRule(iptables.Append, iptables.TableMangle, iptablesRTMarkChainName, rtMarkRule.Spec()...); err != nil {
					errs = append(errs, fmt.Errorf("failed to ensure iptables rule: %w", err))
				}
			}

			//
			// Sync FW SNAT rules
			// These are used to SNAT traffic if the local node is the gateway node.
			//

			// Query all existing SNAT rules in the nat table
			snatRules, err := ipt.ListRules(iptables.TableNAT, iptablesSNATChainName)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
			}

			// Cleanup any conflicting or left-over snat rules for the current rule
			for _, snatRule := range snatRules {
				parsedSNATRule, ok := ParseIPTablesSNATRule(snatRule[2:], ipt.Protocol())
				if ok && strings.Contains(parsedSNATRule.SrcIPSetName, ruleHash) &&
					parsedSNATRule.TransportProtocol == tp && // Only consider rules that match the rule hash and transport protocol
					(!present || len(srcPorts) == 0 ||
						!isGWLocal || // If the gw node is not local, no SNAT rule should exist
						!rule.MatchesIPTablesSNATRule(parsedSNATRule)) {
					if _, err := ipt.DeleteRule(iptables.TableNAT, iptablesSNATChainName, snatRule...); err != nil {
						errs = append(errs, fmt.Errorf("failed to delete conflicting iptables rule: %w", err))
					}
				}
			}

			// Create a new SNAT rule, if the gateway is local
			if present && len(srcPorts) > 0 && isGWLocal {
				snatRule := IPTablesSNATRule{
					SrcIPSetName:      ipsetSrcName,
					SrcPorts:          srcPorts,
					SNATIP:            snatIP,
					Protocol:          ipt.Protocol(),
					TransportProtocol: tp,
				}
				if _, err := ipt.EnsureRule(iptables.Append, iptables.TableNAT, iptablesSNATChainName, snatRule.Spec()...); err != nil {
					errs = append(errs, fmt.Errorf("failed to ensure iptables rule: %w", err))
				}
			}
		}

		//
		// Sync IPSet entries (second half)
		//

		// Delete the ipset, if all rules are absent
		if !present {
			if _, err := iptm.ips.DeleteSet(ipsetSrcName); err != nil {
				errs = append(errs, fmt.Errorf("failed to delete ipset: %w", err))
			}
		}
	}

	return errors.Join(errs...)
}

func (iptm *IPTablesManager) CleanupEgressRules(rules map[string]*EgressRule) error {
	if len(rules) == 0 {
		return nil
	}

	var errs []error

	for _, ipt := range []*iptables.IPTables{iptm.ipt4, iptm.ipt6} {
		expectedIDHashes := make(set.Set[string], len(rules))
		for _, rule := range rules {
			expectedIDHashes.Add(rule.CalcIDHash(ipt.IsIPv6()))
		}

		//
		// Cleanup FW Reject rules
		//

		// Query all existing reject rules in the filter table
		rejectRules, err := ipt.ListRules(iptables.TableFilter, iptablesRejectChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
		}

		// Cleanup any left-over reject rules that do not match any rule ID
		for _, rejectRule := range rejectRules {
			parsedRejectRule, ok := ParseIPTablesRejectRule(rejectRule, ipt.Protocol())
			ruleValid := false
			if ok {
				ruleID := strings.TrimPrefix(parsedRejectRule.SrcIPSetName, ipsetSrcPrefix)
				if expectedIDHashes.Contains(ruleID) {
					ruleValid = true
				}
			}
			if !ruleValid {
				if _, err := ipt.DeleteRule(iptables.TableFilter, iptablesRejectChainName, rejectRule...); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete unknown iptables rule: %w", err))
				}
			}
		}

		//
		// Cleanup RT Mark rules
		//

		// Query all existing rt mark rules in the mangle table
		rtMarkRules, err := ipt.ListRules(iptables.TableMangle, iptablesRTMarkChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
		}

		// Cleanup any left-over rt mark rules that do not match any rule ID
		for _, rtMarkRule := range rtMarkRules {
			parsedRTMarkRule, ok := ParseIPTablesMarkRule(rtMarkRule, ipt.Protocol())
			ruleValid := false
			if ok {
				ruleID := strings.TrimPrefix(parsedRTMarkRule.SrcIPSetName, ipsetSrcPrefix)
				if expectedIDHashes.Contains(ruleID) {
					ruleValid = true
				}
			}
			if !ruleValid {
				if _, err := ipt.DeleteRule(iptables.TableMangle, iptablesRTMarkChainName, rtMarkRule...); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete unknown iptables rule: %w", err))
				}
			}
		}

		//
		// Cleanup FW SNAT rules
		//

		// Query all existing SNAT rules in the nat table
		snatRules, err := ipt.ListRules(iptables.TableNAT, iptablesSNATChainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to list iptables rules: %w", err))
		}

		// Cleanup any left-over snat rules that do not match any rule ID
		for _, snatRule := range snatRules {
			parsedSNATRule, ok := ParseIPTablesSNATRule(snatRule, ipt.Protocol())
			ruleValid := false
			if ok {
				ruleID := strings.TrimPrefix(parsedSNATRule.SrcIPSetName, ipsetSrcPrefix)
				if expectedIDHashes.Contains(ruleID) {
					ruleValid = true
				}
			}
			if !ruleValid {
				if _, err := ipt.DeleteRule(iptables.TableNAT, iptablesSNATChainName, snatRule...); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete unknown iptables rule: %w", err))
				}
			}
		}
	}

	return errors.Join(errs...)
}
