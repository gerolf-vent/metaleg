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

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableFilter, iptables.ChainForward, "-j", iptablesRejectChainName); err != nil {
			return fmt.Errorf("failed to ensure %s filter FORWARD rule: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureChain(iptables.TableNAT, iptablesSNATChainName); err != nil {
			return fmt.Errorf("failed to ensure %s NAT chain: %w", ipt.Protocol(), err)
		}

		if _, err := ipt.EnsureRule(iptables.Prepend, iptables.TableNAT, iptables.ChainPostrouting, "-j", iptablesSNATChainName); err != nil {
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

		//
		// Sync FW ip set (1/3)
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

			foundRejectRule := false

			// Cleanup any conflicting or left-over reject rules for the current rule
			for _, rejectRule := range rejectRules {
				parsedRejectRule, ok := ParseIPTablesRejectRule(rejectRule[2:], ipt.Protocol())
				if ok && // Only consider valid reject rules (invalid ones are cleaned up by the full reconciliation)
					strings.Contains(parsedRejectRule.SrcIPSetName, ruleHash) && // Check if the rule matches the current rule hash
					parsedRejectRule.TransportProtocol == tp { // Only consider rules that match the transport protocol
					// Then remove the rule if:
					if !present || // The rule is absent
						len(srcPorts) == 0 || // No ports are configured for the rule
						isGWLocal || // The gw node is local (because we can SNAT directly)
						(isGWRouteKnown && isGWRouteAllocated) || // The gw node is known and allocated (because we can route to it)
						!rule.MatchesIPTablesRejectRule(parsedRejectRule) || // The rule does not match the desired state
						foundRejectRule { // The rule is a duplicate
						if _, err := ipt.DeleteRule(iptables.TableFilter, iptablesRejectChainName, rejectRule[2:]...); err != nil {
							errs = append(errs, fmt.Errorf("failed to delete conflicting iptables rule: %w", err))
						}
					} else if rule.MatchesIPTablesRejectRule(parsedRejectRule) {
						foundRejectRule = true // The rule is present and matches the desired state, so we keep it
					}
				}
			}

			// Create a reject rule, if:
			if present && // The rule should be present
				len(srcPorts) > 0 && // There are source ports configured
				!isGWLocal && (!isGWRouteKnown || !isGWRouteAllocated) && // This node cannot route to the gateway node
				!foundRejectRule { // No matching reject rule exists
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

			foundRTMarkRule := false

			// Cleanup any conflicting or left-over rt mark rules for the current rule
			for _, rtMarkRule := range rtMarkRules {
				parsedRTMarkRule, ok := ParseIPTablesMarkRule(rtMarkRule[2:], ipt.Protocol())
				if ok && // Only consider valid rt mark rules (invalid ones are cleaned up by the full reconciliation)
					strings.Contains(parsedRTMarkRule.SrcIPSetName, ruleHash) && // Check if the rule matches the current rule hash
					parsedRTMarkRule.TransportProtocol == tp { // Only consider rules that match the transport protocol
					// Then remove the rule if:
					if !present || // The rule is absent
						len(srcPorts) == 0 || // No ports are configured for the rule
						isGWLocal || // The gw node is local (because we can SNAT directly)
						(!isGWRouteKnown || !isGWRouteAllocated) || // The gw node is unknown or not allocated (because we cannot route to it)
						!rule.MatchesIPTablesMarkRule(parsedRTMarkRule, uint32(iptm.fwMask)) || // The rule does not match the desired state
						foundRTMarkRule { // The rule is a duplicate
						if _, err := ipt.DeleteRule(iptables.TableMangle, iptablesRTMarkChainName, rtMarkRule[2:]...); err != nil {
							errs = append(errs, fmt.Errorf("failed to delete conflicting iptables rule: %w", err))
						}
					} else if rule.MatchesIPTablesMarkRule(parsedRTMarkRule, uint32(iptm.fwMask)) {
						foundRTMarkRule = true // The rule is present and matches the desired state, so we keep it
					}
				}
			}

			// Create a new rt mark rule, if:
			if present && // The rule should be present
				len(srcPorts) > 0 && // There are source ports configured
				!isGWLocal && (isGWRouteKnown && isGWRouteAllocated) && // This node can route to the gateway node
				!foundRTMarkRule { // No matching rt mark rule exists
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

			foundSNATRule := false

			// Cleanup any conflicting or left-over snat rules for the current rule
			for _, snatRule := range snatRules {
				parsedSNATRule, ok := ParseIPTablesSNATRule(snatRule[2:], ipt.Protocol())
				if ok && // Only consider valid SNAT rules (invalid ones are cleaned up by the full reconciliation)
					strings.Contains(parsedSNATRule.SrcIPSetName, ruleHash) && // Check if the rule matches the current rule hash
					parsedSNATRule.TransportProtocol == tp { // Only consider rules that match the transport protocol
					// Then remove the rule if:
					if !present || // The rule is absent
						len(srcPorts) == 0 || // No ports are configured for the rule
						!isGWLocal || // The gw node is not local (because we cannot SNAT directly)
						!rule.MatchesIPTablesSNATRule(parsedSNATRule) || // The rule does not match the desired state
						foundSNATRule { // The rule is a duplicate
						if _, err := ipt.DeleteRule(iptables.TableNAT, iptablesSNATChainName, snatRule[2:]...); err != nil {
							errs = append(errs, fmt.Errorf("failed to delete conflicting iptables rule: %w", err))
						}
					} else if rule.MatchesIPTablesSNATRule(parsedSNATRule) {
						foundSNATRule = true // The rule is present and matches the desired state, so we keep it
					}
				}
			}

			// Create a new SNAT rule, if:
			if present && // The rule should be present
				len(srcPorts) > 0 && // There are source ports configured
				isGWLocal && // This node is the gateway node (because we can SNAT directly)
				!foundSNATRule { // No matching SNAT rule exists
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

			//
			// Sync IPSet entries (2/3)
			//

			presentIPs, err := iptm.ips.ListEntries(ipsetSrcName)
			if err != nil {
				errs = append(errs, fmt.Errorf("failed to list ipset entries: %w", err))
			} else {
				for _, presentSrcIP := range presentIPs {
					foundSrcIP := false
					for _, srcIP := range srcIPs {
						if presentSrcIP.Equal(srcIP) {
							foundSrcIP = true
							break
						}
					}
					if !foundSrcIP {
						// Remove the src IP from the ipset, if it is not present in the rule anymore
						if _, err := iptm.ips.DeleteEntry(ipsetSrcName, presentSrcIP); err != nil {
							errs = append(errs, fmt.Errorf("failed to delete ipset entry: %w", err))
						}
					}
				}

				for _, srcIP := range srcIPs {
					if _, err := iptm.ips.EnsureEntry(ipsetSrcName, srcIP); err != nil {
						errs = append(errs, fmt.Errorf("failed to ensure ipset entry: %w", err))
					}
				}
			}
		}

		//
		// Sync IPSet entries (3/3)
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
				if _, err := ipt.DeleteRule(iptables.TableFilter, iptablesRejectChainName, rejectRule[2:]...); err != nil {
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
				if _, err := ipt.DeleteRule(iptables.TableMangle, iptablesRTMarkChainName, rtMarkRule[2:]...); err != nil {
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
				if _, err := ipt.DeleteRule(iptables.TableNAT, iptablesSNATChainName, snatRule[2:]...); err != nil {
					errs = append(errs, fmt.Errorf("failed to delete unknown iptables rule: %w", err))
				}
			}
		}
	}

	return errors.Join(errs...)
}
