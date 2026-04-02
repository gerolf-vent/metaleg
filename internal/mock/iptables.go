package mock

import (
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type IPTables struct {
	IPv6   bool
	Chains map[string]bool       // "table:chain" -> exists
	Rules  map[string][][]string // "table:chain" -> []rulespec
}

func NewIPTables(isIPv6 bool) *IPTables {
	m := &IPTables{
		IPv6:   isIPv6,
		Chains: make(map[string]bool),
		Rules:  make(map[string][][]string),
	}
	for _, table := range []iptables.Table{iptables.TableNAT, iptables.TableFilter, iptables.TableMangle} {
		for _, chain := range []iptables.Chain{iptables.ChainPostrouting, iptables.ChainPrerouting, iptables.ChainForward, iptables.ChainOutput, iptables.ChainInput} {
			key := string(table) + ":" + string(chain)
			m.Chains[key] = true
			m.Rules[key] = nil
		}
	}
	return m
}

func (m *IPTables) key(table iptables.Table, chain iptables.Chain) string {
	return string(table) + ":" + string(chain)
}

func (m *IPTables) IsIPv6() bool { return m.IPv6 }
func (m *IPTables) Protocol() iptables.Protocol {
	if m.IPv6 {
		return iptables.IPv6
	}
	return iptables.IPv4
}

func (m *IPTables) ChainExists(table iptables.Table, chain iptables.Chain) (bool, error) {
	return m.Chains[m.key(table, chain)], nil
}

func (m *IPTables) EnsureChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	k := m.key(table, chain)
	created := !m.Chains[k]
	m.Chains[k] = true
	if _, ok := m.Rules[k]; !ok {
		m.Rules[k] = nil
	}
	return created, nil
}

func (m *IPTables) FlushChain(table iptables.Table, chain iptables.Chain) error {
	k := m.key(table, chain)
	if !m.Chains[k] {
		return fmt.Errorf("chain %s does not exist", chain)
	}
	m.Rules[k] = nil
	return nil
}

func (m *IPTables) DeleteChain(table iptables.Table, chain iptables.Chain) (bool, error) {
	k := m.key(table, chain)
	if !m.Chains[k] {
		return false, nil
	}
	m.Rules[k] = nil
	delete(m.Chains, k)
	delete(m.Rules, k)
	return true, nil
}

func (m *IPTables) RuleExists(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	k := m.key(table, chain)
	target := strings.Join(rulespec, " ")
	for _, r := range m.Rules[k] {
		if strings.Join(r, " ") == target {
			return true, nil
		}
	}
	return false, nil
}

func (m *IPTables) ListRules(table iptables.Table, chain iptables.Chain) ([][]string, error) {
	k := m.key(table, chain)
	if !m.Chains[k] {
		return nil, fmt.Errorf("chain %s does not exist in table %s", chain, table)
	}
	var result [][]string
	for _, r := range m.Rules[k] {
		full := append([]string{"-A", string(chain)}, r...)
		result = append(result, full)
	}
	return result, nil
}

func (m *IPTables) EnsureRule(position iptables.RulePosition, table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	k := m.key(table, chain)
	if !m.Chains[k] {
		return false, fmt.Errorf("chain %s does not exist", chain)
	}

	target := strings.Join(rulespec, " ")
	for _, r := range m.Rules[k] {
		if strings.Join(r, " ") == target {
			return false, nil
		}
	}

	spec := make([]string, len(rulespec))
	copy(spec, rulespec)

	if len(position) > 0 && position[0] == "-I" {
		insertIndex := 0
		if len(position) > 1 {
			parsedIndex, err := strconv.Atoi(position[1])
			if err == nil {
				insertIndex = parsedIndex - 1 // iptables uses 1-based insertion indexes
			}
		}

		if insertIndex < 0 {
			insertIndex = 0
		}
		if insertIndex > len(m.Rules[k]) {
			insertIndex = len(m.Rules[k])
		}

		rules := append(m.Rules[k], nil)
		copy(rules[insertIndex+1:], rules[insertIndex:])
		rules[insertIndex] = spec
		m.Rules[k] = rules
	} else {
		m.Rules[k] = append(m.Rules[k], spec)
	}
	return true, nil
}

func (m *IPTables) DeleteRule(table iptables.Table, chain iptables.Chain, rulespec ...string) (bool, error) {
	k := m.key(table, chain)
	target := strings.Join(rulespec, " ")
	for i, r := range m.Rules[k] {
		if strings.Join(r, " ") == target {
			m.Rules[k] = slices.Delete(m.Rules[k], i, i+1)
			return true, nil
		}
	}
	return false, nil
}

// GetRules returns the raw rule specs (without "-A CHAIN" prefix) for a table:chain.
func (m *IPTables) GetRules(table iptables.Table, chain iptables.Chain) [][]string {
	return m.Rules[m.key(table, chain)]
}
