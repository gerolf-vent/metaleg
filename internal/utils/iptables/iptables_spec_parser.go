package iptables

import (
	"strings"
)

type IPTablesSpecParser struct {
	args [][]string
}

func NewIPTablesSpecParser(args [][]string) *IPTablesSpecParser {
	return &IPTablesSpecParser{
		args: args,
	}
}

func (p *IPTablesSpecParser) Parse(spec []string) (map[string]string, bool) {
	argsMatched := make([]bool, len(p.args))
	specValues := make(map[string]string)

	i := 0
	for i < len(spec) {
		matched := false
		for j, arg := range p.args {
			if len(arg) == 0 {
				continue // Skip empty arg definitions
			}
			if argsMatched[j] {
				continue // This arg was already matched
			}
			if spec[i] == arg[0] {
				if len(spec) < i+len(arg) {
					return nil, false // Not enough values
				}
				for k, expectedValue := range arg[1:] {
					if strings.HasPrefix(expectedValue, "{") && strings.HasSuffix(expectedValue, "}") {
						// Placeholder, accept any value
						placeholderName := expectedValue[1 : len(expectedValue)-1]
						specValues[placeholderName] = spec[i+1+k]
						continue
					}
					if spec[i+1+k] != expectedValue {
						return nil, false // Value does not match
					}
				}
				// All values matched
				argsMatched[j] = true
				i += len(arg)
				matched = true
				break
			}
		}
		if !matched {
			return nil, false // No matching arg found
		}
	}

	for _, matched := range argsMatched {
		if !matched {
			return nil, false // Not all args were matched
		}
	}

	return specValues, true
}
