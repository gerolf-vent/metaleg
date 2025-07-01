package firewall_manager

import (
	"strconv"
	"strings"
)

type IPTablesSNATSkipRule struct {
	FWMask uint32
}

func ParseIPTablesSNATSkipRule(spec []string) (*IPTablesSNATSkipRule, bool) {
	parsedRule := &IPTablesSNATSkipRule{}

	if len(spec) != 7 {
		return nil, false
	}

	var module string
	notI := -1
	for i := 0; i < len(spec); i++ {
		switch spec[i] {
		case "!":
			notI = i + 1
		case "-m":
			if len(spec) < i+2 { // -m requires one argument
				return nil, false
			}
			module = spec[i+1]
			i += 1
		case "--mark":
			if module != "mark" {
				return nil, false // Only valid for mark module
			}
			if len(spec) < i+2 { // --mark requires one argument
				return nil, false
			}
			if notI != i {
				return nil, false // Only interested in rules with "!"
			}

			mark := strings.SplitN(spec[i+1], "/", 2)
			if len(mark) != 2 {
				return nil, false // Expected format is "0x<mark>/0x<mask>"
			}

			fwMark, err := strconv.ParseUint(strings.TrimPrefix(mark[0], "0x"), 16, 32)
			if err != nil {
				return nil, false // Invalid hex format for fw mark
			}
			if fwMark != 0 {
				return nil, false // Only interested in rules with fw mark 0
			}

			fwMask, err := strconv.ParseUint(strings.TrimPrefix(mark[1], "0x"), 16, 32)
			if err != nil {
				return nil, false // Invalid hex format for fw mask
			}
			parsedRule.FWMask = uint32(fwMask)

			i += 1
		case "-j":
			if len(spec) < i+2 { // -j requires one argument
				return nil, false
			}

			if spec[i+1] != "RETURN" {
				return nil, false // Only interested in RETURN rules
			}
			i += 1
		default:
			return nil, false // Unrecognized part of the spec
		}
	}

	return parsedRule, true
}

func (r *IPTablesSNATSkipRule) Spec() []string {
	return []string{"-m", "mark", "!", "--mark", "0x0/0x" + strconv.FormatUint(uint64(r.FWMask), 16), "-j", "RETURN"}
}
