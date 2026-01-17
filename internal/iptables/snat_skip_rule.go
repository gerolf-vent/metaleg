package iptables

import (
	"strconv"
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type SNATSkipRule struct {
	FWMask uint32
}

func ParseSNATSkipRule(spec []string) (*SNATSkipRule, bool) {
	r := &SNATSkipRule{}

	ruleParser := iptables.NewIPTablesSpecParser([][]string{
		{"-m", "mark"},
		{"!", "--mark", "{xmark}"},
		{"-j", "RETURN"},
	})

	values, ok := ruleParser.Parse(spec)
	if !ok {
		return nil, false
	}

	if !strings.HasPrefix(values["xmark"], "0x0/0x") {
		return nil, false
	}

	maskStr := strings.TrimPrefix(values["xmark"], "0x0/0x")
	mask, err := strconv.ParseUint(maskStr, 16, 32)
	if err != nil {
		return nil, false
	}
	r.FWMask = uint32(mask)

	return r, true
}

func (r *SNATSkipRule) Spec() []string {
	if r == nil {
		return []string{"<nil>"}
	}
	return []string{"-m", "mark", "!", "--mark", "0x0/0x" + strconv.FormatUint(uint64(r.FWMask), 16), "-j", "RETURN"}
}

func (r *SNATSkipRule) String() string {
	if r == nil {
		return "<nil>"
	}
	return strings.Join(r.Spec(), " ")
}
