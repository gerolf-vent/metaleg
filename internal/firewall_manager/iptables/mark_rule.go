package iptables

import (
	"strconv"
	"strings"

	"github.com/gerolf-vent/metaleg/internal/utils/iptables"
)

type MarkRule struct {
	SrcIPSetName string
	FWMark       uint32
	FWMask       uint32
	Protocol     iptables.Protocol
}

func ParseMarkRule(spec []string, protocol iptables.Protocol) (*MarkRule, bool) {
	r := &MarkRule{
		Protocol: protocol,
	}

	ruleParser := iptables.NewIPTablesSpecParser([][]string{
		{"-m", "set"},
		{"--match-set", "{setName}", "src"},
		{"-j", "MARK", "--set-xmark", "{xmark}"},
	})

	values, ok := ruleParser.Parse(spec)
	if !ok {
		return nil, false
	}

	r.SrcIPSetName = values["setName"]

	xmarkParts := strings.SplitN(values["xmark"], "/", 2)
	if len(xmarkParts) != 2 {
		return nil, false
	}
	if !strings.HasPrefix(xmarkParts[0], "0x") || !strings.HasPrefix(xmarkParts[1], "0x") {
		return nil, false
	}

	markStr := strings.TrimPrefix(xmarkParts[0], "0x")
	mark, err := strconv.ParseUint(markStr, 16, 32)
	if err != nil {
		return nil, false
	}
	r.FWMark = uint32(mark)

	maskStr := strings.TrimPrefix(xmarkParts[1], "0x")
	mask, err := strconv.ParseUint(maskStr, 16, 32)
	if err != nil {
		return nil, false
	}
	r.FWMask = uint32(mask)

	return r, true
}

func (r *MarkRule) Spec() []string {
	if r == nil {
		return []string{"<nil>"}
	}
	return []string{"-m", "set", "--match-set", r.SrcIPSetName, "src", "-j", "MARK", "--set-xmark", "0x" + strconv.FormatUint(uint64(r.FWMark), 16) + "/0x" + strconv.FormatUint(uint64(r.FWMask), 16)}
}

func (r *MarkRule) String() string {
	if r == nil {
		return "<nil>"
	}
	return strings.Join(r.Spec(), " ")
}

func (r *MarkRule) RuleID() string {
	if r == nil {
		return "<nil>"
	}
	return r.SrcIPSetName
}
