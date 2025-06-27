package route_manager

import (
	"net"

	"github.com/vishvananda/netlink"
)

type NodeRoute struct {
	Name         string
	IPv4         net.IP
	IPv6         net.IP
	ID           uint // Used for computing the fw mark and route table ID, will be lazy allocated
	IDAllocated  bool // Indicates if the ID has been allocated
	FWMark       uint32
	RouteTableID uint32
	RuleCount    uint // Number of egress rules that use this route
}

func (r *NodeRoute) MatchesNLRule(nlRule *netlink.Rule) bool {
	if nlRule == nil {
		return false
	}

	if r.RuleCount == 0 {
		return false // This route is not used by any egress rules
	}

	if nlRule.Mark != r.FWMark {
		return false
	}

	if nlRule.Table != int(r.RouteTableID) {
		return false
	}

	return true
}

func (r *NodeRoute) MatchesNLRoute(nlRoute *netlink.Route) bool {
	if nlRoute == nil {
		return false
	}

	if r.RuleCount == 0 {
		return false // This route is not used by any egress rules
	}

	if nlRoute.Table != int(r.RouteTableID) {
		return false
	}

	if nlRoute.Dst == nil {
		return false
	}

	dstMaskSize, _ := nlRoute.Dst.Mask.Size()
	if dstMaskSize != 0 { // This should be a default route
		return false
	}

	switch nlRoute.Family {
	case netlink.FAMILY_V4:
		if r.IPv4 != nil && r.IPv4.Equal(nlRoute.Gw.To4()) {
			return true
		}
	case netlink.FAMILY_V6:
		if r.IPv6 != nil && r.IPv6.Equal(nlRoute.Gw.To16()) {
			return true
		}
	}

	return false
}
