package route_manager

import (
	"net"
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
