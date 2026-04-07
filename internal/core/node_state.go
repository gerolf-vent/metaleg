package core

type NodeState struct {
	Node
	IDAllocated  bool
	ID           uint32
	FWMark       uint32
	RouteTableID uint32
}
