package core

import (
	"net"
)

type Node struct {
	Name string
	IPv4 net.IP
	IPv6 net.IP
}

func (n *Node) Equals(other *Node) bool {
	return n.Name == other.Name && n.IPv4.Equal(other.IPv4) && n.IPv6.Equal(other.IPv6)
}
