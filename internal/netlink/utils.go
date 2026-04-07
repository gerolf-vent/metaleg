package netlink

import (
	"bytes"
	"net"
)

func maskEquals(a, b *uint32) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
}

func ipNetEquals(a, b *net.IPNet) bool {
	return (a == nil && b == nil) || (a != nil && b != nil && a.IP.Equal(b.IP) && bytes.Equal(a.Mask, b.Mask))
}
