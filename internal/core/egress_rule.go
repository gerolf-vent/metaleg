package core

import (
	"crypto/sha256"
	"encoding/base32"
	"net"
	"strings"
)

type EgressRule struct {
	ID         string   // Unique identifier for the egress rule (namespaced service name)
	SrcIPv4s   []net.IP // Source IPv4 addresses from Pods
	SrcIPv6s   []net.IP // Source IPv6 addresses from Pods
	SNATIPv4   net.IP   // SNAT IPv4 address for egress traffic
	SNATIPv6   net.IP   // SNAT IPv6 address for egress traffic
	GWNodeName string   // Name of the gateway node for egress traffic
}

func NewEgressRule(id string) *EgressRule {
	return &EgressRule{
		ID: id,
	}
}

func (r *EgressRule) CalcIDHash(isIPv6 bool) string {
	var protoPrefix string
	if isIPv6 {
		protoPrefix = "ipv6:"
	}
	hash := sha256.Sum256([]byte(protoPrefix + r.ID))
	encoded := base32.StdEncoding.EncodeToString(hash[:])
	return strings.ToUpper(encoded[:12])
}

func (r *EgressRule) Equals(other *EgressRule) bool {
	if r.ID != other.ID || !r.SNATIPv4.Equal(other.SNATIPv4) || !r.SNATIPv6.Equal(other.SNATIPv6) || r.GWNodeName != other.GWNodeName {
		return false
	}

	if len(r.SrcIPv4s) != len(other.SrcIPv4s) || len(r.SrcIPv6s) != len(other.SrcIPv6s) {
		return false
	}

	if !compareIPSlices(r.SrcIPv4s, other.SrcIPv4s) || !compareIPSlices(r.SrcIPv6s, other.SrcIPv6s) {
		return false
	}

	return true
}

func compareIPSlices(a, b []net.IP) bool {
	if len(a) != len(b) {
		return false
	}
	ipMap := make(map[string]struct{})
	for _, ip := range a {
		ipMap[ip.String()] = struct{}{}
	}
	for _, ip := range b {
		if _, exists := ipMap[ip.String()]; !exists {
			return false
		}
	}
	return true
}
