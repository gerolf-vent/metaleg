package firewall_manager

import (
	"crypto/sha256"
	"encoding/base32"
	"net"
	"strings"

	rm "github.com/gerolf-vent/metaleg/internal/route_manager"
)

type EgressRule struct {
	ID         string        // Unique identifier for the egress rule (namespaced service name)
	SrcIPv4s   []net.IP      // Source IPv4 addresses from Pods
	SrcIPv6s   []net.IP      // Source IPv6 addresses from Pods
	SNATIPv4   net.IP        // SNAT IPv4 address for egress traffic
	SNATIPv6   net.IP        // SNAT IPv6 address for egress traffic
	GWNodeName string        // Name of the gateway node for egress traffic
	GWRoute    *rm.NodeRoute // Gateway route for egress traffic
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
