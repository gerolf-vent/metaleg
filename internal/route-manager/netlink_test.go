package route_manager

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/vishvananda/netlink"
)

// requireNetlinkPrivileges checks if the test has sufficient privileges to perform netlink operations
// If not, it skips the test
func requireNetlinkPrivileges(t *testing.T) {
	t.Helper()

	// Try to perform a simple netlink operation to verify we have the necessary capabilities
	// We'll try to list rules, which is a read-only operation but still requires CAP_NET_ADMIN
	_, err := netlink.RuleList(netlink.FAMILY_V4)
	if err != nil {
		t.Skipf("Skipping netlink test: netlink operations not available: %v", err)
	}
}

// requireNetlinkWritePrivileges checks if the test can perform write operations
func requireNetlinkWritePrivileges(t *testing.T) {
	t.Helper()

	requireNetlinkPrivileges(t)

	// Try to add and immediately delete a test rule to verify write capabilities
	// Use a high table ID that's unlikely to conflict with existing rules
	testTable := 19999
	testRule := netlink.NewRule()
	testRule.Table = testTable
	testRule.Family = netlink.FAMILY_V4

	// Try to add the rule
	err := netlink.RuleAdd(testRule)
	if err != nil {
		t.Skipf("Skipping netlink write test: cannot add test rule: %v", err)
	}

	// Clean up the test rule
	if delErr := netlink.RuleDel(testRule); delErr != nil {
		t.Logf("Warning: failed to clean up test rule: %v", delErr)
	}
}

// TestInterface represents a test network interface with its configuration
type TestInterface struct {
	Name     string
	Link     netlink.Link
	IPv4Addr net.IP
	IPv6Addr net.IP
	IPv4Net  *net.IPNet
	IPv6Net  *net.IPNet
	IPv4Gw   net.IP
	IPv6Gw   net.IP
}

// createTestInterface creates a dummy interface with a subnet for testing
func createTestInterface(t *testing.T, name string) *TestInterface {
	t.Helper()
	requireNetlinkWritePrivileges(t)

	// Make interface name unique and short (max 15 chars for Linux interfaces)
	// Use first few chars of name + short timestamp
	shortName := name
	if len(shortName) > 8 {
		shortName = shortName[:8]
	}
	uniqueName := fmt.Sprintf("%s%d", shortName, time.Now().UnixNano()%1000)

	// Create dummy interface
	dummy := &netlink.Dummy{
		LinkAttrs: netlink.LinkAttrs{
			Name: uniqueName,
		},
	}

	// Add the interface
	err := netlink.LinkAdd(dummy)
	if err != nil {
		t.Fatalf("Failed to create dummy interface %s: %v", name, err)
	}

	// Get the interface back to have the correct index
	link, err := netlink.LinkByName(uniqueName)
	if err != nil {
		t.Fatalf("Failed to get dummy interface %s: %v", uniqueName, err)
	}

	// Set interface up
	err = netlink.LinkSetUp(link)
	if err != nil {
		t.Fatalf("Failed to set interface %s up: %v", uniqueName, err)
	}

	// Configure IPv4 subnet (198.51.100.0/24 - RFC5737 test network)
	ipv4Str := "198.51.100.1/24"
	ipv4Addr, ipv4Net, err := net.ParseCIDR(ipv4Str)
	if err != nil {
		t.Fatalf("Failed to parse IPv4 CIDR %s: %v", ipv4Str, err)
	}

	ipv4AddrLink := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv4Addr,
			Mask: ipv4Net.Mask,
		},
	}

	err = netlink.AddrAdd(link, ipv4AddrLink)
	if err != nil {
		t.Fatalf("Failed to add IPv4 address to %s: %v", uniqueName, err)
	}

	// Configure IPv6 subnet (2001:db8::/64 - RFC3849 test network)
	ipv6Str := "2001:db8::1/64"
	ipv6Addr, ipv6Net, err := net.ParseCIDR(ipv6Str)
	if err != nil {
		t.Fatalf("Failed to parse IPv6 CIDR %s: %v", ipv6Str, err)
	}

	ipv6AddrLink := &netlink.Addr{
		IPNet: &net.IPNet{
			IP:   ipv6Addr,
			Mask: ipv6Net.Mask,
		},
	}

	err = netlink.AddrAdd(link, ipv6AddrLink)
	if err != nil {
		t.Fatalf("Failed to add IPv6 address to %s: %v", uniqueName, err)
	}

	return &TestInterface{
		Name:     uniqueName,
		Link:     link,
		IPv4Addr: ipv4Addr,
		IPv6Addr: ipv6Addr,
		IPv4Net:  ipv4Net,
		IPv6Net:  ipv6Net,
		IPv4Gw:   net.IPv4(198, 51, 100, 254),
		IPv6Gw:   net.ParseIP("2001:db8::fffe"),
	}
}

// destroyTestInterface removes the test interface
func destroyTestInterface(t *testing.T, testIf *TestInterface) {
	t.Helper()
	if testIf == nil {
		return
	}

	err := netlink.LinkDel(testIf.Link)
	if err != nil {
		t.Logf("Warning: failed to remove test interface %s: %v", testIf.Name, err)
	}
}

// GetTestRouteTargets returns multiple test network addresses for route testing
func (ti *TestInterface) GetTestRouteTargets(count int) ([]net.IP, []net.IP) {
	var ipv4Addrs, ipv6Addrs []net.IP

	// Helper to increment an IP by n (works for both v4 (len 4) and v6 (len 16))
	incIP := func(base net.IP, n int) net.IP {
		ip := append(net.IP(nil), base...)
		for j := len(ip) - 1; j >= 0 && n > 0; j-- {
			val := int(ip[j]) + n
			ip[j] = byte(val)
			n = val >> 8
		}
		return ip
	}

	for i := 0; i < count; i++ {
		// Dynamically generate deterministic test IPs inside the interface subnets.
		// We skip:
		// - Network address (.0 / ::)
		// - Interface address (.1 / ::1)
		// So we start at offset 2.
		offset := i + 2

		// IPv4
		ipv4 := incIP(ti.IPv4Net.IP.To4(), offset)
		if !ti.IPv4Net.Contains(ipv4) || ipv4.Equal(ti.IPv4Addr) {
			continue
		}

		// IPv6
		ipv6 := incIP(ti.IPv6Net.IP.To16(), offset)
		if !ti.IPv6Net.Contains(ipv6) || ipv6.Equal(ti.IPv6Addr) {
			continue
		}

		ipv4Addrs = append(ipv4Addrs, ipv4)
		ipv6Addrs = append(ipv6Addrs, ipv6)
	}

	return ipv4Addrs, ipv6Addrs
}

func ipNetEqual(a, b *net.IPNet) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.IP.Equal(b.IP) && (a.Mask.String() == b.Mask.String())
}

func ipEqual(a, b net.IP) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return a.Equal(b)
}
