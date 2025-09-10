package ipset

import (
	"net"
	"os/exec"
	"reflect"
	"testing"
)

func TestProtocolString(t *testing.T) {
	if IPv4.String() != "IPv4" {
		t.Errorf("Expected IPv4.String() to be 'IPv4', got '%s'", IPv4.String())
	}
	if IPv6.String() != "IPv6" {
		t.Errorf("Expected IPv6.String() to be 'IPv6', got '%s'", IPv6.String())
	}
	if Protocol("foo").String() != "Unknown" {
		t.Errorf("Expected unknown protocol to be 'Unknown', got '%s'", Protocol("foo").String())
	}
}

func TestCmdError_Error(t *testing.T) {
	exitErr := &exec.ExitError{}
	e := &CmdError{ExitError: exitErr, cmd: "ipset add foo", msg: "fail"}
	_ = e.Error() // Just ensure it doesn't panic
}

func TestNew(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}
	if ips == nil {
		t.Error("Expected non-nil IPSet")
	} else {
		t.Logf("Found ipset at %s", ips.path)
	}
}

func TestSetLifecycle(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	setName := "testset1234"
	_, _ = ips.DeleteSet(setName) // Clean up before

	_, err = ips.EnsureSet(setName, IPv4)
	if err != nil {
		t.Errorf("EnsureSet failed: %v", err)
	}
	exists, err := ips.SetExists(setName)
	if err != nil || !exists {
		t.Errorf("Expected set to exist after EnsureSet, err: %v", err)
	}
	_, err = ips.DeleteSet(setName)
	if err != nil {
		t.Errorf("DeleteSet failed: %v", err)
	}
}

func TestEntryLifecycle(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	setName := "testset1234"
	_, _ = ips.DeleteSet(setName) // Clean up before

	_, err = ips.EnsureSet(setName, IPv4)
	if err != nil {
		t.Errorf("EnsureSet failed: %v", err)
	}
	ip := net.ParseIP("1.2.3.4")
	_, err = ips.EnsureEntry(setName, ip)
	if err != nil {
		t.Errorf("EnsureEntry failed: %v", err)
	}
	exists, err := ips.EntryExists(setName, ip)
	if err != nil || !exists {
		t.Errorf("EntryExists failed: %v", err)
	}
	entries, err := ips.ListEntries(setName)
	if err != nil {
		t.Errorf("ListEntries failed: %v", err)
	}
	if !reflect.DeepEqual(entries, []net.IP{ip}) {
		t.Errorf("ListEntries = %v, want [%v]", entries, ip)
	}
	_, err = ips.DeleteEntry(setName, ip)
	if err != nil {
		t.Errorf("DeleteEntry failed: %v", err)
	}
	_, _ = ips.DeleteSet(setName)
}

func TestNetworkSetLifecycle(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	setName := "testset1234"
	_, _ = ips.DeleteNetworkSet(setName) // Clean up before

	_, err = ips.EnsureNetworkSet(setName, IPv4)
	if err != nil {
		t.Errorf("EnsureNetworkSet failed: %v", err)
	}
	exists, err := ips.NetworkSetExists(setName)
	if err != nil || !exists {
		t.Errorf("Expected set to exist after EnsureNetworkSet, err: %v", err)
	}
	_, err = ips.DeleteNetworkSet(setName)
	if err != nil {
		t.Errorf("DeleteNetworkSet failed: %v", err)
	}
}

func TestNetworkEntryLifecycle(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	setName := "testnetset1234"
	_, _ = ips.DeleteNetworkSet(setName) // Clean up before

	_, err = ips.EnsureNetworkSet(setName, IPv4)
	if err != nil {
		t.Errorf("EnsureNetworkSet failed: %v", err)
	}
	_, ipnet, _ := net.ParseCIDR("10.1.2.0/24")
	_, err = ips.EnsureNetworkEntry(setName, ipnet)
	if err != nil {
		t.Errorf("EnsureNetworkEntry failed: %v", err)
	}
	exists, err := ips.NetworkEntryExists(setName, *ipnet)
	if err != nil || !exists {
		t.Errorf("NetworkEntryExists failed: %v", err)
	}
	entries, err := ips.ListNetworkEntries(setName)
	if err != nil {
		t.Errorf("ListNetworkEntries failed: %v", err)
	}
	if !reflect.DeepEqual(entries, []net.IPNet{*ipnet}) {
		t.Errorf("ListNetworkEntries = %v, want [%v]", entries, *ipnet)
	}
	_, err = ips.DeleteNetworkEntry(setName, ipnet)
	if err != nil {
		t.Errorf("DeleteNetworkEntry failed: %v", err)
	}
	_, _ = ips.DeleteNetworkSet(setName)
}
