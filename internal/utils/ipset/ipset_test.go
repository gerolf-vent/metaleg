package ipset

import (
	"net"
	"os/exec"
	"reflect"
	"strings"
	"testing"
)

func requireIPSetPrivileges(t *testing.T, ips IPSet) {
	t.Helper()

	// Check if we have enough privileges by attempting a harmless ListSets call.
	_, err := ips.ListSets()
	if err != nil && strings.Contains(err.Error(), "Operation not permitted") {
		t.Skipf("Skipping ipset test: ipset list operation not available: %v", err)
	}
}

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
	}
}

func TestSetLifecycle(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

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

	requireIPSetPrivileges(t, ips)

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

	requireIPSetPrivileges(t, ips)

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

	requireIPSetPrivileges(t, ips)

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

func TestListSets(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

	setName1 := "testlistset1"
	setName2 := "testlistset2"
	_, _ = ips.DeleteSet(setName1)
	_, _ = ips.DeleteSet(setName2)

	_, err = ips.EnsureSet(setName1, IPv4)
	if err != nil {
		t.Fatalf("EnsureSet failed: %v", err)
	}
	_, err = ips.EnsureSet(setName2, IPv6)
	if err != nil {
		t.Fatalf("EnsureSet failed: %v", err)
	}

	sets, err := ips.ListSets()
	if err != nil {
		t.Fatalf("ListSets failed: %v", err)
	}

	found1, found2 := false, false
	for _, s := range sets {
		if s == setName1 {
			found1 = true
		}
		if s == setName2 {
			found2 = true
		}
	}
	if !found1 || !found2 {
		t.Errorf("Expected sets %s and %s to be listed, got %v", setName1, setName2, sets)
	}

	_, _ = ips.DeleteSet(setName1)
	_, _ = ips.DeleteSet(setName2)
}

func TestEnsureSet_SetAlreadyExists(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

	setName := "testset_exists"
	_, _ = ips.DeleteSet(setName) // Clean up before

	// Create the set first
	created, err := ips.EnsureSet(setName, IPv4)
	if err != nil {
		t.Errorf("First EnsureSet failed: %v", err)
	}
	if created {
		t.Error("Expected first EnsureSet to return false (set was created)")
	}

	// Try to ensure the same set again - should return true (already exists)
	exists, err := ips.EnsureSet(setName, IPv4)
	if err != nil {
		t.Errorf("Second EnsureSet failed: %v", err)
	}
	if !exists {
		t.Error("Expected second EnsureSet to return true (set already exists)")
	}

	// Clean up
	_, _ = ips.DeleteSet(setName)
}

func TestDeleteSet_SetDoesNotExist(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

	setName := "testset_nonexistent"

	// Make sure the set doesn't exist
	_, _ = ips.DeleteSet(setName)

	// Verify set doesn't exist
	exists, err := ips.SetExists(setName)
	if err != nil {
		t.Errorf("SetExists failed: %v", err)
	}
	if exists {
		t.Error("Expected set to not exist before test")
	}

	// Try to delete non-existent set - should return true (nothing to delete)
	deleted, err := ips.DeleteSet(setName)
	if err != nil {
		t.Errorf("DeleteSet failed: %v", err)
	}
	if !deleted {
		t.Error("Expected DeleteSet to return true when set doesn't exist")
	}
}

func TestListEntries_SetDoesNotExist(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

	setName := "testset_nonexistent_list"

	// Make sure the set doesn't exist
	_, _ = ips.DeleteSet(setName)

	// Try to list entries from non-existent set - should return error
	_, err = ips.ListEntries(setName)
	if err == nil {
		t.Error("Expected error when listing entries from non-existent set")
	}
}

func TestListEntries_UnexpectedSetType(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

	setName := "testset_wrong_type"
	_, _ = ips.DeleteSet(setName) // Clean up before

	// Create a hash:net set
	_, err = ips.EnsureNetworkSet(setName, IPv4)
	if err != nil {
		t.Errorf("EnsureNetworkSet failed: %v", err)
	}

	// Try to list entries using hash:ip method - should return error about unexpected type
	_, err = ips.ListEntries(setName)
	if err == nil {
		t.Error("Expected error when listing entries with wrong set type")
	}
	if err != nil && !strings.Contains(err.Error(), "unexpected ipset type") {
		t.Errorf("Expected error about unexpected ipset type, got: %v", err)
	}

	// Clean up
	_, _ = ips.DeleteSet(setName)
}

func TestEnsureEntry_SetDoesNotExist(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

	setName := "testset_nonexistent_entry"
	ip := net.ParseIP("1.2.3.4")

	// Make sure the set doesn't exist
	_, _ = ips.DeleteSet(setName)

	// Try to add entry to non-existent set - should return error
	_, err = ips.EnsureEntry(setName, ip)
	if err == nil {
		t.Error("Expected error when adding entry to non-existent set")
	}
}

func TestDeleteEntry_SetDoesNotExist(t *testing.T) {
	ips, err := New()
	if err != nil {
		t.Skip("ipset not available, skipping integration test")
	}

	requireIPSetPrivileges(t, ips)

	setName := "testset_nonexistent_del_entry"
	ip := net.ParseIP("1.2.3.4")

	// Make sure the set doesn't exist
	_, _ = ips.DeleteSet(setName)

	// Try to delete entry from non-existent set - should return error
	_, err = ips.DeleteEntry(setName, ip)
	if err == nil {
		t.Error("Expected error when deleting entry from non-existent set")
	}
}
