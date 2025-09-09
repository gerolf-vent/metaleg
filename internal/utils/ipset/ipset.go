package ipset

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"

	ctrl "sigs.k8s.io/controller-runtime"
)

type Protocol string

const (
	IPv4 Protocol = "inet"
	IPv6 Protocol = "inet6"
)

func (p Protocol) String() string {
	switch p {
	case IPv4:
		return "IPv4"
	case IPv6:
		return "IPv6"
	default:
		return "Unknown"
	}
}

type CmdError struct {
	*exec.ExitError
	cmd string
	msg string
}

func (e *CmdError) Error() string {
	return fmt.Sprintf("Command %q failed with exit code %d: %s", e.cmd, e.ExitCode(), e.msg)
}

type IPSet struct {
	path string
}

func New() (*IPSet, error) {
	var path string
	var err error

	path, err = exec.LookPath("ipset")
	if err != nil {
		return nil, err
	}

	ipset := &IPSet{
		path: path,
	}

	return ipset, nil
}

func (ips *IPSet) SetExists(name string) (bool, error) {
	return ips.setExists(name)
}

func (ips *IPSet) EnsureSet(name string, proto Protocol) (bool, error) {
	return ips.ensureSet(name, proto, "hash:ip")
}

func (ips *IPSet) DeleteSet(name string) (bool, error) {
	return ips.deleteSet(name)
}

func (ips *IPSet) ListEntries(setName string) ([]net.IP, error) {
	entries, err := ips.listEntries(setName, "hash:ip")
	if err != nil {
		return nil, err
	}

	var ipEntries []net.IP
	for _, entry := range entries {
		parsedIP := net.ParseIP(entry)
		if parsedIP != nil {
			ipEntries = append(ipEntries, parsedIP)
		}
	}
	return ipEntries, nil
}

func (ips *IPSet) EntryExists(setName string, entry net.IP) (bool, error) {
	return ips.entryExists(setName, entry.String())
}

func (ips *IPSet) EnsureEntry(setName string, entry net.IP) (bool, error) {
	return ips.ensureEntry(setName, entry.String())
}

func (ips *IPSet) DeleteEntry(setName string, entry net.IP) (bool, error) {
	return ips.deleteEntry(setName, entry.String())
}

func (ips *IPSet) NetworkSetExists(name string) (bool, error) {
	return ips.setExists(name)
}

func (ips *IPSet) EnsureNetworkSet(name string, proto Protocol) (bool, error) {
	return ips.ensureSet(name, proto, "hash:net")
}

func (ips *IPSet) DeleteNetworkSet(name string) (bool, error) {
	return ips.deleteSet(name)
}

func (ips *IPSet) NetworkEntryExists(name string, cidr net.IPNet) (bool, error) {
	return ips.entryExists(name, cidr.String())
}

func (ips *IPSet) ListNetworkEntries(setName string) ([]net.IPNet, error) {
	entries, err := ips.listEntries(setName, "hash:net")
	if err != nil {
		return nil, err
	}

	var cidrEntries []net.IPNet
	for _, entry := range entries {
		_, parsedCIDR, err := net.ParseCIDR(entry)
		if err == nil && parsedCIDR != nil {
			cidrEntries = append(cidrEntries, *parsedCIDR)
		}
	}
	return cidrEntries, nil
}

func (ips *IPSet) EnsureNetworkEntry(setName string, cidr *net.IPNet) (bool, error) {
	return ips.ensureEntry(setName, cidr.String())
}

func (ips *IPSet) DeleteNetworkEntry(setName string, cidr *net.IPNet) (bool, error) {
	return ips.deleteEntry(setName, cidr.String())
}

func (ips *IPSet) setExists(name string) (bool, error) {
	args := []string{"list", name}
	err := ips.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (ips *IPSet) ensureSet(name string, proto Protocol, setType string) (bool, error) {
	args := []string{"create", name, setType, "family", string(proto), "timeout", "0"}
	err := ips.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (ips *IPSet) deleteSet(name string) (bool, error) {
	args := []string{"destroy", name}
	err := ips.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (ips *IPSet) listEntries(setName string, expectedSetType string) ([]string, error) {
	args := []string{"list", "-o", "xml", setName}

	stdout := &bytes.Buffer{}
	err := ips.runWithOutput(args, stdout)
	if err != nil {
		return nil, err
	}

	var data XMLIPSets
	if err := xml.Unmarshal(stdout.Bytes(), &data); err != nil {
		return nil, err
	}

	var entries []string
	for _, set := range data.IPSets {
		if set.Name != setName {
			continue // Skip sets that do not match the requested name
		}
		if set.Type != expectedSetType {
			return nil, fmt.Errorf("unexpected ipset type %q, expected %q", set.Type, expectedSetType)
		}
		entries = make([]string, 0, len(set.Members))
		for _, entry := range set.Members {
			entries = append(entries, entry.Elem)
		}
	}
	return entries, nil
}

func (ips *IPSet) entryExists(setName string, entry string) (bool, error) {
	args := []string{"test", setName, entry}
	err := ips.run(args)
	if err != nil {
		if strings.Contains(err.Error(), fmt.Sprintf("%s is NOT in set %s", entry, setName)) {
			return false, nil
		}
		return false, err
	}
	return true, nil
}

func (ips *IPSet) ensureEntry(setName string, entry string) (bool, error) {
	args := []string{"add", setName, entry}
	err := ips.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "already added") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (ips *IPSet) deleteEntry(setName string, entry string) (bool, error) {
	args := []string{"del", setName, entry}
	err := ips.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return true, nil
		}
		return false, err
	}
	return false, nil
}

func (ips *IPSet) run(args []string) error {
	return ips.runWithOutput(args, nil)
}

func (ips *IPSet) runWithOutput(args []string, stdout io.Writer) error {
	// Prepend the command path to arguments (as exec.Cmd expects the first argument to be the command itself)
	args = append([]string{ips.path}, args...)

	stderr := &bytes.Buffer{}
	cmd := exec.Cmd{
		Path:   ips.path,
		Args:   args,
		Stdout: stdout,
		Stderr: stderr,
	}

	ctrl.Log.V(1).Info("Running command", "command", strings.Join(cmd.Args, " "))

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return &CmdError{
				ExitError: exitErr,
				cmd:       strings.Join(cmd.Args, " "),
				msg:       strings.TrimSpace(stderr.String()),
			}
		} else {
			return err
		}
	}

	return nil
}
