package iptables

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"

	"github.com/google/shlex"
	"golang.org/x/mod/semver"

	ctrl "sigs.k8s.io/controller-runtime"
)

var (
	ErrChainNotExists = errors.New("chain does not exist")
)

const (
	RequiredMinVersion = "1.4.22"
)

type Protocol string

const (
	IPv4 Protocol = "IPv4"
	IPv6 Protocol = "IPv6"
)

func (p Protocol) String() string {
	return string(p)
}

type TransportProtocol string

const (
	TCP TransportProtocol = "tcp"
	UDP TransportProtocol = "udp"
)

func (tp TransportProtocol) String() string {
	return string(tp)
}

type Table string

const (
	TableNAT    Table = "nat"
	TableFilter Table = "filter"
	TableMangle Table = "mangle"
)

type Chain string

const (
	ChainPostrouting Chain = "POSTROUTING"
	ChainPrerouting  Chain = "PREROUTING"
	ChainOutput      Chain = "OUTPUT"
	ChainInput       Chain = "INPUT"
	ChainForward     Chain = "FORWARD"
)

type RulePosition string

const (
	Prepend RulePosition = "-I"
	Append  RulePosition = "-A"
)

type CmdError struct {
	*exec.ExitError
	cmd string
	msg string
}

func (e *CmdError) Error() string {
	return fmt.Sprintf("Command %q failed with exit code %d: %s", e.cmd, e.ExitCode(), e.msg)
}

type IPTables struct {
	sync.Mutex
	path  string
	proto Protocol
}

func New(proto Protocol) (*IPTables, error) {
	var path string
	var err error

	switch proto {
	case IPv4:
		path, err = exec.LookPath("iptables")
		if err != nil {
			return nil, fmt.Errorf("iptables executable not found: %w", err)
		}
	case IPv6:
		path, err = exec.LookPath("ip6tables")
		if err != nil {
			return nil, fmt.Errorf("ip6tables executable not found: %w", err)
		}
	default:
		return nil, os.ErrInvalid
	}

	ipt := &IPTables{
		path:  path,
		proto: proto,
	}

	return ipt, ipt.checkVersion()
}

func (ipt *IPTables) IsIPv6() bool {
	return ipt.proto == IPv6
}

func (ipt *IPTables) Protocol() Protocol {
	return ipt.proto
}

func (ipt *IPTables) ChainExists(table Table, chain Chain) (bool, error) {
	ipt.Lock()
	defer ipt.Unlock()

	args := []string{"-t", string(table), "-L", string(chain)}
	err := ipt.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "No chain/target/match by that name") {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func (ipt *IPTables) EnsureChain(table Table, chain Chain) (bool, error) {
	ipt.Lock()
	defer ipt.Unlock()

	args := []string{"-t", string(table), "-N", string(chain)}
	err := ipt.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "already exists") {
			return true, nil
		}
		return false, err
	}

	return false, nil
}

func (ipt *IPTables) FlushChain(table Table, chain Chain) error {
	ipt.Lock()
	defer ipt.Unlock()

	args := []string{"-t", string(table), "-F", string(chain)}
	err := ipt.run(args)
	if err != nil {
		return err
	}

	return nil
}

func (ipt *IPTables) DeleteChain(table Table, chain Chain) (bool, error) {
	ipt.Lock()
	defer ipt.Unlock()

	args := []string{"-t", string(table), "-F", string(chain)}
	err := ipt.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "No chain/target/match by that name") {
			return true, nil
		}
		return false, err
	}

	args = []string{"-t", string(table), "-X", string(chain)}
	err = ipt.run(args)
	if err != nil {
		if strings.Contains(err.Error(), "No chain/target/match by that name") {
			return true, nil
		}
		return false, err
	}

	return false, nil
}

func (ipt *IPTables) RuleExists(table Table, chain Chain, rulespec ...string) (bool, error) {
	ipt.Lock()
	defer ipt.Unlock()

	return ipt.check(table, chain, rulespec...)
}

func (ipt *IPTables) ListRules(table Table, chain Chain) ([][]string, error) {
	ipt.Lock()
	defer ipt.Unlock()

	args := []string{"-t", string(table), "-S", string(chain)}

	stdout := &bytes.Buffer{}
	err := ipt.runWithOutput(args, stdout)
	if err != nil {
		return nil, err
	}

	scanner := bufio.NewScanner(stdout)
	var rules [][]string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		} else if strings.HasPrefix(line, "-N ") || strings.HasPrefix(line, "-X ") {
			// Skip chain creation or deletion commands
			continue
		}
		rule, err := shlex.Split(line)
		if err != nil {
			return nil, fmt.Errorf("error parsing rule: %w", err)
		}
		rules = append(rules, rule)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return rules, nil
}

func (ipt *IPTables) EnsureRule(position RulePosition, table Table, chain Chain, rulespec ...string) (bool, error) {
	ipt.Lock()
	defer ipt.Unlock()

	exists, err := ipt.check(table, chain, rulespec...)
	if err != nil {
		return false, err
	}

	if !exists {
		createArgs := append([]string{"-t", string(table), string(position), string(chain)}, rulespec...)
		err = ipt.run(createArgs)
		if err != nil {
			return false, err
		}
		return false, nil
	}

	return true, nil
}

func (ipt *IPTables) DeleteRule(table Table, chain Chain, rulespec ...string) (bool, error) {
	ipt.Lock()
	defer ipt.Unlock()

	exists, err := ipt.check(table, chain, rulespec...)
	if err != nil {
		return false, err
	}

	if exists {
		args := append([]string{"-t", string(table), "-D", string(chain)}, rulespec...)
		err = ipt.run(args)
		if err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

func (ipt *IPTables) check(table Table, chain Chain, rulespec ...string) (bool, error) {
	args := append([]string{"-t", string(table), "-C", string(chain)}, rulespec...)

	err := ipt.run(args)
	var exitErr *CmdError
	if err != nil && strings.Contains(err.Error(), "Bad rule") {
		return false, nil
	} else if errors.As(err, &exitErr) {
		if exitErr.ExitCode() == 2 { // Exit code 2 indicates that a dependency does not exist
			return false, nil
		}
		return false, err
	} else if err != nil {
		return false, err
	}
	return true, err
}

func (ipt *IPTables) checkVersion() error {
	args := []string{"--version"}

	stdout := &bytes.Buffer{}
	err := ipt.runWithOutput(args, stdout)
	if err != nil {
		return err
	}

	versionOutput := strings.TrimSpace(stdout.String())
	if versionOutput == "" {
		return fmt.Errorf("failed to determine iptables version for %q: Output is empty", ipt.path)
	}
	// Expected output format: "iptables vX.X.X ..."
	parts := strings.Fields(versionOutput)
	if len(parts) < 2 {
		return fmt.Errorf("failed to determine iptables version for %q: Unexpected output format %q", ipt.path, versionOutput)
	}
	version := parts[1]

	if semver.Compare(version, RequiredMinVersion) < 0 {
		return fmt.Errorf("executable %q (%q) does not satisfy minimum required version %q", ipt.path, version, RequiredMinVersion)
	}

	return nil
}

func (ipt *IPTables) run(args []string) error {
	return ipt.runWithOutput(args, nil)
}

func (ipt *IPTables) runWithOutput(args []string, stdout io.Writer) error {
	// Prepend the command path to arguments (as exec.Cmd expects the first argument to be the command itself)
	args = append([]string{ipt.path}, args...)

	// Wait for the command to complete
	args = append(args, "--wait")

	stderr := &bytes.Buffer{}
	cmd := exec.Cmd{
		Path:   ipt.path,
		Args:   args,
		Stdout: stdout,
		Stderr: stderr,
		Env: []string{
			fmt.Sprintf("PATH=%s", os.Getenv("PATH")),
			"LANG=C", // Ensure consistent output in English
			"LC_ALL=C",
		},
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
