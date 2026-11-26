// Package executor runs the agent's closed set of typed actions. It never executes a
// command string received from the server: every action maps to a fixed program with
// fixed arguments, and the only variable inputs (package and unit names) are validated
// against strict patterns and passed as separate argv elements after "--" where the
// tool supports it.
package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent/collect"
	"github.com/atillakurtulussimsek/Sentrix/internal/agent/inventory"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Executor executes validated commands.
type Executor struct {
	Run           collect.Runner // runs fixed programs; replaced in tests
	Inventory     *inventory.Collector
	Reboot        *collect.RebootCheck
	AllowPatching bool
	// SendInventory uploads a fresh inventory (after patching / refresh).
	SendInventory func(ctx context.Context) error
	// ScheduleReboot is called after the result of a reboot command has been reported.
	ScheduleReboot func(delay time.Duration)
	// PackageManager overrides detection (tests).
	PackageManager string
	Root           string
}

const maxOutput = 64 << 10

// AllowedPrograms is the complete list of programs the executor may start.
var AllowedPrograms = map[string]bool{
	"apt-get": true, "dnf": true, "yum": true, "apk": true, "systemctl": true, "shutdown": true,
}

func (e *Executor) pkgManager() string {
	if e.PackageManager != "" {
		return e.PackageManager
	}
	root := e.Root
	if root == "" {
		root = "/"
	}
	switch {
	case exists(filepath.Join(root, "var/lib/dpkg/status")):
		return "dpkg"
	case exists(filepath.Join(root, "lib/apk/db/installed")):
		return "apk"
	case exists(filepath.Join(root, "var/lib/rpm")), exists(filepath.Join(root, "usr/lib/sysimage/rpm")):
		return "rpm"
	}
	return ""
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}

// run executes an allow-listed program; anything else is refused.
func (e *Executor) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if !AllowedPrograms[name] {
		return nil, fmt.Errorf("program %q is not allowed", name)
	}
	return e.Run(ctx, name, args...)
}

// Execute validates and runs one command, returning its result.
func (e *Executor) Execute(ctx context.Context, cmd protocol.Command) protocol.CommandResult {
	res := protocol.CommandResult{ID: cmd.ID, StartedAt: time.Now().UTC()}
	finish := func(status string, out []byte, err error) protocol.CommandResult {
		res.Status, res.FinishedAt = status, time.Now().UTC()
		res.Output = truncate(string(out))
		if err != nil {
			res.Error = err.Error()
		}
		return res
	}
	if err := cmd.Validate(); err != nil {
		return finish(protocol.StatusRejected, nil, err)
	}
	mutating := cmd.Action != protocol.ActionRefreshInventory && cmd.Action != protocol.ActionScan
	if mutating && !cmd.DryRun && !e.AllowPatching {
		return finish(protocol.StatusRejected, nil, errors.New("patching is disabled on this agent (allow_patching: false)"))
	}
	switch cmd.Action {
	case protocol.ActionRefreshInventory, protocol.ActionScan:
		if e.SendInventory == nil {
			return finish(protocol.StatusFailed, nil, errors.New("inventory not available"))
		}
		if err := e.SendInventory(ctx); err != nil {
			return finish(protocol.StatusFailed, nil, err)
		}
		return finish(protocol.StatusOK, []byte("inventory sent"), nil)
	case protocol.ActionRestartService:
		var p protocol.RestartServiceParams
		_ = json.Unmarshal(cmd.Params, &p)
		if cmd.DryRun {
			return finish(protocol.StatusOK, []byte("would run: systemctl restart -- "+p.Name), nil)
		}
		out, err := e.run(ctx, "systemctl", "restart", "--", p.Name)
		if err != nil {
			return finish(protocol.StatusFailed, out, err)
		}
		return finish(protocol.StatusOK, out, nil)
	case protocol.ActionReboot:
		var p protocol.RebootParams
		_ = json.Unmarshal(cmd.Params, &p)
		if cmd.DryRun {
			return finish(protocol.StatusOK, []byte("would reboot"), nil)
		}
		if e.ScheduleReboot != nil {
			e.ScheduleReboot(time.Duration(p.DelaySeconds) * time.Second)
		}
		return finish(protocol.StatusOK, []byte("reboot scheduled"), nil)
	}
	// patch actions
	return e.patch(ctx, cmd, res)
}

// RebootNow reboots the host (called by the agent after reporting the result).
func (e *Executor) RebootNow(ctx context.Context, delay time.Duration) error {
	if delay <= 0 {
		_, err := e.run(ctx, "systemctl", "reboot")
		return err
	}
	mins := int((delay + time.Minute - 1) / time.Minute)
	_, err := e.run(ctx, "shutdown", "-r", fmt.Sprintf("+%d", mins), "Sentrix scheduled reboot")
	return err
}

func (e *Executor) patch(ctx context.Context, cmd protocol.Command, res protocol.CommandResult) protocol.CommandResult {
	var pkgs []string
	if cmd.Action == protocol.ActionPatchPackages {
		var p protocol.PatchPackagesParams
		_ = json.Unmarshal(cmd.Params, &p)
		pkgs = p.Packages
	}
	pm := e.pkgManager()
	var out []byte
	var changes []protocol.PackageChange
	var err error
	switch pm {
	case "dpkg":
		out, changes, err = e.patchApt(ctx, cmd.Action, pkgs, cmd.DryRun)
	case "rpm":
		out, changes, err = e.patchDnf(ctx, cmd.Action, pkgs, cmd.DryRun)
	case "apk":
		out, changes, err = e.patchApk(ctx, cmd.Action, pkgs, cmd.DryRun)
	default:
		err = errors.New("no supported package manager")
	}
	res.Output, res.Changes, res.FinishedAt = truncate(string(out)), changes, time.Now().UTC()
	if err != nil {
		res.Status, res.Error = protocol.StatusFailed, err.Error()
		return res
	}
	res.Status = protocol.StatusOK
	if !cmd.DryRun {
		if e.SendInventory != nil {
			if ierr := e.SendInventory(ctx); ierr != nil {
				res.Output += "\n[inventory upload failed: " + ierr.Error() + "]"
			}
		}
		if e.Reboot != nil {
			res.RebootReq = e.Reboot.Check(ctx).Required
		}
	}
	return res
}

func aptEnvArgs() []string {
	return []string{"-y", "-q", "-o", "Dpkg::Options::=--force-confdef", "-o", "Dpkg::Options::=--force-confold"}
}

func (e *Executor) securityUpdates(ctx context.Context) ([]protocol.Update, error) {
	if e.Inventory == nil {
		return nil, errors.New("inventory collector not configured")
	}
	inv := e.Inventory.Collect(ctx)
	if len(inv.Errors) > 0 && len(inv.Updates) == 0 {
		return nil, errors.New(strings.Join(inv.Errors, "; "))
	}
	var sec []protocol.Update
	for _, u := range inv.Updates {
		if u.Security {
			sec = append(sec, u)
		}
	}
	return sec, nil
}

func names(us []protocol.Update) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Name)
	}
	return out
}

func (e *Executor) patchApt(ctx context.Context, action protocol.Action, pkgs []string, dry bool) ([]byte, []protocol.PackageChange, error) {
	_, _ = e.run(ctx, "apt-get", "update", "-qq")
	var args []string
	switch action {
	case protocol.ActionPatchAll:
		args = append([]string{"upgrade", "--with-new-pkgs"}, aptEnvArgs()...)
	case protocol.ActionPatchSecurityOnly:
		sec, err := e.securityUpdates(ctx)
		if err != nil {
			return nil, nil, err
		}
		if len(sec) == 0 {
			return []byte("no security updates pending"), nil, nil
		}
		pkgs = names(sec)
		fallthrough
	case protocol.ActionPatchPackages:
		args = append(append([]string{"install", "--only-upgrade"}, aptEnvArgs()...), pkgs...)
	}
	sim := append([]string{"-s"}, args...)
	simOut, err := e.run(ctx, "apt-get", sim...)
	if err != nil {
		return simOut, nil, fmt.Errorf("apt-get simulate: %w", err)
	}
	changes := changesFromApt(simOut)
	if dry {
		return simOut, changes, nil
	}
	out, err := e.run(ctx, "apt-get", args...)
	return out, changes, err
}

func changesFromApt(sim []byte) []protocol.PackageChange {
	var out []protocol.PackageChange
	for _, u := range inventory.ParseAptSimulate(string(sim)) {
		out = append(out, protocol.PackageChange{Name: u.Name, From: u.CurrentVer, To: u.NewVer})
	}
	return out
}

func (e *Executor) dnfTool() string {
	if _, err := e.Run(context.Background(), "dnf", "--version"); err == nil {
		return "dnf"
	}
	return "yum"
}

// dnf transaction lines: " openssl-libs   x86_64   1:3.0.7-27.el9   baseos   2.1 M"
var dnfTxRe = regexp.MustCompile(`^\s+(\S+)\s+(x86_64|aarch64|noarch|i686|ppc64le|s390x)\s+(\S+)\s+\S+\s+[\d.]+\s+[kMG]$`)

// ParseDnfTransaction extracts package NEVRs from the "Upgrading:"/"Installing:" sections
// of a dnf transaction summary.
func ParseDnfTransaction(out string) []protocol.PackageChange {
	var res []protocol.PackageChange
	section := ""
	for _, l := range strings.Split(out, "\n") {
		t := strings.TrimSpace(l)
		switch {
		case strings.HasPrefix(t, "Upgrading:"), strings.HasPrefix(t, "Installing:"), strings.HasPrefix(t, "Installing dependencies:"), strings.HasPrefix(t, "Installing weak dependencies:"):
			section = t
			continue
		case strings.HasSuffix(t, ":") && !strings.Contains(t, " "):
			section = ""
		case strings.HasPrefix(t, "Transaction Summary"):
			return res
		}
		if section == "" {
			continue
		}
		if m := dnfTxRe.FindStringSubmatch(l); m != nil {
			res = append(res, protocol.PackageChange{Name: m[1], To: m[3]})
		}
	}
	return res
}

func (e *Executor) patchDnf(ctx context.Context, action protocol.Action, pkgs []string, dry bool) ([]byte, []protocol.PackageChange, error) {
	tool := e.dnfTool()
	args := []string{"upgrade"}
	switch action {
	case protocol.ActionPatchSecurityOnly:
		args = append(args, "--security")
	case protocol.ActionPatchPackages:
		args = append(args, "--")
		args = append(args, pkgs...)
	}
	if dry {
		out, err := e.run(ctx, tool, append([]string{"--assumeno"}, args...)...)
		// --assumeno exits 1 by design; parse what would happen
		changes := ParseDnfTransaction(string(out))
		if err != nil && len(changes) == 0 && !strings.Contains(string(out), "Nothing to do") && !strings.Contains(string(out), "Operation aborted") {
			return out, nil, fmt.Errorf("%s dry run: %w", tool, err)
		}
		return out, changes, nil
	}
	out, err := e.run(ctx, tool, append([]string{"-y"}, args...)...)
	return out, ParseDnfTransaction(string(out)), err
}

// "(1/2) Upgrading busybox (1.36.1-r15 -> 1.36.1-r20)"
var apkUpgradeRe = regexp.MustCompile(`\(\d+/\d+\) (?:Upgrading|Installing|Replacing) (\S+) \((?:(\S+) -> )?(\S+)\)`)

// ParseAPKUpgrade extracts changes from apk upgrade/add output.
func ParseAPKUpgrade(out string) []protocol.PackageChange {
	var res []protocol.PackageChange
	for _, l := range strings.Split(out, "\n") {
		if m := apkUpgradeRe.FindStringSubmatch(l); m != nil {
			res = append(res, protocol.PackageChange{Name: m[1], From: m[2], To: m[3]})
		}
	}
	return res
}

func (e *Executor) patchApk(ctx context.Context, action protocol.Action, pkgs []string, dry bool) ([]byte, []protocol.PackageChange, error) {
	_, _ = e.run(ctx, "apk", "update", "-q")
	var args []string
	switch action {
	case protocol.ActionPatchAll:
		args = []string{"upgrade"}
	case protocol.ActionPatchSecurityOnly:
		return nil, nil, errors.New("apk has no security metadata; the server sends patch_packages with the fixing packages")
	case protocol.ActionPatchPackages:
		args = append([]string{"upgrade"}, pkgs...)
	}
	if dry {
		args = append([]string{args[0], "-s"}, args[1:]...)
	}
	out, err := e.run(ctx, "apk", args...)
	return out, ParseAPKUpgrade(string(out)), err
}

func truncate(s string) string {
	if len(s) > maxOutput {
		return s[:maxOutput/2] + "\n…[truncated]…\n" + s[len(s)-maxOutput/2:]
	}
	return s
}
