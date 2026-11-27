package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// managePackages installs or removes packages. Every operation is simulated first;
// if the transaction would remove a protected package (directly or as a dependency)
// it is refused before anything changes.
func (e *Executor) managePackages(ctx context.Context, pm string, cmd protocol.Command) ([]byte, []protocol.PackageChange, error) {
	var pkgs []string
	purge := false
	if cmd.Action == protocol.ActionInstallPackages {
		var p protocol.InstallPackagesParams
		_ = json.Unmarshal(cmd.Params, &p)
		pkgs = p.Packages
	} else {
		var p protocol.RemovePackagesParams
		_ = json.Unmarshal(cmd.Params, &p)
		pkgs, purge = p.Packages, p.Purge
	}
	install := cmd.Action == protocol.ActionInstallPackages
	var tool string
	var args, simArgs []string
	var parse func(string) []protocol.PackageChange
	switch pm {
	case "dpkg":
		_, _ = e.run(ctx, "apt-get", "update", "-qq")
		verb := "install"
		if !install {
			verb = "remove"
			if purge {
				verb = "purge"
			}
		}
		tool = "apt-get"
		args = append(append([]string{verb}, aptEnvArgs()...), pkgs...)
		simArgs = append([]string{"-s"}, args...)
		parse = ParseAptTransaction
	case "rpm":
		tool = e.dnfTool()
		verb := "install"
		if !install {
			verb = "remove" // rpm keeps modified config files as .rpmsave; there is no purge
		}
		args = append([]string{"-y", verb, "--"}, pkgs...)
		simArgs = append([]string{"--assumeno", verb, "--"}, pkgs...)
		parse = ParseDnfTransaction
	case "apk":
		_, _ = e.run(ctx, "apk", "update", "-q")
		tool = "apk"
		verb := []string{"add"}
		if !install {
			verb = []string{"del"}
			if purge {
				verb = append(verb, "--purge")
			}
		}
		args = append(append([]string{}, verb...), pkgs...)
		simArgs = append(append(append([]string{}, verb...), "-s"), pkgs...)
		parse = ParseAPKUpgrade
	default:
		return nil, nil, errors.New("no supported package manager")
	}

	simOut, simErr := e.run(ctx, tool, simArgs...)
	changes := parse(string(simOut))
	// dnf --assumeno always exits non-zero; judge it by its output.
	dnfAborted := pm == "rpm" && (len(changes) > 0 || strings.Contains(string(simOut), "Operation aborted"))
	if simErr != nil && !dnfAborted {
		return simOut, changes, fmt.Errorf("%s simulate: %w", tool, simErr)
	}
	if bad := protectedRemovals(changes); len(bad) > 0 {
		return simOut, changes, fmt.Errorf("refused: the transaction would remove protected packages: %s", strings.Join(bad, ", "))
	}
	if !install {
		if missing := notInTransaction(pkgs, changes); len(missing) > 0 {
			return simOut, changes, fmt.Errorf("not installed: %s", strings.Join(missing, ", "))
		}
	}
	if cmd.DryRun {
		return simOut, changes, nil
	}
	out, err := e.run(ctx, tool, args...)
	if pm != "dpkg" {
		if real := parse(string(out)); len(real) > 0 {
			changes = real
		}
	}
	return out, changes, err
}

// protectedRemovals lists removed packages that must never be removed.
func protectedRemovals(changes []protocol.PackageChange) []string {
	var out []string
	for _, c := range changes {
		if c.To == "" && protocol.ProtectedPackage(c.Name) {
			out = append(out, c.Name)
		}
	}
	return out
}

// notInTransaction returns requested packages that the removal does not touch.
func notInTransaction(pkgs []string, changes []protocol.PackageChange) []string {
	removed := map[string]bool{}
	for _, c := range changes {
		if c.To == "" {
			removed[c.Name] = true
		}
	}
	var out []string
	for _, p := range pkgs {
		if !removed[p] {
			out = append(out, p)
		}
	}
	return out
}

// "Remv nano [7.2-1ubuntu0.1]" / "Purg nano [7.2-1ubuntu0.1]"
var aptRemoveRe = regexp.MustCompile(`^(?:Remv|Purg) (\S+)(?: \[([^\]]+)\])?`)

// ParseAptTransaction parses `apt-get -s install|remove|purge` output: installed and
// upgraded packages carry To; removed packages carry only From.
func ParseAptTransaction(out string) []protocol.PackageChange {
	changes := changesFromApt([]byte(out))
	for _, l := range strings.Split(out, "\n") {
		if m := aptRemoveRe.FindStringSubmatch(strings.TrimSpace(l)); m != nil {
			name, _, _ := strings.Cut(m[1], ":") // multiarch "libfoo:i386"
			changes = append(changes, protocol.PackageChange{Name: name, From: m[2]})
		}
	}
	return changes
}
