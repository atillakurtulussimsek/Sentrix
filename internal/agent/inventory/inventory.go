// Package inventory collects what is installed on a host: OS, packages, available
// updates (with security classification), listening ports and container images.
package inventory

import (
	"bufio"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent/collect"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Collector gathers inventory. Root and ProcRoot allow fixture-based tests.
type Collector struct {
	Root     string // "/" in production
	ProcRoot string
	Run      collect.Runner
	// RefreshMetadata runs `apt-get update` / `apk update` before computing updates.
	RefreshMetadata bool
	Docker          *collect.Docker
}

func (c *Collector) path(p string) string { return filepath.Join(c.Root, p) }

// Collect gathers a full inventory; partial failures are reported in Errors.
func (c *Collector) Collect(ctx context.Context) protocol.Inventory {
	inv := protocol.Inventory{CollectedAt: time.Now().UTC()}
	inv.OS = c.OSInfo(ctx)
	var err error
	switch {
	case exists(c.path("var/lib/dpkg/status")):
		inv.PackageManager = "dpkg"
		inv.Packages, err = c.dpkgPackages(ctx)
		if err == nil {
			inv.Updates, err = c.aptUpdates(ctx)
		}
	case exists(c.path("lib/apk/db/installed")):
		inv.PackageManager = "apk"
		inv.Packages, err = ParseAPKInstalled(c.path("lib/apk/db/installed"))
		if err == nil {
			inv.Updates, err = c.apkUpdates(ctx)
		}
	case exists(c.path("var/lib/rpm")) || exists(c.path("usr/lib/sysimage/rpm")):
		inv.PackageManager = "rpm"
		inv.Packages, err = c.rpmPackages(ctx)
		if err == nil {
			inv.Updates, err = c.dnfUpdates(ctx)
		}
	default:
		inv.Errors = append(inv.Errors, "no supported package manager found")
	}
	if err != nil {
		inv.Errors = append(inv.Errors, err.Error())
	}
	inv.Ports = ListeningPorts(c.ProcRoot)
	if c.Docker != nil && c.Docker.Available() {
		inv.Images = c.Docker.Images(ctx)
	}
	return inv
}

// OSInfo reads os-release, kernel, architecture and virtualization type.
func (c *Collector) OSInfo(ctx context.Context) protocol.OSInfo {
	var o protocol.OSInfo
	for _, p := range []string{"etc/os-release", "usr/lib/os-release"} {
		if kv, err := ParseOSRelease(c.path(p)); err == nil {
			o.ID, o.VersionID, o.PrettyName = kv["ID"], kv["VERSION_ID"], kv["PRETTY_NAME"]
			o.Codename = kv["VERSION_CODENAME"]
			if o.Codename == "" {
				o.Codename = kv["UBUNTU_CODENAME"]
			}
			break
		}
	}
	// Alpine's VERSION_ID is the full point release; Debian point release is in /etc/debian_version.
	if b, err := os.ReadFile(filepath.Join(c.ProcRoot, "sys/kernel/osrelease")); err == nil {
		o.Kernel = strings.TrimSpace(string(b))
	}
	o.Arch = unameArch()
	o.Virtualization = "unknown"
	if c.Run != nil {
		if out, err := c.Run(ctx, "systemd-detect-virt"); err == nil || len(out) > 0 {
			if v := strings.TrimSpace(string(out)); v != "" {
				o.Virtualization = v
			}
		}
	}
	if o.Virtualization == "unknown" {
		if exists(c.path(".dockerenv")) || exists(c.path("run/.containerenv")) {
			o.Virtualization = "container"
		}
	}
	return o
}

func unameArch() string {
	switch runtime.GOARCH {
	case "amd64":
		return "x86_64"
	case "arm64":
		return "aarch64"
	}
	return runtime.GOARCH
}

// ParseOSRelease parses an os-release file.
func ParseOSRelease(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	kv := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		k, v, ok := strings.Cut(strings.TrimSpace(sc.Text()), "=")
		if !ok || strings.HasPrefix(k, "#") {
			continue
		}
		kv[k] = strings.Trim(v, `"'`)
	}
	return kv, sc.Err()
}

func exists(p string) bool {
	_, err := os.Stat(p)
	return err == nil
}
