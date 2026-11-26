package inventory

import (
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

const rpmFormat = `%{NAME}\t%{EPOCHNUM}\t%{VERSION}\t%{RELEASE}\t%{ARCH}\t%{SOURCERPM}\n`

func (c *Collector) rpmPackages(ctx context.Context) ([]protocol.Package, error) {
	out, err := c.Run(ctx, "rpm", "-qa", "--qf", rpmFormat)
	if err != nil {
		return nil, fmt.Errorf("rpm -qa: %w", err)
	}
	return ParseRPMQuery(string(out)), nil
}

// EVRString formats epoch:version-release, omitting a zero epoch.
func EVRString(epoch, ver, rel string) string {
	s := ver
	if rel != "" {
		s += "-" + rel
	}
	if epoch != "" && epoch != "0" && epoch != "(none)" {
		s = epoch + ":" + s
	}
	return s
}

// srpmRe splits "openssl-3.0.7-27.el9.src.rpm" into name and version-release.
var srpmRe = regexp.MustCompile(`^(.+)-([^-]+)-([^-]+)\.src\.rpm$`)

// ParseRPMQuery parses rpmFormat output. gpg-pubkey pseudo packages are skipped.
func ParseRPMQuery(s string) []protocol.Package {
	var out []protocol.Package
	for _, l := range strings.Split(s, "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 6 || f[0] == "gpg-pubkey" {
			continue
		}
		p := protocol.Package{Name: f[0], Version: EVRString(f[1], f[2], f[3]), Arch: f[4], SourceName: f[0], SourceVer: EVRString(f[1], f[2], f[3])}
		if m := srpmRe.FindStringSubmatch(f[5]); m != nil {
			p.SourceName = m[1]
			p.SourceVer = EVRString(f[1], m[2], m[3])
		}
		out = append(out, p)
	}
	return out
}

func (c *Collector) dnfUpdates(ctx context.Context) ([]protocol.Update, error) {
	tool := "dnf"
	if _, err := exec.LookPath("dnf"); err != nil {
		tool = "yum"
	}
	// check-update exits 100 when updates are available.
	out, err := c.Run(ctx, tool, "-q", "check-update")
	var ee *exec.ExitError
	updatesAvailable := errors.As(err, &ee) && ee.ExitCode() == 100
	if err != nil && !updatesAvailable {
		return nil, fmt.Errorf("%s check-update: %w", tool, err)
	}
	ups := ParseDnfCheckUpdate(string(out))
	sec, err := c.Run(ctx, tool, "-q", "updateinfo", "list", "--updates", "--security")
	if err == nil {
		secNames := ParseDnfUpdateinfo(string(sec))
		for i := range ups {
			if secNames[ups[i].Name] {
				ups[i].Security = true
			}
		}
	}
	// current versions
	if cur, err := c.rpmPackages(ctx); err == nil {
		m := map[string]string{}
		for _, p := range cur {
			m[p.Name] = p.Version
		}
		for i := range ups {
			ups[i].CurrentVer = m[ups[i].Name]
		}
	}
	return ups, nil
}

// ParseDnfCheckUpdate parses `dnf -q check-update` ("name.arch  [epoch:]ver-rel  repo").
// Lines after "Obsoleting Packages" are ignored.
func ParseDnfCheckUpdate(s string) []protocol.Update {
	var out []protocol.Update
	seen := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		if strings.HasPrefix(l, "Obsoleting") || strings.HasPrefix(l, "Security:") {
			break
		}
		f := strings.Fields(l)
		if len(f) != 3 || strings.HasPrefix(l, " ") {
			continue
		}
		i := strings.LastIndexByte(f[0], '.')
		if i <= 0 {
			continue
		}
		name := f[0][:i]
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, protocol.Update{Name: name, NewVer: f[1], Origin: f[2]})
	}
	return out
}

// RLSA-2024:3501 Important/Sec. openssl-1:3.0.7-27.el9.x86_64
var updateinfoRe = regexp.MustCompile(`^\S+\s+\S+/Sec\.\s+(\S+)$`)

// ParseDnfUpdateinfo returns package names with pending security advisories.
func ParseDnfUpdateinfo(s string) map[string]bool {
	out := map[string]bool{}
	for _, l := range strings.Split(s, "\n") {
		m := updateinfoRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		if n := nevraName(m[1]); n != "" {
			out[n] = true
		}
	}
	return out
}

// nevraName extracts the name from name-[epoch:]version-release.arch.
func nevraName(nevra string) string {
	s := nevra
	if i := strings.LastIndexByte(s, '.'); i > 0 {
		s = s[:i] // arch
	}
	for k := 0; k < 2; k++ { // release, version
		i := strings.LastIndexByte(s, '-')
		if i <= 0 {
			return ""
		}
		s = s[:i]
	}
	return s
}
