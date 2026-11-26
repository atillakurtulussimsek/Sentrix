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

const dpkgFormat = `${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\t${source:Package}\t${source:Version}\n`

func (c *Collector) dpkgPackages(ctx context.Context) ([]protocol.Package, error) {
	out, err := c.Run(ctx, "dpkg-query", "-W", "-f="+dpkgFormat)
	if err != nil {
		return nil, fmt.Errorf("dpkg-query: %w", err)
	}
	return ParseDpkgQuery(string(out)), nil
}

// ParseDpkgQuery parses dpkgFormat output, keeping installed ("ii"/"hi") packages.
func ParseDpkgQuery(s string) []protocol.Package {
	var out []protocol.Package
	for _, l := range strings.Split(s, "\n") {
		f := strings.Split(l, "\t")
		if len(f) < 6 {
			continue
		}
		st := strings.TrimSpace(f[0])
		if len(st) < 2 || st[1] != 'i' {
			continue
		}
		p := protocol.Package{Name: f[1], Version: f[2], Arch: f[3], SourceName: f[4], SourceVer: f[5]}
		if p.SourceName == "" {
			p.SourceName = p.Name
		}
		if p.SourceVer == "" {
			p.SourceVer = p.Version
		}
		out = append(out, p)
	}
	return out
}

func (c *Collector) aptUpdates(ctx context.Context) ([]protocol.Update, error) {
	if c.RefreshMetadata {
		if _, err := c.Run(ctx, "apt-get", "update", "-qq"); err != nil {
			// keep going with cached lists
			_ = err
		}
	}
	out, err := c.Run(ctx, "apt-get", "-s", "-q", "-o", "Debug::NoLocking=true", "dist-upgrade")
	var ee *exec.ExitError
	if err != nil && !errors.As(err, &ee) {
		return nil, fmt.Errorf("apt-get -s dist-upgrade: %w", err)
	}
	return ParseAptSimulate(string(out)), nil
}

// Inst libssl3 [3.0.11-1~deb12u2] (3.0.15-1~deb12u1 Debian-Security:12/stable-security [amd64])
// Inst tzdata (2024a-0+deb12u1 Debian:12.7/stable [all])
var aptInstRe = regexp.MustCompile(`^Inst (\S+)(?: \[([^\]]+)\])? \((\S+) ([^\[]*?)(?: \[[^\]]+\])?\)`)

// ParseAptSimulate parses `apt-get -s dist-upgrade` output. An update is security-relevant
// when any of its origins is a security archive (Debian-Security, *-security pockets).
func ParseAptSimulate(s string) []protocol.Update {
	var out []protocol.Update
	for _, l := range strings.Split(s, "\n") {
		m := aptInstRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		origin := strings.TrimSpace(m[4])
		u := protocol.Update{Name: m[1], CurrentVer: m[2], NewVer: m[3], Origin: origin}
		lo := strings.ToLower(origin)
		u.Security = strings.Contains(lo, "-security") || strings.Contains(lo, "debian-security")
		out = append(out, u)
	}
	return out
}
