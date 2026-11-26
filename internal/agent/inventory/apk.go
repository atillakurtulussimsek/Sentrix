package inventory

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// ParseAPKInstalled parses /lib/apk/db/installed.
func ParseAPKInstalled(path string) ([]protocol.Package, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []protocol.Package
	var cur protocol.Package
	flush := func() {
		if cur.Name != "" {
			if cur.SourceName == "" {
				cur.SourceName = cur.Name
			}
			cur.SourceVer = cur.Version
			out = append(out, cur)
		}
		cur = protocol.Package{}
	}
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		l := sc.Text()
		if l == "" {
			flush()
			continue
		}
		if len(l) < 2 || l[1] != ':' {
			continue
		}
		switch l[0] {
		case 'P':
			cur.Name = l[2:]
		case 'V':
			cur.Version = l[2:]
		case 'A':
			cur.Arch = l[2:]
		case 'o':
			cur.SourceName = l[2:]
		}
	}
	flush()
	return out, sc.Err()
}

func (c *Collector) apkUpdates(ctx context.Context) ([]protocol.Update, error) {
	if c.RefreshMetadata {
		_, _ = c.Run(ctx, "apk", "update", "-q")
	}
	out, err := c.Run(ctx, "apk", "list", "-u")
	if err != nil {
		return nil, fmt.Errorf("apk list -u: %w", err)
	}
	return ParseAPKListUpgradable(string(out)), nil
}

// busybox-1.36.1-r29 x86_64 {busybox} (GPL-2.0-only) [upgradable from: busybox-1.36.1-r15]
var apkUpRe = regexp.MustCompile(`^(\S+) \S+ \{[^}]*\} \([^)]*\) \[upgradable from: (\S+)\]`)

// ParseAPKListUpgradable parses `apk list -u`. apk has no security metadata; the
// server marks updates as security when they fix a matched vulnerability.
func ParseAPKListUpgradable(s string) []protocol.Update {
	var out []protocol.Update
	for _, l := range strings.Split(s, "\n") {
		m := apkUpRe.FindStringSubmatch(strings.TrimSpace(l))
		if m == nil {
			continue
		}
		name, nv := splitAPKNameVersion(m[1])
		_, cv := splitAPKNameVersion(m[2])
		out = append(out, protocol.Update{Name: name, NewVer: nv, CurrentVer: cv})
	}
	return out
}

// splitAPKNameVersion splits "name-1.2.3-r0" (version starts at the first "-<digit>"
// that is followed only by the version and -rN).
func splitAPKNameVersion(s string) (string, string) {
	// release suffix
	i := strings.LastIndex(s, "-r")
	if i <= 0 {
		return s, ""
	}
	j := strings.LastIndexByte(s[:i], '-')
	if j <= 0 {
		return s, ""
	}
	return s[:j], s[j+1:]
}
