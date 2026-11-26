package collect

import (
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// FSStat is the result of statfs for one mount.
type FSStat struct {
	Total, Free, Avail uint64
	Inodes, InodesFree uint64
}

// Disk reports usage and inode usage per real filesystem mount.
type Disk struct {
	ProcRoot string
	// Statfs is replaceable for tests; defaults to the platform implementation.
	Statfs func(path string) (FSStat, error)
}

// Name implements Collector.
func (d *Disk) Name() string { return "disk" }

var pseudoFS = map[string]bool{
	"proc": true, "sysfs": true, "devtmpfs": true, "devpts": true, "tmpfs": true, "cgroup": true, "cgroup2": true,
	"pstore": true, "bpf": true, "securityfs": true, "debugfs": true, "tracefs": true, "configfs": true,
	"fusectl": true, "mqueue": true, "hugetlbfs": true, "autofs": true, "binfmt_misc": true, "overlay": true,
	"squashfs": true, "nsfs": true, "rpc_pipefs": true, "efivarfs": true, "ramfs": true, "fuse.lxcfs": true,
	"selinuxfs": true, "nfsd": true, "shm": true, "iso9660": true,
}

// Mounts returns real mounts (mountpoint → device) from <procRoot>/self/mounts.
func Mounts(procRoot string) (map[string]string, error) {
	lines, err := readLines(procPath(procRoot, "self", "mounts"))
	if err != nil {
		lines, err = readLines(procPath(procRoot, "mounts"))
		if err != nil {
			return nil, err
		}
	}
	out := map[string]string{}
	seenDev := map[string]bool{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 3 || pseudoFS[f[2]] {
			continue
		}
		mp := strings.ReplaceAll(f[1], `\040`, " ")
		if strings.HasPrefix(mp, "/var/lib/docker/") || strings.HasPrefix(mp, "/snap/") || strings.HasPrefix(mp, "/run/") {
			continue
		}
		if seenDev[f[0]] && f[0] != "none" {
			continue // bind mounts of the same device
		}
		seenDev[f[0]] = true
		out[mp] = f[0]
	}
	return out, nil
}

// Collect implements Collector.
func (d *Disk) Collect(now time.Time) ([]protocol.Sample, error) {
	mounts, err := Mounts(d.ProcRoot)
	if err != nil {
		return nil, err
	}
	statfs := d.Statfs
	if statfs == nil {
		statfs = platformStatfs
	}
	var out []protocol.Sample
	for mp := range mounts {
		st, err := statfs(mp)
		if err != nil || st.Total == 0 {
			continue
		}
		lb := Labels("mount", mp)
		used := st.Total - st.Free
		// Like df: percentage relative to space available to unprivileged users.
		pct := 100 * float64(used) / float64(used+st.Avail)
		out = append(out,
			sample(now, "disk.total_bytes", lb, float64(st.Total)),
			sample(now, "disk.used_bytes", lb, float64(used)),
			sample(now, "disk.used_pct", lb, round2(pct)),
		)
		if st.Inodes > 0 {
			out = append(out, sample(now, "disk.inodes_used_pct", lb, round2(100*float64(st.Inodes-st.InodesFree)/float64(st.Inodes))))
		}
	}
	return out, nil
}
