package collect

import (
	"os"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

type ioCounters struct{ rd, rdSect, wr, wrSect, ioMs uint64 }

// DiskIO reports per-device throughput, IOPS and utilisation from /proc/diskstats.
type DiskIO struct {
	ProcRoot string
	SysRoot  string // defaults to /sys; used to skip partitions
	prev     map[string]ioCounters
	prevAt   time.Time
}

// Name implements Collector.
func (d *DiskIO) Name() string { return "diskio" }

func (d *DiskIO) isWholeDisk(name string) bool {
	for _, p := range []string{"loop", "ram", "zram", "sr", "fd"} {
		if strings.HasPrefix(name, p) {
			return false
		}
	}
	sys := d.SysRoot
	if sys == "" {
		sys = "/sys"
	}
	if _, err := os.Stat(sys + "/block/" + name); err == nil {
		return true
	} else if !os.IsNotExist(err) {
		return true
	}
	// /sys not available (fixtures): accept dm-* and names not ending in a digit after a letter disk name
	if strings.HasPrefix(name, "dm-") || strings.HasPrefix(name, "nvme") && !strings.Contains(name, "p") {
		return true
	}
	last := name[len(name)-1]
	return last < '0' || last > '9'
}

// Collect implements Collector.
func (d *DiskIO) Collect(now time.Time) ([]protocol.Sample, error) {
	lines, err := readLines(procPath(d.ProcRoot, "diskstats"))
	if err != nil {
		return nil, err
	}
	cur := map[string]ioCounters{}
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) < 14 || !d.isWholeDisk(f[2]) {
			continue
		}
		cur[f[2]] = ioCounters{parseU(f[3]), parseU(f[5]), parseU(f[7]), parseU(f[9]), parseU(f[12])}
	}
	var out []protocol.Sample
	if d.prev != nil {
		dt := now.Sub(d.prevAt).Seconds()
		for name, c := range cur {
			p, ok := d.prev[name]
			if !ok {
				continue
			}
			lb := Labels("dev", name)
			util := rateOf(p.ioMs, c.ioMs, dt) / 10 // ms busy per s → %
			out = append(out,
				sample(now, "diskio.read_bps", lb, round2(rateOf(p.rdSect, c.rdSect, dt)*512)),
				sample(now, "diskio.write_bps", lb, round2(rateOf(p.wrSect, c.wrSect, dt)*512)),
				sample(now, "diskio.read_iops", lb, round2(rateOf(p.rd, c.rd, dt))),
				sample(now, "diskio.write_iops", lb, round2(rateOf(p.wr, c.wr, dt))),
				sample(now, "diskio.util_pct", lb, round2(min(util, 100))),
			)
		}
	}
	d.prev, d.prevAt = cur, now
	return out, nil
}
