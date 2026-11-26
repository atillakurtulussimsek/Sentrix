package collect

import (
	"strconv"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

type cpuTimes struct{ user, nice, system, idle, iowait, irq, softirq, steal uint64 }

func (c cpuTimes) total() uint64 {
	return c.user + c.nice + c.system + c.idle + c.iowait + c.irq + c.softirq + c.steal
}

// CPU reports total and per-core utilisation, iowait and steal from /proc/stat,
// plus load averages, process counts and uptime.
type CPU struct {
	ProcRoot string
	prev     map[string]cpuTimes
}

// Name implements Collector.
func (c *CPU) Name() string { return "cpu" }

// Collect implements Collector.
func (c *CPU) Collect(now time.Time) ([]protocol.Sample, error) {
	lines, err := readLines(procPath(c.ProcRoot, "stat"))
	if err != nil {
		return nil, err
	}
	cur := map[string]cpuTimes{}
	var out []protocol.Sample
	for _, l := range lines {
		f := strings.Fields(l)
		if len(f) == 0 {
			continue
		}
		switch {
		case strings.HasPrefix(f[0], "cpu") && len(f) >= 9:
			cur[f[0]] = cpuTimes{parseU(f[1]), parseU(f[2]), parseU(f[3]), parseU(f[4]), parseU(f[5]), parseU(f[6]), parseU(f[7]), parseU(f[8])}
		case f[0] == "procs_running" && len(f) > 1:
			out = append(out, sample(now, "system.procs_running", "", float64(parseU(f[1]))))
		case f[0] == "procs_blocked" && len(f) > 1:
			out = append(out, sample(now, "system.procs_blocked", "", float64(parseU(f[1]))))
		}
	}
	if c.prev != nil {
		for name, t := range cur {
			p, ok := c.prev[name]
			if !ok {
				continue
			}
			if t.total() <= p.total() || t.idle < p.idle || t.iowait < p.iowait {
				continue // counter reset (e.g. CPU hotplug)
			}
			dt := float64(t.total() - p.total())
			busy := max(0, dt-float64(t.idle-p.idle)-float64(t.iowait-p.iowait))
			if name == "cpu" {
				out = append(out,
					sample(now, "cpu.usage", "", round2(100*busy/dt)),
					sample(now, "cpu.user", "", round2(100*float64((t.user+t.nice)-(p.user+p.nice))/dt)),
					sample(now, "cpu.system", "", round2(100*float64((t.system+t.irq+t.softirq)-(p.system+p.irq+p.softirq))/dt)),
					sample(now, "cpu.iowait", "", round2(100*float64(t.iowait-p.iowait)/dt)),
					sample(now, "cpu.steal", "", round2(100*float64(t.steal-p.steal)/dt)),
				)
			} else {
				out = append(out, sample(now, "cpu.usage", Labels("core", strings.TrimPrefix(name, "cpu")), round2(100*busy/dt)))
			}
		}
	}
	c.prev = cur
	out = append(out, sample(now, "cpu.cores", "", float64(len(cur)-1)))

	if l, err := readLines(procPath(c.ProcRoot, "loadavg")); err == nil && len(l) > 0 {
		f := strings.Fields(l[0])
		if len(f) >= 4 {
			for i, n := range []string{"load.1", "load.5", "load.15"} {
				v, _ := strconv.ParseFloat(f[i], 64)
				out = append(out, sample(now, n, "", v))
			}
			if _, total, ok := strings.Cut(f[3], "/"); ok {
				out = append(out, sample(now, "system.procs", "", float64(parseU(total))))
			}
		}
	}
	if l, err := readLines(procPath(c.ProcRoot, "uptime")); err == nil && len(l) > 0 {
		if f := strings.Fields(l[0]); len(f) > 0 {
			v, _ := strconv.ParseFloat(f[0], 64)
			out = append(out, sample(now, "system.uptime", "", float64(int64(v))))
		}
	}
	return out, nil
}
