package collect

import (
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Memory reports RAM and swap from /proc/meminfo (bytes and percentages).
type Memory struct{ ProcRoot string }

// Name implements Collector.
func (m *Memory) Name() string { return "memory" }

// Collect implements Collector.
func (m *Memory) Collect(now time.Time) ([]protocol.Sample, error) {
	lines, err := readLines(procPath(m.ProcRoot, "meminfo"))
	if err != nil {
		return nil, err
	}
	kv := map[string]uint64{}
	for _, l := range lines {
		k, v, ok := strings.Cut(l, ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		kv[k] = parseU(f[0]) * 1024
	}
	total, avail := kv["MemTotal"], kv["MemAvailable"]
	if avail == 0 {
		avail = kv["MemFree"] + kv["Buffers"] + kv["Cached"]
	}
	used := total - min(avail, total)
	out := []protocol.Sample{
		sample(now, "mem.total", "", float64(total)),
		sample(now, "mem.used", "", float64(used)),
		sample(now, "mem.available", "", float64(avail)),
		sample(now, "mem.cached", "", float64(kv["Cached"]+kv["Buffers"])),
	}
	if total > 0 {
		out = append(out, sample(now, "mem.used_pct", "", round2(100*float64(used)/float64(total))))
	}
	st, sf := kv["SwapTotal"], kv["SwapFree"]
	out = append(out, sample(now, "swap.total", "", float64(st)), sample(now, "swap.used", "", float64(st-min(sf, st))))
	if st > 0 {
		out = append(out, sample(now, "swap.used_pct", "", round2(100*float64(st-sf)/float64(st))))
	} else {
		out = append(out, sample(now, "swap.used_pct", "", 0))
	}
	return out, nil
}
