package collect

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

const clkTck = 100 // USER_HZ on all supported Linux architectures

type procSample struct {
	name  string
	uid   string
	ticks uint64
	rss   uint64
}

// Processes computes top processes by CPU and memory from /proc/[pid].
type Processes struct {
	ProcRoot string
	prev     map[int]uint64
	prevAt   time.Time
	users    map[string]string
}

// Top returns the top-n processes by CPU and by RSS, and the process count.
func (p *Processes) Top(now time.Time, n int) (byCPU, byMem []protocol.ProcessInfo, count int) {
	entries, err := os.ReadDir(p.ProcRoot)
	if err != nil {
		return nil, nil, 0
	}
	pageSize := uint64(os.Getpagesize()) //nolint:gosec // positive
	cur := map[int]uint64{}
	var all []protocol.ProcessInfo
	dt := now.Sub(p.prevAt).Seconds()
	for _, e := range entries {
		pid, err := strconv.Atoi(e.Name())
		if err != nil {
			continue
		}
		s, ok := readProc(filepath.Join(p.ProcRoot, e.Name()), pageSize)
		if !ok {
			continue
		}
		count++
		cur[pid] = s.ticks
		info := protocol.ProcessInfo{PID: pid, Name: s.name, User: p.userName(s.uid), RSSBytes: s.rss}
		if prev, ok := p.prev[pid]; ok && dt > 0 && s.ticks >= prev {
			info.CPUPercent = round2(100 * float64(s.ticks-prev) / clkTck / dt)
		}
		all = append(all, info)
	}
	p.prev, p.prevAt = cur, now
	sort.Slice(all, func(i, j int) bool { return all[i].CPUPercent > all[j].CPUPercent })
	byCPU = append(byCPU, all[:min(n, len(all))]...)
	sort.Slice(all, func(i, j int) bool { return all[i].RSSBytes > all[j].RSSBytes })
	byMem = append(byMem, all[:min(n, len(all))]...)
	return byCPU, byMem, count
}

func readProc(dir string, pageSize uint64) (procSample, bool) {
	b, err := os.ReadFile(filepath.Join(dir, "stat"))
	if err != nil {
		return procSample{}, false
	}
	s := string(b)
	l, r := strings.IndexByte(s, '('), strings.LastIndexByte(s, ')')
	if l < 0 || r < l {
		return procSample{}, false
	}
	f := strings.Fields(s[r+1:])
	if len(f) < 22 {
		return procSample{}, false
	}
	ps := procSample{name: s[l+1 : r], ticks: parseU(f[11]) + parseU(f[12]), rss: parseU(f[21]) * pageSize}
	if st, err := os.ReadFile(filepath.Join(dir, "status")); err == nil {
		for _, line := range strings.Split(string(st), "\n") {
			if v, ok := strings.CutPrefix(line, "Uid:"); ok {
				if fs := strings.Fields(v); len(fs) > 0 {
					ps.uid = fs[0]
				}
				break
			}
		}
	}
	return ps, true
}

func (p *Processes) userName(uid string) string {
	if p.users == nil {
		p.users = map[string]string{}
		if lines, err := readLines("/etc/passwd"); err == nil {
			for _, l := range lines {
				f := strings.Split(l, ":")
				if len(f) > 2 {
					p.users[f[2]] = f[0]
				}
			}
		}
	}
	if n, ok := p.users[uid]; ok {
		return n
	}
	return uid
}
