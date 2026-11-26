package collect

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

func byKey(s []protocol.Sample) map[string]float64 {
	m := map[string]float64{}
	for _, x := range s {
		k := x.Name
		if x.Labels != "" {
			k += "{" + x.Labels + "}"
		}
		m[k] = x.Value
	}
	return m
}

// copyProc builds a proc tree by overlaying dir onto a fresh temp dir so the
// collector can be pointed at a "changing" /proc.
func swap(t *testing.T, dst, src string) {
	t.Helper()
	err := filepath.Walk(src, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(src, p)
		if info.IsDir() {
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCPU(t *testing.T) {
	root := t.TempDir()
	swap(t, root, "testdata/proc1")
	c := &CPU{ProcRoot: root}
	t0 := time.Unix(1000, 0)
	first, err := c.Collect(t0)
	if err != nil {
		t.Fatal(err)
	}
	m := byKey(first)
	if _, ok := m["cpu.usage"]; ok {
		t.Fatal("first sample must not have usage")
	}
	if m["load.1"] != 0.52 || m["system.procs"] != 315 || m["system.uptime"] != 86400 || m["cpu.cores"] != 2 {
		t.Fatalf("static values: %v", m)
	}
	swap(t, root, "testdata/proc2")
	s, _ := c.Collect(t0.Add(10 * time.Second))
	m = byKey(s)
	// total delta = 900; idle 400, iowait 50 → busy 450 → 50%
	if m["cpu.usage"] != 50 || m["cpu.iowait"] != 5.56 || m["cpu.steal"] != 5.56 || m["cpu.user"] != 33.33 || m["cpu.system"] != 11.11 {
		t.Fatalf("cpu: %v", m)
	}
	if m["cpu.usage{core=0}"] != 61.11 {
		t.Fatalf("core0: %v", m["cpu.usage{core=0}"])
	}
}

func TestMemory(t *testing.T) {
	m := &Memory{ProcRoot: "testdata/proc1"}
	s, err := m.Collect(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	v := byKey(s)
	if v["mem.used_pct"] != 25 || v["swap.used_pct"] != 25 || v["mem.total"] != 8000000*1024 {
		t.Fatalf("%v", v)
	}
}

func TestNetwork(t *testing.T) {
	root := t.TempDir()
	swap(t, root, "testdata/proc1")
	n := &Network{ProcRoot: root}
	t0 := time.Unix(0, 0)
	_, _ = n.Collect(t0)
	swap(t, root, "testdata/proc2")
	v := byKey(must(n.Collect(t0.Add(10 * time.Second))))
	if v["net.rx_bps{iface=eth0}"] != 100000 || v["net.tx_bps{iface=eth0}"] != 20000 || v["net.errors{iface=eth0}"] != 0.2 || v["net.drops{iface=eth0}"] != 0.2 {
		t.Fatalf("%v", v)
	}
	if _, ok := v["net.rx_bps{iface=lo}"]; ok {
		t.Fatal("lo not skipped")
	}
}

func TestDiskIO(t *testing.T) {
	root := t.TempDir()
	swap(t, root, "testdata/proc1")
	d := &DiskIO{ProcRoot: root, SysRoot: "/nonexistent"}
	t0 := time.Unix(0, 0)
	_, _ = d.Collect(t0)
	swap(t, root, "testdata/proc2")
	v := byKey(must(d.Collect(t0.Add(10 * time.Second))))
	if v["diskio.read_bps{dev=sda}"] != 2000*512/10 || v["diskio.write_iops{dev=sda}"] != 50 || v["diskio.util_pct{dev=sda}"] != 10 {
		t.Fatalf("%v", v)
	}
	if _, ok := v["diskio.read_bps{dev=sda1}"]; ok {
		t.Fatal("partition not skipped")
	}
}

func TestDisk(t *testing.T) {
	d := &Disk{ProcRoot: "testdata/proc1", Statfs: func(p string) (FSStat, error) {
		return FSStat{Total: 1000, Free: 200, Avail: 100, Inodes: 100, InodesFree: 25}, nil
	}}
	v := byKey(must(d.Collect(time.Now())))
	if len(v) != 8 {
		t.Fatalf("want 2 mounts × 4 series, got %v", v)
	}
	if v["disk.used_pct{mount=/}"] != 88.89 || v["disk.inodes_used_pct{mount=/var/lib data}"] != 75 {
		t.Fatalf("%v", v)
	}
}

func TestProcesses(t *testing.T) {
	p := &Processes{ProcRoot: "testdata/proc1"}
	cpu, mem, n := p.Top(time.Now(), 5)
	if n != 1 || len(cpu) != 1 || mem[0].Name != "nginx: worker" || mem[0].RSSBytes != 2500*uint64(os.Getpagesize()) {
		t.Fatalf("%v %v %d", cpu, mem, n)
	}
}

func TestReboot(t *testing.T) {
	r := &RebootCheck{Root: "testdata/root", ProcRoot: "testdata/proc1"}
	st := r.Check(context.Background())
	if !st.Required || st.NewestKernel != "6.1.0-21-amd64" || st.RunningKernel != "6.1.0-18-amd64" || len(st.Reasons) != 2 {
		t.Fatalf("%+v", st)
	}
}

func TestFailedUnits(t *testing.T) {
	out := "● nginx.service loaded failed failed A high performance web server\nlogrotate.service loaded failed failed Rotate log files\n"
	u := ParseFailedUnits(out)
	if len(u) != 2 || u[0] != "nginx.service" {
		t.Fatalf("%v", u)
	}
}

func TestDockerStats(t *testing.T) {
	var s DockerStats
	s.CPUStats.CPUUsage.TotalUsage = 200
	s.PreCPUStats.CPUUsage.TotalUsage = 100
	s.CPUStats.SystemUsage = 2000
	s.PreCPUStats.SystemUsage = 1000
	s.CPUStats.OnlineCPUs = 4
	s.MemoryStats.Usage = 1000
	s.MemoryStats.Stats = map[string]uint64{"inactive_file": 300}
	if s.CPUPercent() != 40 || s.MemBytes() != 700 {
		t.Fatalf("%v %v", s.CPUPercent(), s.MemBytes())
	}
}

func TestLabels(t *testing.T) {
	if Labels("mount", "/a,b", "dev", "x=y") != "dev=x_y,mount=/a_b" {
		t.Fatal(Labels("mount", "/a,b", "dev", "x=y"))
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
