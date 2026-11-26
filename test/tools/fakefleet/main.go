// Command fakefleet simulates a fleet of agents against a local dev server. It is a
// development/demo tool only (UI screenshots, live-chart testing on non-Linux machines).
//
//	go run ./test/tools/fakefleet --config deploy/dev/server.yaml --hosts 6
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"log/slog"
	"math"
	"math/rand/v2"
	"os"
	"os/signal"
	"path/filepath"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/server"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

type fakeHost struct {
	name, group string
	os          protocol.OSInfo
	base        float64
	a           *agent.Agent
}

var fleet = []fakeHost{
	{name: "web-01", group: "production", os: protocol.OSInfo{ID: "debian", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-18-amd64", Arch: "x86_64", Virtualization: "kvm"}, base: 35},
	{name: "web-02", group: "production", os: protocol.OSInfo{ID: "debian", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)", Kernel: "6.1.0-21-amd64", Arch: "x86_64", Virtualization: "kvm"}, base: 28},
	{name: "db-01", group: "production", os: protocol.OSInfo{ID: "rocky", VersionID: "9.4", PrettyName: "Rocky Linux 9.4 (Blue Onyx)", Kernel: "5.14.0-427.13.1.el9_4.x86_64", Arch: "x86_64", Virtualization: "kvm"}, base: 55},
	{name: "ci-runner", group: "internal", os: protocol.OSInfo{ID: "ubuntu", VersionID: "24.04", Codename: "noble", PrettyName: "Ubuntu 24.04.1 LTS", Kernel: "6.8.0-45-generic", Arch: "x86_64", Virtualization: "lxc"}, base: 70},
	{name: "mail", group: "internal", os: protocol.OSInfo{ID: "almalinux", VersionID: "8.10", PrettyName: "AlmaLinux 8.10 (Cerulean Leopard)", Kernel: "4.18.0-553.el8_10.x86_64", Arch: "x86_64", Virtualization: "kvm"}, base: 12},
	{name: "edge-proxy", group: "dmz", os: protocol.OSInfo{ID: "alpine", VersionID: "3.19.1", PrettyName: "Alpine Linux v3.19", Kernel: "6.6.14-0-virt", Arch: "aarch64", Virtualization: "kvm"}, base: 18},
}

func main() {
	cfgPath := flag.String("config", "deploy/dev/server.yaml", "server config (dev)")
	n := flag.Int("hosts", len(fleet), "number of hosts")
	flag.Parse()
	cfg := config.DefaultServer()
	if err := config.Load(*cfgPath, &cfg); err != nil {
		fail(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	db, err := store.Open(ctx, filepath.Join(cfg.DataDir, "sentrix.db"))
	if err != nil {
		fail(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	srv, err := server.New(cfg, db, log)
	if err != nil {
		fail(err)
	}
	stateRoot := filepath.Join(cfg.DataDir, "..", "fakefleet")
	hosts := fleet[:min(*n, len(fleet))]
	for i := range hosts {
		h := &hosts[i]
		dir := filepath.Join(stateRoot, h.name)
		if !agent.Enrolled(dir) {
			tok, _, err := srv.CreateEnrollToken(ctx, "fakefleet", h.group, time.Hour)
			if err != nil {
				fail(err)
			}
			if _, err := agent.Enroll(ctx, dir, cfg.GatewayURL, tok, srv.CA().Fingerprint(), h.name, "fake-"+h.name); err != nil {
				fail(err)
			}
		}
		ac := config.DefaultAgent()
		ac.StateDir = dir
		h.a, err = agent.New(ac, log)
		if err != nil {
			fail(err)
		}
	}
	_ = db.Close()
	fmt.Printf("simulating %d hosts; Ctrl-C to stop\n", len(hosts))
	extra := extraInit(ctx, hosts)
	tick := time.NewTicker(10 * time.Second)
	defer tick.Stop()
	for i := 0; ; i++ {
		now := time.Now()
		for k := range hosts {
			h := &hosts[k]
			send(ctx, h, now, i)
			if i%3 == 0 {
				_ = h.a.Post(ctx, protocol.PathState, state(h, now), nil)
			}
			extra(ctx, h, i)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

// extraInit is replaced in later milestones (inventory, command handling).
var extraInit = func(context.Context, []fakeHost) func(context.Context, *fakeHost, int) {
	return func(context.Context, *fakeHost, int) {}
}

func wave(base float64, t time.Time, period float64) float64 {
	x := float64(t.Unix()) / period
	return math.Max(0, math.Min(100, base+15*math.Sin(x)+rand.Float64()*8-4))
}

func send(ctx context.Context, h *fakeHost, now time.Time, i int) {
	ts := now.Unix()
	cpu := wave(h.base, now, 300)
	smp := []protocol.Sample{
		{TS: ts, Name: "cpu.usage", Value: cpu},
		{TS: ts, Name: "cpu.iowait", Value: cpu / 12},
		{TS: ts, Name: "cpu.steal", Value: rand.Float64()},
		{TS: ts, Name: "load.1", Value: cpu / 25},
		{TS: ts, Name: "load.5", Value: h.base / 25},
		{TS: ts, Name: "load.15", Value: h.base / 27},
		{TS: ts, Name: "mem.used_pct", Value: wave(h.base+20, now, 900)},
		{TS: ts, Name: "swap.used_pct", Value: 4},
		{TS: ts, Name: "disk.used_pct", Labels: "mount=/", Value: 40 + h.base/2},
		{TS: ts, Name: "disk.used_pct", Labels: "mount=/var", Value: 30 + h.base/3},
		{TS: ts, Name: "disk.inodes_used_pct", Labels: "mount=/", Value: 12},
		{TS: ts, Name: "net.rx_bps", Labels: "iface=eth0", Value: wave(40, now, 120) * 20000},
		{TS: ts, Name: "net.tx_bps", Labels: "iface=eth0", Value: wave(30, now, 160) * 15000},
		{TS: ts, Name: "diskio.read_bps", Labels: "dev=vda", Value: wave(20, now, 200) * 50000},
		{TS: ts, Name: "diskio.write_bps", Labels: "dev=vda", Value: wave(25, now, 220) * 80000},
		{TS: ts, Name: "system.uptime", Value: float64(86400*12 + i*10)},
		{TS: ts, Name: "system.procs", Value: 180 + h.base},
	}
	_ = h.a.Post(ctx, protocol.PathMetrics, protocol.MetricsBatch{Samples: smp}, nil)
	_ = h.a.Post(ctx, protocol.PathHeartbeat, protocol.Heartbeat{AgentVersion: "0.1.0", Hostname: h.name, BootTime: now.Add(-12 * 24 * time.Hour)}, nil)
}

func state(h *fakeHost, now time.Time) protocol.HostState {
	st := protocol.HostState{CollectedAt: now, Uptime: 86400 * 12, ProcessCount: 180,
		TopCPU: []protocol.ProcessInfo{
			{PID: 1312, Name: "nginx", User: "www-data", CPUPercent: 12.4, RSSBytes: 48 << 20},
			{PID: 2210, Name: "postgres", User: "postgres", CPUPercent: 8.1, RSSBytes: 512 << 20},
			{PID: 901, Name: "sentrix-agent", User: "root", CPUPercent: 0.2, RSSBytes: 14 << 20},
		},
		Reboot:   protocol.RebootStatus{RunningKernel: h.os.Kernel},
		Services: []protocol.ServiceStatus{{Name: "ssh.service", ActiveState: "active", SubState: "running"}},
	}
	st.TopMem = st.TopCPU
	if h.name == "web-01" {
		st.Reboot.Required = true
		st.Reboot.Reasons = []string{"/var/run/reboot-required present (libc6)"}
		st.Reboot.NewestKernel = "6.1.0-21-amd64"
	}
	if h.name == "ci-runner" {
		st.DockerPresent = true
		st.Containers = []protocol.Container{
			{ID: "a1b2c3d4e5f6", Name: "runner", Image: "gitea/act_runner:0.2.10", State: "running", Status: "Up 3 days", CPUPercent: 22.5, MemBytes: 300 << 20},
			{ID: "0f9e8d7c6b5a", Name: "registry", Image: "registry:2", State: "exited", Status: "Exited (1) 2 hours ago", RestartCount: 4},
		}
	}
	if h.name == "mail" {
		st.FailedUnits = []string{"fetchmail.service"}
	}
	return st
}

func fail(err error) {
	fmt.Fprintln(os.Stderr, "error:", err)
	os.Exit(1)
}
