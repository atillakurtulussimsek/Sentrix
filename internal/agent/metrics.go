package agent

import (
	"context"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent/collect"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

type sampler struct {
	mu      sync.Mutex
	pending []protocol.Sample
}

func (s *sampler) add(x ...protocol.Sample) {
	s.mu.Lock()
	s.pending = append(s.pending, x...)
	s.mu.Unlock()
}

func (s *sampler) take() []protocol.Sample {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := s.pending
	s.pending = nil
	return out
}

// EnableMetrics registers the collection, state and send loops.
func (a *Agent) EnableMetrics() error {
	buf, err := NewBuffer(filepath.Join(a.cfg.StateDir, "buffer"), int64(a.cfg.BufferMaxMB)<<20)
	if err != nil {
		return err
	}
	smp := &sampler{}
	collectors := []collect.Collector{
		&collect.CPU{ProcRoot: a.cfg.ProcRoot},
		&collect.Memory{ProcRoot: a.cfg.ProcRoot},
		&collect.Disk{ProcRoot: a.cfg.ProcRoot},
		&collect.DiskIO{ProcRoot: a.cfg.ProcRoot},
		&collect.Network{ProcRoot: a.cfg.ProcRoot},
	}
	a.loops = append(a.loops,
		func(ctx context.Context) { a.collectLoop(ctx, collectors, smp) },
		func(ctx context.Context) { a.stateLoop(ctx, smp) },
		func(ctx context.Context) { a.sendLoop(ctx, smp, buf) },
	)
	return nil
}

func (a *Agent) collectLoop(ctx context.Context, cs []collect.Collector, smp *sampler) {
	tick := time.NewTicker(a.cfg.Interval)
	defer tick.Stop()
	for {
		now := time.Now()
		for _, c := range cs {
			s, err := c.Collect(now)
			if err != nil {
				a.log.Debug("collector failed", "collector", c.Name(), "err", err)
				continue
			}
			smp.add(s...)
		}
		var ms runtime.MemStats
		runtime.ReadMemStats(&ms)
		smp.add(protocol.Sample{TS: now.Unix(), Name: "agent.heap_bytes", Value: float64(ms.HeapAlloc)})
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (a *Agent) sendLoop(ctx context.Context, smp *sampler, buf *Buffer) {
	tick := time.NewTicker(a.cfg.SendInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			// persist whatever is pending so nothing is lost across restarts
			_ = buf.Put(protocol.MetricsBatch{Samples: smp.take()})
			return
		case <-tick.C:
		}
		if err := buf.Put(protocol.MetricsBatch{Samples: smp.take()}); err != nil {
			a.log.Warn("buffer write failed", "err", err)
		}
		n, err := buf.Drain(func(b protocol.MetricsBatch) error {
			return a.c.post(ctx, protocol.PathMetrics, b, nil)
		})
		if err != nil && ctx.Err() == nil {
			a.log.Warn("metrics send failed; buffered", "sent", n, "buffered", buf.Len(), "err", err)
		}
	}
}

func (a *Agent) stateLoop(ctx context.Context, smp *sampler) {
	procs := &collect.Processes{ProcRoot: a.cfg.ProcRoot}
	docker := &collect.Docker{Socket: a.cfg.DockerSocket}
	reboot := &collect.RebootCheck{Root: "/", ProcRoot: a.cfg.ProcRoot, Run: collect.ExecRunner}
	var rebootSt protocol.RebootStatus
	var certs []protocol.CertStatus
	var lastReboot, lastCerts time.Time
	procs.Top(time.Now(), 0) // prime CPU deltas
	tick := time.NewTicker(30 * time.Second)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		now := time.Now()
		st := protocol.HostState{CollectedAt: now.UTC()}
		st.TopCPU, st.TopMem, st.ProcessCount = procs.Top(now, 10)
		watch, endpoints := a.watched()
		st.FailedUnits = collect.FailedUnits(ctx, collect.ExecRunner)
		st.Services = collect.ServiceStates(ctx, collect.ExecRunner, watch)
		if docker.Available() {
			st.DockerPresent = true
			cs, samples, err := docker.Containers(ctx, now)
			if err != nil {
				a.log.Debug("docker", "err", err)
			}
			st.Containers = cs
			smp.add(samples...)
		}
		if now.Sub(lastReboot) > 5*time.Minute {
			rebootSt, lastReboot = reboot.Check(ctx), now
		}
		st.Reboot = rebootSt
		if len(endpoints) > 0 && now.Sub(lastCerts) > time.Hour {
			certs, lastCerts = collect.CheckCerts(ctx, endpoints), now
		}
		st.Certificates = certs
		st.Uptime = int64(now.Sub(bootTime(a.cfg.ProcRoot)).Seconds())
		smp.add(protocol.Sample{TS: now.Unix(), Name: "system.failed_units", Value: float64(len(st.FailedUnits))})
		if err := a.c.post(ctx, protocol.PathState, st, nil); err != nil && ctx.Err() == nil {
			a.log.Warn("state send failed", "err", err)
		}
	}
}

func (a *Agent) watched() ([]string, []string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([]string(nil), a.watchServices...), append([]string(nil), a.tlsEndpoints...)
}
