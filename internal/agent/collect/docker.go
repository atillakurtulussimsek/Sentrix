package collect

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// Docker talks to the Docker Engine API over its unix socket (read-only endpoints).
type Docker struct {
	Socket string
	client *http.Client
}

// Available reports whether the socket exists.
func (d *Docker) Available() bool {
	_, err := os.Stat(d.Socket)
	return err == nil
}

func (d *Docker) http() *http.Client {
	if d.client == nil {
		d.client = &http.Client{Timeout: 15 * time.Second, Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var dl net.Dialer
				return dl.DialContext(ctx, "unix", d.Socket)
			},
		}}
	}
	return d.client
}

func (d *Docker) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker"+path, nil)
	if err != nil {
		return err
	}
	resp, err := d.http().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("docker %s: %s", path, resp.Status)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

type dockerContainer struct {
	ID     string   `json:"Id"`
	Names  []string `json:"Names"`
	Image  string   `json:"Image"`
	State  string   `json:"State"`
	Status string   `json:"Status"`
}

// DockerStats is the subset of the stats response we use.
type DockerStats struct {
	CPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
		OnlineCPUs  int    `json:"online_cpus"`
	} `json:"cpu_stats"`
	PreCPUStats struct {
		CPUUsage struct {
			TotalUsage uint64 `json:"total_usage"`
		} `json:"cpu_usage"`
		SystemUsage uint64 `json:"system_cpu_usage"`
	} `json:"precpu_stats"`
	MemoryStats struct {
		Usage uint64            `json:"usage"`
		Stats map[string]uint64 `json:"stats"`
	} `json:"memory_stats"`
}

// CPUPercent computes CPU% the same way `docker stats` does.
func (s DockerStats) CPUPercent() float64 {
	cpuDelta := float64(s.CPUStats.CPUUsage.TotalUsage) - float64(s.PreCPUStats.CPUUsage.TotalUsage)
	sysDelta := float64(s.CPUStats.SystemUsage) - float64(s.PreCPUStats.SystemUsage)
	if cpuDelta <= 0 || sysDelta <= 0 {
		return 0
	}
	n := s.CPUStats.OnlineCPUs
	if n == 0 {
		n = 1
	}
	return round2(cpuDelta / sysDelta * float64(n) * 100)
}

// MemBytes is usage minus page cache, like `docker stats`.
func (s DockerStats) MemBytes() uint64 {
	cache := s.MemoryStats.Stats["inactive_file"]
	if cache == 0 {
		cache = s.MemoryStats.Stats["total_inactive_file"]
	}
	if cache > s.MemoryStats.Usage {
		return s.MemoryStats.Usage
	}
	return s.MemoryStats.Usage - cache
}

// Containers lists containers with stats for running ones, plus metric samples.
func (d *Docker) Containers(ctx context.Context, now time.Time) ([]protocol.Container, []protocol.Sample, error) {
	var list []dockerContainer
	if err := d.get(ctx, "/containers/json?all=1", &list); err != nil {
		return nil, nil, err
	}
	out := make([]protocol.Container, len(list))
	var mu sync.Mutex
	var samples []protocol.Sample
	var wg sync.WaitGroup
	sem := make(chan struct{}, 4)
	for i, c := range list {
		name := strings.TrimPrefix(strings.Join(c.Names, ","), "/")
		out[i] = protocol.Container{ID: c.ID[:min(12, len(c.ID))], Name: name, Image: c.Image, State: c.State, Status: c.Status}
		wg.Add(1)
		go func(i int, c dockerContainer) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			var insp struct {
				RestartCount int `json:"RestartCount"`
			}
			if err := d.get(ctx, "/containers/"+c.ID+"/json", &insp); err == nil {
				out[i].RestartCount = insp.RestartCount
			}
			if c.State != "running" {
				return
			}
			var st DockerStats
			if err := d.get(ctx, "/containers/"+c.ID+"/stats?stream=false", &st); err != nil {
				return
			}
			out[i].CPUPercent, out[i].MemBytes = st.CPUPercent(), st.MemBytes()
			lb := Labels("container", out[i].Name)
			mu.Lock()
			samples = append(samples,
				sample(now, "docker.cpu_pct", lb, out[i].CPUPercent),
				sample(now, "docker.mem_bytes", lb, float64(out[i].MemBytes)))
			mu.Unlock()
		}(i, c)
	}
	wg.Wait()
	running := 0
	for _, c := range out {
		if c.State == "running" {
			running++
		}
	}
	samples = append(samples, sample(now, "docker.containers_running", "", float64(running)), sample(now, "docker.containers_total", "", float64(len(out))))
	return out, samples, nil
}

// Images returns the image references of all containers.
func (d *Docker) Images(ctx context.Context) []string {
	var list []dockerContainer
	if err := d.get(ctx, "/containers/json?all=1", &list); err != nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range list {
		if !seen[c.Image] {
			seen[c.Image] = true
			out = append(out, c.Image)
		}
	}
	return out
}
