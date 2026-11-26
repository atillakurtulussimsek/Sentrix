package agent

import (
	"context"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent/collect"
	"github.com/atillakurtulussimsek/Sentrix/internal/agent/inventory"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// NewInventoryCollector returns the production inventory collector for cfg.
func NewInventoryCollector(procRoot, dockerSocket string, refresh bool) *inventory.Collector {
	return &inventory.Collector{Root: "/", ProcRoot: procRoot, Run: collect.LongRunner, RefreshMetadata: refresh,
		Docker: &collect.Docker{Socket: dockerSocket}}
}

// EnableInventory registers the periodic inventory loop.
func (a *Agent) EnableInventory() {
	a.invNow = make(chan struct{}, 1)
	a.loops = append(a.loops, a.inventoryLoop)
}

// TriggerInventory requests an immediate inventory run (non-blocking).
func (a *Agent) TriggerInventory() {
	if a.invNow == nil {
		return
	}
	select {
	case a.invNow <- struct{}{}:
	default:
	}
}

// SendInventory collects and uploads inventory once.
func (a *Agent) SendInventory(ctx context.Context) error {
	c := NewInventoryCollector(a.cfg.ProcRoot, a.cfg.DockerSocket, true)
	inv := c.Collect(ctx)
	return a.c.post(ctx, protocol.PathInventory, inv, nil)
}

func (a *Agent) inventoryLoop(ctx context.Context) {
	// small delay so the first heartbeat/metrics go out quickly after start
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		case <-a.invNow:
		}
		start := time.Now()
		if err := a.SendInventory(ctx); err != nil && ctx.Err() == nil {
			a.log.Warn("inventory failed", "err", err)
			timer.Reset(5 * time.Minute)
			continue
		}
		a.log.Info("inventory sent", "took", time.Since(start).Round(time.Millisecond))
		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(a.cfg.InventoryEvery)
	}
}
