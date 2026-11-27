package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent/collect"
	"github.com/atillakurtulussimsek/Sentrix/internal/agent/executor"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

// doneLog remembers results of executed command IDs so redelivered commands are not
// executed twice (idempotency across restarts).
type doneLog struct {
	path string
	mu   sync.Mutex
	m    map[string]protocol.CommandResult
	ord  []string
}

func loadDoneLog(path string) *doneLog {
	d := &doneLog{path: path, m: map[string]protocol.CommandResult{}}
	b, err := os.ReadFile(path)
	if err == nil {
		var list []protocol.CommandResult
		if json.Unmarshal(b, &list) == nil {
			for _, r := range list {
				d.m[r.ID] = r
				d.ord = append(d.ord, r.ID)
			}
		}
	}
	return d
}

func (d *doneLog) get(id string) (protocol.CommandResult, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.m[id]
	return r, ok
}

func (d *doneLog) put(r protocol.CommandResult) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if _, ok := d.m[r.ID]; !ok {
		d.ord = append(d.ord, r.ID)
	}
	d.m[r.ID] = r
	for len(d.ord) > 200 {
		delete(d.m, d.ord[0])
		d.ord = d.ord[1:]
	}
	list := make([]protocol.CommandResult, 0, len(d.ord))
	for _, id := range d.ord {
		x := d.m[id]
		x.Output = "" // keep the file small
		list = append(list, x)
	}
	b, _ := json.Marshal(list)
	_ = os.WriteFile(d.path, b, 0o600)
}

// EnableCommands registers the command long-poll loop.
func (a *Agent) EnableCommands() {
	ex := &executor.Executor{
		Run:             collect.LongRunner,
		Inventory:       NewInventoryCollector(a.cfg.ProcRoot, a.cfg.DockerSocket, true),
		Reboot:          &collect.RebootCheck{Root: "/", ProcRoot: a.cfg.ProcRoot, Run: collect.ExecRunner},
		AllowPatching:   a.cfg.AllowPatching,
		SendInventory:   a.SendInventory,
		AllowSelfUpdate: a.cfg.AllowSelfUpdate,
		UpdateAgent:     a.installUpdate,
	}
	a.loops = append(a.loops, func(ctx context.Context) { a.commandLoop(ctx, ex) })
}

func (a *Agent) commandLoop(ctx context.Context, ex *executor.Executor) {
	done := loadDoneLog(filepath.Join(a.cfg.StateDir, "commands.json"))
	backoff := time.Second
	for ctx.Err() == nil {
		if err := a.pollOnce(ctx, ex, done, 30); err != nil {
			if ctx.Err() != nil {
				return
			}
			a.log.Debug("command poll failed", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, time.Minute)
			continue
		}
		backoff = time.Second
	}
}

// PollOnce fetches and executes pending commands once (used by tests and tools).
func (a *Agent) PollOnce(ctx context.Context, ex *executor.Executor, waitSeconds int) error {
	return a.pollOnce(ctx, ex, loadDoneLog(filepath.Join(a.cfg.StateDir, "commands.json")), waitSeconds)
}

func (a *Agent) pollOnce(ctx context.Context, ex *executor.Executor, done *doneLog, wait int) error {
	var resp protocol.CommandsResponse
	pctx, cancel := context.WithTimeout(ctx, time.Duration(wait+20)*time.Second)
	err := a.c.get(pctx, protocol.PathCommands+"?wait="+strconv.Itoa(wait), &resp)
	cancel()
	if err != nil {
		return err
	}
	for _, cmd := range resp.Commands {
		res, seen := done.get(cmd.ID)
		if seen {
			a.sendResult(ctx, res) // redelivery: report the stored result again
			continue
		}
		a.log.Info("executing command", "id", cmd.ID, "action", cmd.Action, "dry_run", cmd.DryRun)
		var rebootDelay *time.Duration
		restart := false
		ex.ScheduleReboot = func(d time.Duration) { rebootDelay = &d }
		ex.ScheduleRestart = func() { restart = true }
		res = ex.Execute(ctx, cmd)
		done.put(res)
		a.log.Info("command finished", "id", cmd.ID, "status", res.Status, "err", res.Error)
		a.sendResult(ctx, res)
		if restart {
			a.restartSelf() // does not return on success
		}
		if rebootDelay != nil {
			a.log.Warn("rebooting host on server request", "delay", *rebootDelay)
			if err := ex.RebootNow(ctx, *rebootDelay); err != nil {
				a.log.Error("reboot failed", "err", err)
			}
		}
	}
	return nil
}

func (a *Agent) sendResult(ctx context.Context, res protocol.CommandResult) {
	for i := 0; i < 5; i++ {
		if err := a.c.post(ctx, protocol.PathResults, protocol.ResultsRequest{Results: []protocol.CommandResult{res}}, nil); err == nil {
			return
		} else if ctx.Err() != nil {
			return
		}
		time.Sleep(time.Duration(i+1) * 2 * time.Second)
	}
}
