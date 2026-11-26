package server

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/patch"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// Timeouts for plan steps.
var (
	dryRunTimeout  = 30 * time.Minute
	patchTimeout   = 90 * time.Minute
	rebootTimeout  = 20 * time.Minute
	verifyTimeout  = 15 * time.Minute
	snapshotTimout = 30 * time.Minute
)

// PlanRequest describes a patch plan to create.
type PlanRequest struct {
	Name             string
	HostIDs          []string
	Group            string
	Scope            string // security | packages | all
	Packages         []string
	Reboot           string // never | if_required | always
	Canary           int
	MaxParallel      int
	SnapshotHook     string
	SnapshotRequired bool
	PolicyID         string
}

// CreatePlan validates a request, stores the plan and starts the dry run on every host.
func (s *Server) CreatePlan(ctx context.Context, req PlanRequest, actor string) (store.Plan, error) {
	switch req.Scope {
	case "security", "all":
	case "packages":
		if len(req.Packages) == 0 {
			return store.Plan{}, errors.New("scope 'packages' needs at least one package")
		}
		for _, p := range req.Packages {
			if !protocol.ValidPackageName(p) {
				return store.Plan{}, fmt.Errorf("invalid package name %q", p)
			}
		}
	default:
		return store.Plan{}, fmt.Errorf("invalid scope %q", req.Scope)
	}
	if req.Reboot == "" {
		req.Reboot = "never"
	}
	if req.Reboot != "never" && req.Reboot != "if_required" && req.Reboot != "always" {
		return store.Plan{}, fmt.Errorf("invalid reboot option %q", req.Reboot)
	}
	req.MaxParallel = max(1, min(req.MaxParallel, 50))
	req.Canary = max(0, req.Canary)
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		return store.Plan{}, err
	}
	want := map[string]bool{}
	for _, id := range req.HostIDs {
		want[id] = true
	}
	var ids []string
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		if want[h.ID] || want[h.Hostname] || (req.Group != "" && h.Group == req.Group) {
			ids = append(ids, h.ID)
		}
	}
	if len(ids) == 0 {
		return store.Plan{}, errors.New("no matching hosts")
	}
	if req.SnapshotHook != "" {
		if _, err := s.db.GetHook(ctx, req.SnapshotHook); err != nil {
			return store.Plan{}, fmt.Errorf("unknown snapshot hook")
		}
	}
	if req.Name == "" {
		req.Name = fmt.Sprintf("%s patch · %d host(s) · %s", req.Scope, len(ids), time.Now().Format("2006-01-02 15:04"))
	}
	p, err := s.db.CreatePlan(ctx, store.Plan{Name: truncate(req.Name, 200), Scope: req.Scope, Packages: req.Packages, Status: "dry_run", PolicyID: req.PolicyID,
		Reboot: req.Reboot, Canary: req.Canary, MaxParallel: req.MaxParallel, SnapshotHook: req.SnapshotHook, SnapshotRequired: req.SnapshotRequired, CreatedBy: actor}, ids)
	if err != nil {
		return p, err
	}
	s.audit(ctx, actor, "plan.create", p.ID, fmt.Sprintf("name=%q scope=%s hosts=%d reboot=%s canary=%d parallel=%d packages=%s snapshot_hook=%s",
		p.Name, p.Scope, len(ids), p.Reboot, p.Canary, p.MaxParallel, strings.Join(p.Packages, ","), p.SnapshotHook))
	s.kickOrchestrator()
	return p, nil
}

// ApprovePlan approves a plan whose dry run finished.
func (s *Server) ApprovePlan(ctx context.Context, id, actor string) error {
	ok, err := s.db.ApprovePlan(ctx, id, actor)
	if err != nil {
		return err
	}
	if !ok {
		return errors.New("plan is not ready for approval (dry run still running, or already approved/finished)")
	}
	s.audit(ctx, actor, "plan.approve", id, "")
	s.kickOrchestrator()
	return nil
}

// CancelPlan stops a plan; in-flight host steps finish but nothing new starts.
func (s *Server) CancelPlan(ctx context.Context, id, actor string) error {
	p, err := s.db.GetPlan(ctx, id)
	if err != nil {
		return err
	}
	switch p.Status {
	case "done", "failed", "cancelled":
		return errors.New("plan already finished")
	}
	hosts, _ := s.db.ListPlanHosts(ctx, id)
	for _, h := range hosts {
		if h.Status == "pending" || h.Status == "dry_ok" || h.Status == "dry_failed" || h.Status == "dry_run" {
			h.Status, h.Error = "skipped", "plan cancelled"
			_ = s.db.SavePlanHost(ctx, h)
		}
	}
	if err := s.db.UpdatePlanStatus(ctx, id, "cancelled", "cancelled by "+actor); err != nil {
		return err
	}
	s.audit(ctx, actor, "plan.cancel", id, "")
	return nil
}

func (s *Server) kickOrchestrator() {
	select {
	case s.orchKick <- struct{}{}:
	default:
	}
}

func (s *Server) orchestratorLoop(ctx context.Context) {
	t := time.NewTicker(3 * time.Second)
	defer t.Stop()
	for {
		if err := s.AdvancePlans(ctx); err != nil && ctx.Err() == nil {
			s.log.Warn("orchestrator", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-s.orchKick:
		}
	}
}

// AdvancePlans moves every active plan one step forward. It is idempotent and safe to
// call repeatedly (the state is entirely in the database).
func (s *Server) AdvancePlans(ctx context.Context) error {
	s.orchMu.Lock()
	defer s.orchMu.Unlock()
	plans, err := s.db.ListPlans(ctx, "dry_run", "approved", "running")
	if err != nil {
		return err
	}
	var errs []error
	for _, p := range plans {
		var err error
		switch p.Status {
		case "dry_run":
			err = s.advanceDryRun(ctx, p)
		case "approved":
			if err = s.db.UpdatePlanStatus(ctx, p.ID, "running", ""); err == nil {
				s.audit(ctx, "system", "plan.start", p.ID, "")
				p.Status = "running"
				err = s.advanceRun(ctx, p)
			}
		case "running":
			err = s.advanceRun(ctx, p)
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("plan %s: %w", p.ID, err))
		}
	}
	return errors.Join(errs...)
}

// planCommand returns the action and params for a host, or skip=true with a reason.
func (s *Server) planCommand(ctx context.Context, p store.Plan, hostID string) (protocol.Action, any, bool, string) {
	inv, err := s.db.GetInventory(ctx, hostID)
	if err != nil {
		return "", nil, true, "no inventory yet"
	}
	switch p.Scope {
	case "all":
		return protocol.ActionPatchAll, nil, false, ""
	case "security":
		if inv.PackageManager != "apk" {
			return protocol.ActionPatchSecurityOnly, nil, false, ""
		}
		ups, _ := s.db.ListUpdates(ctx, hostID)
		var names []string
		for _, u := range ups {
			if u.Security {
				names = append(names, u.Name)
			}
		}
		if len(names) == 0 {
			return "", nil, true, "no security updates pending"
		}
		return protocol.ActionPatchPackages, protocol.PatchPackagesParams{Packages: names}, false, ""
	default: // packages
		installed, _ := s.db.ListPackages(ctx, hostID, "")
		have := map[string]bool{}
		for _, ip := range installed {
			have[ip.Name] = true
		}
		var names []string
		for _, n := range p.Packages {
			if have[n] {
				names = append(names, n)
			}
		}
		if len(names) == 0 {
			return "", nil, true, "none of the selected packages is installed"
		}
		return protocol.ActionPatchPackages, protocol.PatchPackagesParams{Packages: names}, false, ""
	}
}

func planActor(p store.Plan) string {
	if p.ApprovedBy != "" {
		return p.ApprovedBy
	}
	return p.CreatedBy
}

func (s *Server) advanceDryRun(ctx context.Context, p store.Plan) error {
	hosts, err := s.db.ListPlanHosts(ctx, p.ID)
	if err != nil {
		return err
	}
	now := time.Now()
	allDone := true
	for i := range hosts {
		h := &hosts[i]
		switch h.Status {
		case "pending":
			action, params, skip, why := s.planCommand(ctx, p, h.HostID)
			if skip {
				h.Status, h.Output = "dry_ok", why
				break
			}
			c, err := s.QueueCommand(ctx, h.HostID, action, params, true, p.ID, p.CreatedBy)
			if err != nil {
				h.Status, h.Error = "dry_failed", err.Error()
				break
			}
			h.Status, h.StepCmd, h.StepStarted = "dry_run", c.ID, now
			allDone = false
		case "dry_run":
			c, err := s.db.GetCommand(ctx, h.StepCmd)
			if err != nil {
				return err
			}
			switch c.Status {
			case "ok":
				h.Status = "dry_ok"
				if c.Result != nil {
					h.DryChanges, h.Output = s.fillFromVersions(ctx, h.HostID, c.Result.Changes), c.Result.Output
				}
			case "failed", "rejected", "expired":
				h.Status, h.Error = "dry_failed", commandError(c)
			default:
				if now.Sub(h.StepStarted) > dryRunTimeout {
					h.Status, h.Error = "dry_failed", "dry run timed out (host offline?)"
				} else {
					allDone = false
				}
			}
		}
		if err := s.db.SavePlanHost(ctx, *h); err != nil {
			return err
		}
	}
	if !allDone {
		return nil
	}
	if err := s.db.UpdatePlanStatus(ctx, p.ID, "ready", ""); err != nil {
		return err
	}
	s.audit(ctx, "system", "plan.dry_run_complete", p.ID, summarizeDry(hosts))
	s.hub.Publish(Event{Type: "plan", Data: map[string]string{"id": p.ID, "status": "ready", "name": p.Name}})
	if p.PolicyID != "" {
		// automatic plans approve themselves after a successful dry run
		ok, err := s.db.ApprovePlan(ctx, p.ID, "policy:"+p.PolicyID)
		if err == nil && ok {
			s.audit(ctx, "policy:"+p.PolicyID, "plan.approve", p.ID, "automatic (policy)")
		}
	}
	return nil
}

func summarizeDry(hosts []store.PlanHost) string {
	var parts []string
	for _, h := range hosts {
		parts = append(parts, fmt.Sprintf("%s:%s(%d changes)", h.Hostname, h.Status, len(h.DryChanges)))
	}
	return strings.Join(parts, " ")
}

func commandError(c store.CommandRow) string {
	if c.Status == "expired" {
		return "command expired before the agent picked it up (host offline?)"
	}
	if c.Result != nil {
		if c.Result.Error != "" {
			return c.Result.Error
		}
		return "command " + c.Result.Status
	}
	return "command " + c.Status
}

var activeStates = map[string]bool{"snapshot": true, "patching": true, "rebooting": true, "verifying": true}

func (s *Server) advanceRun(ctx context.Context, p store.Plan) error {
	hosts, err := s.db.ListPlanHosts(ctx, p.ID)
	if err != nil {
		return err
	}
	// normalise dry-run outcomes into execution states
	for i := range hosts {
		h := &hosts[i]
		switch h.Status {
		case "dry_ok":
			if len(h.DryChanges) == 0 {
				h.Status = "skipped"
				if h.Output == "" {
					h.Output = "nothing to update"
				}
			} else {
				h.Status = "pending"
			}
			_ = s.db.SavePlanHost(ctx, *h)
		case "dry_failed":
			h.Status = "skipped"
			_ = s.db.SavePlanHost(ctx, *h)
		}
	}
	for i := range hosts {
		if activeStates[hosts[i].Status] {
			if err := s.stepHost(ctx, p, &hosts[i]); err != nil {
				return err
			}
		}
	}
	states := make([]patch.HostState, len(hosts))
	for i, h := range hosts {
		st := h.Status
		if activeStates[st] {
			st = "active"
		}
		states[i] = patch.HostState{ID: h.HostID, Position: h.Position, Status: st}
	}
	d := patch.NextHosts(states, p.Canary, p.MaxParallel)
	windowClosed := false
	if p.PolicyID != "" {
		windowClosed = !s.policyWindowOpen(ctx, p.PolicyID)
	}
	if !d.Abort && !windowClosed {
		for _, id := range d.Start {
			for i := range hosts {
				if hosts[i].HostID == id {
					if err := s.startHost(ctx, p, &hosts[i]); err != nil {
						return err
					}
				}
			}
		}
	}
	active := 0
	for _, h := range hosts {
		if activeStates[h.Status] {
			active++
		}
	}
	if d.Finish || ((d.Abort || windowClosed) && active == 0) {
		status, msg := "done", ""
		failed := 0
		for i := range hosts {
			h := &hosts[i]
			if h.Status == "failed" {
				failed++
			}
			if h.Status == "pending" {
				h.Status = "skipped"
				switch {
				case d.Abort:
					h.Error = "not started: an earlier host failed"
				case windowClosed:
					h.Error = "not started: maintenance window closed"
				}
				_ = s.db.SavePlanHost(ctx, *h)
			}
		}
		if failed > 0 {
			status, msg = "failed", fmt.Sprintf("%d host(s) failed; rollout stopped", failed)
		} else if windowClosed && !d.Finish {
			msg = "maintenance window closed before all hosts were patched"
		}
		if err := s.db.UpdatePlanStatus(ctx, p.ID, status, msg); err != nil {
			return err
		}
		s.audit(ctx, "system", "plan."+status, p.ID, msg+" "+summarizeRun(hosts))
		s.hub.Publish(Event{Type: "plan", Data: map[string]string{"id": p.ID, "status": status, "name": p.Name, "error": msg}})
	}
	return nil
}

func summarizeRun(hosts []store.PlanHost) string {
	var parts []string
	for _, h := range hosts {
		parts = append(parts, fmt.Sprintf("%s:%s", h.Hostname, h.Status))
	}
	return strings.Join(parts, " ")
}

func (s *Server) startHost(ctx context.Context, p store.Plan, h *store.PlanHost) error {
	host, err := s.db.GetHost(ctx, h.HostID)
	if err != nil {
		return err
	}
	h.StartedAt, h.StepStarted, h.BootTimeBefore = time.Now(), time.Now(), host.BootTime
	h.FindingsBefore, _ = s.db.CountFindings(ctx, h.HostID)
	s.audit(ctx, planActor(p), "plan.host.start", h.HostID, "plan="+p.ID)
	if p.SnapshotHook != "" {
		h.Status = "snapshot"
		if err := s.db.SavePlanHost(ctx, *h); err != nil {
			return err
		}
		go s.runSnapshotStep(s.bgCtx, p, *h)
		return nil
	}
	return s.issuePatch(ctx, p, h)
}

func (s *Server) issuePatch(ctx context.Context, p store.Plan, h *store.PlanHost) error {
	action, params, skip, why := s.planCommand(ctx, p, h.HostID)
	if skip {
		h.Status, h.Output, h.FinishedAt = "skipped", why, time.Now()
		return s.db.SavePlanHost(ctx, *h)
	}
	c, err := s.QueueCommand(ctx, h.HostID, action, params, false, p.ID, planActor(p))
	if err != nil {
		h.Status, h.Error = "failed", err.Error()
		return s.db.SavePlanHost(ctx, *h)
	}
	h.Status, h.StepCmd, h.StepStarted = "patching", c.ID, time.Now()
	return s.db.SavePlanHost(ctx, *h)
}

func (s *Server) failHost(ctx context.Context, p store.Plan, h *store.PlanHost, msg string) error {
	h.Status, h.Error, h.FinishedAt = "failed", msg, time.Now()
	s.audit(ctx, "system", "plan.host.failed", h.HostID, "plan="+p.ID+" "+msg)
	s.hub.Publish(Event{Type: "plan_host", HostID: h.HostID, Data: map[string]string{"plan": p.ID, "status": "failed", "error": msg, "name": p.Name}})
	return s.db.SavePlanHost(ctx, *h)
}

func (s *Server) stepHost(ctx context.Context, p store.Plan, h *store.PlanHost) error {
	now := time.Now()
	switch h.Status {
	case "snapshot":
		if now.Sub(h.StepStarted) > snapshotTimout {
			return s.failHost(ctx, p, h, "snapshot step timed out")
		}
		return nil // the snapshot goroutine moves the host on
	case "patching":
		c, err := s.db.GetCommand(ctx, h.StepCmd)
		if err != nil {
			return err
		}
		switch c.Status {
		case "ok":
			if c.Result != nil {
				h.Changes, h.Output, h.RebootRequired = c.Result.Changes, c.Result.Output, c.Result.RebootReq
				if len(h.Changes) > 0 && len(h.DryChanges) > 0 {
					// installed versions were captured at dry run; the inventory is already post-patch now
					from := map[string]string{}
					for _, d := range h.DryChanges {
						from[d.Name] = d.From
					}
					for i := range h.Changes {
						if h.Changes[i].From == "" {
							h.Changes[i].From = from[h.Changes[i].Name]
						}
					}
				}
			}
			needReboot := p.Reboot == "always" || (p.Reboot == "if_required" && h.RebootRequired)
			if needReboot {
				rc, err := s.QueueCommand(ctx, h.HostID, protocol.ActionReboot, protocol.RebootParams{}, false, p.ID, planActor(p))
				if err != nil {
					return s.failHost(ctx, p, h, "queue reboot: "+err.Error())
				}
				h.Status, h.StepCmd, h.StepStarted = "rebooting", rc.ID, now
			} else {
				h.Status, h.StepStarted = "verifying", now
			}
			return s.db.SavePlanHost(ctx, *h)
		case "failed", "rejected", "expired":
			if c.Result != nil {
				h.Output = c.Result.Output
			}
			return s.failHost(ctx, p, h, "patch failed: "+commandError(c))
		}
		if now.Sub(h.StepStarted) > patchTimeout {
			return s.failHost(ctx, p, h, "patch command timed out")
		}
	case "rebooting":
		host, err := s.db.GetHost(ctx, h.HostID)
		if err != nil {
			return err
		}
		if host.BootTime.After(h.BootTimeBefore) && host.Online(now, s.cfg.OfflineAfter) {
			h.Status, h.StepStarted = "verifying", now
			s.audit(ctx, "system", "plan.host.rebooted", h.HostID, "plan="+p.ID)
			return s.db.SavePlanHost(ctx, *h)
		}
		if now.Sub(h.StepStarted) > rebootTimeout {
			return s.failHost(ctx, p, h, "host did not come back online after reboot")
		}
	case "verifying":
		host, err := s.db.GetHost(ctx, h.HostID)
		if err != nil {
			return err
		}
		inv, ierr := s.db.GetInventory(ctx, h.HostID)
		freshInventory := ierr == nil && !inv.ReceivedAt.Before(h.StartedAt.Truncate(time.Second))
		online := host.Online(now, s.cfg.OfflineAfter)
		if !online || !freshInventory {
			if now.Sub(h.StepStarted) > verifyTimeout {
				return s.failHost(ctx, p, h, "verification timed out (agent offline or no post-patch inventory)")
			}
			return nil
		}
		if down := s.downServices(ctx, h.HostID); len(down) > 0 {
			// give services a moment after reboot before failing
			if now.Sub(h.StepStarted) < 2*time.Minute {
				return nil
			}
			return s.failHost(ctx, p, h, "watched services not active after patch: "+strings.Join(down, ", "))
		}
		h.FindingsAfter, _ = s.db.CountFindings(ctx, h.HostID)
		h.Status, h.FinishedAt = "done", now
		s.audit(ctx, "system", "plan.host.done", h.HostID, fmt.Sprintf("plan=%s changes=%d findings %d→%d reboot_required=%v", p.ID, len(h.Changes), h.FindingsBefore, h.FindingsAfter, h.RebootRequired))
		s.hub.Publish(Event{Type: "plan_host", HostID: h.HostID, Data: map[string]string{"plan": p.ID, "status": "done", "name": p.Name}})
		return s.db.SavePlanHost(ctx, *h)
	}
	return nil
}

// downServices returns watched services that are not active according to the latest state.
func (s *Server) downServices(ctx context.Context, hostID string) []string {
	hs, err := s.db.GetHostSettings(ctx, hostID)
	if err != nil || len(hs.WatchServices) == 0 {
		return nil
	}
	h, err := s.db.GetHost(ctx, hostID)
	if err != nil || h.StateJSON == "" {
		return nil
	}
	st := parseState(h.StateJSON)
	active := map[string]bool{}
	for _, sv := range st.Services {
		active[sv.Name] = sv.ActiveState == "active"
	}
	var down []string
	for _, w := range hs.WatchServices {
		if ok, seen := active[w]; seen && !ok {
			down = append(down, w)
		}
	}
	return down
}

// ---- policies ----

func (s *Server) policyWindowOpen(ctx context.Context, policyID string) bool {
	pols, err := s.db.ListPolicies(ctx)
	if err != nil {
		return false
	}
	for _, p := range pols {
		if p.ID == policyID {
			w, err := patch.ParseWindow(p.WindowCron, time.Duration(p.WindowMinutes)*time.Minute)
			if err != nil {
				return false
			}
			open, _ := w.Open(s.now())
			return open
		}
	}
	return false
}

// RunPolicies evaluates every automatic policy and starts plans inside maintenance windows.
func (s *Server) RunPolicies(ctx context.Context) error {
	pols, err := s.db.ListPolicies(ctx)
	if err != nil {
		return err
	}
	active, err := s.db.ListPlans(ctx, "dry_run", "ready", "approved", "running")
	if err != nil {
		return err
	}
	running := map[string]bool{}
	for _, p := range active {
		if p.PolicyID != "" {
			running[p.PolicyID] = true
		}
	}
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		return err
	}
	counts, _ := s.db.UpdateCounts(ctx)
	now := s.now()
	for _, pol := range pols {
		w, werr := patch.ParseWindow(pol.WindowCron, time.Duration(pol.WindowMinutes)*time.Minute)
		var candidates []string
		for _, h := range hosts {
			if h.Revoked || h.Group != pol.Group || !h.Online(now, s.cfg.OfflineAfter) {
				continue
			}
			c := counts[h.ID]
			if (pol.Mode == patch.ModeAutoSecurity && c[1] > 0) || (pol.Mode == patch.ModeAutoAll && c[0] > 0) {
				candidates = append(candidates, h.ID)
			}
		}
		if werr != nil {
			continue
		}
		ok, why := patch.ShouldRun(patch.PolicyInput{Mode: pol.Mode, Enabled: pol.Enabled, Window: w, Now: now, LastRun: pol.LastRun,
			RunningPlan: running[pol.ID], Candidates: len(candidates)})
		if !ok {
			s.log.Debug("policy not run", "policy", pol.Name, "reason", why)
			continue
		}
		scope := "security"
		if pol.Mode == patch.ModeAutoAll {
			scope = "all"
		}
		p, err := s.CreatePlan(ctx, PlanRequest{Name: "Policy " + pol.Name + " · " + now.Format("2006-01-02 15:04"), HostIDs: candidates, Scope: scope,
			Reboot: pol.Reboot, Canary: pol.Canary, MaxParallel: pol.MaxParallel, SnapshotHook: pol.SnapshotHook, SnapshotRequired: pol.SnapshotRequired,
			PolicyID: pol.ID}, "policy:"+pol.Name)
		if err != nil {
			s.log.Warn("policy plan", "policy", pol.Name, "err", err)
			continue
		}
		_ = s.db.TouchPolicy(ctx, pol.ID)
		s.log.Info("policy started automatic patch plan", "policy", pol.Name, "plan", p.ID, "hosts", len(candidates))
	}
	return nil
}

// fillFromVersions completes package changes whose tool output has no "from" version
// (dnf) with the installed version from the latest inventory.
func (s *Server) fillFromVersions(ctx context.Context, hostID string, changes []protocol.PackageChange) []protocol.PackageChange {
	missing := false
	for _, c := range changes {
		if c.From == "" {
			missing = true
		}
	}
	if !missing {
		return changes
	}
	pkgs, err := s.db.ListPackages(ctx, hostID, "")
	if err != nil {
		return changes
	}
	installed := map[string]string{}
	for _, p := range pkgs {
		installed[p.Name] = p.Version
	}
	out := append([]protocol.PackageChange(nil), changes...)
	for i := range out {
		if out[i].From == "" {
			out[i].From = installed[out[i].Name]
		}
	}
	return out
}
