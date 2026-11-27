package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/patch"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

func (s *Server) handlePlans(w http.ResponseWriter, r *http.Request) {
	plans, err := s.db.ListPlans(r.Context())
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	s.renderPage(w, r, 200, "patches", s.t(r, "nav.patches"), map[string]any{"Plans": plans})
}

func (s *Server) handlePlanNew(w http.ResponseWriter, r *http.Request) {
	sums, err := s.summaries(r)
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	pre := map[string]bool{}
	for _, id := range splitList(r.URL.Query().Get("hosts")) {
		pre[id] = true
	}
	groups := map[string]bool{}
	for _, h := range sums {
		if h.Group != "" {
			groups[h.Group] = true
		}
	}
	hooks, _ := s.db.ListHooks(r.Context())
	scope := r.URL.Query().Get("scope")
	if scope == "" {
		scope = "security"
	}
	s.renderPage(w, r, 200, "patch_new", s.t(r, "plan.new"), map[string]any{"Hosts": sums, "Selected": pre, "Groups": keysOf(groups), "Scope": scope, "Hooks": hooks})
}

func (s *Server) handlePlanCreate(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.httpError(w, r, 400, s.t(r, "common.invalidForm"))
		return
	}
	canary, _ := strconv.Atoi(r.PostFormValue("canary"))
	parallel, _ := strconv.Atoi(r.PostFormValue("max_parallel"))
	req := PlanRequest{Name: strings.TrimSpace(r.PostFormValue("name")), HostIDs: r.PostForm["hosts"], Group: r.PostFormValue("group"),
		Scope: r.PostFormValue("scope"), Packages: splitList(r.PostFormValue("packages")), Reboot: r.PostFormValue("reboot"),
		Canary: canary, MaxParallel: parallel, SnapshotHook: r.PostFormValue("snapshot_hook"), SnapshotRequired: r.PostFormValue("snapshot_required") == "1"}
	p, err := s.CreatePlan(r.Context(), req, actorOf(r))
	if err != nil {
		s.setFlash(w, "error", err.Error())
		http.Redirect(w, r, "/patches/new", http.StatusSeeOther)
		return
	}
	s.setFlash(w, "ok", s.t(r, "plan.flash.created"))
	http.Redirect(w, r, "/patches/"+p.ID, http.StatusSeeOther) //nolint:gosec // uuid
}

func (s *Server) planData(r *http.Request) (store.Plan, []store.PlanHost, error) {
	p, err := s.db.GetPlan(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		return p, nil, err
	}
	hosts, err := s.db.ListPlanHosts(r.Context(), p.ID)
	return p, hosts, err
}

func (s *Server) handlePlan(w http.ResponseWriter, r *http.Request) {
	p, hosts, err := s.planData(r)
	if errors.Is(err, store.ErrNotFound) {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	audit, _ := s.db.ListAudit(r.Context(), p.ID, 200)
	total := 0
	for _, h := range hosts {
		total += len(h.DryChanges)
	}
	var hookName string
	if p.SnapshotHook != "" {
		if hk, err := s.db.GetHook(r.Context(), p.SnapshotHook); err == nil {
			hookName = hk.Name
		}
	}
	d := map[string]any{"Plan": p, "Hosts": hosts, "Audit": audit, "TotalChanges": total, "HookName": hookName,
		"Active": p.Status == "dry_run" || p.Status == "approved" || p.Status == "running"}
	if r.Header.Get("HX-Request") == "true" {
		s.renderTmpl(w, r, 200, "patch", "planbody", "", d)
		return
	}
	s.renderPage(w, r, 200, "patch", p.Name, d)
}

func (s *Server) handlePlanApprove(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if r.PostFormValue("confirm") != "1" {
		s.setFlash(w, "error", s.t(r, "plan.flash.confirmRequired"))
	} else if err := s.ApprovePlan(r.Context(), id, actorOf(r)); err != nil {
		s.setFlash(w, "error", err.Error())
	} else {
		s.setFlash(w, "ok", s.t(r, "plan.flash.approved"))
	}
	http.Redirect(w, r, "/patches/"+id, http.StatusSeeOther) //nolint:gosec // local path
}

func (s *Server) handlePlanCancel(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.CancelPlan(r.Context(), id, actorOf(r)); err != nil {
		s.setFlash(w, "error", err.Error())
	} else {
		s.setFlash(w, "ok", s.t(r, "plan.flash.cancelled"))
	}
	http.Redirect(w, r, "/patches/"+id, http.StatusSeeOther) //nolint:gosec // local path
}

// host actions (operator)
func (s *Server) handleHostAction(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.db.GetHost(r.Context(), id); err != nil {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	action := protocol.Action(r.PostFormValue("action"))
	var params any
	switch action {
	case protocol.ActionRefreshInventory, protocol.ActionScan:
	case protocol.ActionReboot:
		if r.PostFormValue("confirm") != "1" {
			s.setFlash(w, "error", s.t(r, "patch.action.rebootConfirm"))
			http.Redirect(w, r, "/hosts/"+id+"/patches", http.StatusSeeOther) //nolint:gosec // local path
			return
		}
		params = protocol.RebootParams{}
	case protocol.ActionRestartService:
		params = protocol.RestartServiceParams{Name: strings.TrimSpace(r.PostFormValue("service"))}
	default:
		s.httpError(w, r, 400, s.t(r, "patch.action.unsupported"))
		return
	}
	if _, err := s.QueueCommand(r.Context(), id, action, params, false, "", actorOf(r)); err != nil {
		s.setFlash(w, "error", err.Error())
	} else {
		s.setFlash(w, "ok", s.t(r, "patch.action.queued", string(action)))
	}
	http.Redirect(w, r, "/hosts/"+id+"/patches", http.StatusSeeOther) //nolint:gosec // local path
}

func (s *Server) handleHostPatches(w http.ResponseWriter, r *http.Request) {
	h, d, ok := s.hostPage(w, r, "patches")
	if !ok {
		return
	}
	d["Plans"], _ = s.db.HostPlans(r.Context(), h.ID)
	d["Commands"], _ = s.db.ListHostCommands(r.Context(), h.ID, 50)
	d["Settings"], _ = s.db.GetHostSettings(r.Context(), h.ID)
	s.renderPage(w, r, 200, "host_patches", h.Hostname, d)
}

func (s *Server) patchHostTabs(ctx context.Context, _ string) []hostTab {
	return []hostTab{{Key: "patches", Label: s.cat.T(s.ctxLang(ctx), "patch.hostTab"), Path: "/patches"}}
}

func (s *Server) handleHostSettings(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	h, err := s.db.GetHost(r.Context(), id)
	if err != nil {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	hs, _ := s.db.GetHostSettings(r.Context(), id)
	hs.WatchServices = nil
	for _, u := range splitList(r.PostFormValue("watch_services")) {
		if protocol.ValidUnitName(u) {
			hs.WatchServices = append(hs.WatchServices, u)
		}
	}
	hs.TLSEndpoints = splitList(r.PostFormValue("tls_endpoints"))
	hs.ProxmoxVMID = strings.TrimSpace(r.PostFormValue("proxmox_vmid"))
	hs.ProxmoxNode = strings.TrimSpace(r.PostFormValue("proxmox_node"))
	if err := s.db.SaveHostSettings(r.Context(), id, hs); err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	group := truncate(strings.TrimSpace(r.PostFormValue("group")), 64)
	tags := splitList(r.PostFormValue("tags"))
	_ = s.db.SetHostLabels(r.Context(), id, group, tags)
	s.auditReq(r, "host.settings", id, fmt.Sprintf("group=%s tags=%s watch=%s tls=%s proxmox=%s/%s", group, strings.Join(tags, ","), strings.Join(hs.WatchServices, ","), strings.Join(hs.TLSEndpoints, ","), hs.ProxmoxNode, hs.ProxmoxVMID))
	s.setFlash(w, "ok", s.t(r, "patch.hostSettings.saved", h.Hostname))
	http.Redirect(w, r, "/hosts/"+id+"/patches", http.StatusSeeOther) //nolint:gosec // local path
}

// ---- policies (admin) ----

func (s *Server) handlePolicies(w http.ResponseWriter, r *http.Request) {
	pols, _ := s.db.ListPolicies(r.Context())
	hooks, _ := s.db.ListHooks(r.Context())
	type pv struct {
		store.Policy
		NextWindow time.Time
		OpenNow    bool
		Err        string
	}
	var views []pv
	for _, p := range pols {
		v := pv{Policy: p}
		if wd, err := patch.ParseWindow(p.WindowCron, time.Duration(p.WindowMinutes)*time.Minute); err == nil {
			v.OpenNow, _ = wd.Open(time.Now())
			v.NextWindow = wd.Next(time.Now())
		} else {
			v.Err = s.t(r, "patch.policy.windowError", err.Error())
		}
		views = append(views, v)
	}
	hosts, _ := s.db.ListHosts(r.Context())
	groups := map[string]bool{}
	for _, h := range hosts {
		groups[h.Group] = true
	}
	s.renderPage(w, r, 200, "settings_policies", s.t(r, "patch.policy.title"), settingsData("policies", map[string]any{"Policies": views, "Hooks": hooks, "Groups": keysOf(groups)}))
}

func (s *Server) handlePolicySave(w http.ResponseWriter, r *http.Request) {
	wm, _ := strconv.Atoi(r.PostFormValue("window_minutes"))
	mp, _ := strconv.Atoi(r.PostFormValue("max_parallel"))
	can, _ := strconv.Atoi(r.PostFormValue("canary"))
	p := store.Policy{ID: r.PostFormValue("id"), Name: truncate(strings.TrimSpace(r.PostFormValue("name")), 100), Group: strings.TrimSpace(r.PostFormValue("group")),
		Mode: r.PostFormValue("mode"), WindowCron: strings.TrimSpace(r.PostFormValue("window_cron")), WindowMinutes: wm, MaxParallel: max(1, mp), Canary: max(0, can),
		Reboot: r.PostFormValue("reboot"), SnapshotHook: r.PostFormValue("snapshot_hook"), SnapshotRequired: r.PostFormValue("snapshot_required") == "1",
		Enabled: r.PostFormValue("enabled") == "1"}
	back := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/settings/policies", http.StatusSeeOther)
	}
	if p.Name == "" {
		back("error", s.t(r, "patch.policy.nameRequired"))
		return
	}
	switch p.Mode {
	case patch.ModeNotifyOnly, patch.ModeAutoSecurity, patch.ModeAutoAll:
	default:
		back("error", s.t(r, "patch.policy.invalidMode"))
		return
	}
	if p.Reboot != "never" && p.Reboot != "if_required" && p.Reboot != "always" {
		p.Reboot = "never"
	}
	if p.Mode != patch.ModeNotifyOnly {
		if _, err := patch.ParseWindow(p.WindowCron, time.Duration(p.WindowMinutes)*time.Minute); err != nil {
			back("error", s.t(r, "patch.policy.invalidWindow", err.Error()))
			return
		}
		if r.PostFormValue("accept_disclaimer") != "1" {
			back("error", s.t(r, "patch.policy.acceptDisclaimer"))
			return
		}
	}
	p, err := s.db.SavePolicy(r.Context(), p)
	if err != nil {
		back("error", s.t(r, "patch.policy.saveFailed"))
		return
	}
	s.auditReq(r, "policy.save", p.ID, fmt.Sprintf("name=%q group=%q mode=%s window=%q/%dm reboot=%s canary=%d parallel=%d enabled=%v", p.Name, p.Group, p.Mode, p.WindowCron, p.WindowMinutes, p.Reboot, p.Canary, p.MaxParallel, p.Enabled))
	back("ok", s.t(r, "patch.policy.saved"))
}

func (s *Server) handlePolicyDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_ = s.db.DeletePolicy(r.Context(), id)
	s.auditReq(r, "policy.delete", id, "")
	http.Redirect(w, r, "/settings/policies", http.StatusSeeOther)
}
