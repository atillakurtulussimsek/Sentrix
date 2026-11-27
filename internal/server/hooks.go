package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
	"github.com/atillakurtulussimsek/Sentrix/internal/patch"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// runHook executes a pre-patch hook for one host and returns the snapshot name.
func (s *Server) runHook(ctx context.Context, hookID string, t patch.HookTarget) (string, error) {
	hk, err := s.db.GetHook(ctx, hookID)
	if err != nil {
		return "", fmt.Errorf("hook not found: %w", err)
	}
	switch hk.Kind {
	case "proxmox":
		var c patch.ProxmoxConfig
		if err := json.Unmarshal([]byte(hk.Config), &c); err != nil {
			return "", err
		}
		if c.TokenSecret, err = s.box.Open(c.TokenSecret); err != nil {
			return "", err
		}
		return c.Snapshot(ctx, t, s.now())
	case "webhook":
		var c patch.WebhookConfig
		if err := json.Unmarshal([]byte(hk.Config), &c); err != nil {
			return "", err
		}
		if c.Secret, err = s.box.Open(c.Secret); err != nil {
			return "", err
		}
		return c.CallWebhook(ctx, t)
	}
	return "", fmt.Errorf("unknown hook kind %q", hk.Kind)
}

// runSnapshotStep runs the plan's pre-patch hook for a host, then issues the patch.
// If the snapshot fails and the plan requires it, the host is aborted (not patched).
func (s *Server) runSnapshotStep(ctx context.Context, p store.Plan, h store.PlanHost) {
	hs, _ := s.db.GetHostSettings(ctx, h.HostID)
	t := patch.HookTarget{PlanID: p.ID, PlanName: p.Name, HostID: h.HostID, Hostname: h.Hostname, ProxmoxNode: hs.ProxmoxNode, ProxmoxVMID: hs.ProxmoxVMID}
	hctx, cancel := context.WithTimeout(ctx, snapshotTimout)
	name, err := s.runHook(hctx, p.SnapshotHook, t)
	cancel()
	s.orchMu.Lock()
	defer s.orchMu.Unlock()
	cur, lerr := s.planHost(ctx, p.ID, h.HostID)
	if lerr != nil || cur.Status != "snapshot" {
		return // plan cancelled or state changed meanwhile
	}
	if err != nil {
		s.audit(ctx, "system", "plan.host.snapshot_failed", h.HostID, "plan="+p.ID+" "+err.Error())
		if p.SnapshotRequired {
			_ = s.failHost(ctx, p, &cur, s.tDefault("orch.snapshotRequiredFailed", err.Error()))
			s.kickOrchestrator()
			return
		}
		cur.Output = s.tDefault("orch.snapshotOptionalFailed", err.Error())
	} else {
		cur.Snapshot = name
		s.audit(ctx, "system", "plan.host.snapshot", h.HostID, "plan="+p.ID+" snapshot="+name)
	}
	if err := s.issuePatch(ctx, p, &cur); err != nil {
		s.log.Error("issue patch after snapshot", "err", err)
	}
	s.kickOrchestrator()
}

func (s *Server) planHost(ctx context.Context, planID, hostID string) (store.PlanHost, error) {
	hosts, err := s.db.ListPlanHosts(ctx, planID)
	if err != nil {
		return store.PlanHost{}, err
	}
	for _, h := range hosts {
		if h.HostID == hostID {
			return h, nil
		}
	}
	return store.PlanHost{}, store.ErrNotFound
}

// ---- UI ----

type hookView struct {
	store.Hook
	Target string
}

func (s *Server) handleHooks(w http.ResponseWriter, r *http.Request) {
	hooks, _ := s.db.ListHooks(r.Context())
	var views []hookView
	for _, h := range hooks {
		var m map[string]any
		_ = json.Unmarshal([]byte(h.Config), &m)
		target, _ := m["url"].(string)
		views = append(views, hookView{h, target})
	}
	s.renderPage(w, r, 200, "settings_hooks", s.t(r, "settings.nav.hooks"), settingsData("hooks", map[string]any{"Hooks": views}))
}

func (s *Server) handleHookSave(w http.ResponseWriter, r *http.Request) {
	back := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/settings/hooks", http.StatusSeeOther)
	}
	kind := r.PostFormValue("kind")
	name := truncate(strings.TrimSpace(r.PostFormValue("name")), 100)
	if name == "" {
		back("error", s.t(r, "hooks.nameRequired"))
		return
	}
	var cfg any
	switch kind {
	case "proxmox":
		secret, err := s.box.Seal(strings.TrimSpace(r.PostFormValue("token_secret")))
		if err != nil {
			back("error", s.t(r, "hooks.encryptFailed"))
			return
		}
		c := patch.ProxmoxConfig{URL: strings.TrimSpace(r.PostFormValue("url")), TokenID: strings.TrimSpace(r.PostFormValue("token_id")), TokenSecret: secret,
			DefaultNode: strings.TrimSpace(r.PostFormValue("default_node")), Insecure: r.PostFormValue("insecure") == "1",
			CAFingerprint: strings.TrimSpace(r.PostFormValue("ca_fingerprint")), VMState: r.PostFormValue("vmstate") == "1"}
		check := c
		check.TokenSecret = "x"
		if err := check.Validate(); err != nil || r.PostFormValue("token_secret") == "" {
			back("error", s.t(r, "hooks.proxmoxInvalid"))
			return
		}
		cfg = c
	case "webhook":
		secret, err := s.box.Seal(r.PostFormValue("secret"))
		if err != nil {
			back("error", s.t(r, "hooks.encryptFailed"))
			return
		}
		u := strings.TrimSpace(r.PostFormValue("url"))
		if !strings.HasPrefix(u, "https://") && !strings.HasPrefix(u, "http://") {
			back("error", s.t(r, "hooks.webhookUrlRequired"))
			return
		}
		cfg = patch.WebhookConfig{URL: u, Secret: secret}
	default:
		back("error", s.t(r, "hooks.unknownKind"))
		return
	}
	b, _ := json.Marshal(cfg)
	hk, err := s.db.SaveHook(r.Context(), store.Hook{Name: name, Kind: kind, Config: string(b)})
	if err != nil {
		back("error", s.t(r, "hooks.saveFailed"))
		return
	}
	s.auditReq(r, "hook.create", hk.ID, "name="+name+" kind="+kind)
	back("ok", s.t(r, "hooks.saved"))
}

func (s *Server) handleHookTest(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	hk, err := s.db.GetHook(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 30*time.Second)
	defer cancel()
	// key/arg describe the result; the audit log keeps English, the flash uses the request language
	var key string
	var args []any
	kind := "ok"
	switch hk.Kind {
	case "proxmox":
		var c patch.ProxmoxConfig
		_ = json.Unmarshal([]byte(hk.Config), &c)
		c.TokenSecret, _ = s.box.Open(c.TokenSecret)
		v, err := c.Ping(ctx)
		if err != nil {
			key, args, kind = "hooks.connFailed", []any{err.Error()}, "error"
		} else {
			key, args = "hooks.connOk", []any{v}
		}
	case "webhook":
		_, err := s.runHook(ctx, id, patch.HookTarget{PlanID: "test", PlanName: "connection test", Hostname: "sentrix-test"})
		if err != nil {
			key, args, kind = "hooks.webhookFailed", []any{err.Error()}, "error"
		} else {
			key = "hooks.webhookOk"
		}
	default:
		key, kind = "hooks.unknownKind", "error"
	}
	s.auditReq(r, "hook.test", id, s.cat.T(i18n.FallbackLang, key, args...))
	s.setFlash(w, kind, s.t(r, key, args...))
	http.Redirect(w, r, "/settings/hooks", http.StatusSeeOther)
}

func (s *Server) handleHookDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_ = s.db.DeleteHook(r.Context(), id)
	s.auditReq(r, "hook.delete", id, "")
	http.Redirect(w, r, "/settings/hooks", http.StatusSeeOther)
}
