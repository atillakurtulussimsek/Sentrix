package server

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/web"
)

// UIHandler returns the web UI + REST API handler.
func (s *Server) UIHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(s.accessLog, securityHeaders, limitBody)
	r.Get("/healthz", s.handleHealth)
	r.Get("/install.sh", s.handleInstallScript)
	r.Get("/download/{name}", s.handleDownload)
	static, _ := fs.Sub(web.Static, "static")
	r.Handle("/static/*", http.StripPrefix("/static/", cacheStatic(http.FileServer(http.FS(static)))))

	r.Group(func(r chi.Router) {
		r.Use(s.requireSetupDone, s.identify, s.withLang, s.csrf)
		r.Post("/lang", s.handleSetLanguage)
		r.Get("/setup", s.handleSetupForm)
		r.Post("/setup", s.handleSetup)
		r.Get("/login", s.handleLoginForm)
		r.Post("/login", s.handleLogin)
		r.Get("/login/mfa", s.handleMFAForm)
		r.Post("/login/mfa", s.handleMFA)
		r.Post("/logout", s.handleLogout)

		// viewer+
		r.Group(func(r chi.Router) {
			r.Use(s.requireRole(store.RoleViewer))
			r.Get("/", s.handleDashboard)
			r.Get("/hosts", s.handleHosts)
			r.Get("/hosts/{id}", s.handleHostOverview)
			r.Get("/hosts/{id}/state", s.handleHostState)
			r.Get("/hosts/{id}/inventory", s.handleHostInventory)
			r.Get("/hosts/{id}/updates", s.handleHostUpdates)
			r.Get("/hosts/{id}/stream", s.handleHostStream)
			r.Get("/api/v1/hosts", s.apiHosts)
			r.Get("/api/v1/hosts/{id}/series", s.apiSeries)
			r.Get("/api/v1/me", s.apiMe)
			s.viewerRoutes(r)
		})
		// operator+
		r.Group(func(r chi.Router) {
			r.Use(s.requireRole(store.RoleOperator))
			s.operatorRoutes(r)
		})
		// admin
		r.Group(func(r chi.Router) {
			r.Use(s.requireRole(store.RoleAdmin))
			r.Get("/settings", func(w http.ResponseWriter, r *http.Request) {
				http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
			})
			r.Get("/settings/users", s.handleUsers)
			r.Post("/settings/users", s.handleUserCreate)
			r.Post("/settings/users/{id}/role", s.handleUserRole)
			r.Post("/settings/users/{id}/toggle", s.handleUserToggle)
			r.Post("/settings/users/{id}/delete", s.handleUserDelete)
			r.Get("/settings/enrollment", s.handleEnrollment)
			r.Post("/settings/enrollment", s.handleEnrollmentCreate)
			r.Post("/settings/enrollment/{id}/delete", s.handleEnrollmentDelete)
			r.Get("/audit", s.handleAudit)
			r.Post("/hosts/{id}/revoke", s.handleHostRevoke)
			r.Post("/hosts/{id}/delete", s.handleHostDelete)
			s.adminRoutes(r)
		})
		r.NotFound(func(w http.ResponseWriter, r *http.Request) {
			s.httpError(w, r, http.StatusNotFound, s.t(r, "error.notfound"))
		})
	})
	return r
}

func cacheStatic(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=3600")
		h.ServeHTTP(w, r)
	})
}


func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.db.SQL().PingContext(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

const (
	iconDashboard = `<rect x="3" y="3" width="7" height="9" rx="1"/><rect x="14" y="3" width="7" height="5" rx="1"/><rect x="14" y="12" width="7" height="9" rx="1"/><rect x="3" y="16" width="7" height="5" rx="1"/>`
	iconHosts     = `<rect x="2" y="3" width="20" height="7" rx="2"/><rect x="2" y="14" width="20" height="7" rx="2"/><path d="M6 6.5h.01M6 17.5h.01"/>`
	iconVuln      = `<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="M12 8v4M12 16h.01"/>`
	iconPatch     = `<path d="M14.7 6.3a1 1 0 0 0 0 1.4l1.6 1.6a1 1 0 0 0 1.4 0l3.8-3.8a6 6 0 0 1-7.9 7.9l-6.9 6.9a2.1 2.1 0 0 1-3-3l6.9-6.9a6 6 0 0 1 7.9-7.9z"/>`
	iconAlert     = `<path d="M6 8a6 6 0 0 1 12 0c0 7 3 9 3 9H3s3-2 3-9"/><path d="M10.3 21a1.9 1.9 0 0 0 3.4 0"/>`
	iconAudit     = `<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z"/><path d="M14 2v6h6M8 13h8M8 17h5"/>`
	iconSettings  = `<circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1.1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1.1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/>`
)

func (s *Server) nav(r *http.Request, a *authInfo) []navItem {
	p := r.URL.Path
	active := func(prefix string) bool {
		if prefix == "/" {
			return p == "/"
		}
		return strings.HasPrefix(p, prefix)
	}
	items := []navItem{
		{Href: "/", Label: s.t(r, "nav.dashboard"), Icon: iconDashboard, Active: active("/")},
		{Href: "/hosts", Label: s.t(r, "nav.hosts"), Icon: iconHosts, Active: active("/hosts")},
		{Href: "/vulns", Label: s.t(r, "nav.vulns"), Icon: iconVuln, Active: active("/vulns")},
		{Href: "/patches", Label: s.t(r, "nav.patches"), Icon: iconPatch, Active: active("/patches")},
		{Href: "/alerts", Label: s.t(r, "nav.alerts"), Icon: iconAlert, Active: active("/alerts"), Badge: s.firingAlerts(r)},
	}
	if a != nil && store.RoleRank(a.Role) >= store.RoleRank(store.RoleAdmin) {
		items = append(items,
			navItem{Href: "/audit", Label: s.t(r, "nav.audit"), Icon: iconAudit, Active: active("/audit")},
			navItem{Href: "/settings", Label: s.t(r, "nav.settings"), Icon: iconSettings, Active: active("/settings")})
	} else if a != nil {
		items = append(items, navItem{Href: "/settings/account", Label: s.t(r, "nav.settings"), Icon: iconSettings, Active: active("/settings")})
	}
	return items
}

// renderPage renders a full page with layout.
func (s *Server) renderPage(w http.ResponseWriter, r *http.Request, status int, name, title string, data any) {
	s.renderTmpl(w, r, status, name, "layout", title, data)
}

func (s *Server) renderTmpl(w http.ResponseWriter, r *http.Request, status int, name, tmpl, title string, data any) {
	p := page{Title: title, Lang: s.lang(r), Languages: s.cat.Options(), CSRF: s.csrfToken(w, r), AssetVersion: assetVersion, Data: data}
	if a := authFrom(r.Context()); a != nil && (a.Session == nil || !a.Session.MFAPending) {
		u := a.User
		u.Role = a.Role
		p.User = &u
		p.Nav = s.nav(r, a)
		p.FeedsStale = s.feedsStale(r)
	}
	p.Flash = s.popFlash(w, r)
	if err := s.rend.render(w, status, name, tmpl, p); err != nil {
		s.log.Error("render", "template", name, "err", err)
		http.Error(w, "template error", http.StatusInternalServerError)
	}
}

// ---- host summaries ----

type hostSummary struct {
	ID, Hostname, Status, OS, Group string
	Tags                            []string
	LastSeen                        time.Time
	CPU, Mem, Disk                  float64
	RebootRequired                  bool
	RebootSince                     time.Time
	Updates, SecUpdates             int
	Risk                            float64
	Critical, High, KEV             int
	FailedUnits                     []string
	ServicesDown                    []string
}

func (s *Server) hostStatus(h store.Host) string {
	switch {
	case h.Revoked:
		return "revoked"
	case h.Online(time.Now(), s.cfg.OfflineAfter):
		return "online"
	}
	return "offline"
}

func (s *Server) summaries(r *http.Request) ([]*hostSummary, error) {
	hosts, err := s.db.ListHosts(r.Context())
	if err != nil {
		return nil, err
	}
	latest, err := s.db.LatestFleet(r.Context(), "cpu.usage", "mem.used_pct", "disk.used_pct")
	if err != nil {
		return nil, err
	}
	out := make([]*hostSummary, 0, len(hosts))
	for _, h := range hosts {
		hs := &hostSummary{ID: h.ID, Hostname: h.Hostname, Status: s.hostStatus(h), Group: h.Group, Tags: h.Tags, LastSeen: h.LastSeen, CPU: -1, Mem: -1, Disk: -1}
		if m := latest[h.ID]; m != nil {
			if v, ok := m["cpu.usage"]; ok {
				hs.CPU = v
			}
			if v, ok := m["mem.used_pct"]; ok {
				hs.Mem = v
			}
			for k, v := range m {
				if strings.HasPrefix(k, "disk.used_pct") && v > hs.Disk {
					hs.Disk = v
				}
			}
		}
		if h.StateJSON != "" {
			var st protocol.HostState
			if json.Unmarshal([]byte(h.StateJSON), &st) == nil {
				hs.RebootRequired = st.Reboot.Required
				hs.FailedUnits = st.FailedUnits
				for _, sv := range st.Services {
					if sv.ActiveState != "active" {
						hs.ServicesDown = append(hs.ServicesDown, sv.Name)
					}
				}
			}
		}
		out = append(out, hs)
	}
	s.enrichSummaries(r.Context(), out)
	return out, nil
}

// ---- dashboard ----

type attentionItem struct {
	Tone, Host, Href, Text, When string
}

func (s *Server) handleDashboard(w http.ResponseWriter, r *http.Request) {
	sums, err := s.summaries(r)
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	d := map[string]any{"Now": time.Now(), "Total": len(sums)}
	var online, offline, updates, reboots, crit, kev int
	var att []attentionItem
	for _, h := range sums {
		switch h.Status {
		case "online":
			online++
		case "offline":
			offline++
			att = append(att, attentionItem{"bad", h.Hostname, "/hosts/" + h.ID, "Agent offline", relTime(s.cat, s.lang(r), h.LastSeen)})
		}
		updates += h.Updates
		crit += h.Critical
		kev += h.KEV
		if h.RebootRequired {
			reboots++
			att = append(att, attentionItem{"warn", h.Hostname, "/hosts/" + h.ID, "Reboot required", ""})
		}
		if h.Disk >= 90 {
			att = append(att, attentionItem{"bad", h.Hostname, "/hosts/" + h.ID, "Disk " + pctStr(h.Disk) + " full", ""})
		}
		for _, u := range h.FailedUnits {
			att = append(att, attentionItem{"bad", h.Hostname, "/hosts/" + h.ID, "Failed unit " + u, ""})
		}
		if h.KEV > 0 {
			att = append(att, attentionItem{"bad", h.Hostname, "/hosts/" + h.ID + "/vulns?kev=1", pluralize(h.KEV, "known exploited vulnerability", "known exploited vulnerabilities"), ""})
		} else if h.Critical > 0 {
			att = append(att, attentionItem{"bad", h.Hostname, "/hosts/" + h.ID + "/vulns", pluralize(h.Critical, "critical vulnerability", "critical vulnerabilities"), ""})
		}
		if h.SecUpdates > 0 {
			att = append(att, attentionItem{"warn", h.Hostname, "/hosts/" + h.ID + "/updates", pluralize(h.SecUpdates, "security update pending", "security updates pending"), ""})
		}
	}
	risk := append([]*hostSummary(nil), sums...)
	sort.Slice(risk, func(i, j int) bool { return risk[i].Risk > risk[j].Risk })
	var top []*hostSummary
	for _, h := range risk {
		if h.Risk > 0 && len(top) < 8 {
			top = append(top, h)
		}
	}
	if len(att) > 25 {
		att = att[:25]
	}
	d["Online"], d["Offline"], d["Updates"], d["Reboots"], d["Critical"], d["KEV"] = online, offline, updates, reboots, crit, kev
	d["Attention"], d["TopRisk"], d["FeedSync"] = att, top, s.lastFeedSync(r)
	s.renderPage(w, r, 200, "dashboard", s.t(r, "nav.dashboard"), d)
}

func pluralize(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return itoa(n) + " " + many
}

// ---- hosts ----

func (s *Server) handleHosts(w http.ResponseWriter, r *http.Request) {
	sums, err := s.summaries(r)
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	status, group := r.URL.Query().Get("status"), r.URL.Query().Get("group")
	groupSet := map[string]bool{}
	var filtered []*hostSummary
	for _, h := range sums {
		if h.Group != "" {
			groupSet[h.Group] = true
		}
		if status != "" && h.Status != status {
			continue
		}
		if group != "" && h.Group != group {
			continue
		}
		if r.URL.Query().Get("reboot") == "1" && !h.RebootRequired {
			continue
		}
		if q != "" && !strings.Contains(strings.ToLower(h.Hostname+" "+h.Group+" "+strings.Join(h.Tags, " ")+" "+h.OS), q) {
			continue
		}
		filtered = append(filtered, h)
	}
	switch r.URL.Query().Get("sort") {
	case "updates":
		sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Updates > filtered[j].Updates })
	case "risk":
		sort.SliceStable(filtered, func(i, j int) bool { return filtered[i].Risk > filtered[j].Risk })
	}
	groups := make([]string, 0, len(groupSet))
	for g := range groupSet {
		groups = append(groups, g)
	}
	sort.Strings(groups)
	s.renderPage(w, r, 200, "hosts", s.t(r, "nav.hosts"), map[string]any{"Hosts": filtered, "Query": r.URL.Query().Get("q"), "Status": status, "Group": group, "Groups": groups})
}

type hostTab struct {
	Key, Label, Path string
	Count            int
}

type chartDef struct {
	ID, Title, Metrics, Unit string
	ByLabel                  bool
}

var hostCharts = []chartDef{
	{"cpu", "CPU", "cpu.usage,cpu.iowait,cpu.steal", "%", false},
	{"mem", "Memory & swap", "mem.used_pct,swap.used_pct", "%", false},
	{"load", "Load average", "load.1,load.5,load.15", "", false},
	{"disk", "Disk usage", "disk.used_pct", "%", true},
	{"net", "Network", "net.rx_bps,net.tx_bps", "B/s", true},
	{"diskio", "Disk I/O", "diskio.read_bps,diskio.write_bps", "B/s", true},
}

// hostPage loads the host + common header data for host sub-pages.
func (s *Server) hostPage(w http.ResponseWriter, r *http.Request, tab string) (store.Host, map[string]any, bool) {
	h, err := s.db.GetHost(r.Context(), chi.URLParam(r, "id"))
	if errors.Is(err, store.ErrNotFound) {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return h, nil, false
	}
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return h, nil, false
	}
	var st protocol.HostState
	_ = json.Unmarshal([]byte(h.StateJSON), &st)
	d := map[string]any{"Host": h, "Status": s.hostStatus(h), "Tab": tab, "State": st, "OS": s.hostOS(r.Context(), h.ID)}
	d["Tabs"] = s.hostTabs(r.Context(), h.ID)
	return h, d, true
}

func (s *Server) handleHostOverview(w http.ResponseWriter, r *http.Request) {
	h, d, ok := s.hostPage(w, r, "overview")
	if !ok {
		return
	}
	d["Charts"] = hostCharts
	s.renderPage(w, r, 200, "host_overview", h.Hostname, d)
}

func (s *Server) handleHostState(w http.ResponseWriter, r *http.Request) {
	h, err := s.db.GetHost(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	var st protocol.HostState
	_ = json.Unmarshal([]byte(h.StateJSON), &st)
	s.renderTmpl(w, r, 200, "host_overview", "hoststate", "", map[string]any{"Host": h, "State": st})
}

// handleHostStream streams live metric samples for one host via Server-Sent Events.
func (s *Server) handleHostStream(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if _, err := s.db.GetHost(r.Context(), id); err != nil {
		http.NotFound(w, r)
		return
	}
	rc := http.NewResponseController(w)
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("X-Accel-Buffering", "no")
	ch, unsub := s.hub.Subscribe()
	defer unsub()
	_, _ = w.Write([]byte(": connected\n\n"))
	_ = rc.Flush()
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-r.Context().Done():
			return
		case <-ping.C:
			if _, err := w.Write([]byte(": ping\n\n")); err != nil {
				return
			}
			_ = rc.Flush()
		case ev, ok := <-ch:
			if !ok {
				return
			}
			if ev.HostID != id {
				continue
			}
			b, err := json.Marshal(ev.Data)
			if err != nil {
				continue
			}
			if _, err := w.Write([]byte("event: " + ev.Type + "\ndata: " + string(b) + "\n\n")); err != nil {
				return
			}
			_ = rc.Flush()
		}
	}
}

func (s *Server) handleHostRevoke(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.db.SetHostRevoked(r.Context(), id, true); err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	s.auditReq(r, "host.revoke", id, "")
	s.setFlash(w, "ok", "Agent certificate revoked. The agent can no longer connect.")
	http.Redirect(w, r, "/hosts/"+url.PathEscape(id), http.StatusSeeOther) //nolint:gosec // local path
}

func (s *Server) handleHostDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.db.DeleteHost(r.Context(), id); err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	s.auditReq(r, "host.delete", id, "")
	s.setFlash(w, "ok", "Host deleted.")
	http.Redirect(w, r, "/hosts", http.StatusSeeOther)
}

// auditReq records an action by the requesting user.
func (s *Server) auditReq(r *http.Request, action, target, detail string) {
	actor := "anonymous"
	if a := authFrom(r.Context()); a != nil {
		actor = "user:" + a.User.Username
		if a.Session == nil {
			actor += " (" + a.Via + ")"
		}
	}
	s.audit(r.Context(), actor, action, target, detail)
}

var _ = template.HTML("")

func parseState(js string) protocol.HostState {
	var st protocol.HostState
	_ = json.Unmarshal([]byte(js), &st)
	return st
}
