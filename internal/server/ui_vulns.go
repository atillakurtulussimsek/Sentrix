package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln"
)

func vulnFilterFrom(r *http.Request) store.VulnFilter {
	q := r.URL.Query()
	return store.VulnFilter{
		Severity:        q.Get("severity"),
		KEV:             q.Get("kev") == "1",
		Fixable:         q.Get("fixable") == "1",
		Query:           strings.TrimSpace(q.Get("q")),
		IncludeExcepted: q.Get("excepted") == "1",
		Limit:           1000,
	}
}

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	f := vulnFilterFrom(r)
	rows, err := s.db.FleetVulns(r.Context(), f)
	if err != nil {
		s.log.Error("fleet vulns", "err", err)
		s.httpError(w, r, 500, s.t("error.internal"))
		return
	}
	counts, _ := s.db.SeverityCounts(r.Context())
	d := map[string]any{"Rows": rows, "Filter": f, "Counts": counts, "Feeds": s.feedSummary(r.Context())}
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Target") == "vuln-table" {
		s.renderTmpl(w, r, 200, "vulns", "vulntable", "", d)
		return
	}
	s.renderPage(w, r, 200, "vulns", s.t("nav.vulns"), d)
}

type findingView struct {
	store.StoredFinding
	Hostname   string
	Meta       store.VulnMeta
	Components []vuln.RiskComponent
	Exception  *store.Exception
}

func (s *Server) findingViews(ctx context.Context, fs []store.StoredFinding) []findingView {
	ids := make([]string, 0, len(fs))
	for _, f := range fs {
		ids = append(ids, f.VulnID)
	}
	metas, _ := s.db.VulnMetas(ctx, ids)
	hosts, _ := s.db.ListHosts(ctx)
	names := map[string]string{}
	for _, h := range hosts {
		names[h.ID] = h.Hostname
	}
	exc, _ := s.db.ListExceptions(ctx, "")
	now := time.Now()
	out := make([]findingView, 0, len(fs))
	for _, f := range fs {
		v := findingView{StoredFinding: f, Hostname: names[f.HostID], Meta: metas[f.VulnID]}
		_ = json.Unmarshal([]byte(f.RiskJSON), &v.Components)
		for i := range exc {
			if exc[i].Active(now) && exc[i].Covers(f.HostID, f.VulnID) {
				v.Exception = &exc[i]
				break
			}
		}
		out = append(out, v)
	}
	return out
}

func (s *Server) handleVuln(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	meta, err := s.db.GetVuln(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		s.httpError(w, r, 404, "Unknown vulnerability "+id+".")
		return
	}
	if err != nil {
		s.httpError(w, r, 500, s.t("error.internal"))
		return
	}
	fs, _ := s.db.ListFindings(r.Context(), store.FindingFilter{VulnID: id})
	exc, _ := s.db.ListExceptions(r.Context(), id)
	hosts := map[string]bool{}
	for _, f := range fs {
		hosts[f.HostID] = true
	}
	s.renderPage(w, r, 200, "vuln", id, map[string]any{"Meta": meta, "Findings": s.findingViews(r.Context(), fs), "Exceptions": exc,
		"HostCount": len(hosts), "Now": time.Now()})
}

func (s *Server) handleHostVulns(w http.ResponseWriter, r *http.Request) {
	h, d, ok := s.hostPage(w, r, "vulns")
	if !ok {
		return
	}
	fs, _ := s.db.ListFindings(r.Context(), store.FindingFilter{HostID: h.ID})
	views := s.findingViews(r.Context(), fs)
	showExc := r.URL.Query().Get("excepted") == "1"
	kevOnly := r.URL.Query().Get("kev") == "1"
	var shown []findingView
	hidden := 0
	for _, v := range views {
		if v.Exception != nil && !showExc {
			hidden++
			continue
		}
		if kevOnly && !v.Meta.KEV {
			continue
		}
		shown = append(shown, v)
	}
	resolved, _ := s.db.ResolvedFindings(r.Context(), h.ID, 20)
	inv, _ := s.db.GetInventory(r.Context(), h.ID)
	_, _, supported := vuln.Ecosystem(inv.OS)
	d["Findings"], d["Hidden"], d["Resolved"], d["Supported"], d["ShowExcepted"], d["KEVOnly"] = shown, hidden, resolved, supported, showExc, kevOnly
	d["Feeds"] = s.feedSummary(r.Context())
	s.renderPage(w, r, 200, "host_vulns", h.Hostname, d)
}

func (s *Server) handlePackage(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	hosts, err := s.db.HostsWithPackage(r.Context(), name)
	if err != nil {
		s.httpError(w, r, 500, s.t("error.internal"))
		return
	}
	fs, _ := s.db.ListFindings(r.Context(), store.FindingFilter{Package: name})
	s.renderPage(w, r, 200, "package", name, map[string]any{"Name": name, "Hosts": hosts, "Findings": s.findingViews(r.Context(), fs)})
}

func (s *Server) handleExceptionCreate(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	a := authFrom(r.Context())
	kind := r.PostFormValue("kind")
	reason := truncate(strings.TrimSpace(r.PostFormValue("reason")), 1000)
	back := "/vulns/" + url.PathEscape(id)
	if kind != "accepted" && kind != "ignored" || reason == "" {
		s.setFlash(w, "error", "Choose a type and give a reason.")
		http.Redirect(w, r, back, http.StatusSeeOther)
		return
	}
	e := store.Exception{VulnID: id, HostID: r.PostFormValue("host_id"), Kind: kind, Reason: reason, CreatedBy: a.User.Username}
	if days := r.PostFormValue("expires_days"); days != "" && days != "0" {
		if d, err := time.ParseDuration(days + "h"); err == nil {
			e.ExpiresAt = time.Now().Add(d * 24)
		}
	}
	if e.HostID != "" {
		if _, err := s.db.GetHost(r.Context(), e.HostID); err != nil {
			s.httpError(w, r, 400, "unknown host")
			return
		}
	}
	e, err := s.db.CreateException(r.Context(), e)
	if err != nil {
		s.httpError(w, r, 500, s.t("error.internal"))
		return
	}
	scope := "all hosts"
	if e.HostID != "" {
		scope = "host " + e.HostID
	}
	s.auditReq(r, "vuln.exception.create", id, kind+" for "+scope+": "+reason)
	s.setFlash(w, "ok", "Exception recorded.")
	http.Redirect(w, r, back, http.StatusSeeOther)
}

func (s *Server) handleExceptionDelete(w http.ResponseWriter, r *http.Request) {
	e, err := s.db.DeleteException(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.httpError(w, r, 404, s.t("error.notfound"))
		return
	}
	s.auditReq(r, "vuln.exception.delete", e.VulnID, "exception "+e.ID)
	http.Redirect(w, r, "/vulns/"+url.PathEscape(e.VulnID), http.StatusSeeOther) //nolint:gosec // local path
}

type feedView struct {
	store.FeedStatus
	Name, Description string
	Relevant          bool
}

var feedDescriptions = []struct{ key, name, desc string }{
	{"debian-tracker", "Debian Security Tracker", "Fixed versions and open issues for Debian releases (backport-aware)."},
	{"osv-ubuntu", "OSV · Ubuntu", "Ubuntu CVE tracker data via OSV.dev."},
	{"osv-alpine", "OSV · Alpine", "Alpine secdb via OSV.dev."},
	{"osv-rocky", "OSV · Rocky Linux", "Rocky Linux errata (RLSA) via OSV.dev."},
	{"osv-almalinux", "OSV · AlmaLinux", "AlmaLinux errata (ALSA) via OSV.dev."},
	{"cisa-kev", "CISA KEV", "Known exploited vulnerabilities catalog."},
	{"first-epss", "FIRST EPSS", "Exploit prediction scores."},
	{"nvd", "NVD", "CVSS scores for CVEs lacking distro scoring (incremental)."},
}

func (s *Server) feedSummary(ctx context.Context) []feedView {
	st, _ := s.db.GetFeedStatus(ctx)
	ecos, _ := s.fleetEcosystems(ctx)
	var out []feedView
	for _, f := range feedDescriptions {
		rel := true
		if strings.HasPrefix(f.key, "osv-") {
			rel = len(ecos[strings.TrimPrefix(f.key, "osv-")]) > 0
		} else if f.key == "debian-tracker" {
			rel = len(ecos["debian"]) > 0
		}
		out = append(out, feedView{FeedStatus: st[f.key], Name: f.name, Description: f.desc, Relevant: rel})
	}
	return out
}

func (s *Server) handleFeeds(w http.ResponseWriter, r *http.Request) {
	s.renderPage(w, r, 200, "settings_feeds", "Vulnerability feeds", settingsData("feeds", map[string]any{
		"Feeds": s.feedSummary(r.Context()), "Enabled": s.cfg.Feeds.Enabled, "Interval": s.cfg.Feeds.Interval.String(),
		"NVDKey": s.cfg.Feeds.NVDAPIKey != "", "Syncing": s.isSyncing()}))
}

func (s *Server) isSyncing() bool {
	s.feeds.mu.Lock()
	defer s.feeds.mu.Unlock()
	return s.feeds.syncing
}

func (s *Server) handleFeedsSync(w http.ResponseWriter, r *http.Request) {
	if !s.cfg.Feeds.Enabled {
		s.setFlash(w, "error", "Feeds are disabled in the configuration (feeds.enabled).")
		http.Redirect(w, r, "/settings/feeds", http.StatusSeeOther)
		return
	}
	go func() {
		if err := s.SyncFeeds(s.bgCtx, true); err != nil {
			s.log.Warn("manual feed sync", "err", err)
		}
	}()
	s.auditReq(r, "feeds.sync", "", "manual")
	s.setFlash(w, "ok", "Feed synchronisation started. Large feeds can take several minutes.")
	http.Redirect(w, r, "/settings/feeds", http.StatusSeeOther)
}

func (s *Server) enrichRisk(ctx context.Context, sums []*hostSummary) {
	risks, err := s.db.HostRisks(ctx)
	if err != nil {
		return
	}
	for _, h := range sums {
		r := risks[h.ID]
		h.Risk, h.Critical, h.High, h.KEV = r.Risk, r.Critical, r.High, r.KEV
	}
}

func (s *Server) extraHostTabs(ctx context.Context, hostID string) []hostTab {
	risks, _ := s.db.HostRisks(ctx)
	tabs := []hostTab{{Key: "vulns", Label: "Vulnerabilities", Path: "/vulns", Count: risks[hostID].Total}}
	return append(tabs, s.patchHostTabs(ctx, hostID)...)
}

// apiVulns lists fleet vulnerabilities (used by `sentrix cve list`).
func (s *Server) apiVulns(w http.ResponseWriter, r *http.Request) {
	f := vulnFilterFrom(r)
	if sev := r.URL.Query().Get("min_severity"); sev != "" {
		f.Severity = ""
		rows, err := s.db.FleetVulns(r.Context(), f)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, 200, filterMinSeverity(rows, sev))
		return
	}
	rows, err := s.db.FleetVulns(r.Context(), f)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, apiVulnRows(rows))
}

type apiVulnRow struct {
	ID       string  `json:"id"`
	Severity string  `json:"severity"`
	CVSS     float64 `json:"cvss"`
	EPSS     float64 `json:"epss"`
	KEV      bool    `json:"kev"`
	Hosts    int     `json:"hosts"`
	Packages string  `json:"packages"`
	Risk     float64 `json:"risk"`
	Fixable  bool    `json:"fixable"`
	Summary  string  `json:"summary"`
}

var sevRank = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "unknown": 0}

func filterMinSeverity(rows []store.VulnRow, min string) []apiVulnRow {
	var keep []store.VulnRow
	for _, r := range rows {
		if sevRank[r.EffSeverity] >= sevRank[strings.ToLower(min)] {
			keep = append(keep, r)
		}
	}
	return apiVulnRows(keep)
}

func apiVulnRows(rows []store.VulnRow) []apiVulnRow {
	out := make([]apiVulnRow, 0, len(rows))
	for _, r := range rows {
		out = append(out, apiVulnRow{r.ID, r.EffSeverity, r.CVSSScore, r.EPSS, r.KEV, r.Hosts, r.Packages, r.MaxRisk, r.Fixable, r.Summary})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Risk > out[j].Risk })
	return out
}
