package server

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// Package management (admin): every install/remove starts as a dry run on the agent;
// the admin reviews the simulated transaction and applies it within previewTTL.
const previewTTL = time.Hour

// pkgPreview is a dry-run install/remove shown on the host's patches tab.
type pkgPreview struct {
	Cmd        store.CommandRow
	Op         string // install | remove | purge
	Packages   []string
	Installs   []protocol.PackageChange
	Removals   []protocol.PackageChange
	Applied    bool
	Expired    bool
	Applicable bool
}

// pkgOpParams maps a form operation to an action and its parameters.
func pkgOpParams(op string, pkgs []string) (protocol.Action, any, bool) {
	switch op {
	case "install":
		return protocol.ActionInstallPackages, protocol.InstallPackagesParams{Packages: pkgs}, true
	case "remove":
		return protocol.ActionRemovePackages, protocol.RemovePackagesParams{Packages: pkgs}, true
	case "purge":
		return protocol.ActionRemovePackages, protocol.RemovePackagesParams{Packages: pkgs, Purge: true}, true
	}
	return "", nil, false
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

func (s *Server) handlePackagePreview(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	back := "/hosts/" + id + "/patches#packages"
	if _, err := s.db.GetHost(r.Context(), id); err != nil {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	pkgs := dedupe(splitList(r.PostFormValue("packages")))
	action, params, ok := pkgOpParams(r.PostFormValue("op"), pkgs)
	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // local path
	}
	if !ok {
		fail(s.t(r, "pkg.flash.badOp"))
		return
	}
	if len(pkgs) == 0 || len(pkgs) > protocol.MaxManagedPackages {
		fail(s.t(r, "pkg.flash.count", protocol.MaxManagedPackages))
		return
	}
	for _, p := range pkgs {
		if !protocol.ValidPackageName(p) {
			fail(s.t(r, "pkg.flash.invalidName", p))
			return
		}
		if action == protocol.ActionRemovePackages && protocol.ProtectedPackage(p) {
			fail(s.t(r, "pkg.flash.protected", p))
			return
		}
	}
	if _, err := s.QueueCommand(r.Context(), id, action, params, true, "", actorOf(r)); err != nil {
		fail(err.Error())
		return
	}
	s.setFlash(w, "ok", s.t(r, "pkg.flash.previewQueued"))
	http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // local path
}

func (s *Server) handlePackageApply(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	back := "/hosts/" + id + "/patches#packages"
	fail := func(msg string) {
		s.setFlash(w, "error", msg)
		http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // local path
	}
	c, err := s.db.GetCommand(r.Context(), chi.URLParam(r, "cmd"))
	if errors.Is(err, store.ErrNotFound) || (err == nil && c.HostID != id) {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	recent, _ := s.db.ListHostCommands(r.Context(), id, 50)
	pv, ok := buildPreview(c, recent, time.Now())
	switch {
	case !ok:
		fail(s.t(r, "pkg.flash.notPreview"))
		return
	case pv.Applied:
		fail(s.t(r, "pkg.flash.alreadyApplied"))
		return
	case pv.Expired:
		fail(s.t(r, "pkg.flash.expired"))
		return
	case !pv.Applicable:
		fail(s.t(r, "pkg.flash.notApplicable"))
		return
	}
	if len(pv.Removals) > 0 && r.PostFormValue("confirm") != "1" {
		fail(s.t(r, "pkg.flash.confirmRemoval"))
		return
	}
	if _, err := s.QueueCommand(r.Context(), id, c.Action, json.RawMessage(c.Params), false, "", actorOf(r)); err != nil {
		fail(err.Error())
		return
	}
	s.setFlash(w, "ok", s.t(r, "pkg.flash.applied"))
	http.Redirect(w, r, back, http.StatusSeeOther) //nolint:gosec // local path
}

// buildPreview describes a dry-run install/remove command; recent (newest first) is
// used to tell whether it has already been applied.
func buildPreview(c store.CommandRow, recent []store.CommandRow, now time.Time) (pkgPreview, bool) {
	if !c.DryRun || (c.Action != protocol.ActionInstallPackages && c.Action != protocol.ActionRemovePackages) {
		return pkgPreview{}, false
	}
	pv := pkgPreview{Cmd: c, Op: "install"}
	if c.Action == protocol.ActionInstallPackages {
		var p protocol.InstallPackagesParams
		_ = json.Unmarshal([]byte(c.Params), &p)
		pv.Packages = p.Packages
	} else {
		var p protocol.RemovePackagesParams
		_ = json.Unmarshal([]byte(c.Params), &p)
		pv.Packages, pv.Op = p.Packages, "remove"
		if p.Purge {
			pv.Op = "purge"
		}
	}
	if c.Result != nil {
		for _, ch := range c.Result.Changes {
			if ch.To == "" {
				pv.Removals = append(pv.Removals, ch)
			} else {
				pv.Installs = append(pv.Installs, ch)
			}
		}
	}
	for _, o := range recent {
		if !o.DryRun && o.Action == c.Action && o.Params == c.Params && !o.CreatedAt.Before(c.CreatedAt) {
			pv.Applied = true
		}
	}
	finished := !c.FinishedAt.IsZero()
	pv.Expired = finished && now.Sub(c.FinishedAt) > previewTTL
	pv.Applicable = c.Status == protocol.StatusOK && finished && !pv.Expired && !pv.Applied &&
		(len(pv.Installs) > 0 || len(pv.Removals) > 0)
	return pv, true
}

// packagePreviews returns the latest dry-run install/remove commands of a host.
func packagePreviews(cmds []store.CommandRow, now time.Time, limit int) []pkgPreview {
	var out []pkgPreview
	for _, c := range cmds {
		if pv, ok := buildPreview(c, cmds, now); ok && now.Sub(c.CreatedAt) < 24*time.Hour {
			out = append(out, pv)
			if len(out) == limit {
				break
			}
		}
	}
	return out
}

// packageFormDefaults reads ?op=&packages= used by links that prefill the form.
func packageFormDefaults(r *http.Request) (string, string) {
	op := r.URL.Query().Get("op")
	if _, _, ok := pkgOpParams(op, nil); !ok {
		op = "install"
	}
	var names []string
	for _, p := range splitList(r.URL.Query().Get("packages")) {
		if protocol.ValidPackageName(p) {
			names = append(names, p)
		}
	}
	return op, strings.Join(names, " ")
}
