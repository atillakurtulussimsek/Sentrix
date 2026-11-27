package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/auth"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

type settingsSection struct {
	Key, Label, Href string
	Admin            bool
}

var settingsSections = []settingsSection{
	{"users", "Users", "/settings/users", true},
	{"enrollment", "Enrolment", "/settings/enrollment", true},
	{"channels", "Notification channels", "/settings/channels", true},
	{"policies", "Patch policies", "/settings/policies", true},
	{"hooks", "Snapshot hooks", "/settings/hooks", true},
	{"feeds", "Vulnerability feeds", "/settings/feeds", true},
	{"tokens", "API tokens", "/settings/tokens", false},
	{"account", "My account", "/settings/account", false},
}

func settingsData(section string, extra map[string]any) map[string]any {
	d := map[string]any{"Section": section, "Sections": settingsSections}
	for k, v := range extra {
		d[k] = v
	}
	return d
}

func (s *Server) handleUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.db.ListUsers(r.Context())
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	s.renderPage(w, r, 200, "settings_users", "Users", settingsData("users", map[string]any{"Users": users}))
}

func validRole(r string) bool {
	return r == store.RoleAdmin || r == store.RoleOperator || r == store.RoleViewer
}

func (s *Server) handleUserCreate(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimSpace(r.PostFormValue("username"))
	role := r.PostFormValue("role")
	pw := r.PostFormValue("password")
	back := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
	}
	if !validUsername(name) || !validRole(role) {
		back("error", "Invalid username or role.")
		return
	}
	if err := auth.ValidatePassword(pw); err != nil {
		back("error", err.Error())
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		back("error", "internal error")
		return
	}
	u, err := s.db.CreateUser(r.Context(), name, hash, role)
	if err != nil {
		back("error", "Could not create user (name taken?).")
		return
	}
	s.auditReq(r, "user.create", u.ID, fmt.Sprintf("username=%s role=%s", name, role))
	back("ok", "User "+name+" created.")
}

// lastAdminGuard refuses changes that would leave no enabled admin.
func (s *Server) lastAdminGuard(r *http.Request, target store.User) bool {
	if target.Role != store.RoleAdmin || target.Disabled {
		return true
	}
	users, _ := s.db.ListUsers(r.Context())
	n := 0
	for _, u := range users {
		if u.Role == store.RoleAdmin && !u.Disabled {
			n++
		}
	}
	return n > 1
}

func (s *Server) userAction(w http.ResponseWriter, r *http.Request, fn func(u *store.User) (string, error)) {
	u, err := s.db.GetUser(r.Context(), chi.URLParam(r, "id"))
	if err != nil {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	msg, err := fn(&u)
	if err != nil {
		s.setFlash(w, "error", err.Error())
	} else {
		s.setFlash(w, "ok", msg)
	}
	http.Redirect(w, r, "/settings/users", http.StatusSeeOther)
}

func (s *Server) handleUserRole(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, func(u *store.User) (string, error) {
		role := r.PostFormValue("role")
		if !validRole(role) {
			return "", fmt.Errorf("invalid role")
		}
		if role != store.RoleAdmin && !s.lastAdminGuard(r, *u) {
			return "", fmt.Errorf("cannot demote the last admin")
		}
		u.Role = role
		if err := s.db.UpdateUser(r.Context(), *u); err != nil {
			return "", err
		}
		_ = s.db.DeleteUserSessions(r.Context(), u.ID)
		s.auditReq(r, "user.role", u.ID, "username="+u.Username+" role="+role)
		return "Role of " + u.Username + " set to " + role + ".", nil
	})
}

func (s *Server) handleUserToggle(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, func(u *store.User) (string, error) {
		if u.ID == authFrom(r.Context()).User.ID {
			return "", fmt.Errorf("you cannot disable yourself")
		}
		if !u.Disabled && !s.lastAdminGuard(r, *u) {
			return "", fmt.Errorf("cannot disable the last admin")
		}
		u.Disabled = !u.Disabled
		if err := s.db.UpdateUser(r.Context(), *u); err != nil {
			return "", err
		}
		_ = s.db.DeleteUserSessions(r.Context(), u.ID)
		s.auditReq(r, "user.toggle", u.ID, fmt.Sprintf("username=%s disabled=%v", u.Username, u.Disabled))
		return "User updated.", nil
	})
}

func (s *Server) handleUserDelete(w http.ResponseWriter, r *http.Request) {
	s.userAction(w, r, func(u *store.User) (string, error) {
		if u.ID == authFrom(r.Context()).User.ID {
			return "", fmt.Errorf("you cannot delete yourself")
		}
		if !s.lastAdminGuard(r, *u) {
			return "", fmt.Errorf("cannot delete the last admin")
		}
		if err := s.db.DeleteUser(r.Context(), u.ID); err != nil {
			return "", err
		}
		s.auditReq(r, "user.delete", u.ID, "username="+u.Username)
		return "User " + u.Username + " deleted.", nil
	})
}

type tokenView struct {
	store.EnrollToken
	Expired bool
}

func (s *Server) enrollmentPage(w http.ResponseWriter, r *http.Request, status int, newTok map[string]string) {
	toks, err := s.db.ListEnrollTokens(r.Context())
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	views := make([]tokenView, 0, len(toks))
	for _, t := range toks {
		views = append(views, tokenView{t, time.Now().After(t.ExpiresAt)})
	}
	d := map[string]any{"Tokens": views, "Fingerprint": s.ca.Fingerprint()}
	if newTok != nil {
		d["NewToken"] = newTok
	}
	s.renderPage(w, r, status, "settings_enrollment", "Enrolment", settingsData("enrollment", d))
}

func (s *Server) handleEnrollment(w http.ResponseWriter, r *http.Request) {
	s.enrollmentPage(w, r, 200, nil)
}

func (s *Server) handleEnrollmentCreate(w http.ResponseWriter, r *http.Request) {
	ttl, err := time.ParseDuration(r.PostFormValue("ttl"))
	if err != nil || ttl <= 0 || ttl > 30*24*time.Hour {
		ttl = 24 * time.Hour
	}
	note := truncate(strings.TrimSpace(r.PostFormValue("note")), 100)
	group := truncate(strings.TrimSpace(r.PostFormValue("group")), 64)
	tok, t, err := s.CreateEnrollToken(r.Context(), note, group, ttl)
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	s.auditReq(r, "enroll_token.create", t.ID, "note="+note+" group="+group)
	gw := strings.TrimRight(s.cfg.GatewayURL, "/")
	base := strings.TrimRight(s.cfg.BaseURL, "/")
	s.enrollmentPage(w, r, 200, map[string]string{
		"Token": tok, "Gateway": gw, "Fingerprint": s.ca.Fingerprint(),
		"Command": fmt.Sprintf("curl -fsSL %s/install.sh | sudo sh -s -- --server %s --token %s --ca-fingerprint %s", base, gw, tok, s.ca.Fingerprint()),
	})
}

func (s *Server) handleEnrollmentDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	if err := s.db.DeleteEnrollToken(r.Context(), id); err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	s.auditReq(r, "enroll_token.delete", id, "")
	http.Redirect(w, r, "/settings/enrollment", http.StatusSeeOther)
}

func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}
	return s
}
