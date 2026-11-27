package server

import (
	"net/http"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/auth"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

func (s *Server) handleSetupForm(w http.ResponseWriter, r *http.Request) {
	if n, _ := s.db.CountUsers(r.Context()); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	s.renderPage(w, r, 200, "setup", s.t(r, "setup.title"), map[string]any{})
}

func (s *Server) handleSetup(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	s.setupMu.Lock()
	defer s.setupMu.Unlock()
	if n, _ := s.db.CountUsers(ctx); n > 0 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	user := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	fail := func(msg string) {
		s.renderPage(w, r, 400, "setup", s.t(r, "setup.title"), map[string]any{"Error": msg, "Username": user})
	}
	switch {
	case !validUsername(user):
		fail(s.t(r, "setup.err.username"))
		return
	case pw != r.PostFormValue("password2"):
		fail(s.t(r, "setup.err.mismatch"))
		return
	case r.PostFormValue("accept") != "1":
		fail(s.t(r, "setup.err.accept"))
		return
	}
	if err := auth.ValidatePassword(pw); err != nil {
		if len([]rune(pw)) < auth.MinPasswordLength {
			fail(s.t(r, "auth.passwordTooShort", auth.MinPasswordLength))
		} else {
			fail(s.t(r, "auth.passwordTooLong"))
		}
		return
	}
	hash, err := auth.HashPassword(pw)
	if err != nil {
		fail(s.t(r, "error.internal"))
		return
	}
	u, err := s.db.CreateUser(ctx, user, hash, store.RoleAdmin)
	if err != nil {
		fail(s.t(r, "setup.err.create"))
		return
	}
	_ = s.db.SetSetting(ctx, "disclaimer_accepted_at", time.Now().UTC().Format(time.RFC3339)+" by "+user)
	s.setupDone.Store(true)
	s.audit(ctx, "user:"+user, "setup.complete", u.ID, "first admin created, disclaimer accepted")
	if err := s.startSession(ctx, w, r, u, false); err != nil {
		fail(s.t(r, "error.internal"))
		return
	}
	s.setFlash(w, "ok", s.t(r, "setup.welcome"))
	http.Redirect(w, r, "/settings/enrollment", http.StatusSeeOther)
}

const usernameChars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-@"

func validUsername(u string) bool {
	if len(u) < 3 || len(u) > 64 {
		return false
	}
	for _, c := range u {
		if !strings.ContainsRune(usernameChars, c) {
			return false
		}
	}
	return true
}

func safeNext(n string) string {
	if n == "" || !strings.HasPrefix(n, "/") || strings.HasPrefix(n, "//") || strings.HasPrefix(n, "/\\") {
		return "/"
	}
	return n
}

func (s *Server) handleLoginForm(w http.ResponseWriter, r *http.Request) {
	if a := authFrom(r.Context()); a != nil && a.Session != nil {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderPage(w, r, 200, "login", s.t(r, "login.title"), map[string]any{"Next": safeNext(r.URL.Query().Get("next"))})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	user := strings.TrimSpace(r.PostFormValue("username"))
	pw := r.PostFormValue("password")
	next := safeNext(r.PostFormValue("next"))
	ip := clientIP(r)
	fail := func(status int, msg string) {
		s.renderPage(w, r, status, "login", s.t(r, "login.title"), map[string]any{"Error": msg, "Username": user, "Next": next})
	}
	if !s.loginIP.Allowed(ip) || !s.loginUser.Allowed(strings.ToLower(user)) {
		s.log.Warn("login rate limited", "ip", ip, "user", user)
		fail(http.StatusTooManyRequests, s.t(r, "login.limited"))
		return
	}
	u, err := s.db.GetUserByName(ctx, user)
	if err != nil {
		auth.VerifyDummy(pw)
	}
	if err != nil || u.Disabled || auth.VerifyPassword(u.PasswordHash, pw) != nil {
		s.loginIP.Fail(ip)
		s.loginUser.Fail(strings.ToLower(user))
		s.audit(ctx, "anonymous", "login.failed", user, "ip="+ip)
		fail(http.StatusUnauthorized, s.t(r, "login.failed"))
		return
	}
	s.loginIP.Reset(ip)
	s.loginUser.Reset(strings.ToLower(user))
	// rotate any existing session (session fixation)
	if c, err := r.Cookie(cookieSession); err == nil {
		_ = s.db.DeleteSession(ctx, store.HashToken(c.Value))
	}
	mfa := u.TOTPSecret != ""
	if err := s.startSession(ctx, w, r, u, mfa); err != nil {
		fail(500, s.t(r, "error.internal"))
		return
	}
	if mfa {
		s.setCookie(w, "sentrix_next", next, 600)
		http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
		return
	}
	_ = s.db.TouchLogin(ctx, u.ID)
	s.audit(ctx, "user:"+u.Username, "login", u.ID, "ip="+ip)
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // next is sanitised by safeNext (local paths only)
}

func (s *Server) handleMFAForm(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	if a == nil || a.Session == nil {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	if !a.Session.MFAPending {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	s.renderPage(w, r, 200, "login", s.t(r, "mfa.title"), map[string]any{"MFA": true})
}

func (s *Server) handleMFA(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	a := authFrom(ctx)
	if a == nil || a.Session == nil || !a.Session.MFAPending {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}
	key := "mfa:" + a.User.ID
	if !s.loginUser.Allowed(key) {
		s.renderPage(w, r, http.StatusTooManyRequests, "login", s.t(r, "mfa.title"), map[string]any{"MFA": true, "Error": s.t(r, "login.limited")})
		return
	}
	secret, err := s.box.Open(a.User.TOTPSecret)
	if err != nil || !auth.VerifyTOTP(secret, r.PostFormValue("code"), time.Now()) {
		s.loginUser.Fail(key)
		s.audit(ctx, "user:"+a.User.Username, "login.mfa_failed", a.User.ID, "ip="+clientIP(r))
		s.renderPage(w, r, http.StatusUnauthorized, "login", s.t(r, "mfa.title"), map[string]any{"MFA": true, "Error": s.t(r, "mfa.failed")})
		return
	}
	s.loginUser.Reset(key)
	_ = s.db.CompleteMFA(ctx, a.Session.IDHash)
	_ = s.db.TouchLogin(ctx, a.User.ID)
	s.audit(ctx, "user:"+a.User.Username, "login", a.User.ID, "ip="+clientIP(r)+" mfa=totp")
	next := "/"
	if c, err := r.Cookie("sentrix_next"); err == nil {
		next = safeNext(c.Value)
		s.setCookie(w, "sentrix_next", "", -1)
	}
	http.Redirect(w, r, next, http.StatusSeeOther) //nolint:gosec // next is sanitised by safeNext (local paths only)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieSession); err == nil {
		_ = s.db.DeleteSession(r.Context(), store.HashToken(c.Value))
	}
	s.setCookie(w, cookieSession, "", -1)
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}
