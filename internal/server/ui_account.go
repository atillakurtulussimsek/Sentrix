package server

import (
	"encoding/base64"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"rsc.io/qr"

	"github.com/atillakurtulussimsek/Sentrix/internal/auth"
	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

const cookieTOTPSetup = "sentrix_totp_setup"

func qrDataURI(text string) template.URL {
	code, err := qr.Encode(text, qr.M)
	if err != nil {
		return ""
	}
	code.Scale = 5
	return template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(code.PNG())) //nolint:gosec // generated PNG
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	d := map[string]any{"HasTOTP": a.User.TOTPSecret != ""}
	if a.User.TOTPSecret == "" {
		// pending enrolment secret lives sealed in a short-lived cookie until confirmed
		secret := ""
		if c, err := r.Cookie(cookieTOTPSetup); err == nil {
			secret, _ = s.box.Open(c.Value)
		}
		if secret == "" {
			secret = auth.NewTOTPSecret()
			sealed, _ := s.box.Seal(secret)
			s.setCookie(w, cookieTOTPSetup, sealed, 900)
		}
		uri := auth.TOTPURI("Sentrix", a.User.Username, secret)
		d["Secret"], d["URI"], d["QR"] = secret, uri, qrDataURI(uri)
	}
	d["DefaultLangName"] = i18n.DisplayName(s.cfg.Language)
	s.renderPage(w, r, 200, "settings_account", s.t(r, "settings.nav.account"), settingsData("account", d))
}

// handleAccountLanguage stores the user's UI language; an empty value resets it
// to the server default and clears the pre-login language cookie.
func (s *Server) handleAccountLanguage(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	lang := r.PostFormValue("lang")
	if lang != "" && !s.cat.Supported(lang) {
		s.httpError(w, r, http.StatusBadRequest, s.t(r, "lang.unsupported"))
		return
	}
	if err := s.db.SetUserLanguage(r.Context(), a.User.ID, lang); err != nil {
		s.log.Error("set language", "err", err)
		s.httpError(w, r, http.StatusInternalServerError, s.t(r, "error.internal"))
		return
	}
	effective := lang
	if lang == "" {
		s.setCookie(w, cookieLang, "", -1)
		effective = s.cfg.Language
	} else {
		s.setCookie(w, cookieLang, lang, 365*24*3600)
	}
	s.auditReq(r, "user.language", a.User.ID, "language="+lang)
	s.setFlash(w, "ok", s.cat.T(effective, "account.languageSaved"))
	http.Redirect(w, r, "/settings/account", http.StatusSeeOther)
}

// passwordProblem returns a localized reason why pw is unacceptable, or "".
func (s *Server) passwordProblem(r *http.Request, pw string) string {
	if auth.ValidatePassword(pw) == nil {
		return ""
	}
	if len([]rune(pw)) < auth.MinPasswordLength {
		return s.t(r, "account.passwordTooShort", auth.MinPasswordLength)
	}
	return s.t(r, "account.passwordTooLong")
}

func (s *Server) handlePasswordChange(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	back := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/settings/account", http.StatusSeeOther)
	}
	if auth.VerifyPassword(a.User.PasswordHash, r.PostFormValue("current")) != nil {
		s.auditReq(r, "user.password_change_failed", a.User.ID, "wrong current password")
		back("error", s.t(r, "account.wrongCurrent"))
		return
	}
	pw := r.PostFormValue("new")
	if pw != r.PostFormValue("new2") {
		back("error", s.t(r, "account.mismatch"))
		return
	}
	if msg := s.passwordProblem(r, pw); msg != "" {
		back("error", msg)
		return
	}
	h, err := auth.HashPassword(pw)
	if err != nil {
		back("error", s.t(r, "error.internal"))
		return
	}
	u := a.User
	u.PasswordHash = h
	if err := s.db.UpdateUser(r.Context(), u); err != nil {
		back("error", s.t(r, "error.internal"))
		return
	}
	// sign out every other session, keep this one
	_ = s.db.DeleteUserSessions(r.Context(), u.ID)
	if err := s.startSession(r.Context(), w, r, u, false); err != nil {
		back("error", s.t(r, "error.internal"))
		return
	}
	s.auditReq(r, "user.password_change", u.ID, "other sessions revoked")
	back("ok", s.t(r, "account.passwordChanged"))
}

func (s *Server) handleTOTPEnable(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	back := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/settings/account", http.StatusSeeOther)
	}
	c, err := r.Cookie(cookieTOTPSetup)
	if err != nil {
		back("error", s.t(r, "account.setupExpired"))
		return
	}
	secret, err := s.box.Open(c.Value)
	if err != nil || !auth.VerifyTOTP(secret, r.PostFormValue("code"), time.Now()) {
		back("error", s.t(r, "account.codeMismatch"))
		return
	}
	sealed, err := s.box.Seal(secret)
	if err != nil {
		back("error", s.t(r, "error.internal"))
		return
	}
	u := a.User
	u.TOTPSecret = sealed
	if err := s.db.UpdateUser(r.Context(), u); err != nil {
		back("error", s.t(r, "error.internal"))
		return
	}
	s.setCookie(w, cookieTOTPSetup, "", -1)
	s.auditReq(r, "user.totp_enable", u.ID, "")
	back("ok", s.t(r, "account.totpEnabled"))
}

func (s *Server) handleTOTPDisable(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	if auth.VerifyPassword(a.User.PasswordHash, r.PostFormValue("current")) != nil {
		s.setFlash(w, "error", s.t(r, "account.totpPasswordRequired"))
		http.Redirect(w, r, "/settings/account", http.StatusSeeOther)
		return
	}
	u := a.User
	u.TOTPSecret = ""
	_ = s.db.UpdateUser(r.Context(), u)
	s.auditReq(r, "user.totp_disable", u.ID, "")
	s.setFlash(w, "ok", s.t(r, "account.totpDisabled"))
	http.Redirect(w, r, "/settings/account", http.StatusSeeOther)
}

// ---- API tokens ----

type tokenRow struct {
	store.APIToken
	Owner string
}

func (s *Server) handleTokens(w http.ResponseWriter, r *http.Request) { s.tokensPage(w, r, "") }

func (s *Server) tokensPage(w http.ResponseWriter, r *http.Request, newToken string) {
	a := authFrom(r.Context())
	owner := a.User.ID
	if a.Role == store.RoleAdmin {
		owner = ""
	}
	toks, _ := s.db.ListAPITokens(r.Context(), owner)
	users, _ := s.db.ListUsers(r.Context())
	names := map[string]string{}
	for _, u := range users {
		names[u.ID] = u.Username
	}
	var rows []tokenRow
	for _, t := range toks {
		rows = append(rows, tokenRow{t, names[t.UserID]})
	}
	w.Header().Set("Cache-Control", "no-store")
	s.renderPage(w, r, 200, "settings_tokens", s.t(r, "settings.nav.tokens"), settingsData("tokens", map[string]any{"Tokens": rows, "Role": a.Role, "Base": strings.TrimRight(s.cfg.BaseURL, "/"), "NewToken": newToken}))
}

func (s *Server) handleTokenCreate(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	scope := r.PostFormValue("scope")
	if scope != "read" && scope != "operate" && scope != "admin" {
		scope = "read"
	}
	if store.RoleRank(scopeRole(scope)) > store.RoleRank(a.Role) {
		s.setFlash(w, "error", s.t(r, "tokens.tooPrivileged"))
		http.Redirect(w, r, "/settings/tokens", http.StatusSeeOther)
		return
	}
	var ttl time.Duration
	if days := r.PostFormValue("days"); days != "" && days != "0" {
		if d, err := time.ParseDuration(days + "h"); err == nil {
			ttl = d * 24
		}
	}
	name := truncate(strings.TrimSpace(r.PostFormValue("name")), 64)
	if name == "" {
		name = "token"
	}
	tok := GenerateToken("sxa_")
	t, err := s.db.CreateAPIToken(r.Context(), store.HashToken(tok), a.User.ID, name, scope, ttl)
	if err != nil {
		s.httpError(w, r, 500, s.t(r, "error.internal"))
		return
	}
	s.auditReq(r, "api_token.create", t.ID, fmt.Sprintf("name=%s scope=%s ttl=%s", name, scope, ttl))
	s.tokensPage(w, r, tok)
}

func (s *Server) handleTokenDelete(w http.ResponseWriter, r *http.Request) {
	a := authFrom(r.Context())
	owner := a.User.ID
	if a.Role == store.RoleAdmin {
		owner = ""
	}
	id := chi.URLParam(r, "id")
	_ = s.db.DeleteAPIToken(r.Context(), id, owner)
	s.auditReq(r, "api_token.delete", id, "")
	http.Redirect(w, r, "/settings/tokens", http.StatusSeeOther)
}
