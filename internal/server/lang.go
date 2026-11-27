package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
)

const cookieLang = "sentrix_lang"

type langKey struct{}

// withLang resolves the request language: account preference → language cookie
// (pre-login choice) → server default. It must run after identify.
func (s *Server) withLang(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		lang := ""
		if a := authFrom(r.Context()); a != nil && s.cat.Supported(a.User.Language) {
			lang = a.User.Language
		}
		if lang == "" {
			if c, err := r.Cookie(cookieLang); err == nil && s.cat.Supported(c.Value) {
				lang = c.Value
			}
		}
		if lang == "" {
			lang = s.cfg.Language
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), langKey{}, lang)))
	})
}

// lang returns the language resolved for r (server default outside withLang).
func (s *Server) lang(r *http.Request) string {
	if r != nil {
		if l, ok := r.Context().Value(langKey{}).(string); ok {
			return l
		}
	}
	return s.cfg.Language
}

// t translates key into the request's language.
func (s *Server) t(r *http.Request, key string, args ...any) string {
	return s.cat.T(s.lang(r), key, args...)
}

// tDefault translates key into the server default language (notifications, background jobs).
func (s *Server) tDefault(key string, args ...any) string {
	return s.cat.T(s.cfg.Language, key, args...)
}

// handleSetLanguage stores the chosen language in a cookie and, when signed in,
// on the account; then returns to the page the user came from.
func (s *Server) handleSetLanguage(w http.ResponseWriter, r *http.Request) {
	lang := r.PostFormValue("lang")
	if !s.cat.Supported(lang) {
		s.httpError(w, r, http.StatusBadRequest, s.t(r, "lang.unsupported"))
		return
	}
	s.setCookie(w, cookieLang, lang, 365*24*3600)
	if a := authFrom(r.Context()); a != nil && a.Session != nil && !a.Session.MFAPending {
		if err := s.db.SetUserLanguage(r.Context(), a.User.ID, lang); err != nil {
			s.log.Error("set language", "err", err)
			s.httpError(w, r, http.StatusInternalServerError, s.t(r, "error.internal"))
			return
		}
	}
	http.Redirect(w, r, backTo(r), http.StatusSeeOther) //nolint:gosec // backTo only returns same-origin paths (safeNext)
}

// backTo returns the same-origin path of the Referer, or "/".
func backTo(r *http.Request) string {
	if next := safeNext(r.PostFormValue("next")); next != "" && next != "/" {
		return next
	}
	if u, err := url.Parse(r.Referer()); err == nil && (u.Host == "" || u.Host == r.Host) && strings.HasPrefix(u.Path, "/") {
		p := u.Path
		if u.RawQuery != "" {
			p += "?" + u.RawQuery
		}
		return safeNext(p)
	}
	return "/"
}
