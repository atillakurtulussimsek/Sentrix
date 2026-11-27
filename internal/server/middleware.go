package server

import (
	"context"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// securityHeaders sets conservative headers on every UI/API response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https") {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(c int) { s.status = c; s.ResponseWriter.WriteHeader(c) }
func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (s *statusRecorder) Unwrap() http.ResponseWriter { return s.ResponseWriter }

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: 200}
		next.ServeHTTP(rec, r)
		if strings.HasPrefix(r.URL.Path, "/static/") {
			return
		}
		lvl := slog.LevelDebug
		if rec.status >= 500 {
			lvl = slog.LevelError
		}
		s.log.Log(r.Context(), lvl, "http", "method", r.Method, "path", r.URL.Path, "status", rec.status, "dur", time.Since(start).Round(time.Millisecond))
	})
}

// limitBody caps request bodies for the UI/API.
func limitBody(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 2<<20)
		next.ServeHTTP(w, r)
	})
}

// identify attaches session or API-token identity (if any) to the request.
func (s *Server) identify(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
			ip := clientIP(r)
			if !s.loginIP.Allowed("bearer:" + ip) {
				writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "too many failed attempts"})
				return
			}
			tok, u, err := s.db.LookupAPIToken(r.Context(), store.HashToken(strings.TrimPrefix(ah, "Bearer ")))
			if err != nil || u.Disabled {
				s.loginIP.Fail("bearer:" + ip)
				writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid API token"})
				return
			}
			role := scopeRole(tok.Scope)
			if store.RoleRank(u.Role) < store.RoleRank(role) {
				role = u.Role
			}
			ctx := context.WithValue(r.Context(), ctxUser, &authInfo{User: u, Role: role, Via: "token:" + tok.Name})
			next.ServeHTTP(w, r.WithContext(ctx))
			return
		}
		if sess, u := s.loadSession(r); sess != nil {
			if sess.MFAPending {
				// Only the MFA step and logout are reachable until the second factor is verified.
				if r.URL.Path != "/login/mfa" && r.URL.Path != "/logout" && !strings.HasPrefix(r.URL.Path, "/static/") {
					http.Redirect(w, r, "/login/mfa", http.StatusSeeOther)
					return
				}
			}
			ctx := context.WithValue(r.Context(), ctxUser, &authInfo{User: *u, Session: sess, Role: u.Role, Via: "session"})
			r = r.WithContext(ctx)
		}
		next.ServeHTTP(w, r)
	})
}

func scopeRole(scope string) string {
	switch scope {
	case "admin":
		return store.RoleAdmin
	case "operate":
		return store.RoleOperator
	}
	return store.RoleViewer
}

func isAPI(r *http.Request) bool { return strings.HasPrefix(r.URL.Path, "/api/") }

// csrf rejects unsafe requests without a valid token.
func (s *Server) csrf(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := s.checkCSRF(r); err != nil {
			s.log.Warn("csrf rejected", "path", r.URL.Path, "ip", clientIP(r))
			msg := s.t(r, "auth.csrf")
			if isAPI(r) {
				msg = s.cat.T("en", "auth.csrf")
			}
			s.httpError(w, r, http.StatusForbidden, msg)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// requireRole enforces login and a minimum role.
func (s *Server) requireRole(role string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			a := authFrom(r.Context())
			if a == nil || (a.Session != nil && a.Session.MFAPending) {
				if isAPI(r) {
					writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "authentication required"})
					return
				}
				if r.Header.Get("HX-Request") == "true" {
					w.Header().Set("HX-Redirect", "/login")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				http.Redirect(w, r, "/login?next="+url.QueryEscape(r.URL.RequestURI()), http.StatusSeeOther)
				return
			}
			if store.RoleRank(a.Role) < store.RoleRank(role) {
				s.httpError(w, r, http.StatusForbidden, s.t(r, "error.forbidden"))
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// requireSetupDone redirects everything to /setup until the first admin exists.
func (s *Server) requireSetupDone(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !s.setupDone.Load() && !strings.HasPrefix(r.URL.Path, "/static/") && r.URL.Path != "/setup" && r.URL.Path != "/lang" && r.URL.Path != "/healthz" {
			n, err := s.db.CountUsers(r.Context())
			if err == nil && n > 0 {
				s.setupDone.Store(true)
			} else {
				if isAPI(r) {
					writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "setup not completed"})
					return
				}
				http.Redirect(w, r, "/setup", http.StatusSeeOther)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) httpError(w http.ResponseWriter, r *http.Request, code int, msg string) {
	if isAPI(r) {
		writeJSON(w, code, map[string]string{"error": msg})
		return
	}
	s.renderPage(w, r, code, "error", s.t(r, "error.title"), map[string]any{"Code": code, "Message": msg})
}
