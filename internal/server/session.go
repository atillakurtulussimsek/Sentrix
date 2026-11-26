package server

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

const (
	cookieSession = "sentrix_session"
	cookiePre     = "sentrix_pre"
	cookieFlash   = "sentrix_flash"
	sessionIdle   = 12 * time.Hour
	sessionMax    = 7 * 24 * time.Hour
)

// authInfo is attached to authenticated requests.
type authInfo struct {
	User    store.User
	Session *store.Session // nil for API-token requests
	Role    string         // effective role (API token scope may lower it)
	Via     string         // "session" or "token:<name>"
}

func authFrom(ctx context.Context) *authInfo {
	a, _ := ctx.Value(ctxUser).(*authInfo)
	return a
}

func randToken(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// secureCookies marks cookies Secure unless the UI is served over plain HTTP (base_url
// http://…) or dev_insecure_cookies is set; browsers drop Secure cookies on http origins.
func (s *Server) secureCookies() bool {
	return !s.cfg.DevInsecureCookies && !strings.HasPrefix(strings.ToLower(s.cfg.BaseURL), "http://")
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, maxAge int) {
	// Secure is only disabled with dev_insecure_cookies (plain-HTTP local development).
	c := &http.Cookie{Name: name, Value: value, Path: "/", MaxAge: maxAge, HttpOnly: true, //nolint:gosec // see above
		Secure: s.secureCookies(), SameSite: http.SameSiteLaxMode}
	http.SetCookie(w, c)
}

// startSession creates a session for u and sets the cookie.
func (s *Server) startSession(ctx context.Context, w http.ResponseWriter, r *http.Request, u store.User, mfaPending bool) error {
	raw := randToken(32)
	now := time.Now()
	sess := store.Session{IDHash: store.HashToken(raw), UserID: u.ID, CSRFToken: randToken(32), CreatedAt: now,
		ExpiresAt: now.Add(sessionIdle), LastSeen: now, MFAPending: mfaPending}
	ua := r.UserAgent()
	if len(ua) > 200 {
		ua = ua[:200]
	}
	if err := s.db.CreateSession(ctx, sess, clientIP(r), ua); err != nil {
		return err
	}
	s.setCookie(w, cookieSession, raw, 0)
	return nil
}

// loadSession resolves the session cookie; it extends idle sessions up to sessionMax.
func (s *Server) loadSession(r *http.Request) (*store.Session, *store.User) {
	c, err := r.Cookie(cookieSession)
	if err != nil || c.Value == "" {
		return nil, nil
	}
	h := store.HashToken(c.Value)
	sess, err := s.db.GetSession(r.Context(), h)
	if err != nil {
		return nil, nil
	}
	u, err := s.db.GetUser(r.Context(), sess.UserID)
	if err != nil || u.Disabled {
		return nil, nil
	}
	if time.Since(sess.LastSeen) > time.Minute {
		exp := time.Now().Add(sessionIdle)
		if max := sess.CreatedAt.Add(sessionMax); exp.After(max) {
			exp = max
		}
		_ = s.db.TouchSession(r.Context(), h, exp)
	}
	return &sess, &u
}

// csrfToken returns the token to embed in forms for this request.
func (s *Server) csrfToken(w http.ResponseWriter, r *http.Request) string {
	if a := authFrom(r.Context()); a != nil && a.Session != nil {
		return a.Session.CSRFToken
	}
	if c, err := r.Cookie(cookiePre); err == nil && len(c.Value) >= 32 {
		return c.Value
	}
	tok := randToken(32)
	s.setCookie(w, cookiePre, tok, 3600)
	return tok
}

var errCSRF = errors.New("invalid CSRF token")

// checkCSRF validates unsafe requests (synchroniser token for sessions,
// double-submit cookie before login). Bearer-token API calls are exempt.
func (s *Server) checkCSRF(r *http.Request) error {
	switch r.Method {
	case http.MethodGet, http.MethodHead, http.MethodOptions:
		return nil
	}
	a := authFrom(r.Context())
	if a != nil && a.Session == nil {
		return nil // API token: not ambient credentials
	}
	sent := r.Header.Get("X-CSRF-Token")
	if sent == "" {
		sent = r.PostFormValue("csrf")
	}
	var want string
	if a != nil {
		want = a.Session.CSRFToken
	} else if c, err := r.Cookie(cookiePre); err == nil {
		want = c.Value
	}
	if want == "" || subtle.ConstantTimeCompare([]byte(sent), []byte(want)) != 1 {
		return errCSRF
	}
	// Defence in depth: same-origin check when the browser sends Origin.
	if o := r.Header.Get("Origin"); o != "" && o != "null" {
		if u, err := url.Parse(o); err != nil || u.Host != r.Host {
			return errCSRF
		}
	}
	return nil
}

func (s *Server) setFlash(w http.ResponseWriter, kind, msg string) {
	s.setCookie(w, cookieFlash, base64.RawURLEncoding.EncodeToString([]byte(kind+"|"+msg)), 60)
}

func (s *Server) popFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(cookieFlash)
	if err != nil {
		return nil
	}
	s.setCookie(w, cookieFlash, "", -1)
	b, err := base64.RawURLEncoding.DecodeString(c.Value)
	if err != nil {
		return nil
	}
	kind, msg, _ := strings.Cut(string(b), "|")
	return &flash{Kind: kind, Message: msg}
}

func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}
