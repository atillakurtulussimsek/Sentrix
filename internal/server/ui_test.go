package server

import (
	"context"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/auth"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

type uiClient struct {
	t    *testing.T
	base string
	c    *http.Client
}

func newUI(t *testing.T) (*Server, *httptest.Server) {
	s, _ := newTestServer(t)
	ts := httptest.NewServer(s.UIHandler())
	t.Cleanup(ts.Close)
	return s, ts
}

func client(t *testing.T, ts *httptest.Server) *uiClient {
	jar, _ := cookiejar.New(nil)
	return &uiClient{t: t, base: ts.URL, c: &http.Client{Jar: jar, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
}

var csrfRe = regexp.MustCompile(`name="csrf" value="([^"]+)"`)

func (u *uiClient) get(path string) (int, string, string) {
	resp, err := u.c.Get(u.base + path)
	if err != nil {
		u.t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header.Get("Location")
}

func (u *uiClient) csrf(path string) string {
	_, body, _ := u.get(path)
	m := csrfRe.FindStringSubmatch(body)
	if m == nil {
		u.t.Fatalf("no csrf token on %s", path)
	}
	return m[1]
}

func (u *uiClient) post(path string, form url.Values) (int, string) {
	resp, err := u.c.PostForm(u.base+path, form)
	if err != nil {
		u.t.Fatal(err)
	}
	defer resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Location")
}

func mkUser(t *testing.T, s *Server, name, role string) {
	h, _ := auth.HashPassword("password-1234")
	if _, err := s.db.CreateUser(context.Background(), name, h, role); err != nil {
		t.Fatal(err)
	}
}

func (u *uiClient) login(name string) {
	tok := u.csrf("/login")
	code, loc := u.post("/login", url.Values{"csrf": {tok}, "username": {name}, "password": {"password-1234"}})
	if code != http.StatusSeeOther || loc != "/" {
		u.t.Fatalf("login %s: %d %s", name, code, loc)
	}
}

func TestSetupRedirectAndWizard(t *testing.T) {
	_, ts := newUI(t)
	c := client(t, ts)
	if _, _, loc := c.get("/hosts"); loc != "/setup" {
		t.Fatalf("expected setup redirect, got %q", loc)
	}
	tok := c.csrf("/setup")
	// disclaimer must be accepted
	code, _ := c.post("/setup", url.Values{"csrf": {tok}, "username": {"root"}, "password": {"password-1234"}, "password2": {"password-1234"}})
	if code != http.StatusBadRequest {
		t.Fatalf("setup without disclaimer: %d", code)
	}
	code, loc := c.post("/setup", url.Values{"csrf": {tok}, "username": {"root"}, "password": {"password-1234"}, "password2": {"password-1234"}, "accept": {"1"}})
	if code != http.StatusSeeOther || loc != "/settings/enrollment" {
		t.Fatalf("setup: %d %s", code, loc)
	}
	if code, _, _ := c.get("/settings/enrollment"); code != 200 {
		t.Fatalf("admin page after setup: %d", code)
	}
	// setup cannot be repeated
	c2 := client(t, ts)
	if _, _, loc := c2.get("/setup"); loc != "/login" {
		t.Fatalf("second setup: %q", loc)
	}
}

func TestRoleEnforcement(t *testing.T) {
	s, ts := newUI(t)
	mkUser(t, s, "alice", store.RoleAdmin)
	mkUser(t, s, "victor", store.RoleViewer)
	mkUser(t, s, "olga", store.RoleOperator)

	anon := client(t, ts)
	if code, _, loc := anon.get("/settings/users"); code != http.StatusSeeOther || !strings.HasPrefix(loc, "/login") {
		t.Fatalf("anon admin page: %d %s", code, loc)
	}
	if code, _, _ := anon.get("/api/v1/hosts"); code != http.StatusUnauthorized {
		t.Fatalf("anon api: %d", code)
	}

	v := client(t, ts)
	v.login("victor")
	for _, p := range []string{"/", "/hosts", "/api/v1/hosts"} {
		if code, _, _ := v.get(p); code != 200 {
			t.Errorf("viewer %s: %d", p, code)
		}
	}
	adminPages := []string{"/settings/users", "/settings/enrollment", "/audit"}
	for _, p := range adminPages {
		if code, _, _ := v.get(p); code != http.StatusForbidden {
			t.Errorf("viewer reached admin page %s: %d", p, code)
		}
	}
	tok := v.csrf("/hosts")
	if code, _ := v.post("/settings/users", url.Values{"csrf": {tok}, "username": {"evil"}, "password": {"password-1234"}, "role": {"admin"}}); code != http.StatusForbidden {
		t.Errorf("viewer created user: %d", code)
	}
	if _, err := s.db.GetUserByName(context.Background(), "evil"); err == nil {
		t.Fatal("viewer was able to create a user")
	}

	o := client(t, ts)
	o.login("olga")
	if code, _, _ := o.get("/settings/users"); code != http.StatusForbidden {
		t.Errorf("operator reached admin page: %d", code)
	}

	a := client(t, ts)
	a.login("alice")
	for _, p := range adminPages {
		if code, _, _ := a.get(p); code != 200 && p != "/audit" {
			t.Errorf("admin %s: %d", p, code)
		}
	}
}

func TestCSRF(t *testing.T) {
	s, ts := newUI(t)
	mkUser(t, s, "alice", store.RoleAdmin)
	a := client(t, ts)
	a.login("alice")
	// missing token
	if code, _ := a.post("/settings/users", url.Values{"username": {"bob"}, "password": {"password-1234"}, "role": {"viewer"}}); code != http.StatusForbidden {
		t.Fatalf("no csrf: %d", code)
	}
	// wrong token
	if code, _ := a.post("/settings/users", url.Values{"csrf": {"nope"}, "username": {"bob"}, "password": {"password-1234"}, "role": {"viewer"}}); code != http.StatusForbidden {
		t.Fatalf("bad csrf: %d", code)
	}
	tok := a.csrf("/settings/users")
	if code, _ := a.post("/settings/users", url.Values{"csrf": {tok}, "username": {"bob"}, "password": {"password-1234"}, "role": {"viewer"}}); code != http.StatusSeeOther {
		t.Fatalf("good csrf: %d", code)
	}
	// login form also protected (login CSRF)
	c := client(t, ts)
	if code, _ := c.post("/login", url.Values{"username": {"alice"}, "password": {"password-1234"}}); code != http.StatusForbidden {
		t.Fatalf("login without csrf: %d", code)
	}
}

func TestLoginRateLimitAndMFA(t *testing.T) {
	s, ts := newUI(t)
	mkUser(t, s, "alice", store.RoleAdmin)
	c := client(t, ts)
	for i := 0; i < 5; i++ {
		tok := c.csrf("/login")
		if code, _ := c.post("/login", url.Values{"csrf": {tok}, "username": {"alice"}, "password": {"wrong"}}); code != http.StatusUnauthorized {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	tok := c.csrf("/login")
	if code, _ := c.post("/login", url.Values{"csrf": {tok}, "username": {"alice"}, "password": {"password-1234"}}); code != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit, got %d", code)
	}
	s.loginUser.Reset("alice")
	s.loginIP.Reset("127.0.0.1")

	// enable TOTP
	secret := auth.NewTOTPSecret()
	u, _ := s.db.GetUserByName(context.Background(), "alice")
	u.TOTPSecret, _ = s.box.Seal(secret)
	_ = s.db.UpdateUser(context.Background(), u)
	tok = c.csrf("/login")
	if code, loc := c.post("/login", url.Values{"csrf": {tok}, "username": {"alice"}, "password": {"password-1234"}}); loc != "/login/mfa" {
		t.Fatalf("mfa redirect: %d %s", code, loc)
	}
	// pending MFA cannot access pages
	if _, _, loc := c.get("/hosts"); loc != "/login/mfa" {
		t.Fatalf("pending mfa reached hosts: %s", loc)
	}
	tok = c.csrf("/login/mfa")
	code, _ := c.post("/login/mfa", url.Values{"csrf": {tok}, "code": {"000000"}})
	if code != http.StatusUnauthorized {
		t.Fatalf("bad code: %d", code)
	}
	good, _ := auth.TOTPCode(secret, time.Now())
	if _, loc := c.post("/login/mfa", url.Values{"csrf": {tok}, "code": {good}}); loc != "/" {
		t.Fatalf("mfa ok: %s", loc)
	}
	if code, _, _ := c.get("/hosts"); code != 200 {
		t.Fatalf("after mfa: %d", code)
	}
}

func TestOpenRedirect(t *testing.T) {
	for in, want := range map[string]string{"//evil.com": "/", "https://evil.com": "/", "/\\evil": "/", "/hosts?x=1": "/hosts?x=1", "": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q", in, got)
		}
	}
}

func TestSecurityHeaders(t *testing.T) {
	_, ts := newUI(t)
	resp, err := http.Get(ts.URL + "/login")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for _, h := range []string{"Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options", "Referrer-Policy"} {
		if resp.Header.Get(h) == "" {
			t.Errorf("missing %s", h)
		}
	}
}
