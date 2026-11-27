package server

import (
	"bytes"
	"fmt"
	"html/template"
	"io/fs"
	"math"
	"net/http"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln"
	"github.com/atillakurtulussimsek/Sentrix/web"
)

type navItem struct {
	Href, Label string
	Icon        template.HTML
	Active      bool
	Badge       int
}

type flash struct{ Kind, Message string }

type page struct {
	Title        string
	Lang         string
	Languages    []i18n.Option
	CSRF         string
	AssetVersion string
	User         *store.User
	Nav          []navItem
	Flash        *flash
	FeedsStale   bool
	Data         any
}

type renderer struct {
	pages map[string]map[string]*template.Template // lang → name → template
}

// newRenderer parses every page once per language so `t`, `reltime` and
// `duration` resolve in that language without per-request cloning.
func newRenderer(cat *i18n.Catalog) (*renderer, error) {
	r := &renderer{pages: map[string]map[string]*template.Template{}}
	for _, lang := range cat.Languages() {
		pages, err := parsePages(cat, lang)
		if err != nil {
			return nil, err
		}
		r.pages[lang] = pages
	}
	return r, nil
}

func parsePages(cat *i18n.Catalog, lang string) (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"t":    func(key string, args ...any) string { return cat.T(lang, key, args...) },
		"lang": func() string { return lang },
		// riskdetail renders a risk component in lang (falls back to the stored English text).
		"riskdetail": func(c vuln.RiskComponent) string {
			if len(c.Msgs) == 0 {
				return c.Detail
			}
			parts := make([]string, 0, len(c.Msgs))
			for _, m := range c.Msgs {
				args := make([]any, len(m.Args))
				for i, a := range m.Args {
					if strings.HasPrefix(a, "severity.") {
						a = cat.T(lang, a)
					}
					args[i] = a
				}
				parts = append(parts, cat.T(lang, m.Key, args...))
			}
			return strings.Join(parts, "; ")
		},
		// exposed renders the matcher's "<proc> listening on <addr>" evidence in lang.
		"exposed": func(ev string) string {
			if proc, addr, ok := strings.Cut(ev, " listening on "); ok {
				return cat.T(lang, "risk.listening", proc, addr)
			}
			return ev
		},
		"dict": func(kv ...any) map[string]any {
			m := map[string]any{}
			for i := 0; i+1 < len(kv); i += 2 {
				m[fmt.Sprint(kv[i])] = kv[i+1]
			}
			return m
		},
		"list": func(v ...string) []string { return v },
		"ifz": func(n int, zero, nonzero string) string {
			if n == 0 {
				return zero
			}
			return nonzero
		},
		"reltime":  func(t time.Time) string { return relTime(cat, lang, t) },
		"pct":      func(f float64) string { return pctStr(f) },
		"bytes":    humanBytes,
		"duration": func(sec int64) string { return humanDuration(cat, lang, time.Duration(sec)*time.Second) },
		"join":     strings.Join,
		"can": func(u *store.User, role string) bool {
			return u != nil && store.RoleRank(u.Role) >= store.RoleRank(role)
		},
		"riskclass": riskClass,
		"sevclass":  func(s string) string { return strings.ToLower(s) },
		"fmtTime": func(t time.Time) string {
			if t.IsZero() {
				return "–"
			}
			return t.Local().Format("2006-01-02 15:04")
		},
		"add":    func(a, b int) int { return a + b },
		"pf":     func(f float64) string { return fmt.Sprintf("%.1f", f) },
		"mul100": func(f float64) float64 { return f * 100 },
	}
	shared := []string{"templates/layout.html", "templates/host_head.html", "templates/settings_nav.html"}
	entries, err := fs.Glob(web.Templates, "templates/*.html")
	if err != nil {
		return nil, err
	}
	pages := map[string]*template.Template{}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "layout" || name == "host_head" || name == "settings_nav" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(web.Templates, append(shared, e)...)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		pages[name] = t
	}
	return pages, nil
}

func (r *renderer) render(w http.ResponseWriter, status int, name, tmpl string, p page) error {
	t, ok := r.pages[p.Lang][name]
	if !ok {
		return fmt.Errorf("unknown template %q", name)
	}
	var buf bytes.Buffer
	if err := t.ExecuteTemplate(&buf, tmpl, p); err != nil {
		return err
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	_, err := buf.WriteTo(w)
	return err
}

var assetVersion = func() string {
	if version.Commit != "none" {
		return version.Commit
	}
	return fmt.Sprint(time.Now().Unix())
}()

func relTime(cat *i18n.Catalog, lang string, t time.Time) string {
	if t.IsZero() {
		return cat.T(lang, "time.never")
	}
	d := time.Since(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = cat.T(lang, "time.seconds", int(d.Seconds()))
	case d < time.Hour:
		s = cat.T(lang, "time.minutes", int(d.Minutes()))
	case d < 48*time.Hour:
		s = cat.T(lang, "time.hours", int(d.Hours()))
	default:
		s = cat.T(lang, "time.days", int(d.Hours()/24))
	}
	if future {
		return cat.T(lang, "time.in", s)
	}
	return cat.T(lang, "time.ago", s)
}

func pctStr(f float64) string {
	if f < 0 || math.IsNaN(f) {
		return "–"
	}
	return fmt.Sprintf("%.0f%%", f)
}

func humanBytes(b uint64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := uint64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(b)/float64(div), "KMGTPE"[exp])
}

func humanDuration(cat *i18n.Catalog, lang string, d time.Duration) string {
	if d <= 0 {
		return "–"
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return cat.T(lang, "time.days", days) + " " + cat.T(lang, "time.hours", h)
	case h > 0:
		return cat.T(lang, "time.hours", h) + " " + cat.T(lang, "time.minutes", m)
	}
	return cat.T(lang, "time.minutes", m)
}

func riskClass(r float64) string {
	switch {
	case r >= 80:
		return "critical"
	case r >= 60:
		return "high"
	case r >= 30:
		return "medium"
	}
	return "low"
}
