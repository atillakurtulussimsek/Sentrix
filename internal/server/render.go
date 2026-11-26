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
	CSRF         string
	AssetVersion string
	User         *store.User
	Nav          []navItem
	Flash        *flash
	FeedsStale   bool
	Data         any
}

type renderer struct {
	pages map[string]*template.Template
}

func newRenderer(cat *i18n.Catalog, lang string) (*renderer, error) {
	funcs := template.FuncMap{
		"t": func(key string) string { return cat.T(lang, key) },
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
		"reltime":  relTime,
		"pct":      func(f float64) string { return pctStr(f) },
		"bytes":    humanBytes,
		"duration": func(sec int64) string { return humanDuration(time.Duration(sec) * time.Second) },
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
	r := &renderer{pages: map[string]*template.Template{}}
	for _, e := range entries {
		name := strings.TrimSuffix(strings.TrimPrefix(e, "templates/"), ".html")
		if name == "layout" || name == "host_head" || name == "settings_nav" {
			continue
		}
		t, err := template.New(name).Funcs(funcs).ParseFS(web.Templates, append(shared, e)...)
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", name, err)
		}
		r.pages[name] = t
	}
	return r, nil
}

func (r *renderer) render(w http.ResponseWriter, status int, name, tmpl string, p page) error {
	t, ok := r.pages[name]
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

func relTime(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	future := d < 0
	if future {
		d = -d
	}
	var s string
	switch {
	case d < time.Minute:
		s = fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		s = fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		s = fmt.Sprintf("%dh", int(d.Hours()))
	default:
		s = fmt.Sprintf("%dd", int(d.Hours()/24))
	}
	if future {
		return "in " + s
	}
	return s + " ago"
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

func humanDuration(d time.Duration) string {
	if d <= 0 {
		return "–"
	}
	days := int(d.Hours()) / 24
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	switch {
	case days > 0:
		return fmt.Sprintf("%dd %dh", days, h)
	case h > 0:
		return fmt.Sprintf("%dh %dm", h, m)
	}
	return fmt.Sprintf("%dm", m)
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
