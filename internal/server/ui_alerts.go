package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/notify"
	"github.com/atillakurtulussimsek/Sentrix/internal/patch"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

func (s *Server) firingAlerts(r *http.Request) int {
	n, _ := s.db.CountFiring(r.Context())
	return n
}

type alertView struct {
	store.Alert
	Rule     string
	Hostname string
}

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	rules, _ := s.db.ListRules(ctx)
	names := map[string]string{}
	for _, ru := range rules {
		names[ru.ID] = ru.Name
	}
	hosts, _ := s.db.ListHosts(ctx)
	hn := map[string]string{}
	for _, h := range hosts {
		hn[h.ID] = h.Hostname
	}
	view := func(as []store.Alert) []alertView {
		out := make([]alertView, 0, len(as))
		for _, a := range as {
			out = append(out, alertView{a, names[a.RuleID], hn[a.HostID]})
		}
		return out
	}
	firing, _ := s.db.ListAlerts(ctx, "firing", 200)
	pending, _ := s.db.ListAlerts(ctx, "pending", 200)
	resolved, _ := s.db.ListAlerts(ctx, "resolved", 50)
	type ruleView struct {
		store.Rule
		Desc string
	}
	var rv []ruleView
	for _, ru := range rules {
		rv = append(rv, ruleView{ru, ruleConfig(ru).Describe(ru.Kind)})
	}
	chans, _ := s.db.ListChannels(ctx)
	s.renderPage(w, r, 200, "alerts", s.t(r, "nav.alerts"), map[string]any{"Firing": view(firing), "Pending": view(pending), "Resolved": view(resolved),
		"Rules": rv, "Channels": chans})
}

func (s *Server) handleRuleSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.httpError(w, r, 400, "bad form")
		return
	}
	back := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/alerts#rules", http.StatusSeeOther)
	}
	val, _ := strconv.ParseFloat(r.PostFormValue("value"), 64)
	cfg := notify.RuleConfig{Metric: strings.TrimSpace(r.PostFormValue("metric")), Labels: strings.TrimSpace(r.PostFormValue("labels")), Op: r.PostFormValue("op"), Value: val,
		Condition: r.PostFormValue("condition"), OnlyKEV: r.PostFormValue("only_kev") == "1", MinSeverity: r.PostFormValue("min_severity"),
		OnlyFailed: r.PostFormValue("only_failed") == "1", Group: strings.TrimSpace(r.PostFormValue("group"))}
	kind := r.PostFormValue("kind")
	if err := cfg.Validate(kind); err != nil {
		back("error", err.Error())
		return
	}
	forDur, err := time.ParseDuration(defaultStr(r.PostFormValue("for"), "0s"))
	if err != nil {
		back("error", "invalid 'for' duration")
		return
	}
	cool, err := time.ParseDuration(defaultStr(r.PostFormValue("cooldown"), "6h"))
	if err != nil {
		back("error", "invalid cooldown")
		return
	}
	sev := r.PostFormValue("severity")
	if sev != "info" && sev != "warning" && sev != "critical" {
		sev = "warning"
	}
	b, _ := json.Marshal(cfg)
	ru := store.Rule{ID: r.PostFormValue("id"), Name: truncate(strings.TrimSpace(r.PostFormValue("name")), 100), Kind: kind, Config: string(b), Severity: sev,
		Channels: r.PostForm["channels"], For: forDur, Cooldown: cool, Enabled: r.PostFormValue("enabled") == "1"}
	if ru.Name == "" {
		ru.Name = cfg.Describe(kind)
	}
	ru, err = s.db.SaveRule(r.Context(), ru)
	if err != nil {
		back("error", "could not save rule")
		return
	}
	s.auditReq(r, "alert_rule.save", ru.ID, fmt.Sprintf("name=%q kind=%s %s for=%s cooldown=%s enabled=%v", ru.Name, kind, cfg.Describe(kind), forDur, cool, ru.Enabled))
	back("ok", "Rule saved.")
}

func (s *Server) handleRuleToggle(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	rules, _ := s.db.ListRules(r.Context())
	for _, ru := range rules {
		if ru.ID == id {
			ru.Enabled = !ru.Enabled
			_, _ = s.db.SaveRule(r.Context(), ru)
			s.auditReq(r, "alert_rule.toggle", id, fmt.Sprintf("enabled=%v", ru.Enabled))
		}
	}
	http.Redirect(w, r, "/alerts#rules", http.StatusSeeOther)
}

func (s *Server) handleRuleDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_ = s.db.DeleteRule(r.Context(), id)
	s.auditReq(r, "alert_rule.delete", id, "")
	http.Redirect(w, r, "/alerts#rules", http.StatusSeeOther)
}

func defaultStr(v, d string) string {
	if strings.TrimSpace(v) == "" {
		return d
	}
	return v
}

// ---- channels ----

type channelView struct {
	store.Channel
	Target string
}

func (s *Server) handleChannels(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	chans, _ := s.db.ListChannels(ctx)
	var views []channelView
	for _, c := range chans {
		cfg, _ := s.channelConfig(c)
		views = append(views, channelView{c, channelTarget(c.Kind, cfg)})
	}
	logs, _ := s.db.ListNotifications(ctx, 30)
	names := map[string]string{}
	for _, c := range chans {
		names[c.ID] = c.Name
	}
	digestCron, _ := s.db.GetSetting(ctx, "digest_cron")
	digestCh, _ := s.db.GetSetting(ctx, "digest_channels")
	digestLast, _ := s.db.GetSetting(ctx, "digest_last")
	s.renderPage(w, r, 200, "settings_channels", "Notification channels", settingsData("channels", map[string]any{"Channels": views, "Logs": logs, "Names": names,
		"DigestCron": digestCron, "DigestChannels": store.SplitTags(digestCh), "DigestLast": digestLast}))
}

// channelTarget renders a non-secret description of where a channel sends.
func channelTarget(kind string, c notify.Config) string {
	switch kind {
	case "email":
		return c.To + " via " + c.Host
	case "telegram":
		return "chat " + c.ChatID
	case "ntfy":
		return defaultStr(c.URL, "https://ntfy.sh") + "/" + c.Topic
	}
	if u := c.URL; len(u) > 40 {
		return u[:40] + "…"
	}
	return c.URL
}

func (s *Server) handleChannelSave(w http.ResponseWriter, r *http.Request) {
	back := func(kind, msg string) {
		s.setFlash(w, kind, msg)
		http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
	}
	kind := r.PostFormValue("kind")
	port, _ := strconv.Atoi(r.PostFormValue("port"))
	cfg := notify.Config{URL: strings.TrimSpace(r.PostFormValue("url")), ChatID: strings.TrimSpace(r.PostFormValue("chat_id")), Topic: strings.TrimSpace(r.PostFormValue("topic")),
		Host: strings.TrimSpace(r.PostFormValue("host")), Port: port, Username: strings.TrimSpace(r.PostFormValue("username")), From: strings.TrimSpace(r.PostFormValue("from")),
		To: strings.TrimSpace(r.PostFormValue("to")), TLSMode: r.PostFormValue("tls_mode")}
	var err error
	if cfg.Secret, err = s.box.Seal(r.PostFormValue("secret")); err != nil {
		back("error", "encrypt secret")
		return
	}
	if cfg.Token, err = s.box.Seal(r.PostFormValue("token")); err != nil {
		back("error", "encrypt secret")
		return
	}
	if cfg.Password, err = s.box.Seal(r.PostFormValue("password")); err != nil {
		back("error", "encrypt secret")
		return
	}
	switch kind {
	case "webhook", "slack", "discord":
		if !strings.HasPrefix(cfg.URL, "https://") && !strings.HasPrefix(cfg.URL, "http://") {
			back("error", "A webhook URL (http/https) is required.")
			return
		}
	case "telegram":
		if r.PostFormValue("token") == "" || cfg.ChatID == "" {
			back("error", "Telegram needs a bot token and chat ID.")
			return
		}
	case "ntfy":
		if cfg.Topic == "" {
			back("error", "ntfy needs a topic.")
			return
		}
	case "email":
		if cfg.Host == "" || cfg.From == "" || cfg.To == "" {
			back("error", "Email needs SMTP host, from and to.")
			return
		}
	default:
		back("error", "Unknown channel type.")
		return
	}
	b, _ := json.Marshal(cfg) //nolint:gosec // secret fields are sealed (AES-GCM) above
	c, err := s.db.SaveChannel(r.Context(), store.Channel{Name: truncate(strings.TrimSpace(r.PostFormValue("name")), 100), Kind: kind, Config: string(b), Enabled: true})
	if err != nil {
		back("error", "Could not save channel (name taken?).")
		return
	}
	s.auditReq(r, "channel.create", c.ID, "name="+c.Name+" kind="+kind)
	back("ok", "Channel saved. Use “Test” to send a test message.")
}

func (s *Server) channelByID(r *http.Request) (store.Channel, bool) {
	id := chi.URLParam(r, "id")
	chans, _ := s.db.ListChannels(r.Context())
	for _, c := range chans {
		if c.ID == id {
			return c, true
		}
	}
	return store.Channel{}, false
}

func (s *Server) handleChannelTest(w http.ResponseWriter, r *http.Request) {
	c, ok := s.channelByID(r)
	if !ok {
		s.httpError(w, r, 404, s.t(r, "error.notfound"))
		return
	}
	m := notify.Message{Event: "test", Severity: "info", Title: "Sentrix test notification", Body: "If you can read this, the " + c.Kind + " channel “" + c.Name + "” works.",
		URL: strings.TrimRight(s.cfg.BaseURL, "/") + "/settings/channels", Time: time.Now()}
	err := s.sendChannel(r.Context(), c, m)
	status := "sent"
	if err != nil {
		status = "failed"
		s.setFlash(w, "error", "Test failed: "+err.Error())
	} else {
		s.setFlash(w, "ok", "Test message sent to "+c.Name+".")
	}
	errMsg := ""
	if err != nil {
		errMsg = truncate(err.Error(), 300)
	}
	_ = s.db.LogNotification(r.Context(), store.NotificationLog{ChannelID: c.ID, Kind: "test", Status: status, Error: errMsg})
	s.auditReq(r, "channel.test", c.ID, status)
	http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
}

func (s *Server) handleChannelToggle(w http.ResponseWriter, r *http.Request) {
	if c, ok := s.channelByID(r); ok {
		c.Enabled = !c.Enabled
		_, _ = s.db.SaveChannel(r.Context(), c)
		s.auditReq(r, "channel.toggle", c.ID, fmt.Sprintf("enabled=%v", c.Enabled))
	}
	http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
}

func (s *Server) handleChannelDelete(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	_ = s.db.DeleteChannel(r.Context(), id)
	s.auditReq(r, "channel.delete", id, "")
	http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
}

func (s *Server) handleDigestSave(w http.ResponseWriter, r *http.Request) {
	if err := r.ParseForm(); err != nil {
		s.httpError(w, r, 400, "bad form")
		return
	}
	expr := strings.TrimSpace(r.PostFormValue("digest_cron"))
	if expr != "" {
		if _, err := patch.ParseWindow(expr, time.Minute); err != nil {
			s.setFlash(w, "error", err.Error())
			http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
			return
		}
	}
	_ = s.db.SetSetting(r.Context(), "digest_cron", expr)
	_ = s.db.SetSetting(r.Context(), "digest_channels", strings.Join(r.PostForm["digest_channels"], ","))
	s.auditReq(r, "digest.save", "", "cron="+expr)
	if r.PostFormValue("send_now") == "1" {
		if err := s.sendDigest(r.Context()); err != nil {
			s.setFlash(w, "error", err.Error())
		} else {
			s.setFlash(w, "ok", "Digest sent.")
		}
	} else {
		s.setFlash(w, "ok", "Digest schedule saved.")
	}
	http.Redirect(w, r, "/settings/channels", http.StatusSeeOther)
}
