package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/notify"
	"github.com/atillakurtulussimsek/Sentrix/internal/patch"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// seedDefaultRules creates sensible default rules on first start.
func (s *Server) seedDefaultRules(ctx context.Context) error {
	rules, err := s.db.ListRules(ctx)
	if err != nil || len(rules) > 0 {
		return err
	}
	defs := []struct {
		name, kind, sev string
		cfg             notify.RuleConfig
		forDur          time.Duration
	}{
		{"Agent offline", "state", "critical", notify.RuleConfig{Condition: "agent_offline"}, 5 * time.Minute},
		{"Disk almost full", "threshold", "warning", notify.RuleConfig{Metric: "disk.used_pct", Op: ">", Value: 90}, 5 * time.Minute},
		{"Inodes almost exhausted", "threshold", "warning", notify.RuleConfig{Metric: "disk.inodes_used_pct", Op: ">", Value: 90}, 5 * time.Minute},
		{"Failed systemd units", "state", "warning", notify.RuleConfig{Condition: "failed_units"}, 5 * time.Minute},
		{"Watched service down", "state", "critical", notify.RuleConfig{Condition: "service_down"}, 2 * time.Minute},
		{"Reboot pending for 7 days", "state", "warning", notify.RuleConfig{Condition: "reboot_pending"}, 7 * 24 * time.Hour},
		{"New known-exploited vulnerability", "vulnerability", "critical", notify.RuleConfig{OnlyKEV: true}, 0},
		{"New critical vulnerability", "vulnerability", "critical", notify.RuleConfig{MinSeverity: "critical"}, 0},
		{"Patch plan result", "patch", "info", notify.RuleConfig{}, 0},
	}
	for _, d := range defs {
		b, _ := json.Marshal(d.cfg)
		if _, err := s.db.SaveRule(ctx, store.Rule{Name: d.name, Kind: d.kind, Config: string(b), Severity: d.sev, For: d.forDur, Cooldown: 6 * time.Hour, Enabled: true}); err != nil {
			return err
		}
	}
	return nil
}

func ruleConfig(r store.Rule) notify.RuleConfig {
	var c notify.RuleConfig
	_ = json.Unmarshal([]byte(r.Config), &c)
	return c
}

// EvaluateAlerts evaluates threshold and state rules and applies transitions.
func (s *Server) EvaluateAlerts(ctx context.Context) error {
	s.alertMu.Lock()
	defer s.alertMu.Unlock()
	rules, err := s.db.ListRules(ctx)
	if err != nil {
		return err
	}
	open, err := s.db.OpenAlerts(ctx)
	if err != nil {
		return err
	}
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	var errs []error
	for _, r := range rules {
		if r.Kind != "threshold" && r.Kind != "state" {
			continue
		}
		active := map[string]notify.Observation{}
		if r.Enabled {
			obs, err := s.observe(ctx, r, hosts, now)
			if err != nil {
				errs = append(errs, err)
				continue
			}
			for _, o := range obs {
				active[o.Key] = o
			}
		}
		for key, o := range active {
			if err := s.applyTransition(ctx, r, open[key], true, o, now); err != nil {
				errs = append(errs, err)
			}
		}
		for key, a := range open {
			if a.RuleID != r.ID {
				continue
			}
			if _, still := active[key]; !still {
				if err := s.applyTransition(ctx, r, a, false, notify.Observation{Key: key, HostID: a.HostID, Subject: a.Subject, Value: a.Value}, now); err != nil {
					errs = append(errs, err)
				}
			}
		}
	}
	return errors.Join(errs...)
}

func (s *Server) observe(ctx context.Context, r store.Rule, hosts []store.Host, now time.Time) ([]notify.Observation, error) {
	cfg := ruleConfig(r)
	var out []notify.Observation
	var latest map[string]map[string]float64
	if r.Kind == "threshold" {
		var err error
		if latest, err = s.db.LatestFleet(ctx, cfg.Metric); err != nil {
			return nil, err
		}
	}
	for _, h := range hosts {
		if h.Revoked || (cfg.Group != "" && h.Group != cfg.Group) {
			continue
		}
		key := r.ID + ":" + h.ID
		switch r.Kind {
		case "threshold":
			if !h.Online(now, s.cfg.OfflineAfter) {
				continue // stale values must not keep alerts firing; offline has its own rule
			}
			for series, v := range latest[h.ID] {
				labels := ""
				if i := strings.IndexByte(series, '{'); i >= 0 {
					labels = strings.TrimSuffix(series[i+1:], "}")
				}
				if !cfg.LabelsMatch(labels) || !cfg.Breaches(v) {
					continue
				}
				out = append(out, notify.Observation{Key: key + ":" + labels, HostID: h.ID, Host: h.Hostname, Subject: labels, Value: v,
					Message: fmt.Sprintf("%s is %.1f (%s %g)%s", cfg.Metric, v, cfg.Op, cfg.Value, braces(labels))})
			}
		case "state":
			st := parseState(h.StateJSON)
			switch cfg.Condition {
			case "agent_offline":
				if !h.Online(now, s.cfg.OfflineAfter) && !h.LastSeen.IsZero() {
					out = append(out, notify.Observation{Key: key, HostID: h.ID, Host: h.Hostname, Message: "agent offline since " + h.LastSeen.Format(time.RFC3339)})
				}
			case "failed_units":
				if h.Online(now, s.cfg.OfflineAfter) && len(st.FailedUnits) > 0 {
					out = append(out, notify.Observation{Key: key, HostID: h.ID, Host: h.Hostname, Value: float64(len(st.FailedUnits)), Message: "failed units: " + strings.Join(st.FailedUnits, ", ")})
				}
			case "service_down":
				if down := s.downServices(ctx, h.ID); h.Online(now, s.cfg.OfflineAfter) && len(down) > 0 {
					out = append(out, notify.Observation{Key: key, HostID: h.ID, Host: h.Hostname, Message: "watched services down: " + strings.Join(down, ", ")})
				}
			case "reboot_pending":
				if st.Reboot.Required {
					out = append(out, notify.Observation{Key: key, HostID: h.ID, Host: h.Hostname, Message: "reboot required: " + strings.Join(st.Reboot.Reasons, "; ")})
				}
			}
		}
	}
	return out, nil
}

func braces(s string) string {
	if s == "" {
		return ""
	}
	return " {" + s + "}"
}

// applyTransition persists the alert state change and sends notifications.
func (s *Server) applyTransition(ctx context.Context, r store.Rule, a store.Alert, active bool, o notify.Observation, now time.Time) error {
	last, err := s.db.LastFiredNotification(ctx, o.Key)
	if err != nil {
		return err
	}
	exists := a.ID != ""
	status, act := notify.Transition(notify.AlertState{Exists: exists, Status: a.Status, StartedAt: a.StartedAt, LastNotified: a.LastNotified}, active, now, r.For, r.Cooldown, last)
	if status == "" {
		if exists && a.Status == "pending" {
			return s.db.DeleteAlert(ctx, a.ID)
		}
		return nil
	}
	if !exists {
		a = store.Alert{RuleID: r.ID, HostID: o.HostID, Key: o.Key, Severity: r.Severity, StartedAt: now}
	}
	prev := a.Status
	a.Status, a.Subject = status, o.Subject
	if o.Message != "" {
		a.Message = o.Message
	}
	if active {
		a.Value = o.Value
	}
	if status == "firing" && prev != "firing" {
		a.FiredAt = now
	}
	if status == "resolved" {
		a.ResolvedAt = now
	}
	if act != notify.NoAction {
		a.LastNotified = now
	}
	a, err = s.db.SaveAlert(ctx, a)
	if err != nil {
		return err
	}
	if status != prev {
		s.hub.Publish(Event{Type: "alert", HostID: a.HostID, Data: map[string]string{"id": a.ID, "status": status, "rule": r.Name}})
	}
	switch act {
	case notify.NotifyFiring, notify.NotifyRepeat:
		_ = s.db.SetLastFiredNotification(ctx, o.Key, now)
		s.dispatch(ctx, r, a, "firing")
	case notify.NotifyResolved:
		s.dispatch(ctx, r, a, "resolved")
	}
	return nil
}

func (s *Server) hostname(ctx context.Context, id string) string {
	if id == "" {
		return ""
	}
	h, err := s.db.GetHost(ctx, id)
	if err != nil {
		return id
	}
	return h.Hostname
}

// dispatch sends an alert notification to the rule's channels.
func (s *Server) dispatch(ctx context.Context, r store.Rule, a store.Alert, event string) {
	host := s.hostname(ctx, a.HostID)
	title := fmt.Sprintf("[%s] %s", strings.ToUpper(a.Severity), r.Name)
	if event == "resolved" {
		title = "[RESOLVED] " + r.Name
	}
	if host != "" {
		title += " on " + host
	}
	link := strings.TrimRight(s.cfg.BaseURL, "/") + "/alerts"
	if a.HostID != "" {
		link = strings.TrimRight(s.cfg.BaseURL, "/") + "/hosts/" + a.HostID
	}
	m := notify.Message{Event: event, Severity: a.Severity, Title: title, Body: a.Message, Host: host, HostID: a.HostID, AlertID: a.ID, Rule: r.Name, Value: a.Value, URL: link, Time: s.now()}
	s.sendToChannels(ctx, r.Channels, m, a.ID)
}

// sendToChannels delivers m to the given channel IDs (all enabled when empty).
func (s *Server) sendToChannels(ctx context.Context, ids []string, m notify.Message, alertID string) int {
	chans, err := s.db.ListChannels(ctx)
	if err != nil {
		return 0
	}
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	sent := 0
	for _, c := range chans {
		if !c.Enabled || (len(want) > 0 && !want[c.ID]) {
			continue
		}
		if err := s.sendChannel(ctx, c, m); err != nil {
			s.log.Warn("notification failed", "channel", c.Name, "err", err)
			_ = s.db.LogNotification(ctx, store.NotificationLog{ChannelID: c.ID, AlertID: alertID, Kind: m.Event, Status: "failed", Error: truncate(err.Error(), 300)})
			continue
		}
		sent++
		_ = s.db.LogNotification(ctx, store.NotificationLog{ChannelID: c.ID, AlertID: alertID, Kind: m.Event, Status: "sent"})
	}
	return sent
}

func (s *Server) channelConfig(c store.Channel) (notify.Config, error) {
	var cfg notify.Config
	if err := json.Unmarshal([]byte(c.Config), &cfg); err != nil {
		return cfg, err
	}
	var err error
	if cfg.Secret, err = s.box.Open(cfg.Secret); err != nil {
		return cfg, err
	}
	if cfg.Token, err = s.box.Open(cfg.Token); err != nil {
		return cfg, err
	}
	if cfg.Password, err = s.box.Open(cfg.Password); err != nil {
		return cfg, err
	}
	return cfg, nil
}

func (s *Server) sendChannel(ctx context.Context, c store.Channel, m notify.Message) error {
	cfg, err := s.channelConfig(c)
	if err != nil {
		return fmt.Errorf("channel config: %w", err)
	}
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return s.sender.Send(sctx, c.Kind, cfg, m)
}

// alertEventLoop turns findings and plan events into notifications.
func (s *Server) alertEventLoop(ctx context.Context) {
	ch, unsub := s.hub.Subscribe()
	defer unsub()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-ch:
			if !ok {
				return
			}
			switch ev.Type {
			case "findings":
				s.onFindingsEvent(ctx, ev)
			case "plan":
				s.onPlanEvent(ctx, ev)
			}
		}
	}
}

var sevOrder = map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}

func (s *Server) onFindingsEvent(ctx context.Context, ev Event) {
	data, ok := ev.Data.(map[string]any)
	if !ok {
		return
	}
	added, _ := data["added"].([]store.StoredFinding)
	resolved, _ := data["resolved"].([]store.StoredFinding)
	metas, _ := data["metas"].(map[string]store.VulnMeta)
	rules, err := s.db.ListRules(ctx)
	if err != nil {
		return
	}
	s.alertMu.Lock()
	defer s.alertMu.Unlock()
	open, _ := s.db.OpenAlerts(ctx)
	now := s.now()
	host, _ := s.db.GetHost(ctx, ev.HostID)
	for _, r := range rules {
		if r.Kind != "vulnerability" || !r.Enabled {
			continue
		}
		cfg := ruleConfig(r)
		if cfg.Group != "" && host.Group != cfg.Group {
			continue
		}
		var hits []store.StoredFinding
		for _, f := range added {
			m := metas[f.VulnID]
			if cfg.OnlyKEV && !m.KEV {
				continue
			}
			if cfg.MinSeverity != "" && sevOrder[f.Severity] < sevOrder[cfg.MinSeverity] {
				continue
			}
			hits = append(hits, f)
		}
		for _, f := range hits {
			key := r.ID + ":" + ev.HostID + ":" + f.VulnID + ":" + f.Package
			if _, exists := open[key]; exists {
				continue
			}
			fix := "no fix available yet"
			if f.Fixed != "" {
				fix = "fixed in " + f.Fixed
			}
			msg := fmt.Sprintf("%s in %s %s (%s) — risk %.0f", f.VulnID, f.Package, f.Installed, fix, f.Risk)
			if m := metas[f.VulnID]; m.KEV {
				msg += " — listed in CISA KEV"
			}
			_ = s.applyTransition(ctx, r, store.Alert{}, true, notify.Observation{Key: key, HostID: ev.HostID, Subject: f.VulnID, Value: f.Risk, Message: msg}, now)
		}
		for _, f := range resolved {
			key := r.ID + ":" + ev.HostID + ":" + f.VulnID + ":" + f.Package
			if a, ok := open[key]; ok {
				_ = s.applyTransition(ctx, r, a, false, notify.Observation{Key: key, HostID: ev.HostID, Subject: f.VulnID}, now)
			}
		}
	}
}

func (s *Server) onPlanEvent(ctx context.Context, ev Event) {
	data, ok := ev.Data.(map[string]string)
	if !ok || (data["status"] != "done" && data["status"] != "failed") {
		return
	}
	rules, err := s.db.ListRules(ctx)
	if err != nil {
		return
	}
	for _, r := range rules {
		if r.Kind != "patch" || !r.Enabled {
			continue
		}
		if ruleConfig(r).OnlyFailed && data["status"] != "failed" {
			continue
		}
		sev := "info"
		if data["status"] == "failed" {
			sev = "critical"
		}
		body := "Plan " + data["name"] + " finished: " + data["status"]
		if data["error"] != "" {
			body += " — " + data["error"]
		}
		a, err := s.db.SaveAlert(ctx, store.Alert{RuleID: r.ID, Key: r.ID + ":plan:" + data["id"], Status: "resolved", Severity: sev, Subject: data["id"],
			Message: body, StartedAt: s.now(), FiredAt: s.now(), ResolvedAt: s.now(), LastNotified: s.now()})
		if err != nil {
			continue
		}
		m := notify.Message{Event: "patch", Severity: sev, Title: "Patch plan " + data["status"] + ": " + data["name"], Body: body,
			URL: strings.TrimRight(s.cfg.BaseURL, "/") + "/patches/" + data["id"], AlertID: a.ID, Rule: r.Name, Time: s.now()}
		s.sendToChannels(ctx, r.Channels, m, a.ID)
	}
}

// ---- digest ----

// BuildDigest renders the "what needs attention" summary.
func (s *Server) BuildDigest(ctx context.Context) (notify.Message, error) {
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		return notify.Message{}, err
	}
	now := s.now()
	var offline, reboots []string
	for _, h := range hosts {
		if h.Revoked {
			continue
		}
		if !h.Online(now, s.cfg.OfflineAfter) {
			offline = append(offline, h.Hostname)
		}
		if parseState(h.StateJSON).Reboot.Required {
			reboots = append(reboots, h.Hostname)
		}
	}
	counts, _ := s.db.UpdateCounts(ctx)
	type pend struct {
		name     string
		sec, all int
	}
	var pending []pend
	for _, h := range hosts {
		if c := counts[h.ID]; c[0] > 0 {
			pending = append(pending, pend{h.Hostname, c[1], c[0]})
		}
	}
	sort.Slice(pending, func(i, j int) bool { return pending[i].sec > pending[j].sec })
	top, _ := s.db.FleetVulns(ctx, store.VulnFilter{Limit: 5})
	firing, _ := s.db.ListAlerts(ctx, "firing", 20)
	var b strings.Builder
	fmt.Fprintf(&b, "Fleet: %d hosts, %d offline, %d firing alerts.\n", len(hosts), len(offline), len(firing))
	if len(offline) > 0 {
		fmt.Fprintf(&b, "\nOffline: %s\n", strings.Join(offline, ", "))
	}
	if len(top) > 0 {
		b.WriteString("\nTop risks:\n")
		for _, v := range top {
			kev := ""
			if v.KEV {
				kev = " KEV"
			}
			fmt.Fprintf(&b, "  • %s (%s%s, risk %.0f) — %d host(s): %s\n", v.ID, v.EffSeverity, kev, v.MaxRisk, v.Hosts, v.Packages)
		}
	}
	if len(pending) > 0 {
		b.WriteString("\nPending updates:\n")
		for i, p := range pending {
			if i == 10 {
				fmt.Fprintf(&b, "  … and %d more hosts\n", len(pending)-10)
				break
			}
			fmt.Fprintf(&b, "  • %s: %d (%d security)\n", p.name, p.all, p.sec)
		}
	}
	if len(reboots) > 0 {
		fmt.Fprintf(&b, "\nReboot pending: %s\n", strings.Join(reboots, ", "))
	}
	return notify.Message{Event: "digest", Severity: "info", Title: "Sentrix digest — " + now.Format("Mon 2 Jan 2006"), Body: b.String(),
		URL: strings.TrimRight(s.cfg.BaseURL, "/") + "/", Time: now}, nil
}

// digestJob sends the digest according to the configured schedule.
func (s *Server) digestJob(ctx context.Context) error {
	cronExpr, _ := s.db.GetSetting(ctx, "digest_cron")
	if cronExpr == "" {
		return nil // disabled
	}
	w, err := patch.ParseWindow(cronExpr, time.Minute)
	if err != nil {
		return err
	}
	lastS, _ := s.db.GetSetting(ctx, "digest_last")
	var last time.Time
	if lastS != "" {
		last, _ = time.Parse(time.RFC3339, lastS)
	}
	now := s.now()
	open, _ := w.Open(now)
	if !open || now.Sub(last) < 2*time.Minute {
		return nil
	}
	return s.sendDigest(ctx)
}

func (s *Server) sendDigest(ctx context.Context) error {
	m, err := s.BuildDigest(ctx)
	if err != nil {
		return err
	}
	ids, _ := s.db.GetSetting(ctx, "digest_channels")
	s.sendToChannels(ctx, store.SplitTags(ids), m, "")
	return s.db.SetSetting(ctx, "digest_last", s.now().Format(time.RFC3339))
}
