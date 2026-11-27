// Command sentrix-server runs the Sentrix control plane.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/auth"
	"github.com/atillakurtulussimsek/Sentrix/internal/cli"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
	"github.com/atillakurtulussimsek/Sentrix/internal/notify"
	"github.com/atillakurtulussimsek/Sentrix/internal/server"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

// tr translates CLI messages; run binds it to the resolved language.
var tr = cli.Translator(i18n.DefaultLang)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, tr("cli.error", err))
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("sentrix-server", flag.ExitOnError)
	tr = cli.Translator(cli.ResolveLang("", ""))
	cfgPath := fs.String("config", os.Getenv("SENTRIX_CONFIG"), tr("cli.flag.config"))
	langFlag := fs.String("lang", "", tr("cli.flag.lang"))
	fs.Usage = func() {
		tr = cli.Translator(cli.ResolveLang(*langFlag, ""))
		fmt.Fprint(os.Stderr, tr("cli.server.usage"))
	}
	_ = fs.Parse(os.Args[1:])
	tr = cli.Translator(cli.ResolveLang(*langFlag, ""))
	args := fs.Args()
	cmd := "serve"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		fmt.Println("sentrix-server", version.String())
		return nil
	}
	cfg := config.DefaultServer()
	if err := config.Load(*cfgPath, &cfg); err != nil {
		return err
	}
	lang := cli.ResolveLang(*langFlag, cfg.Language)
	tr = cli.Translator(lang)
	if cmd == "healthcheck" { // used by the container HEALTHCHECK (no curl in distroless)
		port := cfg.Listen
		if strings.HasPrefix(port, ":") {
			port = "127.0.0.1" + port
		}
		resp, err := http.Get("http://" + port + "/healthz") //nolint:gosec,noctx // local health probe
		if err != nil {
			return err
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return errors.New(tr("cli.server.unhealthy", resp.Status))
		}
		return nil
	}
	log := cli.Logger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	db, err := store.Open(ctx, filepath.Join(cfg.DataDir, "sentrix.db"))
	if err != nil {
		return err
	}
	defer db.Close()
	srv, err := server.New(cfg, db, log)
	if err != nil {
		return err
	}
	switch cmd {
	case "serve":
		return srv.Run(ctx)
	case "hosts":
		hosts, err := db.ListHosts(ctx)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			st := "offline"
			if h.Online(time.Now(), cfg.OfflineAfter) {
				st = "online"
			}
			fmt.Printf("%s\t%s\t%s\t%s\n", h.ID, h.Hostname, st, h.LastSeen.Format(time.RFC3339))
		}
		return nil
	case "findings":
		ff := flag.NewFlagSet("findings", flag.ExitOnError)
		host := ff.String("host", "", tr("cli.server.flag.host"))
		_ = ff.Parse(args)
		hosts, err := db.ListHosts(ctx)
		if err != nil {
			return err
		}
		for _, h := range hosts {
			if *host != "" && h.Hostname != *host {
				continue
			}
			fs, err := db.ListFindings(ctx, store.FindingFilter{HostID: h.ID})
			if err != nil {
				return err
			}
			for _, f := range fs {
				fixed := f.Fixed
				if fixed == "" {
					fixed = "-"
				}
				fmt.Printf("%s\t%s\t%s\t%s\t%s\t%s\t%.1f\n", h.Hostname, f.VulnID, f.Package, f.Installed, fixed, f.Severity, f.Risk)
			}
		}
		return nil
	case "sync-feeds":
		cfg.Feeds.Enabled = true
		return srv.SyncFeeds(ctx, true)
	case "user":
		if len(args) == 0 || (args[0] != "create" && args[0] != "reset-password") {
			return errors.New(tr("cli.server.usageUser"))
		}
		uf := flag.NewFlagSet("user", flag.ExitOnError)
		name := uf.String("username", "", tr("cli.server.flag.username"))
		role := uf.String("role", "admin", "admin | operator | viewer")
		_ = uf.Parse(args[1:])
		pw := os.Getenv("SENTRIX_PASSWORD")
		if pw == "" {
			fmt.Fprint(os.Stderr, tr("cli.server.passwordPrompt"))
			if _, err := fmt.Fscanln(os.Stdin, &pw); err != nil {
				return err
			}
		}
		if err := auth.ValidatePassword(pw); err != nil {
			return err
		}
		hash, err := auth.HashPassword(pw)
		if err != nil {
			return err
		}
		if args[0] == "create" {
			if store.RoleRank(*role) == 0 {
				return errors.New(tr("cli.server.invalidRole"))
			}
			u, err := db.CreateUser(ctx, *name, hash, *role)
			if err != nil {
				return err
			}
			_ = db.Audit(ctx, "cli:sentrix-server", "user.create", u.ID, "username="+*name+" role="+*role)
			fmt.Println(tr("cli.server.userCreated", u.Username, u.Role))
			return nil
		}
		u, err := db.GetUserByName(ctx, *name)
		if err != nil {
			return errors.New(tr("cli.server.userNotFound", *name))
		}
		u.PasswordHash, u.TOTPSecret, u.Disabled = hash, "", false
		if err := db.UpdateUser(ctx, u); err != nil {
			return err
		}
		_ = db.DeleteUserSessions(ctx, u.ID)
		_ = db.Audit(ctx, "cli:sentrix-server", "user.reset_password", u.ID, "2FA cleared")
		fmt.Println(tr("cli.server.passwordReset", u.Username))
		return nil
	case "audit":
		af := flag.NewFlagSet("audit", flag.ExitOnError)
		target := af.String("target", "", tr("cli.server.flag.target"))
		limit := af.Int("limit", 100, tr("cli.server.flag.limit"))
		_ = af.Parse(args)
		es, err := db.ListAudit(ctx, *target, *limit)
		if err != nil {
			return err
		}
		for i := len(es) - 1; i >= 0; i-- {
			e := es[i]
			fmt.Printf("%s\t%s\t%s\t%s\t%s\n", e.TS.Format(time.RFC3339), e.Actor, e.Action, e.Target, e.Detail)
		}
		return nil
	case "channel":
		if len(args) == 0 || args[0] != "create" {
			return errors.New(tr("cli.server.usageChannel"))
		}
		cf := flag.NewFlagSet("channel create", flag.ExitOnError)
		name := cf.String("name", "", tr("cli.server.flag.channelName"))
		kind := cf.String("kind", "webhook", "webhook | slack | discord | ntfy")
		u := cf.String("url", "", "URL")
		topic := cf.String("topic", "", tr("cli.server.flag.topic"))
		_ = cf.Parse(args[1:])
		b, _ := json.Marshal(notify.Config{URL: *u, Topic: *topic})
		c, err := db.SaveChannel(ctx, store.Channel{Name: *name, Kind: *kind, Config: string(b), Enabled: true})
		if err != nil {
			return err
		}
		fmt.Println(c.ID)
		return nil
	case "rule":
		if len(args) == 0 || args[0] != "create" {
			return errors.New(tr("cli.server.usageRule"))
		}
		rf := flag.NewFlagSet("rule create", flag.ExitOnError)
		name := rf.String("name", "", tr("cli.server.flag.ruleName"))
		metric := rf.String("metric", "", tr("cli.server.flag.metric"))
		labels := rf.String("labels", "", tr("cli.server.flag.labels"))
		op := rf.String("op", ">", "> >= < <=")
		val := rf.Float64("value", 90, tr("cli.server.flag.value"))
		forDur := rf.Duration("for", 5*time.Minute, tr("cli.server.flag.for"))
		cool := rf.Duration("cooldown", 6*time.Hour, tr("cli.server.flag.cooldown"))
		chName := rf.String("channel", "", tr("cli.server.flag.channel"))
		sev := rf.String("severity", "warning", "info | warning | critical")
		_ = rf.Parse(args[1:])
		rc := notify.RuleConfig{Metric: *metric, Labels: *labels, Op: *op, Value: *val}
		if err := rc.Validate("threshold"); err != nil {
			return err
		}
		var chans []string
		if *chName != "" {
			all, _ := db.ListChannels(ctx)
			for _, c := range all {
				if c.Name == *chName {
					chans = append(chans, c.ID)
				}
			}
			if len(chans) == 0 {
				return errors.New(tr("cli.server.channelNotFound", *chName))
			}
		}
		b, _ := json.Marshal(rc)
		r, err := db.SaveRule(ctx, store.Rule{Name: *name, Kind: "threshold", Config: string(b), Severity: *sev, Channels: chans, For: *forDur, Cooldown: *cool, Enabled: true})
		if err != nil {
			return err
		}
		fmt.Println(r.ID)
		return nil
	case "api-token":
		if len(args) == 0 || args[0] != "create" {
			return errors.New(tr("cli.server.usageAPIToken"))
		}
		af := flag.NewFlagSet("api-token create", flag.ExitOnError)
		user := af.String("user", "", tr("cli.server.flag.user"))
		scope := af.String("scope", "read", "read | operate | admin")
		name := af.String("name", "cli", tr("cli.server.flag.tokenName"))
		ttl := af.Duration("ttl", 0, tr("cli.server.flag.apiTTL"))
		_ = af.Parse(args[1:])
		u, err := db.GetUserByName(ctx, *user)
		if err != nil {
			return errors.New(tr("cli.server.userNotFound", *user))
		}
		if *scope != "read" && *scope != "operate" && *scope != "admin" {
			return errors.New(tr("cli.server.invalidScope"))
		}
		tok := server.GenerateToken("sxa_")
		if _, err := db.CreateAPIToken(ctx, store.HashToken(tok), u.ID, *name, *scope, *ttl); err != nil {
			return err
		}
		_ = db.Audit(ctx, "cli:sentrix-server", "api_token.create", u.ID, "name="+*name+" scope="+*scope)
		fmt.Println(tok)
		return nil
	case "stats":
		st, err := db.Stats(ctx)
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(st)
	case "ca-fingerprint":
		fmt.Println(srv.CA().Fingerprint())
		return nil
	case "token":
		if len(args) == 0 || args[0] != "create" {
			return errors.New(tr("cli.server.usageToken"))
		}
		tf := flag.NewFlagSet("token create", flag.ExitOnError)
		note := tf.String("note", "", tr("cli.server.flag.note"))
		group := tf.String("group", "", tr("cli.server.flag.group"))
		ttl := tf.Duration("ttl", 24*time.Hour, tr("cli.server.flag.ttl"))
		_ = tf.Parse(args[1:])
		tok, _, err := srv.CreateEnrollToken(ctx, *note, *group, *ttl)
		if err != nil {
			return err
		}
		fp := srv.CA().Fingerprint()
		fmt.Print(tr("cli.server.tokenCreated", tok, fp, strings.TrimRight(cfg.BaseURL, "/"), tok, fp, cli.ResolveLang("", cfg.Language), cfg.GatewayURL, tok, fp))
		return nil
	default:
		fs.Usage()
		return errors.New(tr("cli.unknownCommand", cmd))
	}
}
