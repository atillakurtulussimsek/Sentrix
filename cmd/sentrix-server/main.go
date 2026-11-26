// Command sentrix-server runs the Sentrix control plane.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/auth"
	"github.com/atillakurtulussimsek/Sentrix/internal/cli"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/server"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

const usage = `Usage: sentrix-server [--config FILE] <command>

Commands:
  serve                       run the server (default)
  token create [--note N] [--group G] [--ttl 24h]
                              create a one-time agent enrolment token
  ca-fingerprint              print the CA fingerprint agents must pin
  stats                       print a JSON summary of stored data
  user create|reset-password --username U [--role R]
                              manage local users (password via SENTRIX_PASSWORD or stdin)
  audit [--target ID]         print the audit log
  api-token create --user U [--scope read|operate|admin] [--name N]
                              create an API token for the sentrix CLI
  hosts                       list hosts and their status
  findings [--host NAME]      list vulnerability findings (TSV)
  sync-feeds                  download vulnerability feeds now and re-match hosts
  version                     print version
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("sentrix-server", flag.ExitOnError)
	cfgPath := fs.String("config", os.Getenv("SENTRIX_CONFIG"), "config file (YAML)")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	_ = fs.Parse(os.Args[1:])
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
		host := ff.String("host", "", "hostname filter")
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
			return fmt.Errorf("usage: user create|reset-password --username U [--role admin|operator|viewer]  (password from SENTRIX_PASSWORD or stdin)")
		}
		uf := flag.NewFlagSet("user", flag.ExitOnError)
		name := uf.String("username", "", "username")
		role := uf.String("role", "admin", "admin | operator | viewer")
		_ = uf.Parse(args[1:])
		pw := os.Getenv("SENTRIX_PASSWORD")
		if pw == "" {
			fmt.Fprint(os.Stderr, "password: ")
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
				return fmt.Errorf("invalid role")
			}
			u, err := db.CreateUser(ctx, *name, hash, *role)
			if err != nil {
				return err
			}
			_ = db.Audit(ctx, "cli:sentrix-server", "user.create", u.ID, "username="+*name+" role="+*role)
			fmt.Println("created", u.Username, u.Role)
			return nil
		}
		u, err := db.GetUserByName(ctx, *name)
		if err != nil {
			return fmt.Errorf("user %q not found", *name)
		}
		u.PasswordHash, u.TOTPSecret, u.Disabled = hash, "", false
		if err := db.UpdateUser(ctx, u); err != nil {
			return err
		}
		_ = db.DeleteUserSessions(ctx, u.ID)
		_ = db.Audit(ctx, "cli:sentrix-server", "user.reset_password", u.ID, "2FA cleared")
		fmt.Println("password reset (2FA disabled) for", u.Username)
		return nil
	case "audit":
		af := flag.NewFlagSet("audit", flag.ExitOnError)
		target := af.String("target", "", "filter by target ID")
		limit := af.Int("limit", 100, "entries")
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
	case "api-token":
		if len(args) == 0 || args[0] != "create" {
			return fmt.Errorf("usage: api-token create --user NAME [--scope read|operate|admin] [--name NAME] [--ttl 720h]")
		}
		af := flag.NewFlagSet("api-token create", flag.ExitOnError)
		user := af.String("user", "", "user the token acts as")
		scope := af.String("scope", "read", "read | operate | admin")
		name := af.String("name", "cli", "token name")
		ttl := af.Duration("ttl", 0, "lifetime (0 = no expiry)")
		_ = af.Parse(args[1:])
		u, err := db.GetUserByName(ctx, *user)
		if err != nil {
			return fmt.Errorf("user %q not found", *user)
		}
		if *scope != "read" && *scope != "operate" && *scope != "admin" {
			return fmt.Errorf("invalid scope")
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
			return fmt.Errorf("usage: token create [--note N] [--group G] [--ttl 24h]")
		}
		tf := flag.NewFlagSet("token create", flag.ExitOnError)
		note := tf.String("note", "", "note")
		group := tf.String("group", "", "group assigned to the enrolled host")
		ttl := tf.Duration("ttl", 24*time.Hour, "token lifetime")
		_ = tf.Parse(args[1:])
		tok, _, err := srv.CreateEnrollToken(ctx, *note, *group, *ttl)
		if err != nil {
			return err
		}
		fmt.Printf("token:          %s\nca fingerprint: %s\n\nsentrix-agent enroll --server %s --token %s --ca-fingerprint %s\n",
			tok, srv.CA().Fingerprint(), cfg.GatewayURL, tok, srv.CA().Fingerprint())
		return nil
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}
