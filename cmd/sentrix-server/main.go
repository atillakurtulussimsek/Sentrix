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
