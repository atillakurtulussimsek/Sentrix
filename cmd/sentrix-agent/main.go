// Command sentrix-agent collects host data and executes typed actions for Sentrix.
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent"
	"github.com/atillakurtulussimsek/Sentrix/internal/cli"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

const usage = `Usage: sentrix-agent [--config FILE] <command>

Commands:
  run                         run the agent (default)
  enroll --server URL --token TOKEN --ca-fingerprint SHA256
                              enrol this host (one-time)
  inventory [--refresh]       print this host's inventory as JSON (no server needed)
  version                     print version
`

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	fs := flag.NewFlagSet("sentrix-agent", flag.ExitOnError)
	cfgPath := fs.String("config", os.Getenv("SENTRIX_AGENT_CONFIG"), "config file (YAML)")
	stateDir := fs.String("state-dir", "", "override state directory")
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	_ = fs.Parse(os.Args[1:])
	args := fs.Args()
	cmd := "run"
	if len(args) > 0 {
		cmd, args = args[0], args[1:]
	}
	if cmd == "version" {
		fmt.Println("sentrix-agent", version.String())
		return nil
	}
	cfg := config.DefaultAgent()
	if err := config.Load(*cfgPath, &cfg); err != nil {
		return err
	}
	if *stateDir != "" {
		cfg.StateDir = *stateDir
	}
	log := cli.Logger(cfg.LogLevel)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	switch cmd {
	case "enroll":
		ef := flag.NewFlagSet("enroll", flag.ExitOnError)
		srv := ef.String("server", cfg.ServerURL, "gateway URL, e.g. https://sentrix.example.com:8443")
		tok := ef.String("token", "", "one-time enrolment token")
		fp := ef.String("ca-fingerprint", "", "SHA-256 fingerprint of the server CA")
		name := ef.String("hostname", "", "override hostname")
		force := ef.Bool("force", false, "re-enrol even if already enrolled")
		_ = ef.Parse(args)
		if agent.Enrolled(cfg.StateDir) && !*force {
			return fmt.Errorf("already enrolled (state in %s); use --force to re-enrol", cfg.StateDir)
		}
		host := *name
		if host == "" {
			host, _ = os.Hostname()
		}
		id, err := agent.Enroll(ctx, cfg.StateDir, *srv, *tok, *fp, host, agent.MachineID())
		if err != nil {
			return err
		}
		fmt.Printf("enrolled as %s\n", id.AgentID)
		return nil
	case "run":
		a, err := agent.New(cfg, log)
		if err != nil {
			return err
		}
		if err := a.EnableMetrics(); err != nil {
			return err
		}
		a.EnableInventory()
		return a.Run(ctx)
	case "inventory":
		ivf := flag.NewFlagSet("inventory", flag.ExitOnError)
		refresh := ivf.Bool("refresh", false, "refresh package metadata (apt-get update / apk update) first")
		_ = ivf.Parse(args)
		inv := agent.NewInventoryCollector(cfg.ProcRoot, cfg.DockerSocket, *refresh).Collect(ctx)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	default:
		fs.Usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}
