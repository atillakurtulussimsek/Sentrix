// Command sentrix-agent collects host data and executes typed actions for Sentrix.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent"
	"github.com/atillakurtulussimsek/Sentrix/internal/cli"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
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
	fs := flag.NewFlagSet("sentrix-agent", flag.ExitOnError)
	tr = cli.Translator(cli.ResolveLang("", ""))
	cfgPath := fs.String("config", os.Getenv("SENTRIX_AGENT_CONFIG"), tr("cli.flag.config"))
	stateDir := fs.String("state-dir", "", tr("cli.agent.flag.stateDir"))
	langFlag := fs.String("lang", "", tr("cli.flag.lang"))
	fs.Usage = func() {
		tr = cli.Translator(cli.ResolveLang(*langFlag, ""))
		fmt.Fprint(os.Stderr, tr("cli.agent.usage"))
	}
	_ = fs.Parse(os.Args[1:])
	tr = cli.Translator(cli.ResolveLang(*langFlag, ""))
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
		srv := ef.String("server", cfg.ServerURL, tr("cli.agent.flag.server"))
		tok := ef.String("token", "", tr("cli.agent.flag.token"))
		fp := ef.String("ca-fingerprint", "", tr("cli.agent.flag.fingerprint"))
		name := ef.String("hostname", "", tr("cli.agent.flag.hostname"))
		force := ef.Bool("force", false, tr("cli.agent.flag.force"))
		_ = ef.Parse(args)
		if agent.Enrolled(cfg.StateDir) && !*force {
			return errors.New(tr("cli.agent.alreadyEnrolled", cfg.StateDir))
		}
		host := *name
		if host == "" {
			host, _ = os.Hostname()
		}
		id, err := agent.Enroll(ctx, cfg.StateDir, *srv, *tok, *fp, host, agent.MachineID(), *name)
		if err != nil {
			return err
		}
		fmt.Println(tr("cli.agent.enrolled", id.AgentID))
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
		a.EnableCommands()
		return a.Run(ctx)
	case "inventory":
		ivf := flag.NewFlagSet("inventory", flag.ExitOnError)
		refresh := ivf.Bool("refresh", false, tr("cli.agent.flag.refresh"))
		_ = ivf.Parse(args)
		inv := agent.NewInventoryCollector(cfg.ProcRoot, cfg.DockerSocket, *refresh).Collect(ctx)
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(inv)
	default:
		fs.Usage()
		return errors.New(tr("cli.unknownCommand", cmd))
	}
}
