package agent

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/pki"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

// Agent is a running sentrix-agent.
type Agent struct {
	cfg  config.Agent
	log  *slog.Logger
	id   Identity
	c    *client
	leaf *x509.Certificate

	mu            sync.Mutex
	watchServices []string
	tlsEndpoints  []string

	// hooks registered by subsystems (collectors, inventory, executor)
	loops []func(context.Context)
}

// New loads the identity from cfg.StateDir and prepares the mTLS client.
func New(cfg config.Agent, log *slog.Logger) (*Agent, error) {
	id, err := LoadIdentity(cfg.StateDir)
	if err != nil {
		return nil, fmt.Errorf("agent is not enrolled (run 'sentrix-agent enroll'): %w", err)
	}
	if cfg.ServerURL == "" {
		cfg.ServerURL = id.ServerURL
	}
	a := &Agent{cfg: cfg, log: log, id: id, watchServices: cfg.WatchServices, tlsEndpoints: cfg.TLSEndpoints}
	if err := a.reloadClient(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Agent) reloadClient() error {
	hc, leaf, err := mtlsClient(a.cfg.StateDir, 60*time.Second)
	if err != nil {
		return err
	}
	a.c = &client{base: a.cfg.ServerURL, http: hc}
	a.leaf = leaf
	return nil
}

// ID returns the agent ID.
func (a *Agent) ID() string { return a.id.AgentID }

// Run blocks until ctx is cancelled.
func (a *Agent) Run(ctx context.Context) error {
	a.log.Info("sentrix agent started", "id", a.id.AgentID, "server", a.cfg.ServerURL, "version", version.Version)
	var wg sync.WaitGroup
	loops := append([]func(context.Context){a.heartbeatLoop}, a.loops...)
	for _, l := range loops {
		wg.Add(1)
		go func(f func(context.Context)) {
			defer wg.Done()
			f(ctx)
		}(l)
	}
	wg.Wait()
	a.log.Info("sentrix agent stopped")
	return nil
}

func (a *Agent) heartbeatLoop(ctx context.Context) {
	interval := 15 * time.Second
	host, _ := os.Hostname()
	boot := bootTime(a.cfg.ProcRoot)
	backoff := time.Second
	for {
		var resp protocol.HeartbeatResponse
		err := a.c.post(ctx, protocol.PathHeartbeat, protocol.Heartbeat{
			AgentVersion: version.Version, Hostname: host, BootTime: boot, SentAt: time.Now().UTC(),
		}, &resp)
		wait := interval
		switch {
		case err == nil:
			backoff = time.Second
			if resp.IntervalSeconds > 0 {
				interval = time.Duration(resp.IntervalSeconds) * time.Second
				wait = interval
			}
			a.mu.Lock()
			if resp.WatchServices != nil {
				a.watchServices = resp.WatchServices
			}
			if resp.TLSEndpoints != nil {
				a.tlsEndpoints = resp.TLSEndpoints
			}
			a.mu.Unlock()
			a.maybeRenew(ctx)
		case ctx.Err() != nil:
			return
		default:
			var he *HTTPError
			if errors.As(err, &he) && he.Status == 403 {
				a.log.Error("server rejected agent certificate (revoked?)", "err", err)
			} else {
				a.log.Warn("heartbeat failed", "err", err)
			}
			wait = min(backoff, interval)
			backoff = min(backoff*2, 5*time.Minute)
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

// maybeRenew renews the client certificate when less than 30 days remain.
func (a *Agent) maybeRenew(ctx context.Context) {
	if a.leaf == nil || time.Until(a.leaf.NotAfter) > 30*24*time.Hour {
		return
	}
	keyPEM, csrPEM, err := pki.NewKeyAndCSR(a.id.AgentID)
	if err != nil {
		return
	}
	var er protocol.EnrollResponse
	if err := a.c.post(ctx, protocol.PathRenew, protocol.RenewRequest{CSRPEM: string(csrPEM)}, &er); err != nil {
		a.log.Warn("certificate renewal failed", "err", err)
		return
	}
	if err := os.WriteFile(filepath.Join(a.cfg.StateDir, fileKey), keyPEM, 0o600); err != nil {
		return
	}
	if err := os.WriteFile(filepath.Join(a.cfg.StateDir, fileCert), []byte(er.CertPEM), 0o600); err != nil {
		return
	}
	if err := a.reloadClient(); err != nil {
		a.log.Error("reload client after renewal", "err", err)
		return
	}
	a.log.Info("agent certificate renewed", "not_after", a.leaf.NotAfter)
}
