// Package server implements the Sentrix control plane: agent gateway, web UI, REST API
// and background jobs.
package server

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base32"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/auth"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/i18n"
	"github.com/atillakurtulussimsek/Sentrix/internal/pki"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/web"
)

// Server is the Sentrix control plane.
type Server struct {
	cfg  config.Server
	db   *store.DB
	ca   *pki.CA
	log  *slog.Logger
	hub  *Hub
	jobs []job
	mets store.MetricStore

	mu          sync.Mutex
	onlineCache map[string]bool

	cat       *i18n.Catalog
	rend      *renderer
	box       *auth.SecretBox
	setupMu   sync.Mutex
	setupDone atomic.Bool
	loginIP   *auth.Limiter
	loginUser *auth.Limiter

	inventoryHooks []func(ctx context.Context, hostID string)
	feeds          feedRunner
	bgCtx          context.Context
	orchKick       chan struct{}
	orchMu         sync.Mutex
	now            func() time.Time
}

type job struct {
	name     string
	interval time.Duration
	fn       func(context.Context) error
}

// New wires a Server from config and an opened store.
func New(cfg config.Server, db *store.DB, log *slog.Logger) (*Server, error) {
	ca, err := pki.LoadOrCreateCA(filepath.Join(cfg.DataDir, "pki"))
	if err != nil {
		return nil, fmt.Errorf("load CA: %w", err)
	}
	cat, err := i18n.Load(web.I18n, "i18n")
	if err != nil {
		return nil, fmt.Errorf("load i18n: %w", err)
	}
	rend, err := newRenderer(cat, cfg.Language)
	if err != nil {
		return nil, err
	}
	key, err := auth.LoadOrCreateKey(filepath.Join(cfg.DataDir, "secret.key"))
	if err != nil {
		return nil, err
	}
	box, err := auth.NewSecretBox(key)
	if err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, db: db, ca: ca, log: log, hub: NewHub(), onlineCache: map[string]bool{}, mets: db.Metrics(),
		cat: cat, rend: rend, box: box,
		loginIP: auth.NewLimiter(20, 15*time.Minute), loginUser: auth.NewLimiter(5, 15*time.Minute),
		orchKick: make(chan struct{}, 1), now: time.Now}
	s.bgCtx = context.Background()
	if cfg.Feeds.Enabled {
		s.jobs = append(s.jobs,
			job{"feeds", 15 * time.Minute, func(ctx context.Context) error { return s.SyncFeeds(ctx, false) }},
			job{"nvd", 3 * time.Minute, s.enrichNVD})
	}
	s.OnInventory(s.afterInventory)
	s.jobs = append(s.jobs,
		job{"presence", 5 * time.Second, s.checkPresence},
		job{"rollup", time.Minute, func(ctx context.Context) error { return s.mets.Rollup(ctx, time.Now()) }},
		job{"sessions", time.Hour, s.db.PruneSessions},
		job{"policies", time.Minute, s.RunPolicies},
		job{"retention", time.Hour, func(ctx context.Context) error {
			r := s.cfg.Retention
			return s.mets.Prune(ctx, time.Now(), r.Raw, r.Minute, r.Hour)
		}},
	)
	return s, nil
}

// CA exposes the internal CA (used by CLI and tests).
func (s *Server) CA() *pki.CA { return s.ca }

// DB exposes the store.
func (s *Server) DB() *store.DB { return s.db }

// AddJob registers a periodic background job (must be called before Run).
func (s *Server) AddJob(name string, every time.Duration, fn func(context.Context) error) {
	s.jobs = append(s.jobs, job{name, every, fn})
}

// GenerateToken returns a random token with the given prefix.
func GenerateToken(prefix string) string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return prefix + strings.ToLower(strings.TrimRight(base32.StdEncoding.EncodeToString(b), "="))
}

// CreateEnrollToken creates a one-time enrolment token and returns its plaintext.
func (s *Server) CreateEnrollToken(ctx context.Context, note, group string, ttl time.Duration) (string, store.EnrollToken, error) {
	tok := GenerateToken("sxe_")
	t, err := s.db.CreateEnrollToken(ctx, store.HashToken(tok), note, group, ttl)
	return tok, t, err
}

// GatewayTLSConfig builds the TLS config for the agent gateway.
func (s *Server) GatewayTLSConfig() (*tls.Config, error) {
	cert, err := s.ca.ServerCertificate(s.cfg.GatewayHosts)
	if err != nil {
		return nil, err
	}
	return &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.VerifyClientCertIfGiven,
		ClientCAs:    s.ca.Pool(),
		NextProtos:   []string{"h2", "http/1.1"},
	}, nil
}

// Run starts all listeners and jobs and blocks until ctx is cancelled.
func (s *Server) Run(ctx context.Context) error {
	tlsCfg, err := s.GatewayTLSConfig()
	if err != nil {
		return err
	}
	gw := &http.Server{Addr: s.cfg.GatewayListen, Handler: s.GatewayHandler(), TLSConfig: tlsCfg,
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}
	ui := &http.Server{Addr: s.cfg.Listen, Handler: s.UIHandler(), ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 120 * time.Second}

	errCh := make(chan error, 2)
	gwLn, err := net.Listen("tcp", s.cfg.GatewayListen)
	if err != nil {
		return fmt.Errorf("gateway listen: %w", err)
	}
	uiLn, err := net.Listen("tcp", s.cfg.Listen)
	if err != nil {
		_ = gwLn.Close()
		return fmt.Errorf("ui listen: %w", err)
	}
	go func() { errCh <- gw.ServeTLS(gwLn, "", "") }()
	go func() {
		if s.cfg.TLSCert != "" {
			errCh <- ui.ServeTLS(uiLn, s.cfg.TLSCert, s.cfg.TLSKey)
		} else {
			errCh <- ui.Serve(uiLn)
		}
	}()
	s.log.Info("sentrix server started", "ui", uiLn.Addr().String(), "gateway", gwLn.Addr().String(), "ca_fingerprint", s.ca.Fingerprint())

	jobCtx, cancelJobs := context.WithCancel(ctx)
	s.bgCtx = jobCtx
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		s.orchestratorLoop(jobCtx)
	}()
	for _, j := range s.jobs {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			s.runJob(jobCtx, j)
		}(j)
	}

	var runErr error
	select {
	case <-ctx.Done():
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	cancelJobs()
	s.hub.Close()
	shutCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_ = gw.Shutdown(shutCtx)
	_ = ui.Shutdown(shutCtx)
	wg.Wait()
	s.log.Info("sentrix server stopped")
	return runErr
}

func (s *Server) runJob(ctx context.Context, j job) {
	t := time.NewTicker(j.interval)
	defer t.Stop()
	for {
		func() {
			defer func() {
				if r := recover(); r != nil {
					s.log.Error("job panic", "job", j.name, "panic", r)
				}
			}()
			if err := j.fn(ctx); err != nil && ctx.Err() == nil {
				s.log.Warn("job failed", "job", j.name, "err", err)
			}
		}()
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

// checkPresence detects online/offline transitions and publishes events.
func (s *Server) checkPresence(ctx context.Context) error {
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, h := range hosts {
		on := h.Online(now, s.cfg.OfflineAfter)
		prev, known := s.onlineCache[h.ID]
		s.onlineCache[h.ID] = on
		if known && prev != on {
			state := "offline"
			if on {
				state = "online"
			}
			s.log.Info("host presence changed", "host", h.Hostname, "state", state)
			s.hub.Publish(Event{Type: "presence", HostID: h.ID, Data: state})
		}
	}
	return nil
}
