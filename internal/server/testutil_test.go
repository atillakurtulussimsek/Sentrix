package server

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

func newTestServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	cfg := config.DefaultServer()
	cfg.DataDir = t.TempDir()
	cfg.DevInsecureCookies = true
	db, err := store.Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s, err := New(cfg, db, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg, err := s.GatewayTLSConfig()
	if err != nil {
		t.Fatal(err)
	}
	gw := httptest.NewUnstartedServer(s.GatewayHandler())
	gw.TLS = tlsCfg
	gw.StartTLS()
	t.Cleanup(gw.Close)
	return s, gw
}

var _ = http.StatusOK
