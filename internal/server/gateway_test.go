package server

import (
	"context"
	"crypto/tls"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

func TestEnrolHeartbeatRevoke(t *testing.T) {
	ctx := context.Background()
	s, gw := newTestServer(t)
	tok, _, err := s.CreateEnrollToken(ctx, "t", "web", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// Wrong fingerprint must fail before the token is spent.
	if _, err := agent.Enroll(ctx, dir, gw.URL, tok, "00ff", "h1", "m1"); err == nil {
		t.Fatal("enrol with wrong fingerprint succeeded")
	}
	id, err := agent.Enroll(ctx, dir, gw.URL, tok, s.CA().Fingerprint(), "h1", "m1")
	if err != nil {
		t.Fatal(err)
	}
	// Token is single-use.
	if _, err := agent.Enroll(ctx, t.TempDir(), gw.URL, tok, s.CA().Fingerprint(), "h2", "m2"); err == nil {
		t.Fatal("token reuse accepted")
	}
	h, err := s.DB().GetHost(ctx, id.AgentID)
	if err != nil || h.Group != "web" || h.Hostname != "h1" {
		t.Fatalf("host %+v err %v", h, err)
	}

	cfg := config.DefaultAgent()
	cfg.StateDir = dir
	a, err := agent.New(cfg, s.log)
	if err != nil {
		t.Fatal(err)
	}
	if err := a.Post(ctx, protocol.PathHeartbeat, protocol.Heartbeat{Hostname: "h1", AgentVersion: "x"}, nil); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
	h, _ = s.DB().GetHost(ctx, id.AgentID)
	if !h.Online(time.Now(), time.Minute) {
		t.Fatal("host not online after heartbeat")
	}
	if err := s.DB().SetHostRevoked(ctx, id.AgentID, true); err != nil {
		t.Fatal(err)
	}
	err = a.Post(ctx, protocol.PathHeartbeat, protocol.Heartbeat{}, nil)
	var he *agent.HTTPError
	if !errors.As(err, &he) || he.Status != 403 {
		t.Fatalf("revoked agent: got %v", err)
	}
}

func TestGatewayRequiresClientCert(t *testing.T) {
	_, gw := newTestServer(t)
	c := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	resp, err := c.Post(gw.URL+protocol.PathHeartbeat, "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
