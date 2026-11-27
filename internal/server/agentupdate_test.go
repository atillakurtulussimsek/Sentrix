package server

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/selfupdate"
)

// signedRelease writes a signed fake agent release for the test key into dir.
func signedRelease(t *testing.T, dir string, priv ed25519.PrivateKey, version string, bin []byte) selfupdate.Manifest {
	t.Helper()
	m := selfupdate.Sign(priv, version, runtime.GOARCH, bin)
	b, _ := json.Marshal(m)
	if err := os.WriteFile(filepath.Join(dir, selfupdate.BinaryName(runtime.GOARCH)), bin, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, selfupdate.ManifestName(runtime.GOARCH)), b, 0o644); err != nil {
		t.Fatal(err)
	}
	return m
}

func goArchInventory(inv protocol.Inventory) protocol.Inventory {
	inv.OS.Arch = map[string]string{"amd64": "x86_64", "arm64": "aarch64"}[runtime.GOARCH]
	return inv
}

func TestAgentSelfUpdateEndToEnd(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("no signed agent builds for this arch")
	}
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(selfupdate.UseTestKey(pub))

	s, gw := newTestServer(t)
	s.cfg.AgentDir = t.TempDir()
	newBin := append([]byte("\x7fELF"), bytes.Repeat([]byte("sentrix"), 1000)...)
	m := signedRelease(t, s.cfg.AgentDir, priv, "v9.9.9", newBin)

	h := newSimHost(t, s, gw.URL, "upd-1")
	if err := h.a.Post(ctx, protocol.PathHeartbeat, protocol.Heartbeat{Hostname: "upd-1", AgentVersion: "v0.1.0"}, nil); err != nil {
		t.Fatal(err)
	}
	if err := h.a.Post(ctx, protocol.PathInventory, goArchInventory(h.inventory()), nil); err != nil {
		t.Fatal(err)
	}
	host, _ := s.db.GetHost(ctx, hostIDByName(t, s, "upd-1"))
	if rel, ok := s.hostAgentUpdate(ctx, host); !ok || rel.Manifest.Version != "v9.9.9" {
		t.Fatalf("update not offered: %+v %v", rel, ok)
	}

	// notify mode: nothing is queued automatically.
	if err := s.AutoUpdateAgents(ctx); err != nil {
		t.Fatal(err)
	}
	if _, found, _ := s.db.LastHostCommand(ctx, host.ID, protocol.ActionUpdateAgent); found {
		t.Fatal("notify mode must not queue updates")
	}

	// auto mode queues exactly one update for the outdated online agent.
	if err := s.db.SetSetting(ctx, settingAgentUpdates, agentUpdatesAuto); err != nil {
		t.Fatal(err)
	}
	if err := s.AutoUpdateAgents(ctx); err != nil {
		t.Fatal(err)
	}
	if err := s.AutoUpdateAgents(ctx); err != nil { // must not queue a second one
		t.Fatal(err)
	}
	cmds, _ := s.db.ListHostCommands(ctx, host.ID, 10)
	n := 0
	for _, c := range cmds {
		if c.Action == protocol.ActionUpdateAgent {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("want 1 queued update_agent, got %d", n)
	}

	// The agent installs the verified binary and asks to restart.
	target := filepath.Join(t.TempDir(), "sentrix-agent")
	if err := os.WriteFile(target, []byte("old"), 0o755); err != nil {
		t.Fatal(err)
	}
	restarted := false
	h.a.SetRestartHook(func() { restarted = true })
	h.ex.AllowSelfUpdate = true
	h.ex.UpdateAgent = func(ctx context.Context, p protocol.UpdateAgentParams) (string, error) {
		return h.a.InstallUpdateTo(ctx, p, target)
	}
	if err := h.a.PollOnce(ctx, h.ex, 0); err != nil {
		t.Fatal(err)
	}
	got, _ := os.ReadFile(target)
	if !bytes.Equal(got, newBin) || !restarted {
		t.Fatalf("binary not replaced (%d bytes) or no restart (%v)", len(got), restarted)
	}
	last, _, _ := s.db.LastHostCommand(ctx, host.ID, protocol.ActionUpdateAgent)
	if last.Status != protocol.StatusOK {
		t.Fatalf("update command status %q (%+v)", last.Status, last.Result)
	}
	_ = m
}

func TestAgentSelfUpdateRejectsTampering(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("no signed agent builds for this arch")
	}
	ctx := context.Background()
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(selfupdate.UseTestKey(pub))
	s, gw := newTestServer(t)
	s.cfg.AgentDir = t.TempDir()
	good := append([]byte("\x7fELF"), bytes.Repeat([]byte("good"), 100)...)
	m := signedRelease(t, s.cfg.AgentDir, priv, "v9.9.9", good)
	h := newSimHost(t, s, gw.URL, "upd-2")
	_ = s.releases() // load the verified release, then tamper with the file on disk
	if err := os.WriteFile(filepath.Join(s.cfg.AgentDir, selfupdate.BinaryName(runtime.GOARCH)), append([]byte("\x7fELF"), bytes.Repeat([]byte("evil"), 100)...), 0o644); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "sentrix-agent")
	_ = os.WriteFile(target, []byte("old"), 0o755)
	p := protocol.UpdateAgentParams{Version: m.Version, Arch: m.Arch, SHA256: m.SHA256}
	if _, err := h.a.InstallUpdateTo(ctx, p, target); err == nil {
		t.Fatal("tampered binary installed")
	}
	// A release signed by another key is refused even if the server offers it.
	_, other, _ := ed25519.GenerateKey(rand.Reader)
	m2 := signedRelease(t, s.cfg.AgentDir, other, "v9.9.9", good)
	s.agentRel.mu.Lock()
	s.agentRel.byArch[runtime.GOARCH] = agentRelease{Manifest: m2, Path: filepath.Join(s.cfg.AgentDir, selfupdate.BinaryName(runtime.GOARCH))}
	s.agentRel.mu.Unlock()
	if _, err := h.a.InstallUpdateTo(ctx, protocol.UpdateAgentParams{Version: m2.Version, Arch: m2.Arch, SHA256: m2.SHA256}, target); err == nil {
		t.Fatal("release signed by a foreign key installed")
	}
	if b, _ := os.ReadFile(target); string(b) != "old" {
		t.Fatal("target modified by a rejected update")
	}
}

func TestCheckAgentReleasesDownloadsSigned(t *testing.T) {
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		t.Skip("no signed agent builds for this arch")
	}
	pub, priv, _ := ed25519.GenerateKey(rand.Reader)
	t.Cleanup(selfupdate.UseTestKey(pub))
	pubDir := t.TempDir()
	signedRelease(t, pubDir, priv, "v2.0.0", append([]byte("\x7fELF"), bytes.Repeat([]byte("x"), 50)...))
	rs := httptest.NewServer(http.FileServer(http.Dir(pubDir)))
	t.Cleanup(rs.Close)
	s, _ := newTestServer(t)
	s.cfg.AgentUpdates.ReleaseURL = rs.URL
	// The other arch has no manifest (404): reported, but the available arch is stored.
	_ = s.CheckAgentReleases(context.Background())
	rel, ok := s.releases()[runtime.GOARCH]
	if !ok || rel.Manifest.Version != "v2.0.0" || rel.Source != "downloaded" {
		t.Fatalf("release not downloaded: %+v", rel)
	}
	if _, err := os.Stat(filepath.Join(s.agentReleaseDir(), selfupdate.BinaryName(runtime.GOARCH))); err != nil {
		t.Fatal(err)
	}
}

func hostIDByName(t *testing.T, s *Server, name string) string {
	t.Helper()
	hosts, _ := s.db.ListHosts(context.Background())
	for _, h := range hosts {
		if h.Hostname == name {
			return h.ID
		}
	}
	t.Fatalf("host %s not found", name)
	return ""
}
