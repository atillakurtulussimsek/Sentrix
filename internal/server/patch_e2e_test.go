package server

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent"
	"github.com/atillakurtulussimsek/Sentrix/internal/agent/executor"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// simHost is an in-process agent whose package manager is simulated.
type simHost struct {
	a       *agent.Agent
	ex      *executor.Executor
	version string // installed openssl version
	upgrade string
}

func (h *simHost) inventory() protocol.Inventory {
	inv := debianInventory(h.version)
	if h.version == h.upgrade {
		inv.Updates = nil
	}
	return inv
}

func newSimHost(t *testing.T, s *Server, gwURL, name string) *simHost {
	t.Helper()
	ctx := context.Background()
	tok, _, _ := s.CreateEnrollToken(ctx, "", "web", time.Hour)
	dir := t.TempDir()
	if _, err := agent.Enroll(ctx, dir, gwURL, tok, s.CA().Fingerprint(), name, name, name); err != nil {
		t.Fatal(err)
	}
	ac := config.DefaultAgent()
	ac.StateDir = dir
	a, err := agent.New(ac, s.log)
	if err != nil {
		t.Fatal(err)
	}
	h := &simHost{a: a, version: "3.0.11-1~deb12u2", upgrade: "3.0.15-1~deb12u1"}
	h.ex = &executor.Executor{AllowPatching: true, PackageManager: "dpkg",
		Run: func(_ context.Context, name string, args ...string) ([]byte, error) {
			if name == "apt-get" && len(args) > 0 && args[0] == "-s" && h.version != h.upgrade {
				return []byte("Inst libssl3 [" + h.version + "] (" + h.upgrade + " Debian-Security:12/stable-security [amd64])\nInst openssl [" + h.version + "] (" + h.upgrade + " Debian-Security:12/stable-security [amd64])\n"), nil
			}
			if name == "apt-get" && len(args) > 0 && args[0] == "install" {
				h.version = h.upgrade // the real upgrade
			}
			return nil, nil
		},
		SendInventory: func(ctx context.Context) error { return a.Post(ctx, protocol.PathInventory, h.inventory(), nil) },
	}
	// security-only uses the inventory collector: emulate it via patch_packages-equivalent output
	if err := a.Post(ctx, protocol.PathHeartbeat, protocol.Heartbeat{Hostname: name}, nil); err != nil {
		t.Fatal(err)
	}
	if err := a.Post(ctx, protocol.PathInventory, h.inventory(), nil); err != nil {
		t.Fatal(err)
	}
	return h
}

func TestPatchPlanEndToEnd(t *testing.T) {
	ctx := context.Background()
	fs := feedServer(t)
	s, gw := newTestServer(t)
	s.cfg.Feeds = config.Feeds{Enabled: true, Interval: time.Hour, DebianURL: fs.URL + "/debian.json", KEVURL: fs.URL + "/kev.json",
		EPSSURL: fs.URL + "/epss.csv.gz", OSVBaseURL: fs.URL + "/osv", NVDURL: fs.URL + "/nvd", OfflineAfter: time.Hour}
	t.Cleanup(func() { s.feeds.run.Lock(); defer s.feeds.run.Unlock() })
	h1 := newSimHost(t, s, gw.URL, "web-1")
	h2 := newSimHost(t, s, gw.URL, "web-2")
	if err := s.SyncFeeds(ctx, true); err != nil {
		t.Fatal(err)
	}
	before := map[string]int{}
	for _, h := range []*simHost{h1, h2} {
		before[h.a.ID()], _ = s.db.CountFindings(ctx, h.a.ID())
		if before[h.a.ID()] == 0 {
			t.Fatal("expected findings before patching")
		}
	}
	// security-only scope on dpkg uses patch_security_only, which needs the inventory
	// collector; the simulated hosts use an explicit package plan instead.
	p, err := s.CreatePlan(ctx, PlanRequest{HostIDs: []string{h1.a.ID(), h2.a.ID()}, Scope: "packages", Packages: []string{"libssl3", "openssl"}, Canary: 1, MaxParallel: 2, Reboot: "if_required"}, "user:alice")
	if err != nil {
		t.Fatal(err)
	}
	step := func() {
		t.Helper()
		if err := s.AdvancePlans(ctx); err != nil {
			t.Fatal(err)
		}
		for _, h := range []*simHost{h1, h2} {
			if err := h.a.PollOnce(ctx, h.ex, 0); err != nil {
				t.Fatal(err)
			}
		}
		if err := s.AdvancePlans(ctx); err != nil {
			t.Fatal(err)
		}
	}
	// dry run
	step()
	p, _ = s.db.GetPlan(ctx, p.ID)
	if p.Status != "ready" {
		t.Fatalf("plan after dry run: %s", p.Status)
	}
	phs, _ := s.db.ListPlanHosts(ctx, p.ID)
	for _, ph := range phs {
		if len(ph.DryChanges) != 2 || ph.DryChanges[0].To != "3.0.15-1~deb12u1" {
			t.Fatalf("dry run changes for %s: %+v", ph.Hostname, ph.DryChanges)
		}
	}
	if h1.version != "3.0.11-1~deb12u2" {
		t.Fatal("dry run modified the host")
	}
	if err := s.ApprovePlan(ctx, p.ID, "user:bob"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 8; i++ {
		step()
		if p, _ = s.db.GetPlan(ctx, p.ID); p.Status == "done" || p.Status == "failed" {
			break
		}
	}
	if p.Status != "done" {
		phs, _ = s.db.ListPlanHosts(ctx, p.ID)
		t.Fatalf("plan status %s (%s): %+v", p.Status, p.Error, phs)
	}
	phs, _ = s.db.ListPlanHosts(ctx, p.ID)
	for _, ph := range phs {
		if ph.Status != "done" || ph.FindingsAfter >= ph.FindingsBefore || ph.FindingsBefore != before[ph.HostID] {
			t.Fatalf("host %s: %+v", ph.Hostname, ph)
		}
	}
	// audit trail
	entries, _ := s.db.ListAudit(ctx, "", 500)
	var actions []string
	for _, e := range entries {
		actions = append(actions, e.Action)
	}
	joined := strings.Join(actions, " ")
	for _, want := range []string{"plan.create", "plan.dry_run_complete", "plan.approve", "plan.start", "command.queue", "command.result.patch_packages", "plan.host.start", "plan.host.done", "plan.done"} {
		if !strings.Contains(joined, want) {
			t.Errorf("audit log missing %s", want)
		}
	}
}

func TestPolicyOutsideWindowDoesNothing(t *testing.T) {
	ctx := context.Background()
	s, gw := newTestServer(t)
	h := newSimHost(t, s, gw.URL, "db-1")
	_ = h
	ups, _ := s.db.UpdateCounts(ctx)
	if ups[h.a.ID()][1] == 0 {
		// mark the pending update as security (no feeds in this test)
		_ = s.db.MarkSecurityUpdates(ctx, h.a.ID(), []string{"libssl3"})
	}
	_, err := s.db.SavePolicy(ctx, store.Policy{Name: "web nightly", Group: "web", Mode: "auto_security", WindowCron: "0 3 * * *", WindowMinutes: 60, MaxParallel: 1, Reboot: "never", Enabled: true})
	if err != nil {
		t.Fatal(err)
	}
	s.now = func() time.Time { return time.Date(2026, 3, 1, 12, 0, 0, 0, time.Local) }
	if err := s.RunPolicies(ctx); err != nil {
		t.Fatal(err)
	}
	if plans, _ := s.db.ListPlans(ctx); len(plans) != 0 {
		t.Fatalf("policy created a plan outside its window: %+v", plans)
	}
	s.now = func() time.Time { return time.Date(2026, 3, 1, 3, 15, 0, 0, time.Local) }
	_ = s.db.MarkSeen(ctx, h.a.ID())
	s.db.SetClock(s.now)
	_ = s.db.MarkSeen(ctx, h.a.ID())
	if err := s.RunPolicies(ctx); err != nil {
		t.Fatal(err)
	}
	plans, _ := s.db.ListPlans(ctx)
	if len(plans) != 1 || plans[0].Scope != "security" || plans[0].PolicyID == "" {
		t.Fatalf("policy inside window: %+v", plans)
	}
	// once per window
	if err := s.RunPolicies(ctx); err != nil {
		t.Fatal(err)
	}
	if plans, _ := s.db.ListPlans(ctx); len(plans) != 1 {
		t.Fatalf("policy ran twice: %d", len(plans))
	}
}
