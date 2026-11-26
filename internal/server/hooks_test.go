package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/patch"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

type pveMock struct {
	mu     sync.Mutex
	fail   bool
	events []string
	srv    *httptest.Server
}

func newPVEMock(t *testing.T, fail bool) *pveMock {
	m := &pveMock{fail: fail}
	m.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		m.mu.Lock()
		defer m.mu.Unlock()
		switch {
		case r.Method == "POST" && strings.HasSuffix(r.URL.Path, "/qemu/201/snapshot"):
			m.events = append(m.events, "snapshot")
			if m.fail {
				http.Error(w, `{"errors":{"snapname":"storage does not support snapshots"}}`, 500)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": "UPID:pve1:1:snap"})
		case strings.Contains(r.URL.Path, "/tasks/"):
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"status": "stopped", "exitstatus": "OK"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(m.srv.Close)
	return m
}

func setupHookPlan(t *testing.T, fail bool) (*Server, *simHost, *pveMock, store.Plan) {
	ctx := context.Background()
	s, gw := newTestServer(t)
	h := newSimHost(t, s, gw.URL, "vm-201")
	mock := newPVEMock(t, fail)
	sealed, _ := s.box.Seal("token-secret")
	cfg, _ := json.Marshal(patch.ProxmoxConfig{URL: mock.srv.URL, TokenID: "sentrix@pve!patch", TokenSecret: sealed, Insecure: true})
	hk, err := s.db.SaveHook(ctx, store.Hook{Name: "pve", Kind: "proxmox", Config: string(cfg)})
	if err != nil {
		t.Fatal(err)
	}
	_ = s.db.SaveHostSettings(ctx, h.a.ID(), store.HostSettings{ProxmoxNode: "pve1", ProxmoxVMID: "201"})
	p, err := s.CreatePlan(ctx, PlanRequest{HostIDs: []string{h.a.ID()}, Scope: "packages", Packages: []string{"libssl3"}, SnapshotHook: hk.ID, SnapshotRequired: true}, "user:t")
	if err != nil {
		t.Fatal(err)
	}
	// dry run
	_ = s.AdvancePlans(ctx)
	_ = h.a.PollOnce(ctx, h.ex, 0)
	_ = s.AdvancePlans(ctx)
	if err := s.ApprovePlan(ctx, p.ID, "user:t"); err != nil {
		t.Fatal(err)
	}
	_ = s.AdvancePlans(ctx) // starts host → snapshot step (async)
	return s, h, mock, p
}

func waitHostStatus(t *testing.T, s *Server, planID string, not string) store.PlanHost {
	t.Helper()
	for i := 0; i < 200; i++ {
		hs, _ := s.db.ListPlanHosts(context.Background(), planID)
		if len(hs) == 1 && hs[0].Status != not {
			return hs[0]
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timeout waiting for host status change")
	return store.PlanHost{}
}

func TestProxmoxSnapshotBeforePatch(t *testing.T) {
	ctx := context.Background()
	s, h, mock, p := setupHookPlan(t, false)
	ph := waitHostStatus(t, s, p.ID, "snapshot")
	if ph.Status != "patching" || !strings.HasPrefix(ph.Snapshot, "sentrix-") {
		t.Fatalf("after snapshot: %+v", ph)
	}
	cmds, _ := s.db.ListHostCommands(ctx, h.a.ID(), 10)
	queued := false
	for _, c := range cmds {
		if !c.DryRun && c.Action == "patch_packages" {
			queued = true
		}
	}
	if !queued {
		t.Fatalf("patch command not queued after snapshot: %+v", cmds)
	}
	mock.mu.Lock()
	if len(mock.events) != 1 {
		t.Fatalf("snapshot calls: %v", mock.events)
	}
	mock.mu.Unlock()
	// finish the run
	for i := 0; i < 5; i++ {
		_ = h.a.PollOnce(ctx, h.ex, 0)
		_ = s.AdvancePlans(ctx)
	}
	p, _ = s.db.GetPlan(ctx, p.ID)
	if p.Status != "done" {
		t.Fatalf("plan %s %s", p.Status, p.Error)
	}
	ent, _ := s.db.ListAudit(ctx, h.a.ID(), 50)
	found := false
	for _, e := range ent {
		if e.Action == "plan.host.snapshot" {
			found = true
		}
	}
	if !found {
		t.Fatal("snapshot not audited")
	}
}

func TestProxmoxSnapshotFailureAbortsHost(t *testing.T) {
	ctx := context.Background()
	s, h, _, p := setupHookPlan(t, true)
	ph := waitHostStatus(t, s, p.ID, "snapshot")
	if ph.Status != "failed" || !strings.Contains(ph.Error, "snapshot failed") {
		t.Fatalf("host: %+v", ph)
	}
	cmds, _ := s.db.ListHostCommands(ctx, h.a.ID(), 10)
	for _, c := range cmds {
		if !c.DryRun && strings.HasPrefix(string(c.Action), "patch") {
			t.Fatalf("host was patched although its snapshot failed: %+v", c)
		}
	}
	if h.version != "3.0.11-1~deb12u2" {
		t.Fatal("packages changed")
	}
	_ = s.AdvancePlans(ctx)
	p, _ = s.db.GetPlan(ctx, p.ID)
	if p.Status != "failed" {
		t.Fatalf("plan status %s", p.Status)
	}
}
