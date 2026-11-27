package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

func countCmds(t *testing.T, s *Server, hostID string, action protocol.Action, dry bool) int {
	t.Helper()
	cmds, _ := s.db.ListHostCommands(context.Background(), hostID, 100)
	n := 0
	for _, c := range cmds {
		if c.Action == action && c.DryRun == dry {
			n++
		}
	}
	return n
}

func TestPackageManagementEndToEnd(t *testing.T) {
	ctx := context.Background()
	s, gw := newTestServer(t)
	ts := httptest.NewServer(s.UIHandler())
	t.Cleanup(ts.Close)
	mkUser(t, s, "alice", store.RoleAdmin)
	mkUser(t, s, "olga", store.RoleOperator)

	h := newSimHost(t, s, gw.URL, "pkg-1")
	hostID := hostIDByName(t, s, "pkg-1")
	var realRuns []string
	h.ex.AllowPackageManagement = true
	h.ex.Run = func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "apt-get" || len(args) < 2 {
			return nil, nil
		}
		switch {
		case args[0] == "-s" && args[1] == "install":
			return []byte("Inst htop (3.3.0-4 Ubuntu:24.04/noble [amd64])\n"), nil
		case args[0] == "-s" && args[1] == "purge":
			return []byte("Purg nano [7.2-1ubuntu0.1]\n"), nil
		case args[0] != "-s" && args[0] != "update":
			realRuns = append(realRuns, args[0])
		}
		return nil, nil
	}
	patches := "/hosts/" + hostID + "/patches"

	// Operators cannot manage packages.
	op := client(t, ts)
	op.login("olga")
	tok := op.csrf(patches)
	if code, _ := op.post("/hosts/"+hostID+"/packages", url.Values{"csrf": {tok}, "op": {"install"}, "packages": {"htop"}}); code != http.StatusForbidden {
		t.Fatalf("operator package preview: %d", code)
	}

	admin := client(t, ts)
	admin.login("alice")
	tok = admin.csrf(patches)
	post := func(path string, v url.Values) {
		v.Set("csrf", tok)
		if code, _ := admin.post(path, v); code != http.StatusSeeOther {
			t.Fatalf("%s: %d", path, code)
		}
	}

	// Protected packages are refused before anything is queued.
	post("/hosts/"+hostID+"/packages", url.Values{"op": {"remove"}, "packages": {"openssh-server"}})
	if countCmds(t, s, hostID, protocol.ActionRemovePackages, true) != 0 {
		t.Fatal("protected removal queued")
	}

	// Install: dry run → preview → apply.
	post("/hosts/"+hostID+"/packages", url.Values{"op": {"install"}, "packages": {"htop htop"}})
	if err := h.a.PollOnce(ctx, h.ex, 0); err != nil {
		t.Fatal(err)
	}
	last, _, _ := s.db.LastHostCommand(ctx, hostID, protocol.ActionInstallPackages)
	if !last.DryRun || last.Status != protocol.StatusOK || len(realRuns) != 0 {
		t.Fatalf("preview: %+v real=%v", last, realRuns)
	}
	_, body, _ := admin.get(patches)
	if !strings.Contains(body, "3.3.0-4") || !strings.Contains(body, "/packages/"+last.ID+"/apply") {
		t.Fatal("preview not rendered")
	}
	post("/hosts/"+hostID+"/packages/"+last.ID+"/apply", url.Values{})
	post("/hosts/"+hostID+"/packages/"+last.ID+"/apply", url.Values{}) // second apply is refused
	if n := countCmds(t, s, hostID, protocol.ActionInstallPackages, false); n != 1 {
		t.Fatalf("want 1 real install, got %d", n)
	}
	if err := h.a.PollOnce(ctx, h.ex, 0); err != nil {
		t.Fatal(err)
	}
	if strings.Join(realRuns, ",") != "install" {
		t.Fatalf("real runs: %v", realRuns)
	}

	// Purge needs the explicit removal acknowledgement.
	post("/hosts/"+hostID+"/packages", url.Values{"op": {"purge"}, "packages": {"nano"}})
	if err := h.a.PollOnce(ctx, h.ex, 0); err != nil {
		t.Fatal(err)
	}
	rm, _, _ := s.db.LastHostCommand(ctx, hostID, protocol.ActionRemovePackages)
	if !strings.Contains(rm.Params, `"purge":true`) {
		t.Fatalf("purge flag lost: %s", rm.Params)
	}
	post("/hosts/"+hostID+"/packages/"+rm.ID+"/apply", url.Values{})
	if countCmds(t, s, hostID, protocol.ActionRemovePackages, false) != 0 {
		t.Fatal("removal applied without acknowledgement")
	}
	post("/hosts/"+hostID+"/packages/"+rm.ID+"/apply", url.Values{"confirm": {"1"}})
	if err := h.a.PollOnce(ctx, h.ex, 0); err != nil {
		t.Fatal(err)
	}
	if strings.Join(realRuns, ",") != "install,purge" {
		t.Fatalf("real runs: %v", realRuns)
	}
}
