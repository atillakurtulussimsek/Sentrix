package patch

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// mockPVE is a minimal Proxmox VE API: snapshot creation + task status.
func mockPVE(t *testing.T, fail bool) (*httptest.Server, *[]string) {
	var calls []string
	var polls int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls = append(calls, r.Method+" "+r.URL.Path)
		if r.Header.Get("Authorization") != "PVEAPIToken=sentrix@pve!patch=secret-uuid" {
			http.Error(w, `{"data":null}`, http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == "POST" && r.URL.Path == "/api2/json/nodes/pve1/qemu/105/snapshot":
			b, _ := io.ReadAll(r.Body)
			f, _ := url.ParseQuery(string(b))
			if !strings.HasPrefix(f.Get("snapname"), "sentrix-") {
				http.Error(w, "bad snapname", 400)
				return
			}
			if fail {
				http.Error(w, `{"data":null,"errors":{"snapname":"snapshot feature is not available"}}`, http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": "UPID:pve1:0001:snapshot:105:sentrix@pve!patch:"})
		case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/api2/json/nodes/pve1/tasks/"):
			st := "running"
			if atomic.AddInt32(&polls, 1) > 1 {
				st = "stopped"
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"status": st, "exitstatus": "OK"}})
		case r.URL.Path == "/api2/json/version":
			_ = json.NewEncoder(w).Encode(map[string]any{"data": map[string]string{"version": "8.2.4"}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func TestProxmoxSnapshot(t *testing.T) {
	srv, calls := mockPVE(t, false)
	c := ProxmoxConfig{URL: srv.URL, TokenID: "sentrix@pve!patch", TokenSecret: "secret-uuid", Insecure: true}
	if v, err := c.Ping(context.Background()); err != nil || v != "8.2.4" {
		t.Fatalf("ping %q %v", v, err)
	}
	name, err := c.Snapshot(context.Background(), HookTarget{PlanID: "abcdef12-3456", Hostname: "web-1", ProxmoxNode: "pve1", ProxmoxVMID: "105"}, time.Date(2026, 1, 2, 3, 4, 0, 0, time.UTC))
	if err != nil || name != "sentrix-abcdef12-20260102T0304" {
		t.Fatalf("%q %v", name, err)
	}
	if len(*calls) < 3 {
		t.Fatalf("calls %v", *calls)
	}
	// wrong token
	bad := c
	bad.TokenSecret = "nope"
	if _, err := bad.Snapshot(context.Background(), HookTarget{ProxmoxNode: "pve1", ProxmoxVMID: "105"}, time.Now()); err == nil {
		t.Fatal("bad token accepted")
	}
	// missing mapping
	if _, err := c.Snapshot(context.Background(), HookTarget{Hostname: "x"}, time.Now()); err == nil {
		t.Fatal("missing mapping accepted")
	}
	// TLS verification on by default: self-signed must fail without insecure/fingerprint
	strict := c
	strict.Insecure = false
	if _, err := strict.Ping(context.Background()); err == nil {
		t.Fatal("self-signed certificate accepted without opt-in")
	}
}

func TestProxmoxSnapshotFailure(t *testing.T) {
	srv, _ := mockPVE(t, true)
	c := ProxmoxConfig{URL: srv.URL, TokenID: "sentrix@pve!patch", TokenSecret: "secret-uuid", Insecure: true}
	if _, err := c.Snapshot(context.Background(), HookTarget{ProxmoxNode: "pve1", ProxmoxVMID: "105"}, time.Now()); err == nil || !strings.Contains(err.Error(), "500") {
		t.Fatalf("expected failure, got %v", err)
	}
}

func TestWebhookHook(t *testing.T) {
	var sig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sig = r.Header.Get("X-Sentrix-Signature")
		_, _ = w.Write([]byte(`{"snapshot":"zfs@pre-patch"}`))
	}))
	defer srv.Close()
	name, err := WebhookConfig{URL: srv.URL, Secret: "k"}.CallWebhook(context.Background(), HookTarget{Hostname: "h"})
	if err != nil || name != "zfs@pre-patch" || !strings.HasPrefix(sig, "sha256=") {
		t.Fatalf("%q %v %q", name, err, sig)
	}
	fail := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "nope", http.StatusServiceUnavailable) }))
	defer fail.Close()
	if _, err := (WebhookConfig{URL: fail.URL}).CallWebhook(context.Background(), HookTarget{}); err == nil {
		t.Fatal("expected failure")
	}
}
