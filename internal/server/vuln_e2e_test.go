package server

import (
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/agent"
	"github.com/atillakurtulussimsek/Sentrix/internal/config"
	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

const feedFixtures = "../../test/fixtures/feeds/"

// feedServer serves the committed fixtures in place of the real feed URLs.
func feedServer(t *testing.T) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	serveFile := func(path, file string) {
		mux.HandleFunc(path, func(w http.ResponseWriter, r *http.Request) {
			b, err := os.ReadFile(feedFixtures + file)
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			w.Header().Set("ETag", `"v1"`)
			if r.Header.Get("If-None-Match") == `"v1"` {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			_, _ = w.Write(b)
		})
	}
	serveFile("/debian.json", "debian-tracker.json")
	serveFile("/kev.json", "kev.json")
	mux.HandleFunc("/nvd", func(w http.ResponseWriter, r *http.Request) {
		b, _ := os.ReadFile(feedFixtures + "nvd-CVE-2024-5535.json")
		if r.URL.Query().Get("cveId") != "CVE-2024-5535" {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	})
	mux.HandleFunc("/epss.csv.gz", func(w http.ResponseWriter, r *http.Request) {
		raw, _ := os.ReadFile(feedFixtures + "epss.csv")
		zw := gzip.NewWriter(w)
		_, _ = zw.Write(raw)
		_ = zw.Close()
	})
	mux.HandleFunc("/osv/", func(w http.ResponseWriter, r *http.Request) {
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		files, _ := filepath.Glob(feedFixtures + "osv/*.json")
		for _, p := range files {
			b, _ := os.ReadFile(p)
			f, _ := zw.Create(filepath.Base(p))
			_, _ = f.Write(b)
		}
		_ = zw.Close()
		_, _ = w.Write(buf.Bytes())
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return ts
}

func debianInventory(opensslVer string) protocol.Inventory {
	return protocol.Inventory{
		CollectedAt:    time.Now(),
		OS:             protocol.OSInfo{ID: "debian", VersionID: "12", Codename: "bookworm", PrettyName: "Debian GNU/Linux 12 (bookworm)"},
		PackageManager: "dpkg",
		Packages: []protocol.Package{
			{Name: "libssl3", Version: opensslVer, Arch: "amd64", SourceName: "openssl", SourceVer: opensslVer},
			{Name: "openssl", Version: opensslVer, Arch: "amd64", SourceName: "openssl", SourceVer: opensslVer},
			{Name: "libc6", Version: "2.36-9+deb12u9", Arch: "amd64", SourceName: "glibc", SourceVer: "2.36-9+deb12u9"},
		},
		Updates: []protocol.Update{{Name: "libssl3", CurrentVer: opensslVer, NewVer: "3.0.15-1~deb12u1"}},
	}
}

func TestVulnerabilityLifecycle(t *testing.T) {
	ctx := context.Background()
	fs := feedServer(t)
	s, gw := newTestServer(t)
	s.cfg.Feeds = config.Feeds{Enabled: true, Interval: time.Hour, DebianURL: fs.URL + "/debian.json", KEVURL: fs.URL + "/kev.json",
		EPSSURL: fs.URL + "/epss.csv.gz", OSVBaseURL: fs.URL + "/osv", NVDURL: fs.URL + "/nvd", OfflineAfter: time.Hour}
	s.feeds.nvdGap = time.Millisecond
	t.Cleanup(func() { s.feeds.run.Lock(); defer s.feeds.run.Unlock(); s.feeds.syncing = false }) // wait for background syncs

	tok, _, _ := s.CreateEnrollToken(ctx, "", "", time.Hour)
	dir := t.TempDir()
	id, err := agent.Enroll(ctx, dir, gw.URL, tok, s.CA().Fingerprint(), "deb1", "m")
	if err != nil {
		t.Fatal(err)
	}
	ac := config.DefaultAgent()
	ac.StateDir = dir
	a, _ := agent.New(ac, s.log)

	// 1. vulnerable openssl
	if err := a.Post(ctx, protocol.PathInventory, debianInventory("3.0.11-1~deb12u2"), nil); err != nil {
		t.Fatal(err)
	}
	if err := s.SyncFeeds(ctx, true); err != nil {
		t.Fatalf("sync: %v", err)
	}
	fsx, _ := s.db.ListFindings(ctx, store.FindingFilter{HostID: id.AgentID})
	byID := map[string]store.StoredFinding{}
	for _, f := range fsx {
		byID[f.VulnID] = f
	}
	f, ok := byID["CVE-2024-5535"]
	if !ok || f.Fixed != "3.0.15-1~deb12u1" || f.Package != "openssl" || f.Installed != "3.0.11-1~deb12u2" {
		t.Fatalf("expected CVE-2024-5535 fixed in 3.0.15-1~deb12u1, got %+v (all: %+v)", f, fsx)
	}
	if g := byID["CVE-2024-2961"]; g.VulnID != "" {
		t.Fatal("glibc 2.36-9+deb12u9 is >= fixed 2.36-9+deb12u6 and must not be reported")
	}
	if g := byID["CVE-2010-4756"]; g.Fixed != "" || g.Severity != "low" {
		t.Fatalf("open glibc issue: %+v", g)
	}
	// apk-style security marking: the pending libssl3 update fixes a CVE
	ups, _ := s.db.ListUpdates(ctx, id.AgentID)
	if len(ups) != 1 || !ups[0].Security {
		t.Fatalf("update not marked security: %+v", ups)
	}
	// NVD enrichment adds CVSS 9.1 → critical
	if err := s.enrichNVD(ctx); err != nil {
		t.Fatal(err)
	}
	f2, _ := s.db.ListFindings(ctx, store.FindingFilter{HostID: id.AgentID, VulnID: "CVE-2024-5535"})
	if len(f2) != 1 || f2[0].Severity != "critical" || f2[0].Risk < 54 {
		t.Fatalf("after NVD: %+v", f2)
	}
	// exception hides it from host risk counts
	before, _ := s.db.HostRisks(ctx)
	_, _ = s.db.CreateException(ctx, store.Exception{VulnID: "CVE-2024-5535", Kind: "accepted", Reason: "test", CreatedBy: "t"})
	after, _ := s.db.HostRisks(ctx)
	if after[id.AgentID].Total != before[id.AgentID].Total-1 {
		t.Fatalf("exception not applied: %+v → %+v", before, after)
	}

	// 2. upgrade: the CVE disappears and is recorded as resolved
	if err := a.Post(ctx, protocol.PathInventory, debianInventory("3.0.15-1~deb12u1"), nil); err != nil {
		t.Fatal(err)
	}
	fsx, _ = s.db.ListFindings(ctx, store.FindingFilter{HostID: id.AgentID, VulnID: "CVE-2024-5535"})
	if len(fsx) != 0 {
		t.Fatalf("CVE still present after upgrade: %+v", fsx)
	}
	res, _ := s.db.ResolvedFindings(ctx, id.AgentID, 10)
	if len(res) == 0 || res[0].VulnID != "CVE-2024-5535" {
		t.Fatalf("resolved: %+v", res)
	}
	st, _ := s.db.GetFeedStatus(ctx)
	if st["debian-tracker"].LastSuccess.IsZero() || st["cisa-kev"].Records != 2 {
		t.Fatalf("feed status %+v", st)
	}
	// second sync: ETag → not modified, record count kept
	if err := s.SyncFeeds(ctx, true); err != nil {
		t.Fatal(err)
	}
	st2, _ := s.db.GetFeedStatus(ctx)
	if st2["debian-tracker"].Records != st["debian-tracker"].Records {
		t.Fatalf("records changed on 304: %d → %d", st["debian-tracker"].Records, st2["debian-tracker"].Records)
	}
}
