package server

import (
	"archive/zip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
	"github.com/atillakurtulussimsek/Sentrix/internal/vuln"
)

// feedRunner serialises feed syncs and matching.
type feedRunner struct {
	run     sync.Mutex // held for the whole sync
	mu      sync.Mutex // protects syncing
	syncing bool
	client  *http.Client
	nvdGap  time.Duration // overrides NVD rate-limit spacing (tests)
}

func (s *Server) feedClient() *http.Client {
	if s.feeds.client == nil {
		s.feeds.client = &http.Client{Timeout: 20 * time.Minute}
	}
	return s.feeds.client
}

// fleetEcosystems returns distro ID → set of ecosystem keys present in inventories.
func (s *Server) fleetEcosystems(ctx context.Context) (map[string]map[string]bool, error) {
	invs, err := s.db.ListInventories(ctx)
	if err != nil {
		return nil, err
	}
	out := map[string]map[string]bool{}
	for _, inv := range invs {
		key, _, ok := vuln.Ecosystem(inv.OS)
		if !ok {
			continue
		}
		if out[inv.OS.ID] == nil {
			out[inv.OS.ID] = map[string]bool{}
		}
		out[inv.OS.ID][key] = true
	}
	return out, nil
}

type fetchResult struct {
	path        string
	etag        string
	notModified bool
}

func (s *Server) fetch(ctx context.Context, rawURL, name, etag string) (fetchResult, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return fetchResult{}, err
	}
	req.Header.Set("User-Agent", "Sentrix/"+version.Version+" (vulnerability feed sync)")
	if etag != "" {
		req.Header.Set("If-None-Match", etag)
	}
	resp, err := s.feedClient().Do(req)
	if err != nil {
		return fetchResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotModified {
		return fetchResult{notModified: true, etag: etag}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return fetchResult{}, fmt.Errorf("GET %s: %s", rawURL, resp.Status)
	}
	dir := filepath.Join(s.cfg.DataDir, "feeds")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fetchResult{}, err
	}
	p := filepath.Join(dir, name)
	f, err := os.Create(p + ".part")
	if err != nil {
		return fetchResult{}, err
	}
	if _, err := io.Copy(f, io.LimitReader(resp.Body, 2<<30)); err != nil {
		f.Close()
		return fetchResult{}, fmt.Errorf("download %s: %w", rawURL, err)
	}
	if err := f.Close(); err != nil {
		return fetchResult{}, err
	}
	if err := os.Rename(p+".part", p); err != nil {
		return fetchResult{}, err
	}
	return fetchResult{path: p, etag: resp.Header.Get("ETag")}, nil
}

func keysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// SyncFeeds downloads all relevant feeds and re-matches every host. Concurrent calls
// are serialised (a second caller waits and then usually finds the feeds fresh).
func (s *Server) SyncFeeds(ctx context.Context, force bool) error {
	s.feeds.run.Lock()
	defer s.feeds.run.Unlock()
	s.feeds.mu.Lock()
	s.feeds.syncing = true
	s.feeds.mu.Unlock()
	defer func() {
		s.feeds.mu.Lock()
		s.feeds.syncing = false
		s.feeds.mu.Unlock()
	}()

	ecos, err := s.fleetEcosystems(ctx)
	if err != nil {
		return err
	}
	status, _ := s.db.GetFeedStatus(ctx)
	var errs []error
	run := func(feed string, fn func(prevETag string) (int, string, error)) {
		st := status[feed]
		if !force && !st.LastSuccess.IsZero() && time.Since(st.LastSuccess) < s.cfg.Feeds.Interval-time.Minute {
			return
		}
		start := time.Now()
		n, etag, err := fn(st.ETag)
		if err != nil {
			s.log.Warn("feed sync failed", "feed", feed, "err", err)
			errs = append(errs, fmt.Errorf("%s: %w", feed, err))
			_ = s.db.RecordFeed(ctx, feed, 0, "", err)
			return
		}
		if n < 0 { // not modified
			n = st.Records
		}
		s.log.Info("feed synced", "feed", feed, "records", n, "took", time.Since(start).Round(time.Second))
		_ = s.db.RecordFeed(ctx, feed, n, etag, nil)
	}

	if deb := ecos["debian"]; len(deb) > 0 {
		run("debian-tracker", func(prev string) (int, string, error) {
			keys := keysOf(deb)
			tag := strings.Join(keys, ",")
			prevTag, prevEco, _ := strings.Cut(prev, "|")
			if prevEco != tag {
				prevTag = ""
			}
			res, err := s.fetch(ctx, s.cfg.Feeds.DebianURL, "debian-tracker.json", prevTag)
			if err != nil {
				return 0, "", err
			}
			if res.notModified {
				return -1, prev, nil
			}
			wanted := map[string]bool{}
			for _, k := range keys {
				wanted[strings.TrimPrefix(k, "debian:")] = true
			}
			f, err := os.Open(res.path)
			if err != nil {
				return 0, "", err
			}
			defer f.Close()
			w, err := s.db.BeginAffected(ctx, "debian-tracker", keys)
			if err != nil {
				return 0, "", err
			}
			n, err := vuln.ParseDebianTracker(f, wanted, w)
			if err != nil {
				w.Rollback()
				return 0, "", err
			}
			return n, res.etag + "|" + tag, w.Commit()
		})
	}
	for _, distro := range []string{"ubuntu", "alpine", "rocky", "almalinux"} {
		keys := ecos[distro]
		if len(keys) == 0 {
			continue
		}
		dir := vuln.OSVEcosystemFiles[distro]
		feed := "osv-" + distro
		run(feed, func(prev string) (int, string, error) {
			tag := strings.Join(keysOf(keys), ",")
			prevTag, prevEco, _ := strings.Cut(prev, "|")
			if prevEco != tag {
				prevTag = ""
			}
			u := strings.TrimRight(s.cfg.Feeds.OSVBaseURL, "/") + "/" + url.PathEscape(dir) + "/all.zip"
			res, err := s.fetch(ctx, u, feed+".zip", prevTag)
			if err != nil {
				return 0, "", err
			}
			if res.notModified {
				return -1, prev, nil
			}
			zr, err := zip.OpenReader(res.path)
			if err != nil {
				return 0, "", err
			}
			defer zr.Close()
			w, err := s.db.BeginAffected(ctx, feed, keysOf(keys))
			if err != nil {
				return 0, "", err
			}
			n, err := vuln.ParseOSVZip(&zr.Reader, feed, keys, w)
			if err != nil {
				w.Rollback()
				return 0, "", err
			}
			return n, res.etag + "|" + tag, w.Commit()
		})
	}
	run("cisa-kev", func(prev string) (int, string, error) {
		res, err := s.fetch(ctx, s.cfg.Feeds.KEVURL, "kev.json", prev)
		if err != nil || res.notModified {
			return -1, prev, err
		}
		f, err := os.Open(res.path)
		if err != nil {
			return 0, "", err
		}
		defer f.Close()
		entries, err := vuln.ParseKEV(f)
		if err != nil {
			return 0, "", err
		}
		return len(entries), res.etag, s.db.SetKEV(ctx, entries)
	})
	run("first-epss", func(prev string) (int, string, error) {
		res, err := s.fetch(ctx, s.cfg.Feeds.EPSSURL, "epss.csv.gz", "")
		if err != nil {
			return 0, "", err
		}
		f, err := os.Open(res.path)
		if err != nil {
			return 0, "", err
		}
		defer f.Close()
		scores := map[string]vuln.EPSSEntry{}
		if _, err := vuln.ParseEPSS(f, func(e vuln.EPSSEntry) error { scores[e.CVE] = e; return nil }); err != nil {
			return 0, "", err
		}
		_, err = s.db.SetEPSS(ctx, scores)
		return len(scores), res.etag, err
	})
	if err := s.RematchAll(ctx); err != nil {
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// RematchAll recomputes findings for every host with an inventory.
func (s *Server) RematchAll(ctx context.Context) error {
	invs, err := s.db.ListInventories(ctx)
	if err != nil {
		return err
	}
	cache := map[string]vuln.AffectedIndex{}
	var errs []error
	for id := range invs {
		if err := s.rematchHost(ctx, id, cache); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}

// rematchHost matches one host's inventory and stores findings with risk scores.
func (s *Server) rematchHost(ctx context.Context, hostID string, cache map[string]vuln.AffectedIndex) error {
	inv, err := s.db.GetInventory(ctx, hostID)
	if err != nil {
		return err
	}
	eco, scheme, ok := vuln.Ecosystem(inv.OS)
	if !ok {
		_, _, err := s.db.ReplaceFindings(ctx, hostID, nil)
		return err
	}
	idx, ok := cache[eco]
	if !ok {
		if idx, err = s.db.AffectedIndex(ctx, eco); err != nil {
			return err
		}
		if cache != nil {
			cache[eco] = idx
		}
	}
	pkgs, err := s.db.ListPackages(ctx, hostID, "")
	if err != nil {
		return err
	}
	ports, _ := s.db.ListPorts(ctx, hostID)
	found := vuln.Match(scheme, pkgs, idx, ports)
	ids := make([]string, 0, len(found))
	for _, f := range found {
		ids = append(ids, f.VulnID)
	}
	metas, err := s.db.VulnMetas(ctx, ids)
	if err != nil {
		return err
	}
	stored := make([]store.StoredFinding, 0, len(found))
	for _, f := range found {
		m := metas[f.VulnID]
		in := riskInput(m, f)
		risk, comps := vuln.Score(in)
		rj, _ := json.Marshal(comps)
		stored = append(stored, store.StoredFinding{HostID: hostID, VulnID: f.VulnID, Package: f.Package, Installed: f.Installed, Fixed: f.Fixed,
			Advisory: f.Advisory, Binaries: f.Binaries, Exposed: f.Exposed, Severity: in.Severity, Risk: risk, RiskJSON: string(rj)})
	}
	added, resolved, err := s.db.ReplaceFindings(ctx, hostID, stored)
	if err != nil {
		return err
	}
	s.markSecurityUpdates(ctx, hostID, scheme, found)
	if len(added) > 0 || len(resolved) > 0 {
		s.log.Info("findings updated", "host", hostID, "total", len(stored), "new", len(added), "resolved", len(resolved))
		s.hub.Publish(Event{Type: "findings", HostID: hostID, Data: map[string]any{"added": added, "resolved": resolved, "metas": metas}})
	}
	return nil
}

func riskInput(m store.VulnMeta, f vuln.Finding) vuln.RiskInput {
	sev := m.Severity
	if (sev == "" || sev == "unknown") && f.DistroSev != "" {
		sev = vuln.NormalizeSeverity(f.DistroSev)
	}
	if sev == "" {
		sev = "unknown"
	}
	return vuln.RiskInput{CVSS: m.CVSSScore, Severity: sev, DistroSev: f.DistroSev, EPSS: m.EPSS, EPSSPct: m.EPSSPct, KEV: m.KEV,
		FixAvailable: f.FixAvailable(), Exposed: f.Exposed != ""}
}

// markSecurityUpdates flags pending updates that fix a matched vulnerability (needed for
// apk, which has no security metadata, and as a cross-check for other distros).
func (s *Server) markSecurityUpdates(ctx context.Context, hostID string, scheme vuln.Scheme, found []vuln.Finding) {
	ups, err := s.db.ListUpdates(ctx, hostID)
	if err != nil || len(ups) == 0 {
		return
	}
	pending := map[string]protocol.Update{}
	for _, u := range ups {
		pending[u.Name] = u
	}
	var names []string
	for _, f := range found {
		if !f.FixAvailable() {
			continue
		}
		for _, b := range append([]string{f.Package}, f.Binaries...) {
			u, ok := pending[b]
			if !ok || u.Security {
				continue
			}
			if scheme == vuln.SchemeDpkg {
				// binary and source versions can differ; any pending update of an affected binary counts
				names = append(names, b)
				continue
			}
			if c, err := vuln.CompareVersions(scheme, u.NewVer, f.Fixed); err == nil && c >= 0 {
				names = append(names, b)
			}
		}
	}
	if len(names) > 0 {
		_ = s.db.MarkSecurityUpdates(ctx, hostID, names)
	}
}

// enrichNVD fetches CVSS data from NVD for CVEs lacking a score (rate limited).
func (s *Server) enrichNVD(ctx context.Context) error {
	if !s.cfg.Feeds.Enabled {
		return nil
	}
	gap, batch := 6500*time.Millisecond, 15
	if s.cfg.Feeds.NVDAPIKey != "" {
		gap, batch = 700*time.Millisecond, 100
	}
	if s.feeds.nvdGap > 0 {
		gap = s.feeds.nvdGap
	}
	ids, err := s.db.CVEsNeedingNVD(ctx, batch)
	if err != nil || len(ids) == 0 {
		return err
	}
	updated := 0
	for i, id := range ids {
		if i > 0 {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(gap):
			}
		}
		req, _ := http.NewRequestWithContext(ctx, http.MethodGet, s.cfg.Feeds.NVDURL+"?cveId="+url.QueryEscape(id), nil)
		req.Header.Set("User-Agent", "Sentrix/"+version.Version)
		if s.cfg.Feeds.NVDAPIKey != "" {
			req.Header.Set("apiKey", s.cfg.Feeds.NVDAPIKey)
		}
		resp, err := s.feedClient().Do(req)
		if err != nil {
			return err
		}
		if resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusTooManyRequests {
			resp.Body.Close()
			return fmt.Errorf("nvd rate limited (%s)", resp.Status)
		}
		info, perr := vuln.ParseNVDCVE(io.LimitReader(resp.Body, 4<<20))
		resp.Body.Close()
		if perr != nil {
			_ = s.db.MarkNVDChecked(ctx, id)
			continue
		}
		if err := s.db.SaveNVDInfo(ctx, info); err == nil {
			updated++
		}
	}
	_ = s.db.RecordFeed(ctx, "nvd", updated, "", nil)
	if updated > 0 {
		return s.RematchAll(ctx)
	}
	return nil
}

// afterInventory re-matches the host and triggers a feed sync when its ecosystem has
// never been synced (new distribution in the fleet).
func (s *Server) afterInventory(ctx context.Context, hostID string) {
	if err := s.rematchHost(ctx, hostID, nil); err != nil {
		s.log.Warn("match host", "host", hostID, "err", err)
	}
	if !s.cfg.Feeds.Enabled {
		return
	}
	inv, err := s.db.GetInventory(ctx, hostID)
	if err != nil {
		return
	}
	feed := "osv-" + inv.OS.ID
	if inv.OS.ID == "debian" {
		feed = "debian-tracker"
	}
	if _, _, ok := vuln.Ecosystem(inv.OS); !ok {
		return
	}
	st, _ := s.db.GetFeedStatus(ctx)
	eco, _, _ := vuln.Ecosystem(inv.OS)
	if f, ok := st[feed]; !ok || f.LastSuccess.IsZero() || !strings.Contains(f.ETag, eco) {
		go func() {
			if err := s.SyncFeeds(s.bgCtx, true); err != nil {
				s.log.Warn("feed sync after new ecosystem", "err", err)
			}
		}()
	}
}

// feedsStale reports whether vulnerability data is missing or older than stale_after.
func (s *Server) feedsStale(r *http.Request) bool {
	if !s.cfg.Feeds.Enabled {
		return false
	}
	st, err := s.db.GetFeedStatus(r.Context())
	if err != nil {
		return false
	}
	ecos, _ := s.fleetEcosystems(r.Context())
	for distro := range ecos {
		feed := "osv-" + distro
		if distro == "debian" {
			feed = "debian-tracker"
		}
		f := st[feed]
		if f.LastSuccess.IsZero() {
			// first sync may still be running
			if f.LastAttempt.IsZero() || f.LastError == "" {
				continue
			}
			return true
		}
		if time.Since(f.LastSuccess) > s.cfg.Feeds.OfflineAfter {
			return true
		}
	}
	return false
}

// lastFeedSync returns the oldest successful sync among the fleet's distro feeds.
func (s *Server) lastFeedSync(r *http.Request) time.Time {
	st, err := s.db.GetFeedStatus(r.Context())
	if err != nil {
		return time.Time{}
	}
	var oldest time.Time
	for name, f := range st {
		if name == "nvd" || f.LastSuccess.IsZero() {
			continue
		}
		if oldest.IsZero() || f.LastSuccess.Before(oldest) {
			oldest = f.LastSuccess
		}
	}
	return oldest
}
