package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/selfupdate"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// Agent update modes.
const (
	agentUpdatesOff    = "off"
	agentUpdatesNotify = "notify"
	agentUpdatesAuto   = "auto"

	settingAgentUpdates = "agent_updates_mode"
	agentUpdateActor    = "system:agent-update"
)

// agentRelease is a verified, signed agent binary the server can offer.
type agentRelease struct {
	Manifest selfupdate.Manifest
	Path     string // binary on disk
	Source   string // "bundled" (agent_dir) or "downloaded"
}

type agentReleaseState struct {
	once      sync.Once
	mu        sync.RWMutex
	byArch    map[string]agentRelease
	checkedAt time.Time
	checkErr  string
	noSigned  bool // the latest published release has no signed agent manifests
}

func (s *Server) agentReleaseDir() string { return filepath.Join(s.cfg.DataDir, "agent-releases") }

// agentUpdateMode returns the effective mode (UI setting overrides the config file).
func (s *Server) agentUpdateMode(ctx context.Context) string {
	if v, err := s.db.GetSetting(ctx, settingAgentUpdates); err == nil {
		switch v {
		case agentUpdatesOff, agentUpdatesNotify, agentUpdatesAuto:
			return v
		}
	}
	switch s.cfg.AgentUpdates.Mode {
	case agentUpdatesOff, agentUpdatesAuto:
		return s.cfg.AgentUpdates.Mode
	}
	return agentUpdatesNotify
}

// releases returns the verified releases per arch, loading them from disk once.
func (s *Server) releases() map[string]agentRelease {
	st := &s.agentRel
	st.once.Do(func() {
		m := map[string]agentRelease{}
		for _, src := range []struct{ dir, name string }{{s.cfg.AgentDir, "bundled"}, {s.agentReleaseDir(), "downloaded"}} {
			if src.dir == "" {
				continue
			}
			for _, arch := range selfupdate.Arches {
				rel, err := loadRelease(src.dir, arch)
				if err != nil {
					if !errors.Is(err, os.ErrNotExist) {
						s.log.Warn("ignoring agent release", "dir", src.dir, "arch", arch, "err", err)
					}
					continue
				}
				rel.Source = src.name
				if cur, ok := m[arch]; !ok || selfupdate.Compare(rel.Manifest.Version, cur.Manifest.Version) > 0 {
					m[arch] = rel
				}
			}
		}
		st.mu.Lock()
		st.byArch = m
		st.mu.Unlock()
	})
	st.mu.RLock()
	defer st.mu.RUnlock()
	out := make(map[string]agentRelease, len(st.byArch))
	for k, v := range st.byArch {
		out[k] = v
	}
	return out
}

// loadRelease reads and fully verifies <dir>/sentrix-agent-linux-<arch>(.sig.json).
func loadRelease(dir, arch string) (agentRelease, error) {
	b, err := os.ReadFile(filepath.Join(dir, selfupdate.ManifestName(arch))) //nolint:gosec // fixed file name in a configured directory
	if err != nil {
		return agentRelease{}, err
	}
	m, err := selfupdate.ParseManifest(b)
	if err != nil {
		return agentRelease{}, err
	}
	if err := selfupdate.VerifyManifest(m, nil); err != nil {
		return agentRelease{}, err
	}
	if m.Arch != arch {
		return agentRelease{}, fmt.Errorf("manifest is for %s", m.Arch)
	}
	path := filepath.Join(dir, selfupdate.BinaryName(arch))
	f, err := os.Open(path) //nolint:gosec // fixed file name in a configured directory
	if err != nil {
		return agentRelease{}, err
	}
	defer f.Close()
	if _, err := selfupdate.VerifyBinary(m, f); err != nil {
		return agentRelease{}, err
	}
	return agentRelease{Manifest: m, Path: path}, nil
}

// CheckAgentReleases fetches the latest signed agent release from release_url and
// stores it when it is newer than what the server already offers.
func (s *Server) CheckAgentReleases(ctx context.Context) error {
	if s.agentUpdateMode(ctx) == agentUpdatesOff || s.cfg.AgentUpdates.ReleaseURL == "" {
		return nil
	}
	cur := s.releases()
	var errs []error
	changed, noSigned := false, false
	for _, arch := range selfupdate.Arches {
		rel, err := s.fetchRelease(ctx, arch, cur[arch])
		if errors.Is(err, errNoSignedRelease) {
			noSigned = true
			continue
		}
		if err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", arch, err))
			continue
		}
		if rel != nil {
			cur[arch] = *rel
			changed = true
			s.log.Info("agent release available", "arch", arch, "version", rel.Manifest.Version)
		}
	}
	err := errors.Join(errs...)
	st := &s.agentRel
	st.mu.Lock()
	if changed {
		st.byArch = cur
	}
	st.checkedAt = s.now()
	st.noSigned = noSigned
	st.checkErr = ""
	if err != nil {
		st.checkErr = err.Error()
	}
	st.mu.Unlock()
	return err
}

var errNoSignedRelease = errors.New("the latest release has no signed agent manifest")

func (s *Server) fetchRelease(ctx context.Context, arch string, cur agentRelease) (*agentRelease, error) {
	base := s.cfg.AgentUpdates.ReleaseURL
	mb, status, err := s.fetchSmall(ctx, base+"/"+selfupdate.ManifestName(arch), 64<<10)
	if status == http.StatusNotFound {
		return nil, errNoSignedRelease
	}
	if err != nil {
		return nil, err
	}
	m, err := selfupdate.ParseManifest(mb)
	if err != nil {
		return nil, err
	}
	if err := selfupdate.VerifyManifest(m, nil); err != nil {
		return nil, err
	}
	if m.Arch != arch {
		return nil, fmt.Errorf("manifest is for %s", m.Arch)
	}
	if cur.Path != "" && selfupdate.Compare(m.Version, cur.Manifest.Version) <= 0 {
		return nil, nil // nothing newer
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+selfupdate.BinaryName(arch), nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.feedClient().Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download agent binary: HTTP %d", resp.StatusCode)
	}
	bin, err := selfupdate.VerifyBinary(m, resp.Body)
	if err != nil {
		return nil, err
	}
	dir := s.agentReleaseDir()
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, selfupdate.BinaryName(arch))
	if err := writeAtomic(path, bin, 0o644); err != nil {
		return nil, err
	}
	if err := writeAtomic(filepath.Join(dir, selfupdate.ManifestName(arch)), mb, 0o644); err != nil {
		return nil, err
	}
	return &agentRelease{Manifest: m, Path: path, Source: "downloaded"}, nil
}

func (s *Server) fetchSmall(ctx context.Context, url string, limit int64) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, 0, err
	}
	resp, err := s.feedClient().Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, resp.StatusCode, fmt.Errorf("GET %s: HTTP %d", url, resp.StatusCode)
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	return b, resp.StatusCode, err
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// agentUpdateFor returns the release a host should move to, if any.
func (s *Server) agentUpdateFor(h store.Host, machineArch string) (agentRelease, bool) {
	arch := selfupdate.GoArch(machineArch)
	if arch == "" || h.AgentVersion == "" {
		return agentRelease{}, false
	}
	rel, ok := s.releases()[arch]
	if !ok || selfupdate.Compare(rel.Manifest.Version, h.AgentVersion) <= 0 {
		return agentRelease{}, false
	}
	return rel, true
}

// hostAgentUpdate is agentUpdateFor for one host (looks up its architecture).
func (s *Server) hostAgentUpdate(ctx context.Context, h store.Host) (agentRelease, bool) {
	if s.agentUpdateMode(ctx) == agentUpdatesOff {
		return agentRelease{}, false
	}
	inv, err := s.db.GetInventory(ctx, h.ID)
	if err != nil {
		return agentRelease{}, false
	}
	return s.agentUpdateFor(h, inv.OS.Arch)
}

// queueAgentUpdate asks a host to install rel.
func (s *Server) queueAgentUpdate(ctx context.Context, hostID string, rel agentRelease, actor string) (store.CommandRow, error) {
	m := rel.Manifest
	return s.QueueCommand(ctx, hostID, protocol.ActionUpdateAgent,
		protocol.UpdateAgentParams{Version: m.Version, Arch: m.Arch, SHA256: m.SHA256}, false, "", actor)
}

// AutoUpdateAgents queues update_agent for outdated online agents in "auto" mode. A host
// is not retried while an update is pending, within an hour of the last attempt, or
// within a day after a failed or rejected attempt.
func (s *Server) AutoUpdateAgents(ctx context.Context) error {
	if s.agentUpdateMode(ctx) != agentUpdatesAuto {
		return nil
	}
	hosts, err := s.db.ListHosts(ctx)
	if err != nil {
		return err
	}
	arches, err := s.db.HostArches(ctx)
	if err != nil {
		return err
	}
	now := s.now()
	for _, h := range hosts {
		if !h.Online(now, s.cfg.OfflineAfter) {
			continue
		}
		rel, ok := s.agentUpdateFor(h, arches[h.ID])
		if !ok {
			continue
		}
		last, found, err := s.db.LastHostCommand(ctx, h.ID, protocol.ActionUpdateAgent)
		if err != nil {
			return err
		}
		if found {
			age := now.Sub(last.CreatedAt)
			switch {
			case last.Status == "queued" || last.Status == "sent":
				continue
			case (last.Status == "failed" || last.Status == "rejected") && age < 24*time.Hour:
				continue
			case age < time.Hour:
				continue
			}
		}
		if _, err := s.queueAgentUpdate(ctx, h.ID, rel, agentUpdateActor); err != nil {
			s.log.Warn("queue agent update", "host", h.Hostname, "err", err)
			continue
		}
		s.log.Info("agent update queued", "host", h.Hostname, "from", h.AgentVersion, "to", rel.Manifest.Version)
	}
	return nil
}

// ---- gateway (mTLS) ----

func (s *Server) handleAgentReleaseManifest(w http.ResponseWriter, r *http.Request) {
	rel, ok := s.releases()[chi.URLParam(r, "arch")]
	if !ok {
		http.Error(w, "no agent release", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(rel.Manifest)
}

func (s *Server) handleAgentReleaseBinary(w http.ResponseWriter, r *http.Request) {
	rel, ok := s.releases()[chi.URLParam(r, "arch")]
	if !ok {
		http.Error(w, "no agent release", http.StatusNotFound)
		return
	}
	f, err := os.Open(rel.Path)
	if err != nil {
		http.Error(w, "agent release unavailable", http.StatusNotFound)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.Error(w, "agent release unavailable", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, selfupdate.BinaryName(rel.Manifest.Arch), st.ModTime(), f)
}

// ---- UI ----

type agentReleaseView struct {
	Arch, Version, Source string
}

type agentUpdatesView struct {
	Mode       string
	ReleaseURL string
	Releases   []agentReleaseView
	CheckedAt  time.Time
	CheckErr   string
	NoSigned   bool
	Outdated   int
}

func (s *Server) agentUpdatesView(ctx context.Context) agentUpdatesView {
	v := agentUpdatesView{Mode: s.agentUpdateMode(ctx), ReleaseURL: s.cfg.AgentUpdates.ReleaseURL}
	for arch, rel := range s.releases() {
		v.Releases = append(v.Releases, agentReleaseView{Arch: arch, Version: rel.Manifest.Version, Source: rel.Source})
	}
	sort.Slice(v.Releases, func(i, j int) bool { return v.Releases[i].Arch < v.Releases[j].Arch })
	st := &s.agentRel
	st.mu.RLock()
	v.CheckedAt, v.CheckErr, v.NoSigned = st.checkedAt, st.checkErr, st.noSigned
	st.mu.RUnlock()
	if hosts, err := s.db.ListHosts(ctx); err == nil {
		arches, _ := s.db.HostArches(ctx)
		for _, h := range hosts {
			if _, ok := s.agentUpdateFor(h, arches[h.ID]); ok && !h.Revoked {
				v.Outdated++
			}
		}
	}
	return v
}

func (s *Server) handleAgentUpdatesMode(w http.ResponseWriter, r *http.Request) {
	mode := r.PostFormValue("mode")
	switch mode {
	case agentUpdatesOff, agentUpdatesNotify, agentUpdatesAuto:
	default:
		s.httpError(w, r, http.StatusBadRequest, s.t(r, "common.invalidForm"))
		return
	}
	if err := s.db.SetSetting(r.Context(), settingAgentUpdates, mode); err != nil {
		s.log.Error("save agent update mode", "err", err)
		s.httpError(w, r, http.StatusInternalServerError, s.t(r, "error.internal"))
		return
	}
	s.audit(r.Context(), actorOf(r), "settings.agent_updates", "", "mode="+mode)
	s.setFlash(w, "ok", s.t(r, "agentupd.saved"))
	http.Redirect(w, r, "/settings/enrollment", http.StatusSeeOther)
}

func (s *Server) handleAgentUpdatesCheck(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()
	if err := s.CheckAgentReleases(ctx); err != nil {
		s.setFlash(w, "error", s.t(r, "agentupd.checkFailed", err.Error()))
	} else {
		s.setFlash(w, "ok", s.t(r, "agentupd.checked"))
	}
	http.Redirect(w, r, "/settings/enrollment", http.StatusSeeOther)
}
