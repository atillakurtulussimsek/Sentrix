package server

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/web"
)

// handleInstallScript serves the agent installer with this server's URLs filled in.
func (s *Server) handleInstallScript(w http.ResponseWriter, _ *http.Request) {
	b, err := web.Static.ReadFile("static/install.sh")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	script := strings.ReplaceAll(string(b), "__SENTRIX_BASE_URL__", strings.TrimRight(s.cfg.BaseURL, "/"))
	script = strings.ReplaceAll(script, "__SENTRIX_GATEWAY_URL__", strings.TrimRight(s.cfg.GatewayURL, "/"))
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	_, _ = w.Write([]byte(script))
}

// handleDownload serves agent binaries from agent_dir (public: binaries are not secret).
func (s *Server) handleDownload(w http.ResponseWriter, r *http.Request) {
	name := chi.URLParam(r, "name")
	switch name {
	case "sentrix-agent-linux-amd64", "sentrix-agent-linux-arm64":
	default:
		http.NotFound(w, r)
		return
	}
	if s.cfg.AgentDir == "" {
		http.Error(w, "agent downloads are not configured on this server (agent_dir)", http.StatusNotFound)
		return
	}
	p := filepath.Join(s.cfg.AgentDir, name)
	f, err := os.Open(p)
	if err != nil {
		http.NotFound(w, r)
		return
	}
	defer f.Close()
	st, err := f.Stat()
	if err != nil {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeContent(w, r, name, st.ModTime(), f)
}
