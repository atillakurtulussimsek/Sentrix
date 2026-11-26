package server

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// UIHandler returns the web UI + REST API handler.
func (s *Server) UIHandler() http.Handler {
	r := chi.NewRouter()
	r.Get("/healthz", s.handleHealth)
	r.Get("/api/v1/hosts", s.apiHosts)
	return r
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if err := s.db.SQL().PingContext(r.Context()); err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "db unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}
