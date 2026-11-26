package server

import (
	"net/http"
	"strings"
)

func (s *Server) handleAudit(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(r.URL.Query().Get("target"))
	entries, err := s.db.ListAudit(r.Context(), target, 500)
	if err != nil {
		s.httpError(w, r, 500, s.t("error.internal"))
		return
	}
	s.renderPage(w, r, 200, "audit", s.t("nav.audit"), map[string]any{"Entries": entries, "Target": target})
}
