package server

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

func (s *Server) agentWatchConfig(_ context.Context, _ store.Host) ([]string, []string) {
	return nil, nil
}

func (s *Server) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleState(w http.ResponseWriter, r *http.Request) {
	h := hostFrom(r.Context())
	var st protocol.HostState
	if err := decodeJSON(r, &st); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	b, _ := json.Marshal(st)
	if err := s.db.SaveHostState(r.Context(), h.ID, string(b)); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleInventory(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleResults(w http.ResponseWriter, _ *http.Request) {
	http.Error(w, "not implemented", http.StatusNotImplemented)
}

func (s *Server) handleCommandsPoll(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, protocol.CommandsResponse{})
}
