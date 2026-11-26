package server

import (
	"encoding/json"
	"net/http"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

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
	s.hub.Publish(Event{Type: "state", HostID: h.ID, Data: st})
	w.WriteHeader(http.StatusNoContent)
}
