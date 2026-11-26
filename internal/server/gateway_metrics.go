package server

import (
	"net/http"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

const maxSamplesPerBatch = 50000

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	h := hostFrom(r.Context())
	var b protocol.MetricsBatch
	if err := decodeJSON(r, &b); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(b.Samples) > maxSamplesPerBatch {
		http.Error(w, "batch too large", http.StatusRequestEntityTooLarge)
		return
	}
	// Reject samples from the far future (clock skew) and older than raw retention.
	now := time.Now()
	valid := b.Samples[:0]
	for _, x := range b.Samples {
		if x.TS <= now.Add(5*time.Minute).Unix() && x.TS >= now.Add(-s.cfg.Retention.Raw).Unix() {
			valid = append(valid, x)
		}
	}
	if err := s.mets.Ingest(r.Context(), h.ID, valid); err != nil {
		s.log.Error("ingest metrics", "host", h.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	_ = s.db.MarkSeen(r.Context(), h.ID)
	s.hub.Publish(Event{Type: "metrics", HostID: h.ID, Data: valid})
	w.WriteHeader(http.StatusNoContent)
}
