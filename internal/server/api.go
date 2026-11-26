package server

import (
	"net/http"
	"time"
)

type apiHost struct {
	ID           string    `json:"id"`
	Hostname     string    `json:"hostname"`
	Status       string    `json:"status"`
	LastSeen     time.Time `json:"last_seen"`
	AgentVersion string    `json:"agent_version"`
	Group        string    `json:"group"`
	Tags         []string  `json:"tags"`
}

func (s *Server) apiHosts(w http.ResponseWriter, r *http.Request) {
	hosts, err := s.db.ListHosts(r.Context())
	if err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	out := make([]apiHost, 0, len(hosts))
	now := time.Now()
	for _, h := range hosts {
		st := "offline"
		if h.Online(now, s.cfg.OfflineAfter) {
			st = "online"
		}
		if h.Revoked {
			st = "revoked"
		}
		out = append(out, apiHost{h.ID, h.Hostname, st, h.LastSeen, h.AgentVersion, h.Group, h.Tags})
	}
	writeJSON(w, http.StatusOK, out)
}
