package server

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// agentWatchConfig returns per-host watched services and TLS endpoints for heartbeats.
func (s *Server) agentWatchConfig(ctx context.Context, h store.Host) ([]string, []string) {
	hs, err := s.db.GetHostSettings(ctx, h.ID)
	if err != nil {
		return nil, nil
	}
	ws, te := hs.WatchServices, hs.TLSEndpoints
	if ws == nil {
		ws = []string{}
	}
	if te == nil {
		te = []string{}
	}
	return ws, te
}

// handleCommandsPoll long-polls for queued commands (up to ?wait seconds, max 30).
func (s *Server) handleCommandsPoll(w http.ResponseWriter, r *http.Request) {
	h := hostFrom(r.Context())
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	wait = max(0, min(wait, 30))
	_ = s.db.MarkSeen(r.Context(), h.ID)
	ch, unsub := s.hub.Subscribe()
	defer unsub()
	deadline := time.NewTimer(time.Duration(wait) * time.Second)
	defer deadline.Stop()
	recheck := time.NewTicker(5 * time.Second)
	defer recheck.Stop()
	for {
		cmds, err := s.db.ClaimCommands(r.Context(), h.ID, 10*time.Minute)
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		if len(cmds) > 0 {
			for _, c := range cmds {
				s.log.Info("command delivered", "host", h.Hostname, "id", c.ID, "action", c.Action, "dry_run", c.DryRun)
			}
			writeJSON(w, http.StatusOK, protocol.CommandsResponse{Commands: cmds})
			return
		}
	waitLoop:
		for {
			select {
			case <-r.Context().Done():
				return
			case <-deadline.C:
				writeJSON(w, http.StatusOK, protocol.CommandsResponse{Commands: []protocol.Command{}})
				return
			case <-recheck.C:
				break waitLoop
			case ev, ok := <-ch:
				if !ok {
					writeJSON(w, http.StatusOK, protocol.CommandsResponse{Commands: []protocol.Command{}})
					return
				}
				if ev.Type == "command_queued" && ev.HostID == h.ID {
					break waitLoop
				}
			}
		}
	}
}

func (s *Server) handleResults(w http.ResponseWriter, r *http.Request) {
	h := hostFrom(r.Context())
	var req protocol.ResultsRequest
	if err := decodeJSON(r, &req); err != nil || len(req.Results) > 50 {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	for _, res := range req.Results {
		c, err := s.db.CompleteCommand(r.Context(), h.ID, res)
		if errors.Is(err, store.ErrNotFound) {
			continue // unknown, foreign or already-completed command: ignore (idempotent)
		}
		if err != nil {
			http.Error(w, "internal error", http.StatusInternalServerError)
			return
		}
		detail := "status=" + res.Status
		if res.Error != "" {
			detail += " error=" + truncate(res.Error, 300)
		}
		if c.DryRun {
			detail += " dry_run"
		}
		s.audit(r.Context(), "agent:"+h.Hostname, "command.result."+string(c.Action), h.ID, detail+" cmd="+c.ID)
		s.hub.Publish(Event{Type: "command_result", HostID: h.ID, Data: map[string]string{"id": c.ID, "plan": c.PlanID, "status": res.Status}})
		s.kickOrchestrator()
	}
	w.WriteHeader(http.StatusNoContent)
}

// QueueCommand enqueues a command for a host and wakes its long-poll.
func (s *Server) QueueCommand(ctx context.Context, hostID string, action protocol.Action, params any, dryRun bool, planID, actor string) (store.CommandRow, error) {
	ttl := 2 * time.Hour
	c, err := s.db.EnqueueCommand(ctx, hostID, action, params, dryRun, planID, actor, ttl)
	if err != nil {
		return c, err
	}
	detail := "action=" + string(action)
	if dryRun {
		detail += " dry_run"
	}
	if planID != "" {
		detail += " plan=" + planID
	}
	s.audit(ctx, actor, "command.queue", hostID, detail+" cmd="+c.ID)
	s.hub.Publish(Event{Type: "command_queued", HostID: hostID})
	return c, nil
}

func actorOf(r *http.Request) string {
	if a := authFrom(r.Context()); a != nil {
		if a.Session == nil {
			return "user:" + a.User.Username + " (" + a.Via + ")"
		}
		return "user:" + a.User.Username
	}
	return "system"
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == '\t' }) {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}
