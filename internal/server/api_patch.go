package server

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

type apiPlanReq struct {
	Name         string   `json:"name"`
	Hosts        []string `json:"hosts"` // IDs or hostnames
	Group        string   `json:"group"`
	Scope        string   `json:"scope"`
	Packages     []string `json:"packages"`
	Reboot       string   `json:"reboot"`
	Canary       int      `json:"canary"`
	MaxParallel  int      `json:"max_parallel"`
	SnapshotHook string   `json:"snapshot_hook"`
}

type apiPlanHost struct {
	HostID         string                   `json:"host_id"`
	Hostname       string                   `json:"hostname"`
	Status         string                   `json:"status"`
	DryRunChanges  []protocol.PackageChange `json:"dry_run_changes"`
	Changes        []protocol.PackageChange `json:"changes"`
	Error          string                   `json:"error,omitempty"`
	FindingsBefore int                      `json:"findings_before"`
	FindingsAfter  int                      `json:"findings_after"`
	RebootRequired bool                     `json:"reboot_required"`
}

type apiPlanResp struct {
	ID         string        `json:"id"`
	Name       string        `json:"name"`
	Scope      string        `json:"scope"`
	Status     string        `json:"status"`
	Error      string        `json:"error,omitempty"`
	CreatedBy  string        `json:"created_by"`
	ApprovedBy string        `json:"approved_by,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
	Hosts      []apiPlanHost `json:"hosts,omitempty"`
}

func toAPIPlan(p store.Plan, hosts []store.PlanHost) apiPlanResp {
	out := apiPlanResp{ID: p.ID, Name: p.Name, Scope: p.Scope, Status: p.Status, Error: p.Error, CreatedBy: p.CreatedBy, ApprovedBy: p.ApprovedBy, CreatedAt: p.CreatedAt}
	for _, h := range hosts {
		out.Hosts = append(out.Hosts, apiPlanHost{h.HostID, h.Hostname, h.Status, h.DryChanges, h.Changes, h.Error, h.FindingsBefore, h.FindingsAfter, h.RebootRequired})
	}
	return out
}

func (s *Server) apiPlans(w http.ResponseWriter, r *http.Request) {
	plans, err := s.db.ListPlans(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "internal error"})
		return
	}
	out := make([]apiPlanResp, 0, len(plans))
	for _, p := range plans {
		out = append(out, toAPIPlan(p, nil))
	}
	writeJSON(w, 200, out)
}

func (s *Server) apiPlan(w http.ResponseWriter, r *http.Request) {
	p, hosts, err := s.planData(r)
	if errors.Is(err, store.ErrNotFound) {
		writeJSON(w, 404, map[string]string{"error": "plan not found"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "internal error"})
		return
	}
	writeJSON(w, 200, toAPIPlan(p, hosts))
}

func (s *Server) apiPlanCreate(w http.ResponseWriter, r *http.Request) {
	var req apiPlanReq
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<20)).Decode(&req); err != nil {
		writeJSON(w, 400, map[string]string{"error": "invalid JSON"})
		return
	}
	p, err := s.CreatePlan(r.Context(), PlanRequest{Name: req.Name, HostIDs: req.Hosts, Group: req.Group, Scope: req.Scope, Packages: req.Packages,
		Reboot: req.Reboot, Canary: req.Canary, MaxParallel: req.MaxParallel, SnapshotHook: req.SnapshotHook, SnapshotRequired: true}, actorOf(r))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": err.Error()})
		return
	}
	hosts, _ := s.db.ListPlanHosts(r.Context(), p.ID)
	writeJSON(w, 201, toAPIPlan(p, hosts))
}

func (s *Server) apiPlanApprove(w http.ResponseWriter, r *http.Request) {
	if err := s.ApprovePlan(r.Context(), chi.URLParam(r, "id"), actorOf(r)); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.apiPlan(w, r)
}

func (s *Server) apiPlanCancel(w http.ResponseWriter, r *http.Request) {
	if err := s.CancelPlan(r.Context(), chi.URLParam(r, "id"), actorOf(r)); err != nil {
		writeJSON(w, 409, map[string]string{"error": err.Error()})
		return
	}
	s.apiPlan(w, r)
}
