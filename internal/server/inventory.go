package server

import (
	"context"
	"net/http"
	"strings"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
)

const maxPackages = 20000

func (s *Server) handleInventory(w http.ResponseWriter, r *http.Request) {
	h := hostFrom(r.Context())
	var inv protocol.Inventory
	if err := decodeJSON(r, &inv); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if len(inv.Packages) > maxPackages || len(inv.Updates) > maxPackages {
		http.Error(w, "inventory too large", http.StatusRequestEntityTooLarge)
		return
	}
	if err := s.db.SaveInventory(r.Context(), h.ID, inv); err != nil {
		s.log.Error("save inventory", "host", h.ID, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.log.Info("inventory received", "host", h.Hostname, "packages", len(inv.Packages), "updates", len(inv.Updates))
	s.hub.Publish(Event{Type: "inventory", HostID: h.ID})
	for _, fn := range s.inventoryHooks {
		fn(context.WithoutCancel(r.Context()), h.ID)
	}
	w.WriteHeader(http.StatusNoContent)
}

// OnInventory registers a callback run after each inventory upload.
func (s *Server) OnInventory(fn func(ctx context.Context, hostID string)) {
	s.inventoryHooks = append(s.inventoryHooks, fn)
}

func osLabel(o protocol.OSInfo) string {
	if o.PrettyName != "" {
		return o.PrettyName
	}
	return strings.TrimSpace(o.ID + " " + o.VersionID)
}

func (s *Server) hostOS(ctx context.Context, hostID string) string {
	inv, err := s.db.GetInventory(ctx, hostID)
	if err != nil {
		return ""
	}
	return osLabel(inv.OS)
}

// enrichSummaries adds inventory and vulnerability data to host summaries.
func (s *Server) enrichSummaries(ctx context.Context, sums []*hostSummary) {
	invs, err := s.db.ListInventories(ctx)
	if err == nil {
		for _, h := range sums {
			if inv, ok := invs[h.ID]; ok {
				h.OS = osLabel(inv.OS)
			}
		}
	}
	if counts, err := s.db.UpdateCounts(ctx); err == nil {
		for _, h := range sums {
			c := counts[h.ID]
			h.Updates, h.SecUpdates = c[0], c[1]
		}
	}
	s.enrichRisk(ctx, sums)
}

func (s *Server) hostTabs(ctx context.Context, hostID string) []hostTab {
	tabs := []hostTab{{Key: "overview", Label: "Overview"}}
	n, _ := s.db.CountPackages(ctx, hostID)
	tabs = append(tabs, hostTab{Key: "inventory", Label: "Inventory", Path: "/inventory", Count: n})
	if c, err := s.db.UpdateCounts(ctx); err == nil {
		tabs = append(tabs, hostTab{Key: "updates", Label: "Updates", Path: "/updates", Count: c[hostID][0]})
	}
	tabs = append(tabs, s.extraHostTabs(ctx, hostID)...)
	return tabs
}

func (s *Server) handleHostInventory(w http.ResponseWriter, r *http.Request) {
	h, d, ok := s.hostPage(w, r, "inventory")
	if !ok {
		return
	}
	q := strings.TrimSpace(r.URL.Query().Get("q"))
	inv, err := s.db.GetInventory(r.Context(), h.ID)
	if err == nil {
		d["Inventory"] = inv
	}
	d["Packages"], _ = s.db.ListPackages(r.Context(), h.ID, q)
	d["Ports"], _ = s.db.ListPorts(r.Context(), h.ID)
	d["Images"], _ = s.db.ListImages(r.Context(), h.ID)
	d["Query"] = q
	if r.Header.Get("HX-Request") == "true" && r.Header.Get("HX-Target") == "pkg-table" {
		s.renderTmpl(w, r, 200, "host_inventory", "pkgtable", "", d)
		return
	}
	s.renderPage(w, r, 200, "host_inventory", h.Hostname, d)
}

func (s *Server) handleHostUpdates(w http.ResponseWriter, r *http.Request) {
	h, d, ok := s.hostPage(w, r, "updates")
	if !ok {
		return
	}
	ups, _ := s.db.ListUpdates(r.Context(), h.ID)
	sec := 0
	for _, u := range ups {
		if u.Security {
			sec++
		}
	}
	d["Updates"], d["Security"] = ups, sec
	if inv, err := s.db.GetInventory(r.Context(), h.ID); err == nil {
		d["Inventory"] = inv
	}
	s.renderPage(w, r, 200, "host_updates", h.Hostname, d)
}
