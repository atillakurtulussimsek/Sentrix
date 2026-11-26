package server

import "github.com/go-chi/chi/v5"

func (s *Server) viewerRoutes(r chi.Router) {
	r.Get("/vulns", s.handleVulns)
	r.Get("/vulns/{id}", s.handleVuln)
	r.Get("/hosts/{id}/vulns", s.handleHostVulns)
	r.Get("/packages/{name}", s.handlePackage)
	r.Get("/api/v1/vulns", s.apiVulns)
	s.viewerRoutesExtra(r)
}

func (s *Server) operatorRoutes(r chi.Router) {
	r.Post("/vulns/{id}/exceptions", s.handleExceptionCreate)
	r.Post("/exceptions/{id}/delete", s.handleExceptionDelete)
	s.operatorRoutesExtra(r)
}

func (s *Server) adminRoutes(r chi.Router) {
	r.Get("/settings/feeds", s.handleFeeds)
	r.Post("/settings/feeds/sync", s.handleFeedsSync)
	s.adminRoutesExtra(r)
}
