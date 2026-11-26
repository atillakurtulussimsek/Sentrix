package server

import "github.com/go-chi/chi/v5"

// Hooks filled in by later milestones.

func (s *Server) viewerRoutesExtra(chi.Router)   {}
func (s *Server) operatorRoutesExtra(chi.Router) {}
func (s *Server) adminRoutesExtra(chi.Router)    {}
