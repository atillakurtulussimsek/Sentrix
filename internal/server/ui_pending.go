package server

import (
	"context"
	"net/http"

	"github.com/go-chi/chi/v5"
)

// Hooks filled in by later milestones.

func (s *Server) viewerRoutesExtra(chi.Router)   {}
func (s *Server) operatorRoutesExtra(chi.Router) {}
func (s *Server) adminRoutesExtra(chi.Router)    {}

func (s *Server) patchHostTabs(context.Context, string) []hostTab { return nil }

func (s *Server) firingAlerts(*http.Request) int { return 0 }
