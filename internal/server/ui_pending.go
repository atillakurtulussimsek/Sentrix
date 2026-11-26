package server

import (
	"context"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// Hooks filled in by later milestones.

func (s *Server) viewerRoutes(chi.Router)   {}
func (s *Server) operatorRoutes(chi.Router) {}
func (s *Server) adminRoutes(chi.Router)    {}

func (s *Server) firingAlerts(*http.Request) int       { return 0 }
func (s *Server) feedsStale(*http.Request) bool        { return false }
func (s *Server) lastFeedSync(*http.Request) time.Time { return time.Time{} }

func (s *Server) enrichRisk(context.Context, []*hostSummary)      {}
func (s *Server) extraHostTabs(context.Context, string) []hostTab { return nil }
