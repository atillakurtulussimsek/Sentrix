package server

import "github.com/go-chi/chi/v5"

func (s *Server) viewerRoutes(r chi.Router) {
	r.Get("/vulns", s.handleVulns)
	r.Get("/vulns/{id}", s.handleVuln)
	r.Get("/hosts/{id}/vulns", s.handleHostVulns)
	r.Get("/packages/{name}", s.handlePackage)
	r.Get("/api/v1/vulns", s.apiVulns)
	r.Get("/alerts", s.handleAlerts)
	r.Get("/patches", s.handlePlans)
	r.Get("/patches/{id}", s.handlePlan)
	r.Get("/hosts/{id}/patches", s.handleHostPatches)
	r.Get("/api/v1/plans", s.apiPlans)
	r.Get("/api/v1/plans/{id}", s.apiPlan)
	s.viewerRoutesExtra(r)
}

func (s *Server) operatorRoutes(r chi.Router) {
	r.Post("/vulns/{id}/exceptions", s.handleExceptionCreate)
	r.Post("/exceptions/{id}/delete", s.handleExceptionDelete)
	r.Get("/patches/new", s.handlePlanNew)
	r.Post("/patches", s.handlePlanCreate)
	r.Post("/patches/{id}/approve", s.handlePlanApprove)
	r.Post("/patches/{id}/cancel", s.handlePlanCancel)
	r.Post("/hosts/{id}/actions", s.handleHostAction)
	r.Post("/api/v1/plans", s.apiPlanCreate)
	r.Post("/api/v1/plans/{id}/approve", s.apiPlanApprove)
	r.Post("/api/v1/plans/{id}/cancel", s.apiPlanCancel)
	s.operatorRoutesExtra(r)
}

func (s *Server) adminRoutes(r chi.Router) {
	r.Get("/settings/feeds", s.handleFeeds)
	r.Post("/settings/feeds/sync", s.handleFeedsSync)
	r.Get("/settings/policies", s.handlePolicies)
	r.Post("/settings/policies", s.handlePolicySave)
	r.Post("/settings/policies/{id}/delete", s.handlePolicyDelete)
	r.Post("/hosts/{id}/settings", s.handleHostSettings)
	r.Post("/alerts/rules", s.handleRuleSave)
	r.Post("/alerts/rules/{id}/toggle", s.handleRuleToggle)
	r.Post("/alerts/rules/{id}/delete", s.handleRuleDelete)
	r.Get("/settings/channels", s.handleChannels)
	r.Post("/settings/channels", s.handleChannelSave)
	r.Post("/settings/channels/{id}/test", s.handleChannelTest)
	r.Post("/settings/channels/{id}/toggle", s.handleChannelToggle)
	r.Post("/settings/channels/{id}/delete", s.handleChannelDelete)
	r.Post("/settings/digest", s.handleDigestSave)
	r.Get("/settings/hooks", s.handleHooks)
	r.Post("/settings/hooks", s.handleHookSave)
	r.Post("/settings/hooks/{id}/test", s.handleHookTest)
	r.Post("/settings/hooks/{id}/delete", s.handleHookDelete)
	s.adminRoutesExtra(r)
}
