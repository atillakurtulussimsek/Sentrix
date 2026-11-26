package server

import (
	"context"

	"github.com/atillakurtulussimsek/Sentrix/internal/store"
)

// runSnapshotStep is implemented in M8 (Proxmox / webhook hooks).
func (s *Server) runSnapshotStep(ctx context.Context, p store.Plan, h store.PlanHost) {
	if err := s.issuePatch(ctx, p, &h); err != nil {
		s.log.Error("issue patch after snapshot", "err", err)
	}
}
