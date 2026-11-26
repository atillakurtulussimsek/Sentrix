package server

import "context"

func (s *Server) audit(ctx context.Context, actor, action, target, detail string) {
	if err := s.db.Audit(ctx, actor, action, target, detail); err != nil {
		s.log.Error("audit write failed", "action", action, "err", err)
	}
}
