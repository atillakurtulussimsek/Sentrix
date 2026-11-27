package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"

	"github.com/atillakurtulussimsek/Sentrix/internal/protocol"
	"github.com/atillakurtulussimsek/Sentrix/internal/store"
	"github.com/atillakurtulussimsek/Sentrix/internal/version"
)

type ctxKey int

const (
	ctxHost ctxKey = iota
	ctxUser
)

const maxAgentBody = 32 << 20

// GatewayHandler returns the agent-facing HTTP handler (served over mTLS).
func (s *Server) GatewayHandler() http.Handler {
	r := chi.NewRouter()
	r.Use(gunzipBody)
	r.Get(protocol.PathCA, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/x-pem-file")
		_, _ = w.Write(s.ca.CertPEM)
	})
	r.Post(protocol.PathEnroll, s.handleEnroll)
	r.Group(func(r chi.Router) {
		r.Use(s.agentAuth)
		r.Post(protocol.PathHeartbeat, s.handleHeartbeat)
		r.Post(protocol.PathRenew, s.handleRenew)
		for path, h := range s.agentRoutes() {
			r.Post(path, h)
		}
		r.Get(protocol.PathCommands, s.handleCommandsPoll)
		r.Get(protocol.PathAgentRelease+"/{arch}", s.handleAgentReleaseManifest)
		r.Get(protocol.PathAgentRelease+"/{arch}/binary", s.handleAgentReleaseBinary)
	})
	r.Get("/healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) })
	return r
}

// agentRoutes is extended by later milestones (metrics, state, inventory, results).
func (s *Server) agentRoutes() map[string]http.HandlerFunc {
	return map[string]http.HandlerFunc{
		protocol.PathMetrics:   s.handleMetrics,
		protocol.PathState:     s.handleState,
		protocol.PathInventory: s.handleInventory,
		protocol.PathResults:   s.handleResults,
	}
}

// agentAuth requires a verified client certificate whose serial matches the
// current, non-revoked certificate of the host named in its CN.
func (s *Server) agentAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
			http.Error(w, "client certificate required", http.StatusUnauthorized)
			return
		}
		leaf := r.TLS.VerifiedChains[0][0]
		h, err := s.db.GetHost(r.Context(), leaf.Subject.CommonName)
		if err != nil {
			http.Error(w, "unknown agent", http.StatusUnauthorized)
			return
		}
		if h.Revoked || h.CertSerial != leaf.SerialNumber.String() {
			http.Error(w, "certificate revoked", http.StatusForbidden)
			return
		}
		ctx := context.WithValue(r.Context(), ctxHost, h)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func hostFrom(ctx context.Context) store.Host {
	h, _ := ctx.Value(ctxHost).(store.Host)
	return h
}

func decodeJSON(r *http.Request, v any) error {
	dec := json.NewDecoder(io.LimitReader(r.Body, maxAgentBody))
	return dec.Decode(v)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.loginIP.Allowed("enroll:" + clientIP(r)) {
		http.Error(w, "too many failed enrolment attempts", http.StatusTooManyRequests)
		return
	}
	var req protocol.EnrollRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	if req.Token == "" || req.Hostname == "" || len(req.Hostname) > 253 {
		http.Error(w, "token and hostname required", http.StatusBadRequest)
		return
	}
	id := uuid.NewString()
	cert, certPEM, err := s.ca.SignAgentCSR([]byte(req.CSRPEM), id, s.cfg.AgentCertValidity)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	h, err := s.db.EnrollHost(r.Context(), store.HashToken(req.Token), store.Host{
		ID: id, Hostname: req.Hostname, MachineID: req.MachineID,
		CertSerial: cert.SerialNumber.String(), CertNotAfter: cert.NotAfter,
	})
	if errors.Is(err, store.ErrTokenInvalid) {
		s.loginIP.Fail("enroll:" + clientIP(r))
		s.log.Warn("enrolment rejected", "hostname", req.Hostname, "remote", r.RemoteAddr)
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	if err != nil {
		s.log.Error("enrol host", "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	s.log.Info("agent enrolled", "host", h.Hostname, "id", h.ID)
	s.audit(r.Context(), "agent:"+h.ID, "host.enroll", h.ID, fmt.Sprintf("hostname=%s", h.Hostname))
	s.hub.Publish(Event{Type: "host_enrolled", HostID: h.ID})
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{AgentID: id, CertPEM: string(certPEM), CACertPEM: string(s.ca.CertPEM)})
}

func (s *Server) handleRenew(w http.ResponseWriter, r *http.Request) {
	h := hostFrom(r.Context())
	var req protocol.RenewRequest
	if err := decodeJSON(r, &req); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	cert, certPEM, err := s.ca.SignAgentCSR([]byte(req.CSRPEM), h.ID, s.cfg.AgentCertValidity)
	if err != nil {
		http.Error(w, "invalid csr", http.StatusBadRequest)
		return
	}
	if err := s.db.UpdateHostCert(r.Context(), h.ID, cert.SerialNumber.String(), cert.NotAfter); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, protocol.EnrollResponse{AgentID: h.ID, CertPEM: string(certPEM), CACertPEM: string(s.ca.CertPEM)})
}

func (s *Server) handleHeartbeat(w http.ResponseWriter, r *http.Request) {
	h := hostFrom(r.Context())
	var hb protocol.Heartbeat
	if err := decodeJSON(r, &hb); err != nil {
		http.Error(w, "bad request", http.StatusBadRequest)
		return
	}
	name := hb.Hostname
	if name == "" {
		name = h.Hostname
	}
	if err := s.db.TouchHost(r.Context(), h.ID, name, hb.AgentVersion, hb.BootTime); err != nil {
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	resp := protocol.HeartbeatResponse{ServerTime: time.Now().UTC(), IntervalSeconds: int(s.cfg.HeartbeatInterval.Seconds())}
	resp.WatchServices, resp.TLSEndpoints = s.agentWatchConfig(r.Context(), h)
	w.Header().Set("X-Sentrix-Server", version.Version)
	writeJSON(w, http.StatusOK, resp)
}
