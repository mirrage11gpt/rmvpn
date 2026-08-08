package server

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/mirrage11gpt/rmvpn/internal/compliance"
	"github.com/mirrage11gpt/rmvpn/internal/enrollment"
	"github.com/mirrage11gpt/rmvpn/internal/policy"
	"github.com/mirrage11gpt/rmvpn/internal/store"
)

type Servers struct {
	store      *store.Store
	policy     *policy.Service
	enrollment *enrollment.Service
	compliance *compliance.Service
	internal   *http.Server
	claim      *http.Server
}

func New(s *store.Store, p *policy.Service, e *enrollment.Service, c *compliance.Service) *Servers {
	return &Servers{store: s, policy: p, enrollment: e, compliance: c}
}

func (s *Servers) StartInternal(address string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/auth", s.auth)
	mux.HandleFunc("POST /v1/authorize", s.authorize)
	mux.HandleFunc("GET /v1/status", s.status)
	mux.HandleFunc("GET /v1/compliance/rules", s.rules)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s.internal = &http.Server{Addr: address, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 30 * time.Second}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	go func() {
		if err := s.internal.Serve(listener); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("internal API stopped", "error", err)
		}
	}()
	return nil
}

func (s *Servers) StartEnrollment(address, certFile, keyFile string, onClaim func()) error {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /v1/enrollment/claim", func(w http.ResponseWriter, r *http.Request) {
		var request enrollment.ClaimRequest
		if err := decodeJSON(w, r, &request); err != nil {
			return
		}
		if err := s.enrollment.Claim(r.Context(), request); err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "node claimed; enrollment endpoint is closing"})
		go func() {
			time.Sleep(200 * time.Millisecond)
			if onClaim != nil {
				onClaim()
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			if s.claim != nil {
				_ = s.claim.Shutdown(ctx)
			}
		}()
	})
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	s.claim = &http.Server{Addr: address, Handler: securityHeaders(mux), ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout: 10 * time.Second, WriteTimeout: 10 * time.Second, IdleTimeout: 20 * time.Second}
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	go func() {
		if err := s.claim.ServeTLS(listener, certFile, keyFile); err != nil && !errors.Is(err, http.ErrServerClosed) {
			slog.Error("enrollment API stopped", "error", err)
		}
	}()
	return nil
}

func (s *Servers) Shutdown(ctx context.Context) error {
	var result error
	if s.internal != nil {
		result = s.internal.Shutdown(ctx)
	}
	if s.claim != nil {
		if err := s.claim.Shutdown(ctx); err != nil && result == nil {
			result = err
		}
	}
	return result
}

func (s *Servers) auth(w http.ResponseWriter, r *http.Request) {
	var request struct {
		Address string `json:"addr"`
		Auth    string `json:"auth"`
		TX      int64  `json:"tx"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	decision, err := s.policy.Authenticate(r.Context(), request.Auth)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authentication backend failed"})
		return
	}
	writeJSON(w, http.StatusOK, decision)
}

func (s *Servers) authorize(w http.ResponseWriter, r *http.Request) {
	var request struct {
		ID             string `json:"id"`
		UDP            bool   `json:"udp"`
		Address        string `json:"addr"`
		InitialPayload []byte `json:"initialPayload"`
	}
	if err := decodeJSON(w, r, &request); err != nil {
		return
	}
	if len(request.InitialPayload) > 64*1024 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "initial payload is too large"})
		return
	}
	ok, reason, err := s.policy.Authorize(r.Context(), request.ID, request.Address, request.InitialPayload)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "authorization backend failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": ok, "reason": reason})
}

func (s *Servers) status(w http.ResponseWriter, r *http.Request) {
	nodeID, _, _ := s.store.State(r.Context(), "node_id")
	e, found, err := s.store.Enrollment(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	alerts, err := s.store.ActiveAlerts(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	claimed := found && e.ClaimedAt != nil
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "nodeId": nodeID, "claimed": claimed, "alerts": alerts})
}

func (s *Servers) rules(w http.ResponseWriter, r *http.Request) {
	rules, version, found, err := s.compliance.CurrentRules(r.Context())
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	if !found {
		writeJSON(w, 404, map[string]string{"error": "compliance feed is unavailable"})
		return
	}
	writeJSON(w, 200, map[string]any{"version": version, "rules": rules})
}

func decodeJSON(w http.ResponseWriter, r *http.Request, destination any) error {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON: " + err.Error()})
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "request must contain one JSON object"})
		return errors.New("trailing JSON")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		next.ServeHTTP(w, r)
	})
}
