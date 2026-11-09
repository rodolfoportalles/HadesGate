package web

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"net/http"

	"github.com/hadesgate/hadesgate/internal/config"
)

type adminPrincipal struct {
	KeyID string
	Label string
	Role  config.AdminRole
}

type principalContextKey struct{}

func (s *Server) authenticateAdmin(r *http.Request) (adminPrincipal, bool) {
	key := requestAPIKey(r)
	if key == "" {
		return adminPrincipal{}, false
	}
	if s.adminKey != "" && len(key) == len(s.adminKey) && subtle.ConstantTimeCompare([]byte(key), []byte(s.adminKey)) == 1 {
		return adminPrincipal{KeyID: "bootstrap", Label: "BOOTSTRAP", Role: config.RoleAdmin}, true
	}
	if s.store != nil {
		credential, ok := s.store.AuthenticateAdminCredential(r.Context(), key)
		if ok {
			label := credential.Label
			if label == "" {
				label = credential.KeyID
			}
			return adminPrincipal{KeyID: credential.KeyID, Label: label, Role: credential.Role}, true
		}
	}
	return adminPrincipal{}, false
}

func principalFromRequest(r *http.Request) adminPrincipal {
	principal, _ := r.Context().Value(principalContextKey{}).(adminPrincipal)
	return principal
}

func (s *Server) requireRole(required config.AdminRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := s.authenticateAdmin(r)
		if !ok {
			writeAuthorizationError(w, http.StatusUnauthorized, "Administrative credential required")
			return
		}
		if principal.Role.Level() < required.Level() {
			writeAuthorizationError(w, http.StatusForbidden, "Insufficient administrative role")
			return
		}
		if limiter := s.adminLimiter.Load(); limiter != nil && !limiter.Allow() {
			w.Header().Set("Retry-After", "30")
			writeAuthorizationError(w, http.StatusTooManyRequests, "Administrative rate limit reached")
			return
		}
		ctx := context.WithValue(r.Context(), principalContextKey{}, principal)
		next(w, r.WithContext(ctx))
	}
}

func (s *Server) requireRoleByMethod(readRole, writeRole config.AdminRole, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		required := writeRole
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			required = readRole
		}
		s.requireRole(required, next)(w, r)
	}
}

func writeAuthorizationError(w http.ResponseWriter, status int, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"error": map[string]string{"message": message, "type": "auth_error"}})
}

func (s *Server) isAdminRequest(r *http.Request) bool {
	_, ok := s.authenticateAdmin(r)
	return ok
}
