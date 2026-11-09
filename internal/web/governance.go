package web

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"

	"github.com/hadesgate/hadesgate/internal/config"
	"github.com/hadesgate/hadesgate/internal/observability"
)

func (s *Server) auditChange(r *http.Request, action, targetType, targetID string, metadata map[string]interface{}) {
	if s.store == nil {
		return
	}
	principal := principalFromRequest(r)
	encoded, _ := json.Marshal(metadata)
	if err := s.store.RecordAuditEvent(r.Context(), config.AuditEvent{ActorKeyID: principal.KeyID, ActorRole: principal.Role, Action: action, TargetType: targetType, TargetID: targetID, Metadata: encoded}); err != nil {
		// The change itself succeeded; make the lost audit visible instead of
		// pretending the trail is complete.
		log.Printf("⚠️  [AUDIT] could not record %s on %s/%s: %v", action, targetType, targetID, err)
	}
}

func (s *Server) handleAdminCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.store == nil {
		http.Error(w, `{"error":{"message":"Config store not initialized"}}`, http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		credentials, err := s.store.ListAdminCredentials(r.Context())
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to list credentials"}}`, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(credentials)
	case http.MethodPost:
		var request struct {
			Label string           `json:"label"`
			Role  config.AdminRole `json:"role"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request); err != nil {
			http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
			return
		}
		credential, err := s.store.CreateAdminCredential(r.Context(), request.Label, request.Role)
		if err != nil {
			http.Error(w, `{"error":{"message":"Invalid credential request"}}`, http.StatusBadRequest)
			return
		}
		s.auditChange(r, "admin_credential.created", "admin_credential", credential.KeyID, map[string]interface{}{"role": credential.Role})
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(credential)
	case http.MethodPut:
		s.handleAdminCredentialRotate(w, r)
	case http.MethodDelete:
		keyID := strings.TrimSpace(r.URL.Query().Get("key_id"))
		if keyID == "" {
			http.Error(w, `{"error":{"message":"key_id is required"}}`, http.StatusBadRequest)
			return
		}
		if principalFromRequest(r).KeyID == keyID {
			http.Error(w, `{"error":{"message":"Cannot revoke the active credential"}}`, http.StatusConflict)
			return
		}
		if err := s.store.DeleteAdminCredential(r.Context(), keyID); err != nil {
			http.Error(w, `{"error":{"message":"Credential not found"}}`, http.StatusNotFound)
			return
		}
		s.auditChange(r, "admin_credential.revoked", "admin_credential", keyID, nil)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAdminCredentialRotate(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost && r.Method != http.MethodPut {
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}
	if s.store == nil {
		http.Error(w, `{"error":{"message":"Config store not initialized"}}`, http.StatusServiceUnavailable)
		return
	}

	// Strictly enforce that ONLY the root HADESGATE_ADMIN_KEY (bootstrap) can rotate!
	principal := principalFromRequest(r)
	if principal.KeyID != "bootstrap" {
		writeAuthorizationError(w, http.StatusForbidden, "Apenas a chave mestre HADESGATE_ADMIN_KEY pode rotacionar credenciais administrativas")
		return
	}

	var request struct {
		KeyID string `json:"key_id"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&request)
	}
	keyID := strings.TrimSpace(request.KeyID)
	if keyID == "" {
		keyID = strings.TrimSpace(r.URL.Query().Get("key_id"))
	}
	if keyID == "" {
		http.Error(w, `{"error":{"message":"key_id is required"}}`, http.StatusBadRequest)
		return
	}

	credential, err := s.store.RotateAdminCredential(r.Context(), keyID)
	if err != nil {
		http.Error(w, fmt.Sprintf(`{"error":{"message":%q}}`, err.Error()), http.StatusBadRequest)
		return
	}

	s.auditChange(r, "admin_credential.rotated", "admin_credential", credential.KeyID, map[string]interface{}{"role": credential.Role})
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(credential)
}

func (s *Server) handleRetention(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	traces := s.gateway.Traces()
	if traces == nil {
		http.Error(w, `{"error":{"message":"Telemetry store not initialized"}}`, http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		policies, err := traces.ListRetentionPolicies(r.Context())
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to list retention policies"}}`, http.StatusInternalServerError)
			return
		}
		_ = json.NewEncoder(w).Encode(policies)
	case http.MethodPut:
		var policy observability.RetentionPolicy
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<10)).Decode(&policy); err != nil {
			http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
			return
		}
		if err := traces.SetRetentionPolicy(r.Context(), policy); err != nil {
			http.Error(w, `{"error":{"message":"Invalid retention policy"}}`, http.StatusBadRequest)
			return
		}
		tenantID := strings.TrimSpace(policy.TenantID)
		if tenantID == "" {
			tenantID = "*"
		}
		s.auditChange(r, "retention.updated", "tenant", tenantID, map[string]interface{}{"retention_days": policy.RetentionDays, "max_rows": policy.MaxRows})
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	case http.MethodDelete:
		tenantID := strings.TrimSpace(r.URL.Query().Get("tenant_id"))
		if tenantID == "" {
			tenantID = "*"
		}
		if err := traces.DeleteRetentionPolicy(r.Context(), tenantID); err != nil {
			http.Error(w, `{"error":{"message":"Failed to delete retention policy"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "retention.deleted", "tenant", tenantID, nil)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAuditEvents(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	events, err := s.store.ListAuditEvents(r.Context(), limit)
	if err != nil {
		http.Error(w, `{"error":{"message":"Failed to export audit events"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.URL.Query().Get("download") == "1" {
		w.Header().Set("Content-Disposition", `attachment; filename="hadesgate-audit.json"`)
	}
	_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": 2, "events": events})
}

func (s *Server) handleAuditVerify(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}
	report, err := s.store.VerifyAuditChain(r.Context())
	if err != nil {
		http.Error(w, `{"error":{"message":"Failed to verify the audit chain"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(report)
}

func (s *Server) handleConfigBackup(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.store == nil {
		http.Error(w, `{"error":{"message":"Config store not initialized"}}`, http.StatusServiceUnavailable)
		return
	}
	switch r.Method {
	case http.MethodGet:
		backup, err := s.store.ExportEncryptedBackup(r.Context())
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to create backup"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "config_backup.exported", "configuration", "global", nil)
		w.Header().Set("Content-Disposition", `attachment; filename="hadesgate-config-backup.json"`)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"version": 1, "backup": backup})
	case http.MethodPost:
		var request struct {
			Backup string `json:"backup"`
		}
		if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 8<<20)).Decode(&request); err != nil {
			http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
			return
		}
		if err := s.store.RestoreEncryptedBackup(r.Context(), request.Backup); err != nil {
			http.Error(w, `{"error":{"message":"Invalid or incompatible backup"}}`, http.StatusBadRequest)
			return
		}
		if err := s.reloadGateway(r.Context()); err != nil {
			http.Error(w, `{"error":{"message":"Backup restored but runtime reload failed"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "config_backup.restored", "configuration", "global", nil)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})
	default:
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
	}
}
