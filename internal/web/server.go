package web

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/url"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hadesgate/hadesgate/internal/anonymizer"
	"github.com/hadesgate/hadesgate/internal/anonymizer/detector"
	"github.com/hadesgate/hadesgate/internal/config"
	"github.com/hadesgate/hadesgate/internal/observability"
	"github.com/hadesgate/hadesgate/internal/policy"
	"github.com/hadesgate/hadesgate/internal/proxy"
	"github.com/hadesgate/hadesgate/internal/webhook"
)

var startTime = time.Now()

// Server serves the web dashboard and internal management APIs.
type Server struct {
	engine                    *anonymizer.Engine
	gateway                   *proxy.Gateway
	adminKey                  string
	providerFingerprintSecret string
	defaultRateLimit          int
	fs                        fs.FS
	store                     *config.Store
	webhook                   *webhook.Dispatcher
	upstream                  *proxy.UpstreamDispatcher
	securityPolicy            *SecurityPolicy
	adminLimiter              atomic.Pointer[proxy.RateLimiter]
}

// NewServer creates a new web Server.
func NewServer(engine *anonymizer.Engine, gateway *proxy.Gateway, adminKey string, staticFS fs.FS) *Server {
	s := &Server{
		engine:   engine,
		gateway:  gateway,
		adminKey: adminKey,
		fs:       staticFS,
	}
	s.adminLimiter.Store(proxy.NewRateLimiter(defaultAdminRateLimit))
	return s
}

// defaultAdminRateLimit bounds the administrative API per minute: enough for
// the dashboard polling and for a person clicking, low enough that a runaway
// extension loop cannot stack 2 MB anonymization scans.
const defaultAdminRateLimit = 120

// SetAdminRateLimit replaces the administrative limiter at boot.
func (s *Server) SetAdminRateLimit(eventsPerMinute int) {
	s.adminLimiter.Store(proxy.NewRateLimiter(eventsPerMinute))
}

// SetStore binds the dynamic configuration store to the server.
func (s *Server) SetStore(store *config.Store) {
	s.store = store
}

// SetWebhook binds the webhook alert dispatcher to the server.
func (s *Server) SetWebhook(wh *webhook.Dispatcher) {
	s.webhook = wh
}

// SetUpstream binds the upstream dispatcher to the server for dynamic routing updates.
func (s *Server) SetUpstream(u *proxy.UpstreamDispatcher) {
	s.upstream = u
}

// SetProviderFingerprintSecret enables transparent BYOK authentication using
// HMAC fingerprints. The secret remains process-local and is never persisted.
func (s *Server) SetProviderFingerprintSecret(secret string) {
	s.providerFingerprintSecret = strings.TrimSpace(secret)
}

// SetDefaultRateLimit preserves the boot-level global limiter across dynamic reloads.
func (s *Server) SetDefaultRateLimit(limit int) {
	s.defaultRateLimit = limit
}

// SetSecurityPolicy enables atomic hot reload of CORS origins and HTTP security policy.
func (s *Server) SetSecurityPolicy(policy *SecurityPolicy) {
	s.securityPolicy = policy
}

func requestAPIKey(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); authHeader != "" {
		return strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	}
	if key := strings.TrimSpace(r.Header.Get("X-API-Key")); key != "" {
		return key
	}
	return ""
}

// RegisterRoutes registers dashboard and management API endpoints on the given multiplexer.
func (s *Server) RegisterRoutes(mux *http.ServeMux) {
	// Public / Status & Metrics endpoints
	mux.HandleFunc("/api/status", s.handleStatus)
	mux.HandleFunc("/api/auth/verify", s.handleAuthVerify)
	mux.HandleFunc("/metrics", s.handleMetrics)
	mux.HandleFunc("/api/metrics", s.handleMetrics)

	// Protected management API endpoints (enforces API key)
	mux.HandleFunc("/api/test-anonymize", s.requireRole(config.RoleOperator, s.handleTestAnonymize))
	mux.HandleFunc("/api/playground/", s.requireRole(config.RoleOperator, s.handlePlaygroundProxy))
	mux.HandleFunc("/api/vault", s.requireRole(config.RoleViewer, s.handleVault))
	mux.HandleFunc("/api/traces", s.requireRoleByMethod(config.RoleViewer, config.RoleOperator, s.handleTraces))
	mux.HandleFunc("/api/config", s.requireRoleByMethod(config.RoleViewer, config.RoleOperator, s.handleConfig))
	mux.HandleFunc("/api/tenants", s.requireRoleByMethod(config.RoleViewer, config.RoleOperator, s.handleTenants))
	mux.HandleFunc("/api/provider-credentials", s.requireRoleByMethod(config.RoleViewer, config.RoleOperator, s.handleProviderCredentials))
	mux.HandleFunc("/api/webhooks/test", s.requireRole(config.RoleOperator, s.handleWebhookTest))
	mux.HandleFunc("/api/anvisa/status", s.requireRole(config.RoleViewer, s.handleAnvisaStatus))
	mux.HandleFunc("/api/anvisa/sync", s.requireRole(config.RoleOperator, s.handleAnvisaSync))
	mux.HandleFunc("/api/admin-credentials", s.requireRole(config.RoleAdmin, s.handleAdminCredentials))
	mux.HandleFunc("/api/admin-credentials/rotate", s.requireRole(config.RoleAdmin, s.handleAdminCredentialRotate))
	mux.HandleFunc("/api/retention", s.requireRoleByMethod(config.RoleViewer, config.RoleOperator, s.handleRetention))
	mux.HandleFunc("/api/audit/events", s.requireRole(config.RoleViewer, s.handleAuditEvents))
	mux.HandleFunc("/api/config-backup", s.requireRole(config.RoleAdmin, s.handleConfigBackup))

	// Static frontend assets handler
	if s.fs != nil {
		fileServer := http.FileServer(http.FS(s.fs))
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			// Don't intercept API, Proxy, Multi-tenant, or Metrics routes
			if strings.HasPrefix(r.URL.Path, "/v1") || strings.HasPrefix(r.URL.Path, "/api") ||
				strings.HasPrefix(r.URL.Path, "/gemini") || strings.HasPrefix(r.URL.Path, "/anthropic") ||
				strings.HasPrefix(r.URL.Path, "/t/") || strings.HasPrefix(r.URL.Path, "/p/") ||
				strings.HasPrefix(r.URL.Path, "/g/") ||
				r.URL.Path == "/metrics" {
				http.NotFound(w, r)
				return
			}
			fileServer.ServeHTTP(w, r)
		})
	}
}

func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	metrics := s.gateway.Metrics()
	activeSessions := s.engine.Vault().ActiveSessionsCount()
	uptime := int64(time.Since(startTime).Seconds())

	var b strings.Builder
	b.WriteString("# HELP hadesgate_requests_total Total number of HTTP requests processed.\n")
	b.WriteString("# TYPE hadesgate_requests_total counter\n")
	fmt.Fprintf(&b, "hadesgate_requests_total %d\n\n", metrics.TotalRequests)

	b.WriteString("# HELP hadesgate_streaming_requests_total Total number of streaming requests.\n")
	b.WriteString("# TYPE hadesgate_streaming_requests_total counter\n")
	fmt.Fprintf(&b, "hadesgate_streaming_requests_total %d\n\n", metrics.StreamRequests)

	b.WriteString("# HELP hadesgate_entities_masked_total Total sensitive entities masked.\n")
	b.WriteString("# TYPE hadesgate_entities_masked_total counter\n")
	fmt.Fprintf(&b, "hadesgate_entities_masked_total %d\n\n", metrics.EntitiesMasked)

	b.WriteString("# HELP hadesgate_active_streams Current active SSE streaming connections.\n")
	b.WriteString("# TYPE hadesgate_active_streams gauge\n")
	fmt.Fprintf(&b, "hadesgate_active_streams %d\n\n", metrics.ActiveStreams)

	b.WriteString("# HELP hadesgate_active_vault_sessions Current active temporary sessions in memory vault.\n")
	b.WriteString("# TYPE hadesgate_active_vault_sessions gauge\n")
	fmt.Fprintf(&b, "hadesgate_active_vault_sessions %d\n\n", activeSessions)

	b.WriteString("# HELP hadesgate_uptime_seconds Total seconds since gateway started.\n")
	b.WriteString("# TYPE hadesgate_uptime_seconds counter\n")
	fmt.Fprintf(&b, "hadesgate_uptime_seconds %d\n\n", uptime)

	b.WriteString("# HELP hadesgate_memory_alloc_bytes Current allocated heap memory in bytes.\n")
	b.WriteString("# TYPE hadesgate_memory_alloc_bytes gauge\n")
	fmt.Fprintf(&b, "hadesgate_memory_alloc_bytes %d\n\n", m.Alloc)

	b.WriteString("# HELP hadesgate_goroutines Current number of running goroutines.\n")
	b.WriteString("# TYPE hadesgate_goroutines gauge\n")
	fmt.Fprintf(&b, "hadesgate_goroutines %d\n\n", runtime.NumGoroutine())

	if s.gateway.Traces() != nil {
		summary := s.gateway.Traces().GetSummary()
		b.WriteString("# HELP hadesgate_blocked_requests_total Total requests blocked by policy.\n")
		b.WriteString("# TYPE hadesgate_blocked_requests_total counter\n")
		fmt.Fprintf(&b, "hadesgate_blocked_requests_total %d\n\n", summary.BlockedRequests)

		if len(summary.EntityTypeCounts) > 0 {
			b.WriteString("# HELP hadesgate_entity_detections_total Detections grouped by entity type.\n")
			b.WriteString("# TYPE hadesgate_entity_detections_total counter\n")
			for eType, cnt := range summary.EntityTypeCounts {
				fmt.Fprintf(&b, "hadesgate_entity_detections_total{type=%q} %d\n", eType, cnt)
			}
			b.WriteString("\n")
		}
	}

	w.WriteHeader(http.StatusOK)
	w.Write([]byte(b.String()))
}

type StatusResponse struct {
	Status         string               `json:"status"`
	Version        string               `json:"version"`
	UptimeSeconds  int64                `json:"uptime_seconds"`
	MemoryAllocMB  float64              `json:"memory_alloc_mb"`
	Goroutines     int                  `json:"goroutines"`
	ActiveSessions int                  `json:"active_sessions"`
	Metrics        proxy.MetricsTracker `json:"metrics"`
	AuthRequired   bool                 `json:"auth_required"`
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	isAuth := s.isAdminRequest(r)

	// Unauthenticated callers get a basic status ping without operational metrics
	if !isAuth {
		json.NewEncoder(w).Encode(map[string]interface{}{
			"status":         "online",
			"version":        "1.3.0",
			"uptime_seconds": int64(time.Since(startTime).Seconds()),
			"auth_required":  true,
		})
		return
	}

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	resp := StatusResponse{
		Status:         "online",
		Version:        "1.3.0",
		UptimeSeconds:  int64(time.Since(startTime).Seconds()),
		MemoryAllocMB:  float64(m.Alloc) / 1024 / 1024,
		Goroutines:     runtime.NumGoroutine(),
		ActiveSessions: s.engine.Vault().ActiveSessionsCount(),
		Metrics:        s.gateway.Metrics(),
		AuthRequired:   true,
	}

	json.NewEncoder(w).Encode(resp)
}

type TestAnonymizeRequest struct {
	Prompt      string `json:"prompt"`
	RecordTrace bool   `json:"record_trace,omitempty"`
	Provider    string `json:"provider,omitempty"`
	Model       string `json:"model,omitempty"`
	Tenant      string `json:"tenant,omitempty"`
}

type TestAnonymizeResponse struct {
	Original      string                      `json:"original"`
	Sanitized     string                      `json:"sanitized"`
	Entities      []anonymizer.DetectedEntity `json:"entities"`
	TokenMap      map[string]string           `json:"token_map"`
	LatencyMicros int64                       `json:"latency_micros"`
}

func (s *Server) handleTestAnonymize(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Limit request body to 2MB to prevent memory exhaustion DoS
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20)

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "Failed to read body or body exceeds 2MB limit", http.StatusBadRequest)
		return
	}

	var req TestAnonymizeRequest
	if err := json.Unmarshal(body, &req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	start := time.Now()
	var randBytes [8]byte
	_, _ = rand.Read(randBytes[:])
	testSessionID := fmt.Sprintf("ext_%d_%s", time.Now().UnixNano(), hex.EncodeToString(randBytes[:]))
	tenant := strings.TrimSpace(req.Tenant)
	if tenant == "" {
		tenant = strings.TrimSpace(r.Header.Get("X-HadesGate-Tenant"))
	}
	if tenant == "" {
		tenant = "default"
	}
	principal := principalFromRequest(r)
	tenantName := s.resolveTenantName(tenant)

	var tenantPolicy *policy.Engine
	if s.gateway != nil {
		tenantPolicy = s.gateway.PolicyForTenant(tenant)
	}
	res := s.engine.AnonymizeWithOptions(testSessionID, req.Prompt, anonymizer.AnonymizeOptions{
		IsTypeDisabled: func(entityType detector.EntityType) bool {
			return tenantPolicy != nil && tenantPolicy.IsDisabled(string(entityType))
		},
	})
	s.engine.Vault().DeleteSession(testSessionID)
	elapsed := (time.Since(start).Nanoseconds() + 500) / 1000
	if elapsed == 0 && len(req.Prompt) > 0 {
		elapsed = 1
	}

	provider := strings.ToLower(strings.TrimSpace(req.Provider))
	if provider == "" {
		provider = "extension"
	}
	model := strings.TrimSpace(req.Model)
	if model == "" {
		model = "browser-shield"
	}

	detectedTypes, piiTypes, secretTypes := observability.ClassifyEntities(res.Entities)

	var decision policy.Decision
	if s.gateway != nil {
		decision = s.gateway.PolicyForTenant(tenant).Decide(detectedTypes)
	} else {
		decision = policy.Decision{Action: policy.Mask}
	}

	w.Header().Set("X-HadesGate-Policy-Action", string(decision.Action))

	if decision.Action == policy.Block {
		if s.webhook != nil {
			s.webhook.Dispatch(webhook.Event{
				Event:           "block",
				RequestID:       testSessionID,
				TenantID:        tenant,
				Action:          "block",
				BlockedEntities: decision.Types,
				Model:           model,
				ClientIP:        r.RemoteAddr,
				Details:         "Extension prompt blocked by entity DLP policy",
			})
		}

		if req.RecordTrace && s.gateway != nil && s.gateway.Traces() != nil && strings.TrimSpace(req.Prompt) != "" {
			s.gateway.Traces().Record(observability.Trace{
				ID:              testSessionID,
				Tenant:          tenant,
				TenantName:      tenantName,
				UserLabel:       principal.Label,
				UserRole:        string(principal.Role),
				PolicyAction:    "block",
				Timestamp:       start,
				Provider:        provider,
				Model:           model,
				Language:        observability.DetectLanguage(req.Prompt),
				Stream:          false,
				StatusCode:      http.StatusForbidden,
				DurationMs:      float64(elapsed) / 1000.0,
				AnonDurationUs:  elapsed,
				EntitiesCount:   len(res.Entities),
				EntityTypes:     detectedTypes,
				PIITypes:        piiTypes,
				SecretTypes:     secretTypes,
				SanitizedPrompt: telemetryPrompt(tenantPolicy, res.SanitizedText),
			})
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"error":            "sensitive_data_blocked",
			"message":          "Prompt contains sensitive data blocked by DLP policy",
			"blocked":          true,
			"blocked_entities": decision.Types,
		})
		return
	}

	if req.RecordTrace && s.gateway != nil && s.gateway.Traces() != nil && strings.TrimSpace(req.Prompt) != "" {
		s.gateway.Traces().Record(observability.Trace{
			ID:              testSessionID,
			Tenant:          tenant,
			TenantName:      tenantName,
			UserLabel:       principal.Label,
			UserRole:        string(principal.Role),
			PolicyAction:    string(decision.Action),
			Timestamp:       start,
			Provider:        provider,
			Model:           model,
			Language:        observability.DetectLanguage(req.Prompt),
			Stream:          false,
			StatusCode:      http.StatusOK,
			DurationMs:      float64(elapsed) / 1000.0,
			AnonDurationUs:  elapsed,
			EntitiesCount:   len(res.Entities),
			EntityTypes:     detectedTypes,
			PIITypes:        piiTypes,
			SecretTypes:     secretTypes,
			SanitizedPrompt: telemetryPrompt(tenantPolicy, res.SanitizedText),
		})
	}

	resp := TestAnonymizeResponse{
		Original:      req.Prompt,
		Sanitized:     res.SanitizedText,
		Entities:      res.Entities,
		TokenMap:      res.TokenMap,
		LatencyMicros: elapsed,
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handlePlaygroundProxy(w http.ResponseWriter, r *http.Request) {
	if s.gateway == nil {
		http.Error(w, `{"error":{"message":"Gateway not initialized","type":"server_error"}}`, http.StatusServiceUnavailable)
		return
	}
	subPath := strings.TrimPrefix(r.URL.Path, "/api/playground")
	if !strings.HasPrefix(subPath, "/") {
		subPath = "/" + subPath
	}
	tenant := strings.TrimSpace(r.Header.Get("X-HadesGate-Tenant"))
	if tenant == "" {
		tenant = "default"
	}
	principal := principalFromRequest(r)
	ctx := proxy.ContextWithUser(r.Context(), principal.Label, string(principal.Role))
	s.gateway.DispatchPreAuthenticated(w, r.WithContext(ctx), tenant, subPath)
}

func (s *Server) resolveTenantName(tenant string) string {
	if s.gateway != nil {
		return s.gateway.ResolveTenantName(tenant)
	}
	tenant = strings.TrimSpace(tenant)
	if tenant == "" || tenant == "default" || tenant == "*" {
		return "GLOBAL"
	}
	return tenant
}

func telemetryPrompt(tenantPolicy *policy.Engine, sanitizedPrompt string) string {
	if tenantPolicy != nil && tenantPolicy.HasDisabledActions() {
		return ""
	}
	return sanitizedPrompt
}

func (s *Server) handleVault(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	resp := map[string]interface{}{
		"active_sessions": s.engine.Vault().ActiveSessionsCount(),
	}
	json.NewEncoder(w).Encode(resp)
}

func (s *Server) handleTraces(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	requestedTenant := strings.TrimSpace(r.URL.Query().Get("tenant_id"))

	if r.Method == http.MethodDelete {
		if s.gateway.Traces() != nil {
			if requestedTenant == "" {
				s.gateway.Traces().Clear()
			} else if err := s.gateway.Traces().ClearTenant(requestedTenant); err != nil {
				http.Error(w, `{"error":{"message":"failed to clear tenant traces"}}`, http.StatusInternalServerError)
				return
			}
		}
		s.auditChange(r, "telemetry.cleared", "tenant", requestedTenant, nil)
		json.NewEncoder(w).Encode(map[string]string{"message": "Traces cleared successfully"})
		return
	}

	var tracesList interface{} = []interface{}{}
	var summary interface{} = map[string]interface{}{}
	total := 0
	page := 1
	limit := 10

	query := r.URL.Query()
	if pStr := query.Get("page"); pStr != "" {
		if pVal, err := strconv.Atoi(pStr); err == nil && pVal >= 1 {
			page = pVal
		}
	}
	if lStr := query.Get("limit"); lStr != "" {
		if lVal, err := strconv.Atoi(lStr); err == nil && lVal >= 1 {
			limit = lVal
		}
	}

	if s.gateway.Traces() != nil {
		offset := (page - 1) * limit
		if offset < 0 {
			offset = 0
		}
		var pagedTraces []observability.Trace
		var totalCount int
		if requestedTenant == "" {
			pagedTraces, totalCount = s.gateway.Traces().GetPaged(limit, offset)
			summary = s.gateway.Traces().GetSummary()
		} else {
			pagedTraces, totalCount = s.gateway.Traces().GetPagedForTenant(requestedTenant, limit, offset)
			summary = s.gateway.Traces().GetSummaryForTenant(requestedTenant)
		}
		for i := range pagedTraces {
			if pagedTraces[i].TenantName == "" {
				pagedTraces[i].TenantName = s.resolveTenantName(pagedTraces[i].Tenant)
			}
		}
		tracesList = pagedTraces
		total = totalCount
	}

	resp := map[string]interface{}{
		"traces":  tracesList,
		"summary": summary,
		"pagination": map[string]interface{}{
			"page":        page,
			"limit":       limit,
			"total":       total,
			"total_pages": (total + limit - 1) / limit,
		},
	}
	json.NewEncoder(w).Encode(resp)
}

type AuthVerifyRequest struct {
	Key string `json:"key"`
}

type AuthVerifyResponse struct {
	Valid   bool             `json:"valid"`
	DevMode bool             `json:"dev_mode"`
	KeyID   string           `json:"key_id,omitempty"`
	Role    config.AdminRole `json:"role,omitempty"`
}

func (s *Server) handleAuthVerify(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	if r.Method != http.MethodPost {
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}

	// Protect against resource exhaustion / DoS
	r.Body = http.MaxBytesReader(w, r.Body, 16<<10) // 16KB limit

	var req AuthVerifyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(AuthVerifyResponse{Valid: false, DevMode: false})
		return
	}

	reqKey := strings.TrimSpace(req.Key)
	if reqKey == "" || (s.adminKey == "" && s.gateway == nil) {
		json.NewEncoder(w).Encode(AuthVerifyResponse{
			Valid:   false,
			DevMode: false,
		})
		return
	}

	verifyRequest := r.Clone(r.Context())
	verifyRequest.Header.Set("Authorization", "Bearer "+reqKey)
	principal, isValid := s.authenticateAdmin(verifyRequest)
	json.NewEncoder(w).Encode(AuthVerifyResponse{
		Valid:   isValid,
		DevMode: false,
		KeyID:   principal.KeyID,
		Role:    principal.Role,
	})
}

func (s *Server) reloadGateway(ctx context.Context) error {
	if s.store == nil || s.gateway == nil {
		return nil
	}
	dynCfg, err := s.store.GetDynamicConfig(ctx)
	if err != nil {
		return err
	}
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return err
	}

	tenantKeys := make(map[string]string, len(tenants))
	tenantPolicies := make(map[string]map[string]string, len(tenants))
	tenantRateLimits := make(map[string]int, len(tenants))
	tenantNames := make(map[string]string, len(tenants)*2)

	for _, t := range tenants {
		name := strings.TrimSpace(t.Name)
		if name == "" {
			name = t.ID
		}
		tenantNames[t.ID] = name
		slug := strings.ToLower(strings.TrimSpace(t.Name))
		if slug != "" {
			tenantNames[slug] = name
		}

		tenantKeys[t.ID] = t.ProxyKey
		tenantRateLimits[t.ID] = t.RateLimit

		// Inherit global actions and merge tenant overrides
		combinedActions := make(map[string]string, len(dynCfg.EntityActions)+len(t.EntityActions))
		for k, v := range dynCfg.EntityActions {
			combinedActions[k] = v
		}
		for k, v := range t.EntityActions {
			action := strings.TrimSpace(v)
			if action != "" && action != "inherit" {
				combinedActions[k] = action
			}
		}
		tenantPolicies[t.ID] = combinedActions

		// Also register slug/name mapping if non-empty
		if slug != "" && slug != strings.ToLower(t.ID) {
			tenantKeys[slug] = t.ProxyKey
			tenantRateLimits[slug] = t.RateLimit
			tenantPolicies[slug] = combinedActions
		}
	}

	s.gateway.UpdateDynamicConfig(dynCfg.EntityActions, tenantKeys, tenantPolicies, tenantRateLimits, s.defaultRateLimit, dynCfg.GlobalProxyKey)
	s.gateway.SetTenantNames(tenantNames)
	s.gateway.UpdateThresholds(dynCfg.FamilyThresholds, dynCfg.EntityThresholds)

	if s.upstream != nil {
		s.upstream.SetEnableEgressScan(dynCfg.EnableEgressScan)
		if dynCfg.OllamaBaseURL != "" {
			s.upstream.SetOllamaBaseURL(dynCfg.OllamaBaseURL)
		}
	}

	if s.webhook != nil {
		evts := make(map[string]bool, len(dynCfg.WebhookEvents))
		for _, e := range dynCfg.WebhookEvents {
			evts[e] = true
		}
		s.webhook.UpdateConfig(webhook.Config{
			URL:    dynCfg.WebhookURL,
			Secret: dynCfg.WebhookSecret,
			Events: evts,
		})
	}
	if s.securityPolicy != nil {
		s.securityPolicy.UpdateAllowedOrigins(dynCfg.CORSAllowedOrigins)
	}

	fingerprints, err := s.store.ProviderKeyFingerprints(ctx)
	if err != nil {
		return err
	}
	s.gateway.UpdateProviderKeyFingerprints(s.providerFingerprintSecret, fingerprints)

	return nil
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.store == nil {
		http.Error(w, `{"error":{"message":"Config store not initialized"}}`, http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		cfg, err := s.store.GetDynamicConfig(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}
		globalConfigured := cfg.GlobalProxyKey != ""
		if !globalConfigured && s.gateway != nil {
			globalConfigured = s.gateway.GlobalProxyKey() != ""
		}
		json.NewEncoder(w).Encode(publicDynamicConfig(cfg, globalConfigured))

	case http.MethodPut:
		var newCfg config.DynamicConfig
		if err := json.NewDecoder(r.Body).Decode(&newCfg); err != nil {
			http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
			return
		}

		cleanWebhookURL := strings.TrimSpace(newCfg.WebhookURL)
		if cleanWebhookURL != "" && cleanWebhookURL != "__CLEAR__" {
			u, err := url.Parse(cleanWebhookURL)
			if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
				http.Error(w, `{"error":{"message":"Endpoint URL do Webhook inválida. Deve iniciar com http:// ou https://"}}`, http.StatusBadRequest)
				return
			}
		}

		if err := s.store.SaveDynamicConfig(r.Context(), newCfg); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}

		if err := s.reloadGateway(r.Context()); err != nil {
			http.Error(w, `{"error":{"message":"Configuration saved but runtime reload failed"}}`, http.StatusInternalServerError)
			return
		}
		effectiveCfg, err := s.store.GetDynamicConfig(r.Context())
		if err != nil {
			http.Error(w, `{"error":{"message":"Configuration saved but could not be reloaded"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "configuration.updated", "configuration", "global", map[string]interface{}{"entity_action_count": len(effectiveCfg.EntityActions), "egress_scan": effectiveCfg.EnableEgressScan})
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     true,
			"config": publicDynamicConfig(effectiveCfg, effectiveCfg.GlobalProxyKey != ""),
		})

	default:
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
	}
}

type dynamicConfigResponse struct {
	EntityActions            map[string]string  `json:"entity_actions"`
	GlobalProxyKey           string             `json:"global_proxy_key"`
	GlobalProxyKeyConfigured bool               `json:"global_proxy_key_configured"`
	WebhookURL               string             `json:"webhook_url"`
	WebhookURLConfigured     bool               `json:"webhook_url_configured"`
	WebhookURLPreview        string             `json:"webhook_url_preview,omitempty"`
	WebhookSecret            string             `json:"webhook_secret"`
	WebhookSecretConfigured  bool               `json:"webhook_secret_configured"`
	WebhookEvents            []string           `json:"webhook_events"`
	EnableEgressScan         bool               `json:"enable_egress_scan"`
	OllamaBaseURL            string             `json:"ollama_base_url"`
	CORSAllowedOrigins       []string           `json:"cors_allowed_origins"`
	FamilyThresholds         map[string]float64 `json:"family_thresholds,omitempty"`
	EntityThresholds         map[string]float64 `json:"entity_thresholds,omitempty"`
}

func webhookPreview(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return "[INVÁLIDO: " + raw + "]"
	}
	return u.Scheme + "://" + u.Host + "/*"
}

func publicDynamicConfig(cfg config.DynamicConfig, globalConfigured bool) dynamicConfigResponse {
	return dynamicConfigResponse{
		EntityActions:            cfg.EntityActions,
		GlobalProxyKey:           "",
		GlobalProxyKeyConfigured: globalConfigured,
		WebhookURL:               "",
		WebhookURLConfigured:     cfg.WebhookURL != "",
		WebhookURLPreview:        webhookPreview(cfg.WebhookURL),
		WebhookSecret:            "",
		WebhookSecretConfigured:  cfg.WebhookSecret != "",
		WebhookEvents:            cfg.WebhookEvents,
		EnableEgressScan:         cfg.EnableEgressScan,
		OllamaBaseURL:            cfg.OllamaBaseURL,
		CORSAllowedOrigins:       cfg.CORSAllowedOrigins,
		FamilyThresholds:         cfg.FamilyThresholds,
		EntityThresholds:         cfg.EntityThresholds,
	}
}

type tenantConfigResponse struct {
	ID                 string            `json:"id"`
	Name               string            `json:"name"`
	ProxyKey           string            `json:"proxy_key"`
	ProxyKeyConfigured bool              `json:"proxy_key_configured"`
	RateLimit          int               `json:"rate_limit"`
	EntityActions      map[string]string `json:"entity_actions"`
	UpdatedAt          time.Time         `json:"updated_at"`
}

func publicTenant(tenant config.TenantConfig) tenantConfigResponse {
	return tenantConfigResponse{
		ID:                 tenant.ID,
		Name:               tenant.Name,
		ProxyKey:           "",
		ProxyKeyConfigured: tenant.ProxyKey != "",
		RateLimit:          tenant.RateLimit,
		EntityActions:      tenant.EntityActions,
		UpdatedAt:          tenant.UpdatedAt,
	}
}

func publicTenants(tenants []config.TenantConfig) []tenantConfigResponse {
	result := make([]tenantConfigResponse, 0, len(tenants))
	for _, tenant := range tenants {
		result = append(result, publicTenant(tenant))
	}
	return result
}

func (s *Server) handleTenants(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.store == nil {
		http.Error(w, `{"error":{"message":"Config store not initialized"}}`, http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		tenants, err := s.store.ListTenants(r.Context())
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}
		if tenants == nil {
			tenants = []config.TenantConfig{}
		}
		json.NewEncoder(w).Encode(publicTenants(tenants))

	case http.MethodPost:
		var tenant config.TenantConfig
		if err := json.NewDecoder(r.Body).Decode(&tenant); err != nil {
			http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
			return
		}
		tenant.ID = strings.TrimSpace(tenant.ID)
		tenant.Name = strings.TrimSpace(tenant.Name)
		tenant.ProxyKey = strings.TrimSpace(tenant.ProxyKey)
		if tenant.Name == "" && tenant.ID == "" {
			http.Error(w, `{"error":{"message":"Tenant name is required"}}`, http.StatusBadRequest)
			return
		}
		savedTenant, err := s.store.SaveTenant(r.Context(), tenant)
		if err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}

		if err := s.reloadGateway(r.Context()); err != nil {
			http.Error(w, `{"error":{"message":"Tenant saved but runtime reload failed"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "tenant.created", "tenant", savedTenant.ID, map[string]interface{}{"rate_limit": savedTenant.RateLimit, "policy_count": len(savedTenant.EntityActions)})
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     true,
			"tenant": publicTenant(savedTenant),
		})

	case http.MethodPut:
		var payload struct {
			config.TenantConfig
			OriginalID string `json:"original_id"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
			return
		}
		origID := strings.TrimSpace(payload.OriginalID)
		if origID == "" {
			origID = payload.ID
		}
		if err := s.store.UpdateTenant(r.Context(), origID, payload.TenantConfig); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}

		if err := s.reloadGateway(r.Context()); err != nil {
			http.Error(w, `{"error":{"message":"Tenant saved but runtime reload failed"}}`, http.StatusInternalServerError)
			return
		}
		tenants, err := s.store.ListTenants(r.Context())
		if err != nil {
			http.Error(w, `{"error":{"message":"Tenant saved but could not be reloaded"}}`, http.StatusInternalServerError)
			return
		}
		var updated config.TenantConfig
		for _, tenant := range tenants {
			if tenant.ID == payload.ID {
				updated = tenant
				break
			}
		}
		s.auditChange(r, "tenant.updated", "tenant", payload.ID, map[string]interface{}{"original_id": origID, "rate_limit": payload.RateLimit, "policy_count": len(payload.EntityActions)})
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     true,
			"tenant": publicTenant(updated),
		})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, `{"error":{"message":"Tenant ID is required in query parameter ?id="}}`, http.StatusBadRequest)
			return
		}

		if err := s.store.DeleteTenant(r.Context(), id); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":{"message":%q}}`, err.Error()), http.StatusInternalServerError)
			return
		}

		if err := s.reloadGateway(r.Context()); err != nil {
			http.Error(w, `{"error":{"message":"Tenant deleted but runtime reload failed"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "tenant.deleted", "tenant", id, nil)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok": true,
		})

	default:
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
	}
}

type providerCredentialRequest struct {
	TenantID    string `json:"tenant_id"`
	Provider    string `json:"provider"`
	Label       string `json:"label"`
	ProviderKey string `json:"provider_key"`
}

func (s *Server) handleProviderCredentials(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if s.store == nil || s.gateway == nil {
		http.Error(w, `{"error":{"message":"Credential store not initialized"}}`, http.StatusServiceUnavailable)
		return
	}
	if s.providerFingerprintSecret == "" {
		http.Error(w, `{"error":{"message":"HADESGATE_FINGERPRINT_SECRET is required"}}`, http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		credentials, err := s.store.ListProviderCredentials(r.Context(), r.URL.Query().Get("tenant_id"))
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to list provider credentials"}}`, http.StatusInternalServerError)
			return
		}
		if credentials == nil {
			credentials = []config.ProviderCredential{}
		}
		_ = json.NewEncoder(w).Encode(credentials)

	case http.MethodPost:
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		var request providerCredentialRequest
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
			return
		}
		request.TenantID = strings.TrimSpace(request.TenantID)
		request.Provider = strings.ToLower(strings.TrimSpace(request.Provider))
		request.Label = strings.TrimSpace(request.Label)
		request.ProviderKey = strings.TrimSpace(request.ProviderKey)
		if request.TenantID == "" || request.ProviderKey == "" {
			http.Error(w, `{"error":{"message":"tenant_id and provider_key are required"}}`, http.StatusBadRequest)
			return
		}
		fingerprint, err := proxy.ProviderKeyFingerprint(s.providerFingerprintSecret, request.ProviderKey)
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to fingerprint provider key"}}`, http.StatusBadRequest)
			return
		}
		credentialID, err := newOpaqueID("pcred_")
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to create credential ID"}}`, http.StatusInternalServerError)
			return
		}
		credential, err := s.store.SaveProviderCredential(r.Context(), config.ProviderCredential{
			ID:          credentialID,
			TenantID:    request.TenantID,
			Provider:    request.Provider,
			Label:       request.Label,
			KeyHint:     providerKeyHint(request.ProviderKey),
			Fingerprint: fingerprint,
		})
		request.ProviderKey = ""
		if err != nil {
			http.Error(w, `{"error":{"message":"Failed to save provider credential"}}`, http.StatusBadRequest)
			return
		}
		if err := s.reloadGateway(r.Context()); err != nil {
			http.Error(w, `{"error":{"message":"Credential saved but reload failed"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "provider_credential.created", "provider_credential", credential.ID, map[string]interface{}{"tenant_id": credential.TenantID, "provider": credential.Provider})
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{"ok": true, "credential": credential})

	case http.MethodDelete:
		id := strings.TrimSpace(r.URL.Query().Get("id"))
		if id == "" {
			http.Error(w, `{"error":{"message":"Credential ID is required"}}`, http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteProviderCredential(r.Context(), id); err != nil {
			http.Error(w, `{"error":{"message":"Provider credential not found"}}`, http.StatusNotFound)
			return
		}
		if err := s.reloadGateway(r.Context()); err != nil {
			http.Error(w, `{"error":{"message":"Credential revoked but reload failed"}}`, http.StatusInternalServerError)
			return
		}
		s.auditChange(r, "provider_credential.revoked", "provider_credential", id, nil)
		_ = json.NewEncoder(w).Encode(map[string]bool{"ok": true})

	default:
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
	}
}

func newOpaqueID(prefix string) (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return prefix + hex.EncodeToString(raw[:]), nil
}

func providerKeyHint(key string) string {
	runes := []rune(strings.TrimSpace(key))
	if len(runes) <= 4 {
		return "••••"
	}
	return "••••" + string(runes[len(runes)-4:])
}

func (s *Server) handleWebhookTest(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}

	if s.webhook == nil {
		http.Error(w, `{"error":{"message":"Webhook dispatcher not initialized"}}`, http.StatusServiceUnavailable)
		return
	}

	var reqBody struct {
		URL    string `json:"url"`
		Secret string `json:"secret"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&reqBody)
	}

	evt := webhook.Event{
		Event:     "test_ping",
		Timestamp: time.Now().UTC(),
		Details:   "Disparo de teste manual originado do Console Web do HadesGate",
	}

	var err error
	if strings.TrimSpace(reqBody.URL) != "" {
		err = s.webhook.TestDispatchTarget(reqBody.URL, reqBody.Secret, evt)
	} else {
		err = s.webhook.TestDispatch(evt)
	}

	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":      true,
		"message": "Webhook test alert delivered successfully",
	})
}

func (s *Server) handleAnvisaStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodGet {
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}

	var status detector.MedicationCatalogStatus
	if s.engine != nil {
		if med := s.engine.MedicationDetector(); med != nil {
			status = med.Status()
		}
	}

	json.NewEncoder(w).Encode(status)
}

func (s *Server) handleAnvisaSync(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodPost {
		http.Error(w, `{"error":{"message":"Method not allowed"}}`, http.StatusMethodNotAllowed)
		return
	}

	if s.engine == nil || s.engine.MedicationDetector() == nil {
		http.Error(w, `{"error":{"message":"Medication detector not available in engine"}}`, http.StatusServiceUnavailable)
		return
	}

	med := s.engine.MedicationDetector()
	sync := detector.NewAnvisaSynchronizer(med)

	res, err := sync.CheckAndSync(r.Context(), false)
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":    false,
			"error": err.Error(),
		})
		return
	}

	json.NewEncoder(w).Encode(map[string]interface{}{
		"ok":     true,
		"result": res,
	})
}
