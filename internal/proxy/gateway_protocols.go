package proxy

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hadesgate/hadesgate/internal/anonymizer"
	"github.com/hadesgate/hadesgate/internal/observability"
	"github.com/hadesgate/hadesgate/internal/policy"
	"github.com/hadesgate/hadesgate/internal/protocol"
	"github.com/hadesgate/hadesgate/internal/stream"
)

// HandleResponses protects and forwards OpenAI Responses API requests.
func (g *Gateway) HandleResponses(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddUint64(&g.metrics.TotalRequests, 1)
	tenant, authenticated := g.authenticateTenant(r)
	if g.proxyAuthRequired() && !authenticated {
		writeProtocolError(w, http.StatusUnauthorized, "auth_error", "Invalid or missing API key")
		return
	}
	if !g.allowTenantRequest(tenant) {
		w.Header().Set("Retry-After", "60")
		writeProtocolError(w, http.StatusTooManyRequests, "rate_limit_error", "Tenant request rate limit reached")
		return
	}
	select {
	case g.requestSlots <- struct{}{}:
		defer func() { <-g.requestSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeProtocolError(w, http.StatusTooManyRequests, "rate_limit_error", "Gateway concurrency limit reached")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request_error", "Request body exceeds 10MB or could not be read")
		return
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON payload")
		return
	}

	requestID, err := newRequestID()
	if err != nil {
		writeProtocolError(w, http.StatusInternalServerError, "server_error", "Failed to create secure request context")
		return
	}
	w.Header().Set("X-HadesGate-Request-ID", requestID)
	defer g.engine.Vault().DeleteSession(requestID)
	tenantPolicy := g.PolicyForTenant(tenant)

	model, _ := payload["model"].(string)
	isStreaming, _ := payload["stream"].(bool)
	if isStreaming {
		atomic.AddUint64(&g.metrics.StreamRequests, 1)
		atomic.AddInt64(&g.metrics.ActiveStreams, 1)
		defer atomic.AddInt64(&g.metrics.ActiveStreams, -1)
	}
	entities := 0
	var collectedEntities []anonymizer.DetectedEntity
	var sanitizedInput string
	var detectedLang string
	var scannedChars int
	anonStart := time.Now()
	protocol.TransformResponses(payload, func(role, text string) string {
		scannedChars += len(text)
		if role == "user" && text != "" {
			detectedLang = observability.DetectLanguage(text)
		}
		result := g.anonymizeWithPolicy(requestID, text, tenantPolicy)
		entities += len(result.Entities)
		collectedEntities = append(collectedEntities, result.Entities...)
		if role == "user" {
			sanitizedInput = result.SanitizedText
		}
		return result.SanitizedText
	})
	anonElapsedNs := time.Since(anonStart).Nanoseconds()
	anonDurationUs := (anonElapsedNs + 500) / 1000
	if anonDurationUs == 0 && scannedChars > 0 {
		anonDurationUs = 1
	}
	atomic.AddUint64(&g.metrics.EntitiesMasked, uint64(entities))

	entityTypes, piiTypes, secretTypes := observability.ClassifyEntities(collectedEntities)
	var targetURL, apiKey string
	var isMock bool
	userInfo := g.userForRequest(r)
	tenantName := g.ResolveTenantName(tenant)

	statusCode := http.StatusOK
	defer func() {
		if g.traces != nil {
			g.traces.Record(observability.Trace{
				ID: requestID, Tenant: tenant, TenantName: tenantName,
				UserLabel: userInfo.Label, UserRole: userInfo.Role,
				PolicyAction: w.Header().Get("X-HadesGate-Policy-Action"),
				Timestamp:    start, Provider: observability.InferProvider("responses", model, targetURL, isMock),
				Model: model, Language: detectedLang, Stream: isStreaming,
				StatusCode: statusCode, DurationMs: float64(time.Since(start).Microseconds()) / 1000,
				AnonDurationUs: anonDurationUs, EntitiesCount: entities,
				EntityTypes: entityTypes, PIITypes: piiTypes, SecretTypes: secretTypes,
				SanitizedPrompt: telemetryPromptForPolicy(tenantPolicy, sanitizedInput),
			})
		}
	}()
	decision := tenantPolicy.Decide(entityTypes)
	// The deferred trace reads the final policy through this response header.
	w.Header().Set("X-HadesGate-Policy-Action", string(decision.Action))
	if decision.Action == policy.Block {
		statusCode = http.StatusBadRequest
		writeProtocolError(w, statusCode, "sensitive_data_blocked", "Request blocked by entity policy")
		return
	}

	if entities > 0 {
		protocol.InjectResponsesSystemInstruction(payload, protocol.PlaceholderSystemInstruction)
	}

	sanitized, err := json.Marshal(payload)
	if err != nil {
		statusCode = http.StatusInternalServerError
		writeProtocolError(w, statusCode, "server_error", "Failed to serialize sanitized request")
		return
	}
	if g.upstream == nil {
		statusCode = http.StatusServiceUnavailable
		writeProtocolError(w, statusCode, "upstream_not_configured", "Responses API requires a configured upstream provider")
		return
	}
	if decision.Action == policy.RouteLocal {
		targetURL = g.upstream.ResolveLocalTarget("/responses")
	} else {
		targetURL, apiKey, isMock, err = g.upstream.ResolveTargetForEndpoint(g.routingRequestForUpstream(r), model, "/responses")
	}
	if err != nil {
		statusCode = http.StatusBadRequest
		writeProtocolError(w, statusCode, "invalid_upstream", err.Error())
		return
	}
	if isMock {
		statusCode = http.StatusServiceUnavailable
		writeProtocolError(w, statusCode, "upstream_not_configured", "Responses API requires a configured upstream provider")
		return
	}
	detok := stream.NewDetokenizer(requestID, g.engine.Vault())
	if err := g.upstream.ForwardResponsesRequest(r.Context(), targetURL, apiKey, sanitized, isStreaming, detok, w, r.Header); err != nil {
		statusCode = http.StatusBadGateway
		writeProtocolError(w, statusCode, "upstream_error", err.Error())
	}
}

// HandleAnthropicMessages protects and forwards Anthropic Messages requests.
func (g *Gateway) HandleAnthropicMessages(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddUint64(&g.metrics.TotalRequests, 1)
	tenant, authenticated := g.authenticateTenant(r)
	if g.proxyAuthRequired() && !authenticated {
		writeProtocolError(w, http.StatusUnauthorized, "auth_error", "Invalid or missing API key")
		return
	}
	if !g.allowTenantRequest(tenant) {
		w.Header().Set("Retry-After", "60")
		writeProtocolError(w, http.StatusTooManyRequests, "rate_limit_error", "Tenant request rate limit reached")
		return
	}
	select {
	case g.requestSlots <- struct{}{}:
		defer func() { <-g.requestSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeProtocolError(w, http.StatusTooManyRequests, "rate_limit_error", "Gateway concurrency limit reached")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request_error", "Request body exceeds 10MB or could not be read")
		return
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON payload")
		return
	}
	requestID, err := newRequestID()
	if err != nil {
		writeProtocolError(w, http.StatusInternalServerError, "server_error", "Failed to create secure request context")
		return
	}
	w.Header().Set("X-HadesGate-Request-ID", requestID)
	defer g.engine.Vault().DeleteSession(requestID)
	tenantPolicy := g.PolicyForTenant(tenant)

	model, _ := payload["model"].(string)
	isStreaming, _ := payload["stream"].(bool)
	if isStreaming {
		atomic.AddUint64(&g.metrics.StreamRequests, 1)
		atomic.AddInt64(&g.metrics.ActiveStreams, 1)
		defer atomic.AddInt64(&g.metrics.ActiveStreams, -1)
	}
	entities := 0
	var collectedEntities []anonymizer.DetectedEntity
	var sanitizedInput string
	var detectedLang string
	var scannedChars int
	anonStart := time.Now()
	protocol.TransformAnthropic(payload, func(role, text string) string {
		scannedChars += len(text)
		if role == "user" && text != "" {
			detectedLang = observability.DetectLanguage(text)
		}
		result := g.anonymizeWithPolicy(requestID, text, tenantPolicy)
		entities += len(result.Entities)
		collectedEntities = append(collectedEntities, result.Entities...)
		if role == "user" {
			sanitizedInput = result.SanitizedText
		}
		return result.SanitizedText
	})
	anonElapsedNs := time.Since(anonStart).Nanoseconds()
	anonDurationUs := (anonElapsedNs + 500) / 1000
	if anonDurationUs == 0 && scannedChars > 0 {
		anonDurationUs = 1
	}
	atomic.AddUint64(&g.metrics.EntitiesMasked, uint64(entities))

	entityTypes, piiTypes, secretTypes := observability.ClassifyEntities(collectedEntities)
	var targetURL string
	statusCode := http.StatusOK
	userInfo := g.userForRequest(r)
	tenantName := g.ResolveTenantName(tenant)

	defer func() {
		if g.traces != nil {
			g.traces.Record(observability.Trace{
				ID: requestID, Tenant: tenant, TenantName: tenantName,
				UserLabel: userInfo.Label, UserRole: userInfo.Role,
				PolicyAction: w.Header().Get("X-HadesGate-Policy-Action"),
				Timestamp:    start, Provider: observability.InferProvider("anthropic", model, targetURL, false),
				Model: model, Language: detectedLang, Stream: isStreaming,
				StatusCode: statusCode, DurationMs: float64(time.Since(start).Microseconds()) / 1000,
				AnonDurationUs: anonDurationUs, EntitiesCount: entities,
				EntityTypes: entityTypes, PIITypes: piiTypes, SecretTypes: secretTypes,
				SanitizedPrompt: telemetryPromptForPolicy(tenantPolicy, sanitizedInput),
			})
		}
	}()
	decision := tenantPolicy.Decide(entityTypes)
	w.Header().Set("X-HadesGate-Policy-Action", string(decision.Action))
	if decision.Action == policy.Block {
		statusCode = http.StatusBadRequest
		writeProtocolError(w, statusCode, "sensitive_data_blocked", "Request blocked by entity policy")
		return
	}
	if decision.Action == policy.RouteLocal {
		statusCode = http.StatusBadRequest
		writeProtocolError(w, statusCode, "route_local_not_supported", "Anthropic route_local requires a local Anthropic-compatible endpoint")
		return
	}

	if entities > 0 {
		protocol.InjectAnthropicSystemInstruction(payload, protocol.PlaceholderSystemInstruction)
	}

	sanitized, err := json.Marshal(payload)
	if err != nil {
		statusCode = http.StatusInternalServerError
		writeProtocolError(w, statusCode, "server_error", "Failed to serialize sanitized request")
		return
	}
	if g.upstream == nil {
		statusCode = http.StatusServiceUnavailable
		writeProtocolError(w, statusCode, "upstream_not_configured", "Anthropic provider is not configured")
		return
	}
	var apiKey string
	// X-Upstream-Key wins over a registered BYOK credential, matching the
	// OpenAI-compatible path.
	providerKey := trimBearer(r.Header.Get("X-Upstream-Key"))
	if providerKey == "" {
		_, providerKey, _ = g.providerCredentialForRequest(r)
	}
	targetURL, apiKey, err = g.upstream.ResolveAnthropicTargetForKey(providerKey)
	if err != nil {
		statusCode = http.StatusServiceUnavailable
		writeProtocolError(w, statusCode, "upstream_not_configured", err.Error())
		return
	}
	detok := stream.NewDetokenizer(requestID, g.engine.Vault())
	if err := g.upstream.ForwardAnthropicRequest(r.Context(), targetURL, apiKey, sanitized, isStreaming, detok, w, r.Header); err != nil {
		statusCode = http.StatusBadGateway
		writeProtocolError(w, statusCode, "upstream_error", err.Error())
	}
}

// HandleGeminiModels protects and forwards Google Gemini native REST/SDK requests
// (/v1beta/models/{model}:generateContent and :streamGenerateContent).
func (g *Gateway) HandleGeminiModels(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeProtocolError(w, http.StatusMethodNotAllowed, "invalid_request_error", "Method not allowed")
		return
	}

	model, action, validRoute := parseGeminiModelAction(r.URL.Path)
	if !validRoute {
		writeProtocolError(w, http.StatusNotFound, "not_found_error", "Unsupported Gemini endpoint or invalid model identifier")
		return
	}

	start := time.Now()
	atomic.AddUint64(&g.metrics.TotalRequests, 1)
	tenant, authenticated := g.authenticateTenant(r)
	if g.proxyAuthRequired() && !authenticated {
		writeProtocolError(w, http.StatusUnauthorized, "auth_error", "Invalid or missing API key")
		return
	}
	if !g.allowTenantRequest(tenant) {
		w.Header().Set("Retry-After", "60")
		writeProtocolError(w, http.StatusTooManyRequests, "rate_limit_error", "Tenant request rate limit reached")
		return
	}
	select {
	case g.requestSlots <- struct{}{}:
		defer func() { <-g.requestSlots }()
	default:
		w.Header().Set("Retry-After", "1")
		writeProtocolError(w, http.StatusTooManyRequests, "rate_limit_error", "Gateway concurrency limit reached")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	body, err := io.ReadAll(r.Body)
	if err != nil {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request_error", "Request body exceeds 10MB or could not be read")
		return
	}
	var payload map[string]interface{}
	if err := json.Unmarshal(body, &payload); err != nil {
		writeProtocolError(w, http.StatusBadRequest, "invalid_request_error", "Invalid JSON payload")
		return
	}

	requestID, err := newRequestID()
	if err != nil {
		writeProtocolError(w, http.StatusInternalServerError, "server_error", "Failed to create secure request context")
		return
	}
	w.Header().Set("X-HadesGate-Request-ID", requestID)
	defer g.engine.Vault().DeleteSession(requestID)
	tenantPolicy := g.PolicyForTenant(tenant)

	isStreaming := action == "streamGenerateContent"
	isSSE := isStreaming && strings.EqualFold(r.URL.Query().Get("alt"), "sse")
	if isStreaming {
		atomic.AddUint64(&g.metrics.StreamRequests, 1)
		atomic.AddInt64(&g.metrics.ActiveStreams, 1)
		defer atomic.AddInt64(&g.metrics.ActiveStreams, -1)
	}

	entities := 0
	var collectedEntities []anonymizer.DetectedEntity
	var sanitizedInput string
	var detectedLang string
	var scannedChars int
	anonStart := time.Now()
	protocol.TransformGemini(payload, func(role, text string) string {
		scannedChars += len(text)
		if role == "user" && text != "" {
			detectedLang = observability.DetectLanguage(text)
		}
		result := g.anonymizeWithPolicy(requestID, text, tenantPolicy)
		entities += len(result.Entities)
		collectedEntities = append(collectedEntities, result.Entities...)
		if role == "user" {
			sanitizedInput = result.SanitizedText
		}
		return result.SanitizedText
	})
	anonElapsedNs := time.Since(anonStart).Nanoseconds()
	anonDurationUs := (anonElapsedNs + 500) / 1000
	if anonDurationUs == 0 && scannedChars > 0 {
		anonDurationUs = 1
	}
	atomic.AddUint64(&g.metrics.EntitiesMasked, uint64(entities))

	entityTypes, piiTypes, secretTypes := observability.ClassifyEntities(collectedEntities)
	var targetURL string
	statusCode := http.StatusOK
	userInfo := g.userForRequest(r)
	tenantName := g.ResolveTenantName(tenant)

	defer func() {
		if g.traces != nil {
			g.traces.Record(observability.Trace{
				ID: requestID, Tenant: tenant, TenantName: tenantName,
				UserLabel: userInfo.Label, UserRole: userInfo.Role,
				PolicyAction: w.Header().Get("X-HadesGate-Policy-Action"),
				Timestamp:    start, Provider: observability.InferProvider("gemini", model, targetURL, false),
				Model: model, Language: detectedLang, Stream: isStreaming,
				StatusCode: statusCode, DurationMs: float64(time.Since(start).Microseconds()) / 1000,
				AnonDurationUs: anonDurationUs, EntitiesCount: entities,
				EntityTypes: entityTypes, PIITypes: piiTypes, SecretTypes: secretTypes,
				SanitizedPrompt: telemetryPromptForPolicy(tenantPolicy, sanitizedInput),
			})
		}
	}()

	decision := tenantPolicy.Decide(entityTypes)
	w.Header().Set("X-HadesGate-Policy-Action", string(decision.Action))
	if decision.Action == policy.Block {
		statusCode = http.StatusBadRequest
		writeProtocolError(w, statusCode, "sensitive_data_blocked", "Request blocked by entity policy")
		return
	}
	if decision.Action == policy.RouteLocal {
		statusCode = http.StatusBadRequest
		writeProtocolError(w, statusCode, "route_local_not_supported", "Gemini native route_local requires an OpenAI-compatible client (/v1/chat/completions)")
		return
	}

	if entities > 0 {
		protocol.InjectGeminiSystemInstruction(payload, protocol.PlaceholderSystemInstruction)
	}

	sanitized, err := json.Marshal(payload)
	if err != nil {
		statusCode = http.StatusInternalServerError
		writeProtocolError(w, statusCode, "server_error", "Failed to serialize sanitized request")
		return
	}
	if g.upstream == nil {
		statusCode = http.StatusServiceUnavailable
		writeProtocolError(w, statusCode, "upstream_not_configured", "Gemini provider is not configured")
		return
	}
	var apiKey string
	routingRequest := r
	if _, providerKey, ok := g.providerCredentialForRequest(r); ok {
		routingRequest = r.Clone(r.Context())
		routingRequest.Header = r.Header.Clone()
		routingRequest.Header.Set("X-Upstream-Key", providerKey)
	}
	targetURL, apiKey, err = g.upstream.ResolveGeminiTarget(routingRequest, model, action, isSSE)
	if err != nil {
		statusCode = http.StatusServiceUnavailable
		writeProtocolError(w, statusCode, "upstream_not_configured", err.Error())
		return
	}
	detok := stream.NewDetokenizer(requestID, g.engine.Vault())
	if err := g.upstream.ForwardGeminiRequest(r.Context(), targetURL, apiKey, sanitized, isSSE, detok, w, r.Header); err != nil {
		statusCode = http.StatusBadGateway
		writeProtocolError(w, statusCode, "upstream_error", err.Error())
	}
}

// parseGeminiModelAction validates paths matching (/gemini)?/v1beta/models/{model}:{action}
// and rejects path traversal or unsupported actions.
func parseGeminiModelAction(urlPath string) (model, action string, ok bool) {
	trimmed := strings.TrimPrefix(urlPath, "/gemini")
	const prefix = "/v1beta/models/"
	if !strings.HasPrefix(trimmed, prefix) {
		return "", "", false
	}
	rest := trimmed[len(prefix):]
	colonIdx := strings.LastIndexByte(rest, ':')
	if colonIdx <= 0 {
		return "", "", false
	}
	model = rest[:colonIdx]
	action = rest[colonIdx+1:]
	if action != "generateContent" && action != "streamGenerateContent" {
		return "", "", false
	}
	if len(model) == 0 || len(model) > 128 {
		return "", "", false
	}
	for i := 0; i < len(model); i++ {
		c := model[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		if !isAlphaNum && c != '-' && c != '_' && c != '.' {
			return "", "", false
		}
	}
	return model, action, true
}

func writeProtocolError(w http.ResponseWriter, status int, errorType, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]interface{}{
		"error": map[string]string{"message": message, "type": errorType},
	})
}
