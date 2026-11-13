package proxy

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/hadesgate/hadesgate/internal/anonymizer"
	"github.com/hadesgate/hadesgate/internal/anonymizer/detector"
	"github.com/hadesgate/hadesgate/internal/observability"
	"github.com/hadesgate/hadesgate/internal/policy"
	"github.com/hadesgate/hadesgate/internal/protocol"
	"github.com/hadesgate/hadesgate/internal/stream"
	"github.com/hadesgate/hadesgate/internal/webhook"
)

// MetricsTracker records gateway activity.
type MetricsTracker struct {
	TotalRequests    uint64
	StreamRequests   uint64
	EntitiesMasked   uint64
	ActiveStreams    int64
	AvgLatencyMicros uint64
}

// UserContext carries non-sensitive administrative user metadata for telemetry.
type UserContext struct {
	Label string
	Role  string
}

type userCtxKey struct{}

// ContextWithUser associates administrative / user metadata with the request context.
func ContextWithUser(ctx context.Context, label, role string) context.Context {
	return context.WithValue(ctx, userCtxKey{}, UserContext{Label: label, Role: role})
}

// UserFromContext extracts administrative / user metadata from the request context.
func UserFromContext(ctx context.Context) (UserContext, bool) {
	u, ok := ctx.Value(userCtxKey{}).(UserContext)
	return u, ok
}

// Gateway handles OpenAI-compatible reverse proxy requests.
type Gateway struct {
	mu                        sync.RWMutex
	engine                    *anonymizer.Engine
	upstream                  *UpstreamDispatcher
	mock                      *MockLLM
	globalProxyKey            string
	traces                    *observability.TraceLogger
	metrics                   MetricsTracker
	requestSlots              chan struct{}
	policy                    *policy.Engine
	tenantKeys                map[string]string
	tenantNames               map[string]string
	tenantPolicies            map[string]*policy.Engine
	rateLimiters              map[string]*tokenBucketLimiter
	providerKeyFingerprints   map[string][]string
	providerFingerprintSecret string
	allowLegacyURLKeys        bool
	webhook                   *webhook.Dispatcher
}

type GatewayOptions struct {
	MaxConcurrent             int
	GlobalProxyKey            string
	EntityActions             map[string]string
	TenantKeys                map[string]string
	TenantNames               map[string]string
	TenantEntityActions       map[string]map[string]string
	RateLimitPerMinute        int
	TenantRateLimits          map[string]int
	ProviderKeyFingerprints   map[string][]string
	ProviderFingerprintSecret string
	AllowLegacyURLKeys        bool
	Webhook                   *webhook.Dispatcher
}

type tokenBucketLimiter struct {
	mu         sync.Mutex
	capacity   float64
	tokens     float64
	ratePerSec float64
	lastRefill time.Time
}

func newTokenBucketLimiter(limitPerMinute int) *tokenBucketLimiter {
	if limitPerMinute <= 0 {
		return nil
	}
	cap := float64(limitPerMinute)
	return &tokenBucketLimiter{
		capacity:   cap,
		tokens:     cap,
		ratePerSec: cap / 60.0,
		lastRefill: time.Now(),
	}
}

func (l *tokenBucketLimiter) allow(now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.lastRefill.IsZero() {
		l.lastRefill = now
		l.tokens = l.capacity
	}

	elapsed := now.Sub(l.lastRefill).Seconds()
	if elapsed > 0 {
		l.tokens += elapsed * l.ratePerSec
		if l.tokens > l.capacity {
			l.tokens = l.capacity
		}
		l.lastRefill = now
	}

	if l.tokens >= 1.0 {
		l.tokens -= 1.0
		return true
	}
	return false
}

// NewGateway creates an initialized Gateway instance.
func NewGateway(engine *anonymizer.Engine, upstream *UpstreamDispatcher, proxyKey string, traces *observability.TraceLogger) *Gateway {
	return NewGatewayWithLimit(engine, upstream, proxyKey, traces, 128)
}

// NewGatewayWithLimit creates a gateway with a fixed, allocation-free concurrency guard.
func NewGatewayWithLimit(engine *anonymizer.Engine, upstream *UpstreamDispatcher, proxyKey string, traces *observability.TraceLogger, maxConcurrent int) *Gateway {
	return NewGatewayWithOptions(engine, upstream, traces, GatewayOptions{MaxConcurrent: maxConcurrent, GlobalProxyKey: proxyKey})
}

// NewGatewayWithOptions creates a gateway using only proxy-scoped credentials from options.
func NewGatewayWithOptions(engine *anonymizer.Engine, upstream *UpstreamDispatcher, traces *observability.TraceLogger, options GatewayOptions) *Gateway {
	maxConcurrent := options.MaxConcurrent
	if maxConcurrent <= 0 {
		maxConcurrent = 128
	}
	familyResolver := func(entityType string) string {
		return string(anonymizer.FamilyForEntity(detector.EntityType(entityType)))
	}
	tenantPolicies := make(map[string]*policy.Engine, len(options.TenantEntityActions))
	for tenant, actions := range options.TenantEntityActions {
		tenantPolicies[tenant] = policy.New(mergeEntityActions(options.EntityActions, actions)).WithFamilyResolver(familyResolver)
	}
	rateLimiters := make(map[string]*tokenBucketLimiter, len(options.TenantRateLimits)+1)
	if options.RateLimitPerMinute > 0 {
		rateLimiters["default"] = newTokenBucketLimiter(options.RateLimitPerMinute)
	}
	for tenant, limit := range options.TenantRateLimits {
		if limit > 0 {
			rateLimiters[tenant] = newTokenBucketLimiter(limit)
		}
	}
	return &Gateway{
		engine:                    engine,
		upstream:                  upstream,
		mock:                      NewMockLLM(),
		globalProxyKey:            options.GlobalProxyKey,
		traces:                    traces,
		requestSlots:              make(chan struct{}, maxConcurrent),
		policy:                    policy.New(options.EntityActions).WithFamilyResolver(familyResolver),
		tenantKeys:                cloneStringMap(options.TenantKeys),
		tenantNames:               cloneStringMap(options.TenantNames),
		tenantPolicies:            tenantPolicies,
		rateLimiters:              rateLimiters,
		providerKeyFingerprints:   cloneFingerprintMap(options.ProviderKeyFingerprints),
		providerFingerprintSecret: options.ProviderFingerprintSecret,
		allowLegacyURLKeys:        options.AllowLegacyURLKeys,
		webhook:                   options.Webhook,
	}
}

// ProviderKeyFingerprint returns the stable keyed fingerprint used to identify
// a provider credential without persisting the original secret.
func ProviderKeyFingerprint(secret, providerKey string) (string, error) {
	secret = strings.TrimSpace(secret)
	providerKey = strings.TrimSpace(providerKey)
	if secret == "" {
		return "", fmt.Errorf("provider fingerprint secret is not configured")
	}
	if providerKey == "" {
		return "", fmt.Errorf("provider key is empty")
	}
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte(providerKey))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

func cloneFingerprintMap(source map[string][]string) map[string][]string {
	cloned := make(map[string][]string, len(source))
	for tenant, fingerprints := range source {
		cloned[tenant] = append([]string(nil), fingerprints...)
	}
	return cloned
}

func cloneStringMap(source map[string]string) map[string]string {
	cloned := make(map[string]string, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

// Traces returns the active in-memory trace logger.
func (g *Gateway) Traces() *observability.TraceLogger {
	return g.traces
}

// Metrics returns a snapshot of runtime metrics.
func (g *Gateway) Metrics() MetricsTracker {
	return MetricsTracker{
		TotalRequests:  atomic.LoadUint64(&g.metrics.TotalRequests),
		StreamRequests: atomic.LoadUint64(&g.metrics.StreamRequests),
		EntitiesMasked: atomic.LoadUint64(&g.metrics.EntitiesMasked),
		ActiveStreams:  atomic.LoadInt64(&g.metrics.ActiveStreams),
	}
}

// authenticate validates request credentials against proxy-scoped keys only.
func (g *Gateway) authenticate(r *http.Request) bool {
	_, ok := g.authenticateTenant(r)
	return ok
}

type tenantCtxKey struct{}
type preAuthCtxKey struct{}

// GlobalProxyKey returns the currently configured global proxy key.
func (g *Gateway) GlobalProxyKey() string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.globalProxyKey
}

// SetTenantNames sets the mapping of tenant IDs/slugs to human-readable names.
func (g *Gateway) SetTenantNames(names map[string]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.tenantNames = cloneStringMap(names)
}

// ResolveTenantName converts a tenant ID or slug to its configured name, or "GLOBAL".
func (g *Gateway) ResolveTenantName(tenant string) string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	tenant = strings.TrimSpace(tenant)
	if tenant == "" || tenant == "default" || tenant == "*" {
		return "GLOBAL"
	}
	if name, ok := g.tenantNames[tenant]; ok && strings.TrimSpace(name) != "" {
		return name
	}
	return tenant
}

func (g *Gateway) userForRequest(r *http.Request) UserContext {
	if user, ok := UserFromContext(r.Context()); ok && user.Label != "" {
		return user
	}
	return UserContext{}
}

func (g *Gateway) isGlobalKeyValid(key string) bool {
	if key == "" {
		return false
	}
	g.mu.RLock()
	globalKey := g.globalProxyKey
	g.mu.RUnlock()

	if globalKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(globalKey)) == 1 {
		return true
	}
	return false
}

func (g *Gateway) proxyAuthRequired() bool {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return g.globalProxyKey != "" || len(g.tenantKeys) > 0 || len(g.providerKeyFingerprints) > 0
}

func (g *Gateway) authenticateTenant(r *http.Request) (string, bool) {
	// 0. Pre-authenticated routes (via secret key embedded in /p/{key}/ or /t/{proxy_key}/)
	if isPreAuth, _ := r.Context().Value(preAuthCtxKey{}).(bool); isPreAuth {
		if pathTenant, _ := r.Context().Value(tenantCtxKey{}).(string); pathTenant != "" {
			return pathTenant, true
		}
	}

	pathTenant, _ := r.Context().Value(tenantCtxKey{}).(string)

	headerKeys := requestHeaderCredentials(r)
	g.mu.RLock()
	allowLegacyURLKeys := g.allowLegacyURLKeys
	g.mu.RUnlock()
	gatewayKeys := append([]string(nil), headerKeys...)
	if allowLegacyURLKeys {
		if queryKey := strings.TrimSpace(r.URL.Query().Get("key")); queryKey != "" {
			gatewayKeys = append(gatewayKeys, queryKey)
		}
	}

	if !g.proxyAuthRequired() {
		if pathTenant != "" {
			return pathTenant, true
		}
		return "default", true
	}

	// 1. Authenticate only against the global proxy key or tenant proxy keys.
	for _, key := range gatewayKeys {
		if tenant, ok := g.AuthenticateKey(key); ok {
			if pathTenant != "" {
				g.mu.RLock()
				expectedKey := g.tenantKeys[pathTenant]
				g.mu.RUnlock()
				if tenant == "default" || (expectedKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(expectedKey)) == 1) {
					return pathTenant, true
				}
			}
			return tenant, true
		}
	}

	// 2. Transparent BYOK mode: authenticate the tenant by a keyed fingerprint
	// of the provider credential while forwarding the original key upstream.
	for _, key := range requestProviderCredentials(r) {
		if tenant, ok := g.authenticateProviderKey(key); ok {
			if pathTenant != "" && tenant != pathTenant {
				return "", false
			}
			return tenant, true
		}
	}

	return "", false
}

func requestHeaderCredentials(r *http.Request) []string {
	values := make([]string, 0, 3)
	if authHeader := strings.TrimSpace(r.Header.Get("Authorization")); authHeader != "" {
		values = append(values, trimBearer(authHeader))
	}
	for _, header := range []string{"X-API-Key", "X-Goog-Api-Key"} {
		if key := strings.TrimSpace(r.Header.Get(header)); key != "" {
			values = append(values, key)
		}
	}
	return values
}

// trimBearer strips a Bearer prefix case-insensitively: SDKs and proxies are
// inconsistent about the casing of the scheme.
func trimBearer(header string) string {
	header = strings.TrimSpace(header)
	if len(header) >= 7 && strings.EqualFold(header[:7], "Bearer ") {
		return strings.TrimSpace(header[7:])
	}
	return header
}

func requestProviderCredentials(r *http.Request) []string {
	values := requestHeaderCredentials(r)
	if queryKey := strings.TrimSpace(r.URL.Query().Get("key")); queryKey != "" {
		values = append(values, queryKey)
	}
	return values
}

func (g *Gateway) providerCredentialForRequest(r *http.Request) (string, string, bool) {
	for _, key := range requestProviderCredentials(r) {
		if tenant, ok := g.authenticateProviderKey(key); ok {
			return tenant, key, true
		}
	}
	return "", "", false
}

func (g *Gateway) routingRequestForUpstream(r *http.Request) *http.Request {
	if _, _, ok := g.providerCredentialForRequest(r); ok {
		return r
	}
	clone := r.Clone(r.Context())
	clone.Header = r.Header.Clone()
	clone.Header.Del("Authorization")
	clone.Header.Del("X-API-Key")
	clone.Header.Del("X-Goog-Api-Key")
	return clone
}

func (g *Gateway) authenticateProviderKey(key string) (string, bool) {
	if strings.TrimSpace(key) == "" {
		return "", false
	}
	g.mu.RLock()
	secret := g.providerFingerprintSecret
	fingerprints := cloneFingerprintMap(g.providerKeyFingerprints)
	g.mu.RUnlock()

	candidate, err := ProviderKeyFingerprint(secret, key)
	if err != nil {
		return "", false
	}
	for tenant, expectedList := range fingerprints {
		for _, expected := range expectedList {
			if len(candidate) == len(expected) && subtle.ConstantTimeCompare([]byte(candidate), []byte(expected)) == 1 {
				return tenant, true
			}
		}
	}
	return "", false
}

// UpdateProviderKeyFingerprints atomically replaces the transparent BYOK credential index.
func (g *Gateway) UpdateProviderKeyFingerprints(secret string, fingerprints map[string][]string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.providerFingerprintSecret = secret
	g.providerKeyFingerprints = cloneFingerprintMap(fingerprints)
}

// AuthenticateKey verifies if key matches the global proxy key or a tenant proxy key.
func (g *Gateway) AuthenticateKey(key string) (string, bool) {
	if key == "" {
		return "", false
	}
	g.mu.RLock()
	globalProxyKey := g.globalProxyKey
	tenantKeys := g.tenantKeys
	g.mu.RUnlock()

	if globalProxyKey != "" && subtle.ConstantTimeCompare([]byte(key), []byte(globalProxyKey)) == 1 {
		return "default", true
	}
	for tenant, tenantKey := range tenantKeys {
		if subtle.ConstantTimeCompare([]byte(key), []byte(tenantKey)) == 1 {
			return tenant, true
		}
	}
	return "", false
}

// AuthenticateProviderKey validates a registered transparent BYOK credential.
func (g *Gateway) AuthenticateProviderKey(key string) (string, bool) {
	return g.authenticateProviderKey(key)
}

// HandleTenantPath routes path-prefixed requests like /t/{identifier}/v1/chat/completions.
// If {identifier} matches a registered tenant's proxy_key, the request is pre-authorized!
func (g *Gateway) HandleTenantPath(w http.ResponseWriter, r *http.Request) {
	trimmed := strings.TrimPrefix(r.URL.Path, "/t/")
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	rawIdentifier := parts[0]
	subPath := "/"
	if len(parts) == 2 {
		subPath = "/" + parts[1]
	}

	var targetTenant string
	var preAuth bool

	g.mu.RLock()
	allowLegacyURLKeys := g.allowLegacyURLKeys
	// 1. Check if rawIdentifier is a tenant's proxy_key (constant-time check per tenant)
	if allowLegacyURLKeys {
		for tID, pKey := range g.tenantKeys {
			if subtle.ConstantTimeCompare([]byte(rawIdentifier), []byte(pKey)) == 1 {
				if targetTenant == "" || g.tenantPolicies[tID] != nil {
					targetTenant = tID
				}
				preAuth = true
			}
		}
	}
	if targetTenant == "" {
		// 2. Check if rawIdentifier is a tenant ID or slug
		if _, exists := g.tenantKeys[rawIdentifier]; exists {
			targetTenant = rawIdentifier
		} else if _, exists := g.tenantPolicies[rawIdentifier]; exists {
			targetTenant = rawIdentifier
		}
	}
	g.mu.RUnlock()

	if targetTenant == "" {
		writeProtocolError(w, http.StatusUnauthorized, "auth_error", "Unknown tenant or invalid tenant proxy key in URL")
		return
	}

	ctx := context.WithValue(r.Context(), tenantCtxKey{}, targetTenant)
	if preAuth {
		ctx = context.WithValue(ctx, preAuthCtxKey{}, true)
	}
	r2 := r.Clone(ctx)
	r2.URL.Path = subPath

	g.dispatchSubPath(w, r2, subPath)
}

// HandleGlobalProxyPath routes requests like /p/{key}/v1/chat/completions using a rotated global proxy key.
func (g *Gateway) HandleGlobalProxyPath(w http.ResponseWriter, r *http.Request) {
	g.mu.RLock()
	allowLegacyURLKeys := g.allowLegacyURLKeys
	g.mu.RUnlock()
	if !allowLegacyURLKeys {
		writeProtocolError(w, http.StatusGone, "legacy_url_auth_disabled", "Credential-bearing proxy URLs are disabled; use the provider key in its native authorization header")
		return
	}
	trimmed := strings.TrimPrefix(r.URL.Path, "/p/")
	if strings.HasPrefix(r.URL.Path, "/g/") {
		trimmed = strings.TrimPrefix(r.URL.Path, "/g/")
	}
	parts := strings.SplitN(trimmed, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}

	key := parts[0]
	if !g.isGlobalKeyValid(key) {
		writeProtocolError(w, http.StatusUnauthorized, "auth_error", "Invalid or unauthorized global proxy key in URL path")
		return
	}

	subPath := "/"
	if len(parts) == 2 {
		subPath = "/" + parts[1]
	}

	ctx := context.WithValue(r.Context(), tenantCtxKey{}, "default")
	ctx = context.WithValue(ctx, preAuthCtxKey{}, true)
	r2 := r.Clone(ctx)
	r2.URL.Path = subPath

	g.dispatchSubPath(w, r2, subPath)
}

// DispatchPreAuthenticated routes an internally-authorized request (e.g. from the dashboard Playground)
// directly to the appropriate protocol handler with a pre-authenticated context.
func (g *Gateway) DispatchPreAuthenticated(w http.ResponseWriter, r *http.Request, tenant, subPath string) {
	if tenant == "" {
		tenant = "default"
	}
	ctx := context.WithValue(r.Context(), tenantCtxKey{}, tenant)
	ctx = context.WithValue(ctx, preAuthCtxKey{}, true)
	r2 := r.Clone(ctx)
	r2.URL.Path = subPath
	g.dispatchSubPath(w, r2, subPath)
}

func (g *Gateway) dispatchSubPath(w http.ResponseWriter, r *http.Request, subPath string) {
	if strings.HasPrefix(subPath, "/v1/chat/completions") || strings.HasPrefix(subPath, "/chat/completions") {
		g.HandleChatCompletions(w, r)
		return
	}
	if strings.HasPrefix(subPath, "/v1/responses") || strings.HasPrefix(subPath, "/responses") {
		g.HandleResponses(w, r)
		return
	}
	if strings.HasPrefix(subPath, "/v1/messages") || strings.HasPrefix(subPath, "/anthropic/v1/messages") {
		g.HandleAnthropicMessages(w, r)
		return
	}
	if strings.HasPrefix(subPath, "/v1beta/models/") || strings.HasPrefix(subPath, "/gemini/v1beta/models/") {
		g.HandleGeminiModels(w, r)
		return
	}
	if strings.HasPrefix(subPath, "/v1/models") || strings.HasPrefix(subPath, "/models") {
		g.HandleModels(w, r)
		return
	}

	http.NotFound(w, r)
}

// PolicyForTenant returns the active policy engine for the given tenant or global fallback.
func (g *Gateway) PolicyForTenant(tenant string) *policy.Engine {
	g.mu.RLock()
	defer g.mu.RUnlock()
	if tenantPolicy := g.tenantPolicies[tenant]; tenantPolicy != nil {
		return tenantPolicy
	}
	return g.policy
}

func (g *Gateway) policyForTenant(tenant string) *policy.Engine {
	return g.PolicyForTenant(tenant)
}

func (g *Gateway) anonymizeWithPolicy(sessionID, text string, tenantPolicy *policy.Engine) anonymizer.Result {
	return g.engine.AnonymizeWithOptions(sessionID, text, anonymizer.AnonymizeOptions{
		IsTypeDisabled: func(entityType detector.EntityType) bool {
			return tenantPolicy.IsDisabled(string(entityType))
		},
		FilterMatches: tenantPolicy.FilterContextualMatches,
	})
}

func telemetryPromptForPolicy(tenantPolicy *policy.Engine, sanitizedPrompt string) string {
	if tenantPolicy.HasDisabledActions() {
		return ""
	}
	return sanitizedPrompt
}

func mergeEntityActions(global, tenant map[string]string) map[string]string {
	merged := make(map[string]string, len(global)+len(tenant))
	for entityType, action := range global {
		merged[entityType] = action
	}
	for entityType, action := range tenant {
		normalized := strings.ToLower(strings.TrimSpace(action))
		if normalized == "" || normalized == "inherit" {
			continue
		}
		merged[entityType] = normalized
	}
	return merged
}

func (g *Gateway) allowTenantRequest(tenant string) bool {
	g.mu.RLock()
	limiter := g.rateLimiters[tenant]
	if limiter == nil && tenant != "default" {
		limiter = g.rateLimiters["default"]
	}
	g.mu.RUnlock()
	return limiter == nil || limiter.allow(time.Now())
}

// UpdateDynamicConfig atomically reconfigures DLP policies, tenant keys, rate limiters, and global proxy key at runtime.
func (g *Gateway) UpdateDynamicConfig(entityActions map[string]string, tenantKeys map[string]string, tenantPolicies map[string]map[string]string, tenantRateLimits map[string]int, defaultRateLimit int, globalProxyKey string) {
	g.mu.Lock()
	defer g.mu.Unlock()

	familyResolver := func(entityType string) string {
		return string(anonymizer.FamilyForEntity(detector.EntityType(entityType)))
	}

	g.policy = policy.New(entityActions).WithFamilyResolver(familyResolver)
	g.tenantKeys = cloneStringMap(tenantKeys)
	// Assign unconditionally: a cleared key must be revoked immediately
	// instead of surviving in memory until the next restart.
	g.globalProxyKey = globalProxyKey

	compiledTenantPolicies := make(map[string]*policy.Engine, len(tenantPolicies))
	for tenant, actions := range tenantPolicies {
		compiledTenantPolicies[tenant] = policy.New(mergeEntityActions(entityActions, actions)).WithFamilyResolver(familyResolver)
	}
	g.tenantPolicies = compiledTenantPolicies

	limiters := make(map[string]*tokenBucketLimiter, len(tenantRateLimits)+1)
	if defaultRateLimit > 0 {
		limiters["default"] = newTokenBucketLimiter(defaultRateLimit)
	}
	for tenant, limit := range tenantRateLimits {
		if limit > 0 {
			limiters[tenant] = newTokenBucketLimiter(limit)
		}
	}
	g.rateLimiters = limiters
}

// UpdateThresholds dynamically updates family and entity confidence thresholds in the engine.
func (g *Gateway) UpdateThresholds(family map[string]float64, entity map[string]float64) {
	if g.engine != nil {
		g.engine.SetThresholds(family, entity)
	}
}

// Engine returns the underlying Anonymizer Engine.
func (g *Gateway) Engine() *anonymizer.Engine {
	return g.engine
}

// HandleChatCompletions processes incoming /v1/chat/completions requests.
func (g *Gateway) HandleChatCompletions(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	atomic.AddUint64(&g.metrics.TotalRequests, 1)

	// 1. Authenticate using proxy-scoped credentials only.
	tenant, authenticated := g.authenticateTenant(r)
	if g.proxyAuthRequired() && !authenticated {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"Invalid or missing API key","type":"auth_error"}}`))
		return
	}
	if !g.allowTenantRequest(tenant) {
		w.Header().Set("Retry-After", "60")
		writeProtocolError(w, http.StatusTooManyRequests, "rate_limit_error", "Tenant request rate limit reached")
		if g.webhook != nil {
			g.webhook.Dispatch(webhook.Event{
				Event:    "rate_limit",
				TenantID: tenant,
				Action:   "rate_limit",
				ClientIP: clientIP(r),
				Details:  "Tenant request rate limit reached",
			})
		}
		return
	}

	select {
	case g.requestSlots <- struct{}{}:
		defer func() { <-g.requestSlots }()
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		w.Write([]byte(`{"error":{"message":"Gateway concurrency limit reached","type":"rate_limit_error"}}`))
		return
	}

	// 2. Read and parse request body (limited to 10MB to prevent DoS)
	r.Body = http.MaxBytesReader(w, r.Body, 10<<20)
	bodyBytes, err := io.ReadAll(r.Body)
	if err != nil {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte(`{"error":{"message":"Failed to read request body or body exceeds 10MB limit"}}`))
		return
	}

	var rawPayload map[string]interface{}
	if err := json.Unmarshal(bodyBytes, &rawPayload); err != nil {
		http.Error(w, `{"error":{"message":"Invalid JSON payload"}}`, http.StatusBadRequest)
		return
	}

	// 3. Create an internal request-scoped vault ID. Client-provided correlation
	// IDs must never select another request's plaintext mappings.
	sessionID, err := newRequestID()
	if err != nil {
		http.Error(w, `{"error":{"message":"Failed to create secure request context"}}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("X-HadesGate-Request-ID", sessionID)
	defer g.engine.Vault().DeleteSession(sessionID)
	tenantPolicy := g.PolicyForTenant(tenant)

	// 4. Anonymize messages in the payload
	modelName, _ := rawPayload["model"].(string)
	if modelName == "" {
		modelName = "gpt-4o"
	}
	isStreaming, _ := rawPayload["stream"].(bool)
	if isStreaming {
		atomic.AddUint64(&g.metrics.StreamRequests, 1)
		atomic.AddInt64(&g.metrics.ActiveStreams, 1)
		defer atomic.AddInt64(&g.metrics.ActiveStreams, -1)
	}

	var totalEntitiesMasked int
	var lastUserPrompt string
	var detectedLang string
	var collectedEntities []anonymizer.DetectedEntity
	var scannedChars int
	tokenMap := make(map[string]string)
	anonStart := time.Now()

	protocol.TransformChatCompletions(rawPayload, func(role, content string) string {
		scannedChars += len(content)
		if role == "user" && content != "" {
			detectedLang = observability.DetectLanguage(content)
		}
		anonResult := g.anonymizeWithPolicy(sessionID, content, tenantPolicy)
		totalEntitiesMasked += len(anonResult.Entities)
		collectedEntities = append(collectedEntities, anonResult.Entities...)
		for k, v := range anonResult.TokenMap {
			tokenMap[k] = v
		}
		if role == "user" {
			lastUserPrompt = anonResult.SanitizedText
		}
		return anonResult.SanitizedText
	})

	anonElapsedNs := time.Since(anonStart).Nanoseconds()
	anonDurationUs := (anonElapsedNs + 500) / 1000
	if anonDurationUs == 0 && scannedChars > 0 {
		anonDurationUs = 1
	}
	atomic.AddUint64(&g.metrics.EntitiesMasked, uint64(totalEntitiesMasked))

	detectedTypes, piiTypes, secretTypes := observability.ClassifyEntities(collectedEntities)
	decision := tenantPolicy.Decide(detectedTypes)
	w.Header().Set("X-HadesGate-Policy-Action", string(decision.Action))

	statusCode := http.StatusOK
	var targetURL, apiKey string
	isMock := true
	userInfo := g.userForRequest(r)
	tenantName := g.ResolveTenantName(tenant)

	// Record non-sensitive anonymization trace on completion
	defer func() {
		if g.traces != nil {
			g.traces.Record(observability.Trace{
				ID:              sessionID,
				Tenant:          tenant,
				TenantName:      tenantName,
				UserLabel:       userInfo.Label,
				UserRole:        userInfo.Role,
				PolicyAction:    string(decision.Action),
				Timestamp:       start,
				Provider:        observability.InferProvider("chat", modelName, targetURL, isMock),
				Model:           modelName,
				Language:        detectedLang,
				Stream:          isStreaming,
				StatusCode:      statusCode,
				DurationMs:      float64(time.Since(start).Microseconds()) / 1000.0,
				AnonDurationUs:  anonDurationUs,
				EntitiesCount:   totalEntitiesMasked,
				EntityTypes:     detectedTypes,
				PIITypes:        piiTypes,
				SecretTypes:     secretTypes,
				SanitizedPrompt: telemetryPromptForPolicy(tenantPolicy, lastUserPrompt),
			})
		}
	}()

	if decision.Action == policy.Block {
		statusCode = http.StatusBadRequest
		isMock = modelName == "mock" || strings.HasPrefix(strings.ToLower(modelName), "mock/")
		writeProtocolError(w, statusCode, "sensitive_data_blocked", "Request blocked by entity policy")
		if g.webhook != nil {
			g.webhook.Dispatch(webhook.Event{
				Event:           "block",
				RequestID:       sessionID,
				TenantID:        tenant,
				Action:          "block",
				BlockedEntities: decision.Types,
				Model:           modelName,
				ClientIP:        clientIP(r),
				Details:         "Request blocked by entity DLP policy",
			})
		}
		return
	}

	// 5. Route to upstream or Mock before serializing payload (allows provider-specific model normalization)
	if g.upstream != nil {
		var resolveErr error
		if decision.Action == policy.RouteLocal {
			targetURL, apiKey, isMock = g.upstream.ResolveLocalTarget("/chat/completions"), "", false
		} else {
			targetURL, apiKey, isMock, resolveErr = g.upstream.ResolveTarget(g.routingRequestForUpstream(r), modelName)
		}
		if resolveErr != nil {
			statusCode = http.StatusBadRequest
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(statusCode)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"error": map[string]string{
					"message": resolveErr.Error(),
					"type":    "invalid_upstream",
				},
			})
			return
		}
	}

	if strings.HasPrefix(strings.ToLower(modelName), "gemini/") && strings.Contains(targetURL, "/v1beta/openai/") {
		rawPayload["model"] = modelName[len("gemini/"):]
	}

	forwardHeaders := r.Header
	if decision.Action == policy.RouteLocal {
		enrichedHeaders := r.Header.Clone()
		familySet := make(map[anonymizer.Family]bool)
		var famList []string
		for _, ent := range collectedEntities {
			fam := anonymizer.FamilyForEntity(ent.Type)
			if !familySet[fam] {
				familySet[fam] = true
				famList = append(famList, string(fam))
			}
		}
		sort.Strings(famList)
		enrichedHeaders.Set("X-HadesGate-Route-Action", "route_local")
		enrichedHeaders.Set("X-HadesGate-Sensitive-Families", strings.Join(famList, ","))
		enrichedHeaders.Set("X-HadesGate-Sensitive-Types", strings.Join(decision.Types, ","))
		enrichedHeaders.Set("X-HadesGate-Sensitive-Count", strconv.Itoa(len(collectedEntities)))
		forwardHeaders = enrichedHeaders

		// Inject enriched local reasoning instructions to guide the on-premise model
		localInstruction := BuildLocalReasoningInstruction(collectedEntities)
		protocol.InjectChatCompletionsSystemInstruction(rawPayload, localInstruction)
	} else if totalEntitiesMasked > 0 {
		protocol.InjectChatCompletionsSystemInstruction(rawPayload, protocol.PlaceholderSystemInstruction)
	}

	// Re-serialize sanitized payload
	sanitizedBytes, err := json.Marshal(rawPayload)
	if err != nil {
		statusCode = http.StatusInternalServerError
		http.Error(w, `{"error":{"message":"Failed to serialize sanitized request"}}`, statusCode)
		return
	}

	// 6. Initialize streaming detokenizer for this response
	detok := stream.NewDetokenizer(sessionID, g.engine.Vault())

	if isMock {
		if isStreaming {
			pr, pw := io.Pipe()
			go func() {
				g.mock.GenerateStream(pw, sessionID, modelName, lastUserPrompt, tokenMap)
				pw.Close()
			}()
			if g.upstream != nil {
				if err := g.upstream.HandleStreamingResponse(pr, detok, w); err != nil {
					statusCode = http.StatusInternalServerError
					http.Error(w, err.Error(), statusCode)
				}
			} else {
				u := NewUpstreamDispatcher(UpstreamConfig{})
				_ = u.HandleStreamingResponse(pr, detok, w)
			}
		} else {
			g.sendMockNonStreamingResponse(w, sessionID, modelName, tokenMap, detok)
		}
		return
	}

	// 7. Forward to real upstream LLM
	if err := g.upstream.ForwardRequest(r.Context(), targetURL, apiKey, sanitizedBytes, isStreaming, detok, w, forwardHeaders); err != nil {
		statusCode = http.StatusBadGateway
		http.Error(w, fmt.Sprintf(`{"error":{"message":"%s"}}`, err.Error()), statusCode)
		return
	}

	_ = start // can be used for latency metrics
}

func newRequestID() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return "req_" + hex.EncodeToString(random[:]), nil
}

func (g *Gateway) sendMockNonStreamingResponse(w http.ResponseWriter, reqID, model string, tokens map[string]string, detok *stream.Detokenizer) {
	var tokenMentions []string
	for tok := range tokens {
		tokenMentions = append(tokenMentions, tok)
	}

	content := "Recebido com sucesso! "
	if len(tokenMentions) > 0 {
		content += fmt.Sprintf("Processamos os dados: %s. ", strings.Join(tokenMentions, " e "))
	}
	content += "Operação concluída em conformidade com a LGPD."

	if detok != nil {
		content = detok.Feed(content) + detok.Flush()
	}

	resp := map[string]interface{}{
		"id":      fmt.Sprintf("chatcmpl-mock-%s", reqID),
		"object":  "chat.completion",
		"created": time.Now().Unix(),
		"model":   model,
		"choices": []map[string]interface{}{
			{
				"index": 0,
				"message": map[string]string{
					"role":    "assistant",
					"content": content,
				},
				"finish_reason": "stop",
			},
		},
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(resp)
}

// HandleModels returns available models, querying upstream router if configured.
func (g *Gateway) HandleModels(w http.ResponseWriter, r *http.Request) {
	if g.proxyAuthRequired() && !g.authenticate(r) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		w.Write([]byte(`{"error":{"message":"Invalid or missing API key","type":"auth_error"}}`))
		return
	}

	// Try querying upstream models if router/upstream is configured
	if g.upstream != nil {
		if data, err := g.upstream.FetchModels(r.Context(), r); err == nil && len(data) > 0 {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			w.Write(data)
			return
		}
	}

	models := map[string]interface{}{
		"object": "list",
		"data": []map[string]interface{}{
			{"id": "gpt-4o", "object": "model", "owned_by": "openai"},
			{"id": "gpt-4o-mini", "object": "model", "owned_by": "openai"},
			{"id": "gemini-2.5-flash", "object": "model", "owned_by": "google"},
			{"id": "gemini-2.5-pro", "object": "model", "owned_by": "google"},
			{"id": "mock", "object": "model", "owned_by": "hadesgate"},
			{"id": "ollama/llama3", "object": "model", "owned_by": "ollama"},
		},
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models)
}

// BuildLocalReasoningInstruction formats an audit directive informing an on-premise local LLM
// of the sensitive data families and entities detected by HadesGate.
func BuildLocalReasoningInstruction(entities []anonymizer.DetectedEntity) string {
	if len(entities) == 0 {
		return protocol.PlaceholderSystemInstruction
	}

	familySet := make(map[anonymizer.Family]bool)
	var details []string

	for _, ent := range entities {
		fam := anonymizer.FamilyForEntity(ent.Type)
		familySet[fam] = true

		detail := fmt.Sprintf("- Token: %s | Família: %s | Tipo: %s", ent.Token, fam, ent.Type)
		if ent.SubType != "" {
			detail += fmt.Sprintf(" (%s)", ent.SubType)
		}
		if len(ent.ContextFound) > 0 {
			detail += fmt.Sprintf(" | Contexto: [%s]", strings.Join(ent.ContextFound, ", "))
		}
		details = append(details, detail)
	}

	var famList []string
	for f := range familySet {
		famList = append(famList, string(f))
	}
	sort.Strings(famList)

	return fmt.Sprintf(`[HADESGATE // ROTEAMENTO LOCAL DE PRIVACIDADE // ZERO-PII ON-PREMISE]
Esta requisição foi desviada para este modelo local sob a política de segurança 'route_local', pois contém dados sensíveis que não podem transitar em nuvem pública:
- Macro-Famílias Detectadas: %s
- Entidades Identificadas no Contexto:
%s

Diretrizes para o Modelo Local:
1. Trate os tokens [HG_...] como dados operacionais reais em seu perímetro seguro e isolado.
2. Utilize as informações de família e contexto acima para avaliar se o dado se enquadra de fato no escopo da operação solicitada pelo usuário.
3. Cumpra a solicitação com máxima acurácia analítica mantendo os mesmos identificadores na resposta para restauração transparente.`,
		strings.Join(famList, ", "),
		strings.Join(details, "\n"),
	)
}

// clientIP prefers the first X-Forwarded-For hop, which is the real client
// behind a reverse proxy. The header is client-controlled when the gateway is
// exposed directly, so it is telemetry only.
func clientIP(r *http.Request) string {
	if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
		if first := strings.TrimSpace(strings.Split(forwarded, ",")[0]); first != "" {
			return first
		}
	}
	return r.RemoteAddr
}
