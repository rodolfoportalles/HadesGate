package proxy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/hadesgate/hadesgate/internal/anonymizer"
	"github.com/hadesgate/hadesgate/internal/protocol"
	"github.com/hadesgate/hadesgate/internal/stream"
	"github.com/hadesgate/hadesgate/internal/webhook"
)

// UpstreamConfig holds configuration for upstream LLM providers.
type UpstreamConfig struct {
	DefaultProvider             string
	OpenAIBaseURL               string
	OpenAIKey                   string
	AnthropicURL                string
	AnthropicKey                string
	GeminiURL                   string
	GeminiKey                   string
	OllamaBaseURL               string
	AdminKey                    string
	Timeout                     time.Duration
	AllowDynamicUpstream        bool
	AllowPrivateDynamicUpstream bool
	DynamicUpstreamAllowedHosts []string
	PrivateUpstreamAllowedHosts []string
	MaxResponseBytes            int64
	MaxSSEEventBytes            int
	EnableEgressScan            bool
	Engine                      *anonymizer.Engine
	Webhook                     *webhook.Dispatcher
}

// UpstreamDispatcher routes and proxies requests to the appropriate upstream LLM.
type UpstreamDispatcher struct {
	cfg                  UpstreamConfig
	httpClient           *http.Client
	lookupIP             lookupIPFunc
	privateUpstreamHosts map[string]struct{}
	enableEgressScan     atomic.Bool
	ollamaBaseURL        atomic.Value
}

// NewUpstreamDispatcher creates a new UpstreamDispatcher.
func NewUpstreamDispatcher(cfg UpstreamConfig) *UpstreamDispatcher {
	if cfg.OpenAIBaseURL == "" {
		cfg.OpenAIBaseURL = "https://api.openai.com/v1"
	}
	if cfg.GeminiURL == "" {
		cfg.GeminiURL = "https://generativelanguage.googleapis.com"
	}
	if cfg.OllamaBaseURL == "" {
		cfg.OllamaBaseURL = "http://localhost:11434/v1"
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 120 * time.Second
	}
	if cfg.MaxResponseBytes <= 0 {
		cfg.MaxResponseBytes = 20 << 20
	}
	if cfg.MaxSSEEventBytes <= 0 {
		cfg.MaxSSEEventBytes = 1 << 20
	}

	dispatcher := &UpstreamDispatcher{
		cfg:                  cfg,
		lookupIP:             net.DefaultResolver.LookupIPAddr,
		privateUpstreamHosts: privateUpstreamHostSet(cfg),
	}
	dispatcher.enableEgressScan.Store(cfg.EnableEgressScan)
	dispatcher.ollamaBaseURL.Store(cfg.OllamaBaseURL)
	dispatcher.httpClient = &http.Client{
		Timeout:       cfg.Timeout,
		CheckRedirect: RejectRedirects,
		Transport: &http.Transport{
			DialContext:         dispatcher.dialContext,
			ForceAttemptHTTP2:   true,
			MaxIdleConns:        100,
			MaxIdleConnsPerHost: 20,
			IdleConnTimeout:     90 * time.Second,
		},
	}
	return dispatcher
}

// isMatchingAdminKey checks if the authorization token matches PrivaGate's admin key.
func isMatchingAdminKey(authHeader, adminKey string) bool {
	if adminKey == "" {
		return false
	}
	token := trimBearer(authHeader)
	return subtle.ConstantTimeCompare([]byte(token), []byte(adminKey)) == 1
}

// ResolveTarget determines where to send the request based on model, headers, and config.
func (u *UpstreamDispatcher) ResolveTarget(r *http.Request, model string) (targetURL, apiKey string, isMock bool, err error) {
	return u.ResolveTargetForEndpoint(r, model, "/chat/completions")
}

// ResolveTargetForEndpoint resolves an OpenAI-compatible endpoint.
func (u *UpstreamDispatcher) ResolveTargetForEndpoint(r *http.Request, model, endpoint string) (targetURL, apiKey string, isMock bool, err error) {
	authHeader := r.Header.Get("Authorization")
	upstreamKey := r.Header.Get("X-Upstream-Key")

	// Determine upstream authorization key
	var key string
	if upstreamKey != "" {
		key = upstreamKey
		if !strings.HasPrefix(key, "Bearer ") {
			key = "Bearer " + key
		}
	} else if u.cfg.AdminKey != "" && isMatchingAdminKey(authHeader, u.cfg.AdminKey) {
		// Client authenticated using PrivaGate's admin key; don't leak it upstream
		if u.cfg.OpenAIKey != "" {
			key = "Bearer " + u.cfg.OpenAIKey
		}
	} else if authHeader != "" {
		key = authHeader
	} else if u.cfg.OpenAIKey != "" {
		key = "Bearer " + u.cfg.OpenAIKey
	}

	// 1. Check custom override header (e.g. X-Upstream-Url: http://localhost:20128/v1)
	if custom := r.Header.Get("X-Upstream-Url"); custom != "" {
		validated, validationErr := u.validateDynamicUpstream(r.Context(), custom)
		if validationErr != nil {
			return "", "", false, validationErr
		}
		trimmed := strings.TrimRight(validated, "/")
		if !strings.HasSuffix(trimmed, endpoint) {
			trimmed += endpoint
		}
		return trimmed, key, false, nil
	}

	// 2. Check model prefix or mock
	if model == "mock" || strings.HasPrefix(model, "mock/") {
		return "", "", true, nil
	}

	if strings.HasPrefix(model, "ollama/") {
		return strings.TrimRight(u.ollamaURL(), "/") + endpoint, "", false, nil
	}

	isDefaultOpenAI := u.cfg.OpenAIBaseURL == "" || u.cfg.OpenAIBaseURL == "https://api.openai.com/v1"
	lowerModel := strings.ToLower(strings.TrimSpace(model))
	isGeminiModel := strings.HasPrefix(lowerModel, "gemini-") || strings.HasPrefix(lowerModel, "gemini/")
	isDefaultGeminiURL := u.cfg.GeminiURL == "" || geminiRootURL(u.cfg.GeminiURL) == "https://generativelanguage.googleapis.com"

	if isGeminiModel && (u.cfg.GeminiKey != "" || !isDefaultGeminiURL || isDefaultOpenAI) {
		var geminiBearer string
		if upstreamKey != "" {
			geminiBearer = upstreamKey
			if !strings.HasPrefix(geminiBearer, "Bearer ") {
				geminiBearer = "Bearer " + geminiBearer
			}
		} else if u.cfg.GeminiKey != "" {
			geminiBearer = "Bearer " + u.cfg.GeminiKey
		} else if u.cfg.AdminKey == "" && authHeader != "" {
			geminiBearer = authHeader
		}
		if geminiBearer == "" {
			return "", "", false, fmt.Errorf("gemini provider is not configured")
		}
		return geminiRootURL(u.cfg.GeminiURL) + "/v1beta/openai" + endpoint, geminiBearer, false, nil
	}

	if isDefaultOpenAI && strings.HasPrefix(model, "groq/") {
		return "https://api.groq.com/openai/v1" + endpoint, key, false, nil
	}

	// Fallback to mock only if default cloud OpenAI is configured with no API key anywhere
	if isDefaultOpenAI && key == "" {
		return "", "", true, nil
	}

	baseURL := strings.TrimRight(u.cfg.OpenAIBaseURL, "/")
	if !strings.HasSuffix(baseURL, endpoint) {
		baseURL += endpoint
	}

	return baseURL, key, false, nil
}

func (u *UpstreamDispatcher) validateDynamicUpstream(ctx context.Context, raw string) (string, error) {
	if !u.cfg.AllowDynamicUpstream {
		return "", fmt.Errorf("dynamic upstream override is disabled")
	}

	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || parsed.Host == "" {
		return "", fmt.Errorf("invalid dynamic upstream URL")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return "", fmt.Errorf("dynamic upstream scheme must be http or https")
	}
	if parsed.User != nil {
		return "", fmt.Errorf("dynamic upstream URL must not contain userinfo")
	}
	if parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("dynamic upstream URL must not contain query parameters or fragments")
	}

	targetHost := strings.ToLower(parsed.Host)
	for _, allowed := range u.cfg.DynamicUpstreamAllowedHosts {
		if strings.ToLower(strings.TrimSpace(allowed)) == targetHost {
			addresses, resolveErr := u.resolveHost(ctx, parsed.Hostname())
			if resolveErr != nil {
				return "", fmt.Errorf("resolving dynamic upstream host: %w", resolveErr)
			}
			allowPrivate := u.cfg.AllowPrivateDynamicUpstream && u.isPrivateUpstreamAllowed(parsed.Hostname(), effectivePort(parsed))
			if validationErr := validateResolvedAddresses(addresses, allowPrivate); validationErr != nil {
				return "", validationErr
			}
			return parsed.String(), nil
		}
	}

	return "", fmt.Errorf("dynamic upstream host %q is not allowed", parsed.Host)
}

// ForwardRequest sends the sanitized request to the upstream LLM and detokenizes the response.
func (u *UpstreamDispatcher) ForwardRequest(
	ctx context.Context,
	targetURL, apiKey string,
	reqBody []byte,
	isStreaming bool,
	detok *stream.Detokenizer,
	w http.ResponseWriter,
	inHeaders http.Header,
) error {
	return u.forwardRequest(ctx, targetURL, apiKey, reqBody, isStreaming, detok, w, inHeaders, "chat", "Authorization")
}

// ForwardResponsesRequest forwards an OpenAI Responses/Codex request.
func (u *UpstreamDispatcher) ForwardResponsesRequest(
	ctx context.Context,
	targetURL, apiKey string,
	reqBody []byte,
	isStreaming bool,
	detok *stream.Detokenizer,
	w http.ResponseWriter,
	inHeaders http.Header,
) error {
	return u.forwardRequest(ctx, targetURL, apiKey, reqBody, isStreaming, detok, w, inHeaders, "responses", "Authorization")
}

// ForwardAnthropicRequest forwards an Anthropic Messages request.
func (u *UpstreamDispatcher) ForwardAnthropicRequest(ctx context.Context, targetURL, apiKey string, reqBody []byte, isStreaming bool, detok *stream.Detokenizer, w http.ResponseWriter, inHeaders http.Header) error {
	return u.forwardRequest(ctx, targetURL, apiKey, reqBody, isStreaming, detok, w, inHeaders, "anthropic", "X-API-Key")
}

// ForwardGeminiRequest forwards a Google Gemini generateContent or streamGenerateContent request.
func (u *UpstreamDispatcher) ForwardGeminiRequest(ctx context.Context, targetURL, apiKey string, reqBody []byte, isSSE bool, detok *stream.Detokenizer, w http.ResponseWriter, inHeaders http.Header) error {
	return u.forwardRequest(ctx, targetURL, apiKey, reqBody, isSSE, detok, w, inHeaders, "gemini", "x-goog-api-key")
}

// ResolveAnthropicTarget returns the configured Anthropic Messages endpoint.
func (u *UpstreamDispatcher) ResolveAnthropicTarget() (string, string, error) {
	return u.ResolveAnthropicTargetForKey("")
}

// ResolveAnthropicTargetForKey resolves Anthropic using a registered BYOK key
// when present, falling back to the server-managed credential.
func (u *UpstreamDispatcher) ResolveAnthropicTargetForKey(providerKey string) (string, string, error) {
	base := strings.TrimRight(u.cfg.AnthropicURL, "/")
	if base == "" {
		base = "https://api.anthropic.com"
	}
	key := strings.TrimSpace(providerKey)
	if key == "" {
		key = u.cfg.AnthropicKey
	}
	if key == "" {
		return "", "", fmt.Errorf("anthropic provider is not configured")
	}
	if !strings.HasSuffix(base, "/v1/messages") {
		base += "/v1/messages"
	}
	return base, key, nil
}

// ResolveGeminiTarget returns the configured Google Gemini native endpoint and API key.
func (u *UpstreamDispatcher) ResolveGeminiTarget(r *http.Request, model, action string, isSSE bool) (string, string, error) {
	key := strings.TrimSpace(r.Header.Get("X-Upstream-Key"))
	if key != "" {
		key = trimBearer(key)
	} else if u.cfg.GeminiKey != "" {
		key = u.cfg.GeminiKey
	} else if u.cfg.AdminKey == "" {
		key = strings.TrimSpace(r.Header.Get("X-Goog-Api-Key"))
	}
	if key == "" {
		return "", "", fmt.Errorf("gemini provider is not configured")
	}

	target := fmt.Sprintf("%s/v1beta/models/%s:%s", geminiRootURL(u.cfg.GeminiURL), url.PathEscape(model), action)
	if isSSE {
		target += "?alt=sse"
	}
	return target, key, nil
}

func geminiRootURL(raw string) string {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return "https://generativelanguage.googleapis.com"
	}
	base = strings.TrimSuffix(base, "/openai")
	base = strings.TrimSuffix(base, "/v1beta")
	return strings.TrimRight(base, "/")
}

// ResolveLocalTarget returns the explicitly configured local OpenAI-compatible endpoint.
func (u *UpstreamDispatcher) ResolveLocalTarget(endpoint string) string {
	base := strings.TrimRight(u.ollamaURL(), "/")
	if !strings.HasSuffix(base, endpoint) {
		base += endpoint
	}
	return base
}

func (u *UpstreamDispatcher) forwardRequest(
	ctx context.Context,
	targetURL, apiKey string,
	reqBody []byte,
	isStreaming bool,
	detok *stream.Detokenizer,
	w http.ResponseWriter,
	inHeaders http.Header,
	streamProtocol string,
	authHeaderName string,
) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, targetURL, bytes.NewReader(reqBody))
	if err != nil {
		return fmt.Errorf("creating upstream request: %w", err)
	}

	// Forward client custom headers (routing tags, referers, etc.)
	for hk, vals := range inHeaders {
		lower := strings.ToLower(hk)
		if lower == "authorization" || lower == "content-type" || lower == "content-length" ||
			lower == "host" || lower == "x-api-key" || lower == "x-goog-api-key" || lower == "x-session-id" ||
			lower == "x-upstream-url" || lower == "x-upstream-key" ||
			lower == "accept-encoding" || lower == "origin" || lower == "referer" ||
			lower == "sec-fetch-mode" || lower == "sec-fetch-site" || lower == "sec-fetch-dest" {
			continue
		}
		for _, val := range vals {
			req.Header.Add(hk, val)
		}
	}

	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Content-Type", "application/json")
	if apiKey != "" {
		req.Header.Set(authHeaderName, apiKey)
	}
	if streamProtocol == "anthropic" {
		if req.Header.Get("Anthropic-Version") == "" {
			req.Header.Set("Anthropic-Version", "2023-06-01")
		}
		req.Header.Set("Anthropic-Dangerous-Direct-Browser-Access", "true")
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("upstream request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, err := readLimitedBody(resp.Body, u.cfg.MaxResponseBytes)
		if err != nil {
			return fmt.Errorf("reading upstream error response: %w", err)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return nil
	}

	if isStreaming {
		if streamProtocol != "chat" {
			return u.HandleGenericStreamingResponse(resp.Body, detok, w, streamProtocol)
		}
		return u.HandleStreamingResponse(resp.Body, detok, w)
	}

	return u.HandleNonStreamingResponse(resp.Body, detok, w)
}

// HandleGenericStreamingResponse preserves provider events while restoring text deltas.
func (u *UpstreamDispatcher) HandleGenericStreamingResponse(upstreamBody io.Reader, detok *stream.Detokenizer, w http.ResponseWriter, streamProtocol string) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming not supported by response writer")
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	state, filterFactory := u.streamingEgressFilterFactory(detok, w)
	var egressFilter stream.FragmentFilter
	if filterFactory != nil {
		egressFilter = filterFactory()
	}
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	scanner := bufio.NewScanner(upstreamBody)
	initialBufferSize := 64 << 10
	if u.cfg.MaxSSEEventBytes < initialBufferSize {
		initialBufferSize = u.cfg.MaxSSEEventBytes
	}
	scanner.Buffer(make([]byte, initialBufferSize), u.cfg.MaxSSEEventBytes)

	sawDone := false
	for scanner.Scan() {
		line := scanner.Text()
		if !strings.HasPrefix(line, "data:") {
			fmt.Fprintln(w, line)
			flusher.Flush()
			continue
		}
		data := strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		if data == "[DONE]" {
			sawDone = true
			pending := detok.Flush()
			if egressFilter != nil {
				pending = egressFilter.Feed(pending) + egressFilter.Flush()
			}
			if pending != "" {
				flushEvent := buildGenericFlushEvent(streamProtocol, pending)
				encoded, _ := json.Marshal(flushEvent)
				fmt.Fprintf(w, "data: %s\n\n", encoded)
			}
			fmt.Fprintln(w, "data: [DONE]")
			flusher.Flush()
			continue
		}

		var event interface{}
		decoder := json.NewDecoder(strings.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&event); err != nil {
			fmt.Fprintln(w, line)
			flusher.Flush()
			continue
		}
		transform := detok.Feed
		if egressFilter != nil {
			transform = func(text string) string {
				return egressFilter.Feed(detok.Feed(text))
			}
		}
		protocol.TransformStreamingEvent(event, transform)
		encoded, err := json.Marshal(event)
		if err != nil {
			return err
		}
		fmt.Fprintf(w, "data: %s\n", encoded)
		flusher.Flush()
	}
	if err := scanner.Err(); err != nil {
		return err
	}
	if !sawDone {
		pending := detok.Flush()
		if egressFilter != nil {
			pending = egressFilter.Feed(pending) + egressFilter.Flush()
		}
		if pending != "" {
			flushEvent := buildGenericFlushEvent(streamProtocol, pending)
			if encoded, err := json.Marshal(flushEvent); err == nil {
				fmt.Fprintf(w, "data: %s\n\n", encoded)
				flusher.Flush()
			}
		}
	}
	u.finishStreamingEgress(state, w)
	return nil
}

func buildGenericFlushEvent(streamProtocol, pending string) map[string]interface{} {
	switch streamProtocol {
	case "anthropic":
		return map[string]interface{}{
			"type":  "content_block_delta",
			"index": 0,
			"delta": map[string]interface{}{"type": "text_delta", "text": pending},
		}
	case "gemini":
		return map[string]interface{}{
			"candidates": []interface{}{
				map[string]interface{}{
					"content": map[string]interface{}{
						"role":  "model",
						"parts": []interface{}{map[string]interface{}{"text": pending}},
					},
					"index": 0,
				},
			},
		}
	default:
		return map[string]interface{}{
			"type":  "response.output_text.delta",
			"delta": pending,
		}
	}
}

// FetchModels queries the upstream /models endpoint if configured.
func (u *UpstreamDispatcher) FetchModels(ctx context.Context, r *http.Request) ([]byte, error) {
	isDefaultOpenAI := u.cfg.OpenAIBaseURL == "" || u.cfg.OpenAIBaseURL == "https://api.openai.com/v1"
	authHeader := r.Header.Get("Authorization")
	upstreamKey := r.Header.Get("X-Upstream-Key")

	var key string
	if upstreamKey != "" {
		key = upstreamKey
		if !strings.HasPrefix(key, "Bearer ") {
			key = "Bearer " + key
		}
	} else if u.cfg.AdminKey != "" && isMatchingAdminKey(authHeader, u.cfg.AdminKey) {
		if u.cfg.OpenAIKey != "" {
			key = "Bearer " + u.cfg.OpenAIKey
		}
	} else if authHeader != "" {
		key = authHeader
	} else if u.cfg.OpenAIKey != "" {
		key = "Bearer " + u.cfg.OpenAIKey
	}

	if isDefaultOpenAI && key == "" {
		return nil, fmt.Errorf("no api key available for default openai upstream")
	}

	baseURL := strings.TrimRight(u.cfg.OpenAIBaseURL, "/")
	modelsURL := baseURL + "/models"

	client := &http.Client{Timeout: 4 * time.Second}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, modelsURL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating upstream models request: %w", err)
	}

	if key != "" {
		req.Header.Set("Authorization", key)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("upstream models request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("upstream models returned status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

// HandleStreamingResponse processes upstream SSE chunks, detokenizing with sliding-window buffer.
func (u *UpstreamDispatcher) HandleStreamingResponse(upstreamBody io.Reader, detok *stream.Detokenizer, w http.ResponseWriter) error {
	flusher, ok := w.(http.Flusher)
	if !ok {
		return fmt.Errorf("streaming not supported by response writer")
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	state, filterFactory := u.streamingEgressFilterFactory(detok, w)
	w.WriteHeader(http.StatusOK)
	flusher.Flush()

	processor := stream.NewSSEProcessorWithFilter(detok, filterFactory)
	scanner := bufio.NewScanner(upstreamBody)
	initialBufferSize := 64 << 10
	if u.cfg.MaxSSEEventBytes < initialBufferSize {
		initialBufferSize = u.cfg.MaxSSEEventBytes
	}
	scanner.Buffer(make([]byte, initialBufferSize), u.cfg.MaxSSEEventBytes)

	for scanner.Scan() {
		line := scanner.Text()
		outputLines := processor.ProcessLine(line)
		for _, out := range outputLines {
			if out == "" {
				fmt.Fprint(w, "\n")
			} else {
				fmt.Fprintf(w, "%s\n", out)
			}
		}
		flusher.Flush()
	}

	if err := scanner.Err(); err != nil {
		return err
	}
	for _, out := range processor.Flush() {
		if out == "" {
			fmt.Fprint(w, "\n")
		} else {
			fmt.Fprintf(w, "%s\n", out)
		}
	}
	flusher.Flush()
	u.finishStreamingEgress(state, w)
	return nil
}

type streamingEgressState struct {
	detected    bool
	entityTypes []string
}

func (u *UpstreamDispatcher) streamingEgressFilterFactory(detok *stream.Detokenizer, w http.ResponseWriter) (*streamingEgressState, stream.FragmentFilterFactory) {
	if !u.enableEgressScan.Load() || u.cfg.Engine == nil || detok == nil {
		return nil, nil
	}

	w.Header().Add("Trailer", "X-HadesGate-Egress-Detected")
	state := &streamingEgressState{}
	known := detok.GetKnownPlaintexts()
	return state, func() stream.FragmentFilter {
		return &egressStreamFilter{
			engine:          u.cfg.Engine,
			knownPlaintexts: known,
			onDetected: func(entities []anonymizer.DetectedEntity) {
				state.detected = true
				for _, entity := range entities {
					state.entityTypes = append(state.entityTypes, string(entity.Type))
				}
			},
		}
	}
}

func (u *UpstreamDispatcher) finishStreamingEgress(state *streamingEgressState, w http.ResponseWriter) {
	if state == nil || !state.detected {
		return
	}
	w.Header().Set("X-HadesGate-Egress-Detected", "true")
	if u.cfg.Webhook != nil {
		u.cfg.Webhook.Dispatch(webhook.Event{
			Event:           "egress_leak",
			Action:          "egress_masked",
			BlockedEntities: state.entityTypes,
			Details:         "Unmapped sensitive data leaked in an LLM stream was detected and masked",
		})
	}
}

// HandleNonStreamingResponse detokenizes non-streaming responses.
func (u *UpstreamDispatcher) HandleNonStreamingResponse(upstreamBody io.Reader, detok *stream.Detokenizer, w http.ResponseWriter) error {
	body, err := readLimitedBody(upstreamBody, u.cfg.MaxResponseBytes)
	if err != nil {
		return err
	}

	var decoded interface{}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()
	if err := decoder.Decode(&decoded); err != nil {
		return fmt.Errorf("decoding upstream JSON response: %w", err)
	}
	if arr, isArray := decoded.([]interface{}); isArray {
		protocol.TransformStreamingEvent(arr, detok.Feed)
		if pending := detok.Flush(); pending != "" {
			arr = append(arr, buildGenericFlushEvent("gemini", pending))
			decoded = arr
		}
	} else {
		protocol.TransformAllResponseStrings(decoded, detok.Restore)
	}

	// Optional Egress DLP Scanning
	if u.enableEgressScan.Load() && u.cfg.Engine != nil && detok != nil {
		known := detok.GetKnownPlaintexts()
		egressDetected := false
		var leakedEntities []string
		protocol.TransformAllResponseStrings(decoded, func(str string) string {
			res := u.cfg.Engine.ScanEgress(known, str)
			if len(res.LeakedEntities) > 0 {
				egressDetected = true
				for _, le := range res.LeakedEntities {
					leakedEntities = append(leakedEntities, string(le.Type))
				}
			}
			return res.SanitizedText
		})
		if egressDetected {
			w.Header().Set("X-HadesGate-Egress-Detected", "true")
			if u.cfg.Webhook != nil {
				u.cfg.Webhook.Dispatch(webhook.Event{
					Event:           "egress_leak",
					Action:          "egress_masked",
					BlockedEntities: leakedEntities,
					Details:         "Unmapped sensitive data leaked in LLM response was detected and masked",
				})
			}
		}
	}

	detokenized, err := json.Marshal(decoded)
	if err != nil {
		return fmt.Errorf("encoding restored upstream response: %w", err)
	}

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	_, err = w.Write(detokenized)
	return err
}

func readLimitedBody(r io.Reader, maxBytes int64) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r, maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > maxBytes {
		return nil, fmt.Errorf("response exceeds %d byte limit", maxBytes)
	}
	return body, nil
}

// RequestPayload represents the minimal OpenAI chat request JSON.
type RequestPayload struct {
	Model    string        `json:"model"`
	Messages []ChatMessage `json:"messages"`
	Stream   bool          `json:"stream"`
	// Preserve other fields
	Extra map[string]interface{} `json:"-"`
}

// ChatMessage represents a single message in the chat conversation.
type ChatMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

// SetEnableEgressScan updates the egress scanning flag at runtime.
func (u *UpstreamDispatcher) SetEnableEgressScan(enabled bool) {
	if u != nil {
		u.enableEgressScan.Store(enabled)
	}
}

// SetOllamaBaseURL updates the local Ollama/agents base URL at runtime.
func (u *UpstreamDispatcher) SetOllamaBaseURL(url string) {
	if u != nil {
		u.ollamaBaseURL.Store(url)
	}
}

func (u *UpstreamDispatcher) ollamaURL() string {
	if value := u.ollamaBaseURL.Load(); value != nil {
		return value.(string)
	}
	return ""
}
