package proxy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/hadesgate/hadesgate/internal/anonymizer"
	"github.com/hadesgate/hadesgate/internal/anonymizer/vault"
	"github.com/hadesgate/hadesgate/internal/observability"
	"github.com/hadesgate/hadesgate/internal/protocol"
	"github.com/hadesgate/hadesgate/internal/webhook"
)

func newTestGateway(proxyKey string, upstream *UpstreamDispatcher) *Gateway {
	memVault := vault.NewMemoryVault(time.Minute)
	anonCfg := anonymizer.DefaultConfig()
	engine := anonymizer.NewEngine(anonCfg, memVault)
	traces := observability.NewTraceLogger(100)
	return NewGatewayWithOptions(engine, upstream, traces, GatewayOptions{GlobalProxyKey: proxyKey})
}

func TestGateway_AdminKeyCannotAuthenticateModelProxy(t *testing.T) {
	v := vault.NewMemoryVault(time.Minute)
	t.Cleanup(v.Close)
	eng := anonymizer.NewEngine(anonymizer.DefaultConfig(), v)
	traces := observability.NewTraceLogger(10)
	t.Cleanup(func() { _ = traces.Close() })
	gw := NewGatewayWithOptions(eng, nil, traces, GatewayOptions{
		GlobalProxyKey: "model-proxy-secret",
	})
	body := `{"model":"mock","messages":[{"role":"user","content":"hello"}]}`

	adminReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	adminReq.Header.Set("Authorization", "Bearer admin-only-secret")
	adminW := httptest.NewRecorder()
	gw.HandleChatCompletions(adminW, adminReq)
	if adminW.Code != http.StatusUnauthorized {
		t.Fatalf("admin key authenticated model proxy: got %d, want 401", adminW.Code)
	}

	proxyReq := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	proxyReq.Header.Set("Authorization", "Bearer model-proxy-secret")
	proxyW := httptest.NewRecorder()
	gw.HandleChatCompletions(proxyW, proxyReq)
	if proxyW.Code != http.StatusOK {
		t.Fatalf("proxy key did not authenticate model proxy: got %d: %s", proxyW.Code, proxyW.Body.String())
	}
}

func TestGatewayHandleModels(t *testing.T) {
	gw := newTestGateway("secret-key", nil)

	// Case 1: Unauthorized
	reqUnauth := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	wUnauth := httptest.NewRecorder()
	gw.HandleModels(wUnauth, reqUnauth)
	if wUnauth.Code != http.StatusUnauthorized {
		t.Errorf("HandleModels() without auth got %d, want %d", wUnauth.Code, http.StatusUnauthorized)
	}

	// Case 2: Authorized fallback to static list
	reqAuth := httptest.NewRequest(http.MethodGet, "/v1/models", nil)
	reqAuth.Header.Set("Authorization", "Bearer secret-key")
	wAuth := httptest.NewRecorder()
	gw.HandleModels(wAuth, reqAuth)
	if wAuth.Code != http.StatusOK {
		t.Errorf("HandleModels() with auth got %d, want %d", wAuth.Code, http.StatusOK)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(wAuth.Body.Bytes(), &res); err != nil {
		t.Fatalf("HandleModels() invalid JSON: %v", err)
	}
	data, ok := res["data"].([]interface{})
	if !ok || len(data) == 0 {
		t.Errorf("HandleModels() expected non-empty models array")
	}
}

func TestGatewayHandleChatCompletionsMock(t *testing.T) {
	gw := newTestGateway("secret-key", nil)

	payload := map[string]interface{}{
		"model": "mock",
		"messages": []map[string]string{
			{
				"role":    "user",
				"content": "Meu CPF é 529.982.247-25 e meu nome é João Silva",
			},
		},
	}
	body, _ := json.Marshal(payload)

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("HandleChatCompletions() got status %d, want 200", w.Code)
	}

	var res map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &res); err != nil {
		t.Fatalf("Failed to parse response JSON: %v", err)
	}

	choices, ok := res["choices"].([]interface{})
	if !ok || len(choices) == 0 {
		t.Fatalf("Expected choices in response")
	}
	choice := choices[0].(map[string]interface{})
	msg := choice["message"].(map[string]interface{})
	content := msg["content"].(string)

	if content == "" {
		t.Errorf("Expected content in response message")
	}

	if requestID := w.Header().Get("X-HadesGate-Request-ID"); requestID == "" {
		t.Error("expected X-HadesGate-Request-ID response header")
	}
	if active := gw.engine.Vault().ActiveSessionsCount(); active != 0 {
		t.Fatalf("request-scoped vault was not purged, active sessions: %d", active)
	}

	traces, err := json.Marshal(gw.traces.GetAll())
	if err != nil {
		t.Fatalf("failed to marshal traces: %v", err)
	}
	if bytes.Contains(traces, []byte("529.982.247-25")) {
		t.Fatal("raw PII leaked into observability traces")
	}
}

func TestGatewayRejectsDynamicUpstreamByDefault(t *testing.T) {
	upstream := NewUpstreamDispatcher(UpstreamConfig{
		OpenAIBaseURL: "https://api.openai.com/v1",
		OpenAIKey:     "configured-key",
	})
	gw := newTestGateway("secret-key", upstream)

	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"olá"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	req.Header.Set("X-Upstream-Url", "http://169.254.169.254/latest")
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusBadRequest)
	}
	if active := gw.engine.Vault().ActiveSessionsCount(); active != 0 {
		t.Fatalf("request-scoped vault was not purged, active sessions: %d", active)
	}
}

func TestGatewayRejectsWhenConcurrencyLimitIsReached(t *testing.T) {
	gw := newTestGateway("secret-key", nil)
	gw.requestSlots = make(chan struct{}, 1)
	gw.requestSlots <- struct{}{}
	defer func() { <-gw.requestSlots }()

	body := []byte(`{"model":"mock","messages":[{"role":"user","content":"olá"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("got status %d, want %d", w.Code, http.StatusTooManyRequests)
	}
	if w.Header().Get("Retry-After") != "1" {
		t.Fatal("expected Retry-After header")
	}
}

func TestGatewayResponsesMasksAndRestoresInput(t *testing.T) {
	var upstreamInput string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/responses" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		upstreamInput, _ = request["input"].(string)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "resp_1",
			"output": []interface{}{map[string]interface{}{
				"type":    "message",
				"content": []interface{}{map[string]interface{}{"type": "output_text", "text": upstreamInput}},
			}},
		})
	}))
	defer server.Close()

	upstream := NewUpstreamDispatcher(UpstreamConfig{OpenAIBaseURL: server.URL, OpenAIKey: "upstream-key"})
	gw := newTestGateway("secret-key", upstream)
	body := []byte(`{"model":"gpt-4o","input":"Contate alice@example.com","stream":false}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/responses", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	w := httptest.NewRecorder()

	gw.HandleResponses(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(upstreamInput, "alice@example.com") {
		t.Fatalf("raw email reached upstream: %s", upstreamInput)
	}
	if !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Fatalf("email was not restored in response: %s", w.Body.String())
	}
}

func TestGatewayAnthropicMasksAndRestoresContent(t *testing.T) {
	var upstreamText string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/messages" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		if r.Header.Get("X-API-Key") != "anthropic-secret" {
			t.Fatalf("Anthropic key missing")
		}
		if r.Header.Get("Anthropic-Version") == "" {
			t.Fatalf("Anthropic-Version missing")
		}
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		messages := request["messages"].([]interface{})
		upstreamText = messages[0].(map[string]interface{})["content"].(string)
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"id": "msg_1", "type": "message", "role": "assistant",
			"content": []interface{}{map[string]interface{}{"type": "text", "text": upstreamText}},
		})
	}))
	defer server.Close()

	upstream := NewUpstreamDispatcher(UpstreamConfig{AnthropicURL: server.URL, AnthropicKey: "anthropic-secret"})
	gw := newTestGateway("secret-key", upstream)
	body := []byte(`{"model":"claude-test","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/anthropic/v1/messages", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	w := httptest.NewRecorder()

	gw.HandleAnthropicMessages(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(upstreamText, "529.982.247-25") {
		t.Fatalf("raw CPF reached upstream: %s", upstreamText)
	}
	if !strings.Contains(w.Body.String(), "529.982.247-25") {
		t.Fatalf("CPF was not restored: %s", w.Body.String())
	}
}

func TestGatewayEntityPolicyBlock(t *testing.T) {
	base := newTestGateway("secret-key", nil)
	gw := NewGatewayWithOptions(base.engine, nil, base.traces, GatewayOptions{
		MaxConcurrent:  4,
		GlobalProxyKey: "secret-key",
		EntityActions:  map[string]string{"CPF": "block"},
	})
	body := []byte(`{"model":"mock","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
	if w.Header().Get("X-HadesGate-Policy-Action") != "block" {
		t.Fatalf("policy header missing: %v", w.Header())
	}
}

func TestGatewayEntityPolicyRoutesLocal(t *testing.T) {
	called := false
	var receivedHeaders http.Header
	var receivedBody map[string]interface{}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		receivedHeaders = r.Header.Clone()
		_ = json.NewDecoder(r.Body).Decode(&receivedBody)
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("unexpected local path: %s", r.URL.Path)
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []interface{}{map[string]interface{}{"message": map[string]interface{}{"role": "assistant", "content": "ok"}}},
		})
	}))
	defer server.Close()

	base := newTestGateway("secret-key", nil)
	upstream := NewUpstreamDispatcher(UpstreamConfig{
		OpenAIBaseURL: "https://cloud.invalid/v1", OpenAIKey: "cloud-key",
		OllamaBaseURL: server.URL + "/v1",
	})
	gw := NewGatewayWithOptions(base.engine, upstream, base.traces, GatewayOptions{
		MaxConcurrent:  4,
		GlobalProxyKey: "secret-key",
		EntityActions:  map[string]string{"CPF": "route_local"},
	})
	body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusOK || !called {
		t.Fatalf("local route failed, status=%d called=%v body=%s", w.Code, called, w.Body.String())
	}
	if w.Header().Get("X-HadesGate-Policy-Action") != "route_local" {
		t.Fatalf("policy header missing: %v", w.Header())
	}

	// Verify enriched headers forwarded to local upstream
	if receivedHeaders.Get("X-HadesGate-Route-Action") != "route_local" {
		t.Errorf("expected X-HadesGate-Route-Action header 'route_local', got %q", receivedHeaders.Get("X-HadesGate-Route-Action"))
	}
	if receivedHeaders.Get("X-HadesGate-Sensitive-Families") != "PERSONAL" {
		t.Errorf("expected X-HadesGate-Sensitive-Families header 'PERSONAL', got %q", receivedHeaders.Get("X-HadesGate-Sensitive-Families"))
	}
	if receivedHeaders.Get("X-HadesGate-Sensitive-Types") != "CPF" {
		t.Errorf("expected X-HadesGate-Sensitive-Types header 'CPF', got %q", receivedHeaders.Get("X-HadesGate-Sensitive-Types"))
	}

	// Verify local reasoning instruction injected into payload
	messages, _ := receivedBody["messages"].([]interface{})
	if len(messages) < 2 {
		t.Fatalf("expected at least 2 messages (system + user), got %d", len(messages))
	}
	firstMsg, _ := messages[0].(map[string]interface{})
	sysContent, _ := firstMsg["content"].(string)
	if !strings.Contains(sysContent, "ROTEAMENTO LOCAL DE PRIVACIDADE") || !strings.Contains(sysContent, "Macro-Famílias Detectadas: PERSONAL") {
		t.Errorf("expected local reasoning prompt in system message, got: %s", sysContent)
	}
}

func TestGatewayTenantScopedPolicy(t *testing.T) {
	base := newTestGateway("default-key", nil)
	gw := NewGatewayWithOptions(base.engine, nil, base.traces, GatewayOptions{
		MaxConcurrent:  4,
		GlobalProxyKey: "default-key",
		TenantKeys:     map[string]string{"regulated": "tenant-key"},
		TenantEntityActions: map[string]map[string]string{
			"regulated": {"CPF": "block"},
		},
	})
	body := []byte(`{"model":"mock","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`)

	tenantRequest := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	tenantRequest.Header.Set("Authorization", "Bearer tenant-key")
	tenantResponse := httptest.NewRecorder()
	gw.HandleChatCompletions(tenantResponse, tenantRequest)
	if tenantResponse.Code != http.StatusBadRequest {
		t.Fatalf("tenant policy was not applied: %d %s", tenantResponse.Code, tenantResponse.Body.String())
	}

	defaultRequest := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	defaultRequest.Header.Set("Authorization", "Bearer default-key")
	defaultResponse := httptest.NewRecorder()
	gw.HandleChatCompletions(defaultResponse, defaultRequest)
	if defaultResponse.Code != http.StatusOK {
		t.Fatalf("global default policy should mask: %d %s", defaultResponse.Code, defaultResponse.Body.String())
	}
}

func TestGateway_DisabledDLPActionGlobalAndTenant(t *testing.T) {
	const rawCPF = "529.982.247-25"

	requests := make(chan string, 3)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload struct {
			Messages []struct {
				Role    string `json:"role"`
				Content string `json:"content"`
			} `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Errorf("decode upstream request: %v", err)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		for _, message := range payload.Messages {
			if message.Role == "user" {
				requests <- message.Content
				break
			}
		}
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"choices": []interface{}{map[string]interface{}{
				"message": map[string]interface{}{"role": "assistant", "content": "ok"},
			}},
		})
	}))
	defer server.Close()

	newGateway := func(options GatewayOptions) *Gateway {
		v := vault.NewMemoryVault(time.Minute)
		t.Cleanup(v.Close)
		engine := anonymizer.NewEngine(anonymizer.DefaultConfig(), v)
		traces := observability.NewTraceLogger(10)
		t.Cleanup(func() { _ = traces.Close() })
		upstream := NewUpstreamDispatcher(UpstreamConfig{OpenAIBaseURL: server.URL, OpenAIKey: "upstream-key"})
		return NewGatewayWithOptions(engine, upstream, traces, options)
	}

	send := func(gw *Gateway, key string) string {
		t.Helper()
		body := []byte(`{"model":"gpt-4o","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`)
		req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+key)
		w := httptest.NewRecorder()
		gw.HandleChatCompletions(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("request failed: status=%d body=%s", w.Code, w.Body.String())
		}
		return <-requests
	}

	globalGateway := newGateway(GatewayOptions{
		GlobalProxyKey: "global-key",
		EntityActions:  map[string]string{"CPF": "disabled"},
	})
	if upstreamText := send(globalGateway, "global-key"); !strings.Contains(upstreamText, rawCPF) {
		t.Fatalf("globally disabled CPF was still anonymized: %q", upstreamText)
	}
	if traces := globalGateway.Traces().GetAll(); len(traces) != 1 || traces[0].SanitizedPrompt != "" {
		t.Fatalf("plaintext-capable policy must suppress persisted prompts: %+v", traces)
	}

	tenantGateway := newGateway(GatewayOptions{
		GlobalProxyKey: "global-key",
		EntityActions:  map[string]string{"CPF": "mask"},
		TenantKeys:     map[string]string{"analytics": "tenant-key"},
		TenantEntityActions: map[string]map[string]string{
			"analytics": {"CPF": "disabled"},
		},
	})
	if upstreamText := send(tenantGateway, "tenant-key"); !strings.Contains(upstreamText, rawCPF) {
		t.Fatalf("tenant-disabled CPF was still anonymized: %q", upstreamText)
	}
	if traces := tenantGateway.Traces().GetAll(); len(traces) != 1 || traces[0].SanitizedPrompt != "" {
		t.Fatalf("tenant plaintext-capable policy must suppress persisted prompts: %+v", traces)
	}
	if upstreamText := send(tenantGateway, "global-key"); strings.Contains(upstreamText, rawCPF) {
		t.Fatalf("tenant disable leaked into global policy: %q", upstreamText)
	}
}

func TestGateway_DisabledDLPActionAppliesToStreamingRequests(t *testing.T) {
	const rawCPF = "529.982.247-25"
	var upstreamText string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var payload map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
			t.Fatalf("decode streaming upstream request: %v", err)
		}
		messages := payload["messages"].([]interface{})
		for _, rawMessage := range messages {
			message := rawMessage.(map[string]interface{})
			if message["role"] == "user" {
				upstreamText, _ = message["content"].(string)
			}
		}
		w.Header().Set("Content-Type", "text/event-stream")
		fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
	}))
	defer server.Close()

	v := vault.NewMemoryVault(time.Minute)
	defer v.Close()
	engine := anonymizer.NewEngine(anonymizer.DefaultConfig(), v)
	traces := observability.NewTraceLogger(10)
	defer traces.Close()
	upstream := NewUpstreamDispatcher(UpstreamConfig{OpenAIBaseURL: server.URL, OpenAIKey: "upstream-key"})
	gw := NewGatewayWithOptions(engine, upstream, traces, GatewayOptions{
		GlobalProxyKey: "global-key",
		EntityActions:  map[string]string{"CPF": "disabled"},
	})

	body := []byte(`{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer global-key")
	w := httptest.NewRecorder()
	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("streaming request failed: status=%d body=%s", w.Code, w.Body.String())
	}
	if !strings.Contains(upstreamText, rawCPF) {
		t.Fatalf("disabled CPF was anonymized in streaming request: %q", upstreamText)
	}
	if active := v.ActiveSessionsCount(); active != 0 {
		t.Fatalf("streaming request vault was not purged: %d active sessions", active)
	}
}

func TestGateway_ContextualHealthPolicyForStreamingAndNonStreaming(t *testing.T) {
	tests := []struct {
		name                   string
		stream                 bool
		prompt                 string
		actions                map[string]string
		medication             string
		person                 string
		wantMedicationUpstream bool
	}{
		{name: "standalone non-streaming", prompt: "Crie uma receita de Amoxicilina 500mg.", wantMedicationUpstream: true},
		{name: "linked non-streaming", prompt: "Paciente João Pedro dos Santos deve tomar Amoxicilina 500mg.", wantMedicationUpstream: false},
		{name: "standalone streaming", stream: true, prompt: "Crie uma receita de Amoxicilina 500mg.", wantMedicationUpstream: true},
		{name: "linked streaming", stream: true, prompt: "Paciente João Pedro dos Santos deve tomar Amoxicilina 500mg.", wantMedicationUpstream: false},
		{name: "explicit mask override", prompt: "Crie uma receita de Amoxicilina 500mg.", actions: map[string]string{"MEDICATION": "mask"}, wantMedicationUpstream: false},
		{name: "disabled identity still anchors health", prompt: "Paciente João Pedro dos Santos deve tomar Amoxicilina 500mg.", actions: map[string]string{"PERSON": "disabled"}, wantMedicationUpstream: false},
		{name: "fully lowercase name remains linked", prompt: "gere uma receita de dipirona 1g para roberto da silva", medication: "dipirona", person: "roberto da silva", wantMedicationUpstream: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var upstreamText string
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				var payload map[string]interface{}
				if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
					t.Fatalf("decode upstream request: %v", err)
				}
				for _, rawMessage := range payload["messages"].([]interface{}) {
					message := rawMessage.(map[string]interface{})
					if message["role"] == "user" {
						upstreamText, _ = message["content"].(string)
					}
				}
				if test.stream {
					w.Header().Set("Content-Type", "text/event-stream")
					fmt.Fprint(w, "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"ok\"}}]}\n\ndata: [DONE]\n\n")
					return
				}
				_ = json.NewEncoder(w).Encode(map[string]interface{}{"id": "chatcmpl-contextual", "choices": []interface{}{map[string]interface{}{"message": map[string]interface{}{"role": "assistant", "content": "ok"}}}})
			}))
			defer server.Close()

			v := vault.NewMemoryVault(time.Minute)
			defer v.Close()
			engine := anonymizer.NewEngine(anonymizer.DefaultConfig(), v)
			traces := observability.NewTraceLogger(10)
			defer traces.Close()
			upstream := NewUpstreamDispatcher(UpstreamConfig{OpenAIBaseURL: server.URL, OpenAIKey: "upstream-key"})
			gateway := NewGatewayWithOptions(engine, upstream, traces, GatewayOptions{GlobalProxyKey: "global-key", EntityActions: test.actions})
			body, _ := json.Marshal(map[string]interface{}{"model": "gpt-4o", "stream": test.stream, "messages": []interface{}{map[string]interface{}{"role": "user", "content": test.prompt}}})
			request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer global-key")
			response := httptest.NewRecorder()
			gateway.HandleChatCompletions(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("request failed: %d %s", response.Code, response.Body.String())
			}
			medication := test.medication
			if medication == "" {
				medication = "Amoxicilina"
			}
			containsMedication := strings.Contains(upstreamText, medication)
			if containsMedication != test.wantMedicationUpstream {
				t.Fatalf("unexpected upstream health payload %q", upstreamText)
			}
			if !test.wantMedicationUpstream && !strings.Contains(upstreamText, "[HG_") {
				t.Fatalf("protected health context did not contain placeholders: %q", upstreamText)
			}
			if test.person != "" && strings.Contains(upstreamText, test.person) {
				t.Fatalf("linked person reached upstream without masking: %q", upstreamText)
			}
			if test.person != "" && (!strings.Contains(upstreamText, "_PERSON_") || !strings.Contains(upstreamText, "_MEDICATION_")) {
				t.Fatalf("expected linked PERSON and MEDICATION placeholders upstream: %q", upstreamText)
			}
		})
	}
}

func TestGateway_PathAndKeyRouting(t *testing.T) {
	base := newTestGateway("default-key", nil)
	gw := NewGatewayWithOptions(base.engine, nil, base.traces, GatewayOptions{
		MaxConcurrent:      4,
		GlobalProxyKey:     "default-key",
		TenantKeys:         map[string]string{"financeiro": "fin-secret"},
		AllowLegacyURLKeys: true,
		TenantEntityActions: map[string]map[string]string{
			"financeiro": {"CPF": "block"},
		},
	})

	// Test AuthenticateKey
	if tenant, ok := gw.AuthenticateKey("fin-secret"); !ok || tenant != "financeiro" {
		t.Fatalf("expected fin-secret to authenticate as financeiro, got %q, %v", tenant, ok)
	}
	if tenant, ok := gw.AuthenticateKey("default-key"); !ok || tenant != "default" {
		t.Fatalf("expected default-key to authenticate as default, got %q, %v", tenant, ok)
	}
	if _, ok := gw.AuthenticateKey("wrong-key"); ok {
		t.Fatalf("expected wrong-key to fail")
	}

	// Test HandleTenantPath: /t/financeiro/v1/chat/completions with query param key
	body := []byte(`{"model":"mock","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`)
	req := httptest.NewRequest(http.MethodPost, "/t/financeiro/v1/chat/completions?key=fin-secret", bytes.NewReader(body))
	w := httptest.NewRecorder()
	gw.HandleTenantPath(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected blocked request for tenant financeiro, got %d: %s", w.Code, w.Body.String())
	}
}

func TestGatewayTenantRateLimit(t *testing.T) {
	base := newTestGateway("default-key", nil)
	gw := NewGatewayWithOptions(base.engine, nil, base.traces, GatewayOptions{
		MaxConcurrent:      4,
		GlobalProxyKey:     "default-key",
		RateLimitPerMinute: 1,
	})
	body := []byte(`{"model":"mock","messages":[{"role":"user","content":"olá"}]}`)

	firstRequest := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	firstRequest.Header.Set("Authorization", "Bearer default-key")
	firstResponse := httptest.NewRecorder()
	gw.HandleChatCompletions(firstResponse, firstRequest)
	if firstResponse.Code != http.StatusOK {
		t.Fatalf("first request failed: %d", firstResponse.Code)
	}

	secondRequest := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	secondRequest.Header.Set("Authorization", "Bearer default-key")
	secondResponse := httptest.NewRecorder()
	gw.HandleChatCompletions(secondResponse, secondRequest)
	if secondResponse.Code != http.StatusTooManyRequests {
		t.Fatalf("second request got %d, want 429", secondResponse.Code)
	}
	if secondResponse.Header().Get("Retry-After") != "60" {
		t.Fatal("missing tenant rate-limit Retry-After header")
	}
}

func TestTokenBucketRefill(t *testing.T) {
	limiter := newTokenBucketLimiter(60) // 1 token per second
	now := time.Now()

	// Drain all 60 tokens
	for i := 0; i < 60; i++ {
		if !limiter.allow(now) {
			t.Fatalf("expected token %d to be allowed", i)
		}
	}
	// 61st token should be rejected at the same instant
	if limiter.allow(now) {
		t.Fatal("expected request 61 to be rejected when bucket is empty")
	}

	// Advance time by 2.5 seconds -> should refill 2 tokens
	after := now.Add(2500 * time.Millisecond)
	if !limiter.allow(after) {
		t.Fatal("expected request to be allowed after refill")
	}
	if !limiter.allow(after) {
		t.Fatal("expected second request to be allowed after refill")
	}
	if limiter.allow(after) {
		t.Fatal("expected third request to be rejected")
	}
}

func TestGatewayGeminiGenerateContentMasksAndRestores(t *testing.T) {
	var upstreamPrompt string
	var upstreamSysInstruction string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-flash:generateContent" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		if got := r.Header.Get("x-goog-api-key"); got != "gemini-secret" {
			t.Fatalf("expected upstream x-goog-api-key 'gemini-secret', got %q", got)
		}
		if r.Header.Get("Accept-Encoding") != "identity" {
			t.Fatalf("expected Accept-Encoding: identity, got %q", r.Header.Get("Accept-Encoding"))
		}

		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		if sysMap, ok := request["systemInstruction"].(map[string]interface{}); ok {
			if parts, ok := sysMap["parts"].([]interface{}); ok && len(parts) > 0 {
				upstreamSysInstruction, _ = parts[0].(map[string]interface{})["text"].(string)
			}
		}
		contents := request["contents"].([]interface{})
		parts := contents[0].(map[string]interface{})["parts"].([]interface{})
		upstreamPrompt, _ = parts[0].(map[string]interface{})["text"].(string)

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"candidates": []interface{}{
				map[string]interface{}{
					"content": map[string]interface{}{
						"role":  "model",
						"parts": []interface{}{map[string]interface{}{"text": "Recibo emitido para " + upstreamPrompt}},
					},
					"finishReason": "STOP",
				},
			},
		})
	}))
	defer server.Close()

	upstream := NewUpstreamDispatcher(UpstreamConfig{
		GeminiURL: server.URL,
		GeminiKey: "gemini-secret",
		AdminKey:  "secret-key",
	})
	gw := newTestGateway("secret-key", upstream)

	body := []byte(`{"contents":[{"role":"user","parts":[{"text":"CPF 529.982.247-25"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/v1beta/models/gemini-2.5-flash:generateContent", bytes.NewReader(body))
	req.Header.Set("x-goog-api-key", "secret-key")
	req.Header.Set("Origin", "http://localhost:3000")
	w := httptest.NewRecorder()

	gw.HandleGeminiModels(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
	if strings.Contains(upstreamPrompt, "529.982.247-25") {
		t.Fatalf("raw CPF reached Gemini upstream: %s", upstreamPrompt)
	}
	if upstreamSysInstruction != protocol.PlaceholderSystemInstruction {
		t.Fatalf("expected PlaceholderSystemInstruction injected into systemInstruction, got %q", upstreamSysInstruction)
	}
	if !strings.Contains(w.Body.String(), "529.982.247-25") {
		t.Fatalf("CPF was not restored in Gemini response: %s", w.Body.String())
	}
	if active := gw.engine.Vault().ActiveSessionsCount(); active != 0 {
		t.Fatalf("request-scoped vault was not purged, active sessions: %d", active)
	}

	allTraces := gw.traces.GetAll()
	if len(allTraces) != 1 {
		t.Fatalf("expected 1 trace, got %d", len(allTraces))
	}
	if allTraces[0].Provider != "gemini" || allTraces[0].Model != "gemini-2.5-flash" {
		t.Fatalf("unexpected trace provider/model: %+v", allTraces[0])
	}
	if strings.Contains(allTraces[0].SanitizedPrompt, "529.982.247-25") ||
		strings.Contains(allTraces[0].SanitizedPrompt, "[HADESGATE PRIVACY PROXY DIRECTIVE]") {
		t.Fatalf("unexpected SanitizedPrompt in trace: %q", allTraces[0].SanitizedPrompt)
	}
}

func TestGatewayGeminiStreamSSERestoresSplitTokenAndFlushesEOF(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/models/gemini-2.5-pro:streamGenerateContent" {
			t.Fatalf("unexpected upstream path: %s", r.URL.Path)
		}
		if r.URL.RawQuery != "alt=sse" {
			t.Fatalf("expected upstream query 'alt=sse' without client key leak, got %q", r.URL.RawQuery)
		}
		if got := r.Header.Get("x-goog-api-key"); got != "gemini-secret" {
			t.Fatalf("expected upstream x-goog-api-key 'gemini-secret', got %q", got)
		}

		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode upstream request: %v", err)
		}
		contents := request["contents"].([]interface{})
		parts := contents[0].(map[string]interface{})["parts"].([]interface{})
		maskedText := parts[0].(map[string]interface{})["text"].(string)

		// Split the [HG_...] token mid-placeholder across two SSE events, plus trailing unclosed '[' at EOF
		mid := len(maskedText) / 2
		partA := maskedText[:mid]
		partB := maskedText[mid:] + " [OK"

		w.Header().Set("Content-Type", "text/event-stream")
		flusher, _ := w.(http.Flusher)
		chunk1, _ := json.Marshal(map[string]interface{}{
			"candidates": []interface{}{
				map[string]interface{}{
					"content": map[string]interface{}{
						"role":  "model",
						"parts": []interface{}{map[string]interface{}{"text": "Confirmado: " + partA}},
					},
					"index": 0,
				},
			},
		})
		chunk2, _ := json.Marshal(map[string]interface{}{
			"candidates": []interface{}{
				map[string]interface{}{
					"content": map[string]interface{}{
						"role":  "model",
						"parts": []interface{}{map[string]interface{}{"text": partB}},
					},
					"finishReason": "STOP",
					"index":        0,
				},
			},
		})
		fmt.Fprintf(w, "data: %s\n\n", chunk1)
		flusher.Flush()
		fmt.Fprintf(w, "data: %s\n\n", chunk2)
		flusher.Flush()
	}))
	defer server.Close()

	upstream := NewUpstreamDispatcher(UpstreamConfig{
		GeminiURL: server.URL,
		GeminiKey: "gemini-secret",
		AdminKey:  "secret-key",
	})
	gw := newTestGateway("secret-key", upstream)

	body := []byte(`{"contents":[{"parts":[{"text":"529.982.247-25"}]}]}`)
	req := httptest.NewRequest(http.MethodPost, "/gemini/v1beta/models/gemini-2.5-pro:streamGenerateContent?alt=sse", bytes.NewReader(body))
	req.Header.Set("X-Goog-Api-Key", "secret-key")
	w := httptest.NewRecorder()

	gw.HandleGeminiModels(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
	sseOut := w.Body.String()
	if !strings.Contains(sseOut, "529.982.247-25") {
		t.Fatalf("split CPF token was not restored in Gemini SSE stream: %s", sseOut)
	}
	if !strings.Contains(sseOut, "[OK") {
		t.Fatalf("trailing partial bracket buffer was not flushed on EOF: %s", sseOut)
	}
	if active := gw.engine.Vault().ActiveSessionsCount(); active != 0 {
		t.Fatalf("request-scoped vault was not purged, active sessions: %d", active)
	}
}

func TestGatewayChatCompletionsRoutesGeminiOpenAICompatible(t *testing.T) {
	var upstreamModel string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1beta/openai/chat/completions" {
			t.Fatalf("unexpected Gemini OpenAI-compat path: %s", r.URL.Path)
		}
		if got := r.Header.Get("Authorization"); got != "Bearer gemini-secret" {
			t.Fatalf("expected Bearer gemini-secret, got %q", got)
		}
		var request map[string]interface{}
		if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		upstreamModel, _ = request["model"].(string)
		messages := request["messages"].([]interface{})
		lastMsg := messages[len(messages)-1].(map[string]interface{})
		userContent, _ := lastMsg["content"].(string)

		w.Header().Set("Content-Type", "text/event-stream")
		chunk, _ := json.Marshal(map[string]interface{}{
			"choices": []interface{}{
				map[string]interface{}{
					"index": 0,
					"delta": map[string]interface{}{"content": userContent},
				},
			},
		})
		fmt.Fprintf(w, "data: %s\n\ndata: [DONE]\n\n", chunk)
	}))
	defer server.Close()

	upstream := NewUpstreamDispatcher(UpstreamConfig{
		GeminiURL: server.URL,
		GeminiKey: "gemini-secret",
		AdminKey:  "secret-key",
	})
	gw := newTestGateway("secret-key", upstream)

	body := []byte(`{"model":"gemini/gemini-2.5-flash","messages":[{"role":"user","content":"Contato alice@example.com"}],"stream":true}`)
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer secret-key")
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("got status %d: %s", w.Code, w.Body.String())
	}
	if upstreamModel != "gemini-2.5-flash" {
		t.Fatalf("expected stripped model 'gemini-2.5-flash', got %q", upstreamModel)
	}
	if !strings.Contains(w.Body.String(), "alice@example.com") {
		t.Fatalf("email was not restored in Gemini OpenAI-compatible SSE stream: %s", w.Body.String())
	}
}

func TestGatewayGeminiRejectsPathTraversalAndUnsupportedAction(t *testing.T) {
	gw := newTestGateway("secret-key", nil)
	for _, badPath := range []string{
		"/v1beta/models/../admin:generateContent",
		"/v1beta/models/gemini-2.5-flash:deleteModel",
		"/v1beta/models/:generateContent",
	} {
		req := httptest.NewRequest(http.MethodPost, badPath, bytes.NewReader([]byte(`{}`)))
		req.Header.Set("Authorization", "Bearer secret-key")
		w := httptest.NewRecorder()
		gw.HandleGeminiModels(w, req)
		if w.Code != http.StatusNotFound {
			t.Fatalf("expected 404 for %s, got %d", badPath, w.Code)
		}
	}
}

func TestGatewayWebhookOnBlock(t *testing.T) {
	var receivedEvent webhook.Event
	done := make(chan struct{}, 1)

	whServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&receivedEvent)
		w.WriteHeader(http.StatusOK)
		select {
		case done <- struct{}{}:
		default:
		}
	}))
	defer whServer.Close()

	whDisp := webhook.NewDispatcher(webhook.Config{
		URL:     whServer.URL,
		Timeout: 2 * time.Second,
	})
	defer whDisp.Close()

	memVault := vault.NewMemoryVault(time.Minute)
	defer memVault.Close()
	engine := anonymizer.NewEngine(anonymizer.DefaultConfig(), memVault)
	traces := observability.NewTraceLogger(100)

	gw := NewGatewayWithOptions(engine, nil, traces, GatewayOptions{
		GlobalProxyKey: "proxy-key",
		EntityActions: map[string]string{
			"API_KEY": "block",
		},
		Webhook: whDisp,
	})

	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"Key sk-proj-1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer proxy-key")
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request, got %d", w.Code)
	}

	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for webhook alert on block")
	}

	if receivedEvent.Event != "block" {
		t.Fatalf("expected event 'block', got '%s'", receivedEvent.Event)
	}
	if len(receivedEvent.BlockedEntities) == 0 || receivedEvent.BlockedEntities[0] != "API_KEY" {
		t.Fatalf("expected API_KEY in BlockedEntities, got %+v", receivedEvent.BlockedEntities)
	}
}

func TestGateway_TenantPathRequiresMatchingTenantKey(t *testing.T) {
	memVault := vault.NewMemoryVault(time.Minute)
	defer memVault.Close()
	engine := anonymizer.NewEngine(anonymizer.DefaultConfig(), memVault)
	traces := observability.NewTraceLogger(100)

	gw := NewGatewayWithOptions(engine, nil, traces, GatewayOptions{
		GlobalProxyKey: "sec_HG_global_test_key",
		EntityActions: map[string]string{
			"CPF": "mask",
		},
		TenantKeys: map[string]string{
			"01": "sec_HG_alpha",
			"02": "sec_HG_beta",
		},
		TenantEntityActions: map[string]map[string]string{
			"01": {"CPF": "block"},
			"02": {"CPF": "disabled"},
		},
	})

	body := `{"model":"mock","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`
	call := func(path, key string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
		if key != "" {
			req.Header.Set("Authorization", "Bearer "+key)
		}
		w := httptest.NewRecorder()
		gw.HandleTenantPath(w, req)
		return w
	}

	// A key of tenant 01 on tenant 02's path must use tenant 02's policy
	// (CPF disabled), not return 400 from tenant 01's block rule.
	if w := call("/t/02/v1/chat/completions", "sec_HG_alpha"); w.Code != http.StatusOK {
		t.Fatalf("tenant 01 key on tenant 02 path: expected 200 with tenant 02 policy, got %d: %s", w.Code, w.Body.String())
	}
	if got, _ := traces.GetPagedForTenant("02", 10, 0); len(got) != 1 {
		t.Fatalf("expected the request to be traced under tenant 02, got %d traces", len(got))
	}
	if got, _ := traces.GetPagedForTenant("01", 10, 0); len(got) != 0 {
		t.Fatalf("expected no trace under tenant 01, got %d", len(got))
	}

	// The legitimate key keeps working.
	if w := call("/t/02/v1/chat/completions", "sec_HG_beta"); w.Code != http.StatusOK {
		t.Fatalf("tenant 02 key: expected 200, got %d", w.Code)
	}

	// The reverse direction must keep tenant 01's block policy.
	if w := call("/t/01/v1/chat/completions", "sec_HG_beta"); w.Code != http.StatusBadRequest {
		t.Fatalf("tenant 02 key on tenant 01 path: expected 400, got %d", w.Code)
	}

	// The global key stays allowed on every tenant path.
	if w := call("/t/02/v1/chat/completions", "sec_HG_global_test_key"); w.Code != http.StatusOK {
		t.Fatalf("global key on tenant path: expected 200, got %d", w.Code)
	}

	// Unknown credentials are still rejected.
	if w := call("/t/02/v1/chat/completions", "sec_HG_unknown"); w.Code != http.StatusUnauthorized {
		t.Fatalf("unknown key: expected 401, got %d", w.Code)
	}
}

func TestGateway_TenantPathAndPassthrough(t *testing.T) {
	memVault := vault.NewMemoryVault(time.Minute)
	defer memVault.Close()
	engine := anonymizer.NewEngine(anonymizer.DefaultConfig(), memVault)
	traces := observability.NewTraceLogger(100)
	providerFingerprint, err := ProviderKeyFingerprint("fingerprint-secret", "sk-proj-upstream-client-key-123456")
	if err != nil {
		t.Fatalf("fingerprinting provider key: %v", err)
	}

	gw := NewGatewayWithOptions(engine, nil, traces, GatewayOptions{
		GlobalProxyKey: "sec_HG_global_test_key",
		EntityActions: map[string]string{
			"CPF": "mask",
		},
		TenantKeys: map[string]string{
			"01":         "sec_HG_fin",
			"financeiro": "sec_HG_fin",
		},
		TenantEntityActions: map[string]map[string]string{
			"01": {
				"CPF": "block", // Tenant 01 blocks CPF!
			},
		},
		ProviderFingerprintSecret: "fingerprint-secret",
		ProviderKeyFingerprints: map[string][]string{
			"01": {providerFingerprint},
		},
		AllowLegacyURLKeys: true,
	})

	// 1. Calling /t/01/v1/chat/completions with tenant key, passing CPF -> should BLOCK (HTTP 400) because tenant 01 blocks CPF
	body := `{"model":"gpt-4o","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`
	req1 := httptest.NewRequest(http.MethodPost, "/t/01/v1/chat/completions", strings.NewReader(body))
	req1.Header.Set("Authorization", "Bearer sec_HG_fin")
	w1 := httptest.NewRecorder()
	gw.HandleTenantPath(w1, req1)
	if w1.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request (blocked by tenant policy), got %d: %s", w1.Code, w1.Body.String())
	}

	// 2. Calling /t/01/v1/chat/completions with upstream provider key (sk-proj-...) -> tenant 01 is recognized and CPF blocked
	req2 := httptest.NewRequest(http.MethodPost, "/t/01/v1/chat/completions", strings.NewReader(body))
	req2.Header.Set("Authorization", "Bearer sk-proj-upstream-client-key-123456")
	w2 := httptest.NewRecorder()
	gw.HandleTenantPath(w2, req2)
	if w2.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request for tenant 01 with upstream key, got %d: %s", w2.Code, w2.Body.String())
	}

	// 3. Calling global /v1/chat/completions with a registered provider key resolves tenant 01 without a secret URL.
	req3 := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req3.Header.Set("Authorization", "Bearer sk-proj-upstream-client-key-123456")
	w3 := httptest.NewRecorder()
	gw.HandleChatCompletions(w3, req3)
	if w3.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request from tenant policy for registered provider key, got %d", w3.Code)
	}

	// 4. Calling /t/unknown_tenant/v1/chat/completions with unknown key -> 401 Unauthorized
	req4 := httptest.NewRequest(http.MethodPost, "/t/unknown_tenant/v1/chat/completions", strings.NewReader(body))
	req4.Header.Set("Authorization", "Bearer sk-proj-random-key")
	w4 := httptest.NewRecorder()
	gw.HandleTenantPath(w4, req4)
	if w4.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for unknown tenant, got %d", w4.Code)
	}

	// 5. Calling /t/{tenant_proxy_key}/v1/chat/completions (Transparent Proxy with Key in URL) -> Pre-authenticated as tenant 01!
	req5 := httptest.NewRequest(http.MethodPost, "/t/sec_HG_fin/v1/chat/completions", strings.NewReader(body))
	req5.Header.Set("Authorization", "Bearer sk-proj-upstream-real-openai-key")
	w5 := httptest.NewRecorder()
	gw.HandleTenantPath(w5, req5)
	// Tenant 01 blocks CPF, so it should be blocked (HTTP 400 Bad Request)
	if w5.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 Bad Request (blocked by tenant 01 via proxy_key in URL), got %d: %s", w5.Code, w5.Body.String())
	}

	// 6. Calling /p/{global_proxy_key}/v1/chat/completions (Global Transparent Proxy) -> Pre-authenticated as global default!
	req6 := httptest.NewRequest(http.MethodPost, "/p/sec_HG_global_test_key/v1/chat/completions", strings.NewReader(body))
	req6.Header.Set("Authorization", "Bearer sk-proj-upstream-real-openai-key")
	w6 := httptest.NewRecorder()
	gw.HandleGlobalProxyPath(w6, req6)
	// Global policy is MASK, so it should succeed (HTTP 200 OK)
	if w6.Code != http.StatusOK {
		t.Fatalf("expected 200 OK for global proxy route, got %d: %s", w6.Code, w6.Body.String())
	}

	// 7. Calling /p/invalid_key/v1/chat/completions -> 401 Unauthorized
	req7 := httptest.NewRequest(http.MethodPost, "/p/invalid_key/v1/chat/completions", strings.NewReader(body))
	req7.Header.Set("Authorization", "Bearer sk-proj-upstream-real-openai-key")
	w7 := httptest.NewRecorder()
	gw.HandleGlobalProxyPath(w7, req7)
	if w7.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for invalid global proxy key, got %d", w7.Code)
	}
}

func TestGateway_TenantPathRejectsUnregisteredProviderKey(t *testing.T) {
	v := vault.NewMemoryVault(time.Minute)
	t.Cleanup(v.Close)
	eng := anonymizer.NewEngine(anonymizer.DefaultConfig(), v)
	gw := NewGatewayWithOptions(eng, nil, nil, GatewayOptions{
		TenantKeys: map[string]string{"financeiro": "tenant-proxy-secret"},
	})

	body := `{"model":"mock","messages":[{"role":"user","content":"olá"}]}`
	req := httptest.NewRequest(http.MethodPost, "/t/financeiro/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer unregistered-provider-key")
	w := httptest.NewRecorder()

	gw.HandleTenantPath(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("unregistered provider key authenticated tenant path: got %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestGateway_TransparentProviderKeyFingerprint(t *testing.T) {
	const (
		fingerprintSecret = "stable-fingerprint-secret"
		providerKey       = "sk-provider-original-secret"
	)
	fingerprint, err := ProviderKeyFingerprint(fingerprintSecret, providerKey)
	if err != nil {
		t.Fatalf("fingerprinting provider key: %v", err)
	}
	if strings.Contains(fingerprint, providerKey) || len(fingerprint) != 64 {
		t.Fatalf("unexpected provider fingerprint representation: %q", fingerprint)
	}

	v := vault.NewMemoryVault(time.Minute)
	t.Cleanup(v.Close)
	eng := anonymizer.NewEngine(anonymizer.DefaultConfig(), v)
	gw := NewGatewayWithOptions(eng, nil, nil, GatewayOptions{
		TenantEntityActions: map[string]map[string]string{
			"financeiro": {"CPF": "block"},
		},
		ProviderFingerprintSecret: fingerprintSecret,
		ProviderKeyFingerprints: map[string][]string{
			"financeiro": {fingerprint},
		},
	})

	body := `{"model":"mock","messages":[{"role":"user","content":"CPF 529.982.247-25"}]}`
	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+providerKey)
	w := httptest.NewRecorder()

	gw.HandleChatCompletions(w, req)
	if w.Code != http.StatusBadRequest {
		t.Fatalf("registered provider key did not resolve tenant policy: got %d, want %d; body=%s", w.Code, http.StatusBadRequest, w.Body.String())
	}
}

func TestGateway_RoutingRequestNeverForwardsHadesGateKey(t *testing.T) {
	v := vault.NewMemoryVault(time.Minute)
	t.Cleanup(v.Close)
	eng := anonymizer.NewEngine(anonymizer.DefaultConfig(), v)
	gw := NewGatewayWithOptions(eng, nil, nil, GatewayOptions{
		TenantKeys: map[string]string{"financeiro": "tenant-secret"},
	})

	req := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", nil)
	req.Header.Set("Authorization", "Bearer tenant-secret")
	routed := gw.routingRequestForUpstream(req)
	if got := routed.Header.Get("Authorization"); got != "" {
		t.Fatalf("HadesGate tenant key would be forwarded upstream: %q", got)
	}
}
