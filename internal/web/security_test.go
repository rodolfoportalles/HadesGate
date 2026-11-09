package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestSecurityMiddleware_CORS(t *testing.T) {
	dummyHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	allowedOrigins := []string{
		"http://localhost:3000",
		"https://app.hadesgate.dev",
		"chrome-extension://*",
	}

	handler := SecurityMiddleware(dummyHandler, allowedOrigins)

	tests := []struct {
		name          string
		origin        string
		method        string
		wantAllow     bool
		wantOriginVal string
		wantPreflight bool
	}{
		{
			name:          "Allowed Exact Origin",
			origin:        "http://localhost:3000",
			method:        http.MethodGet,
			wantAllow:     true,
			wantOriginVal: "http://localhost:3000",
		},
		{
			name:          "Allowed Second Origin",
			origin:        "https://app.hadesgate.dev",
			method:        http.MethodPost,
			wantAllow:     true,
			wantOriginVal: "https://app.hadesgate.dev",
		},
		{
			name:          "Allowed Chrome Extension Wildcard",
			origin:        "chrome-extension://abcdefghijklmnop",
			method:        http.MethodGet,
			wantAllow:     true,
			wantOriginVal: "chrome-extension://abcdefghijklmnop",
		},
		{
			name:          "Disallowed Malicious Origin",
			origin:        "https://evil-site.com",
			method:        http.MethodGet,
			wantAllow:     false,
			wantOriginVal: "",
		},
		{
			name:          "Preflight OPTIONS for Allowed Origin",
			origin:        "http://localhost:3000",
			method:        http.MethodOptions,
			wantAllow:     true,
			wantOriginVal: "http://localhost:3000",
			wantPreflight: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, "/v1/chat/completions", nil)
			if tt.origin != "" {
				req.Header.Set("Origin", tt.origin)
			}
			w := httptest.NewRecorder()

			handler.ServeHTTP(w, req)

			// Verify Security Headers
			if got := w.Header().Get("X-Content-Type-Options"); got != "nosniff" {
				t.Errorf("expected X-Content-Type-Options: nosniff, got %q", got)
			}
			if got := w.Header().Get("X-Frame-Options"); got != "DENY" {
				t.Errorf("expected X-Frame-Options: DENY, got %q", got)
			}
			if got := w.Header().Get("Link"); got != "<https://github.com/rodolfoportalles/HadesGate>; rel=\"source\"" {
				t.Errorf("unexpected AGPL source offer: %q", got)
			}
			if got := w.Header().Get("X-HadesGate-License"); got != "AGPL-3.0-only" {
				t.Errorf("unexpected SPDX license header: %q", got)
			}

			// Verify CORS
			gotOrigin := w.Header().Get("Access-Control-Allow-Origin")
			if tt.wantAllow {
				if gotOrigin != tt.wantOriginVal {
					t.Errorf("expected Access-Control-Allow-Origin %q, got %q", tt.wantOriginVal, gotOrigin)
				}
			} else {
				if gotOrigin != "" {
					t.Errorf("expected empty Access-Control-Allow-Origin for rejected origin, got %q", gotOrigin)
				}
			}

			if tt.wantPreflight && w.Code != http.StatusNoContent {
				t.Errorf("expected 204 for OPTIONS, got %d", w.Code)
			}
		})
	}
}

func TestSecurityMiddleware_DefaultDenyAndRejectsDisallowedPrivatePreflight(t *testing.T) {
	called := false
	handler := SecurityMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}), nil)

	req := httptest.NewRequest(http.MethodOptions, "/api/config", nil)
	req.Header.Set("Origin", "https://evil.example")
	req.Header.Set("Access-Control-Request-Private-Network", "true")
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Fatalf("expected disallowed preflight to be rejected, got %d", w.Code)
	}
	if called {
		t.Fatal("disallowed preflight reached the protected handler")
	}
	if got := w.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("default CORS policy allowed an origin: %q", got)
	}
	if got := w.Header().Get("Access-Control-Allow-Private-Network"); got != "" {
		t.Fatalf("private-network access was exposed to a rejected origin: %q", got)
	}
}

func TestSecurityPolicy_HotReloadsCORSOrigins(t *testing.T) {
	policy := NewSecurityPolicy([]string{"https://old.example"})
	handler := policy.Handler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	request := func(origin string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodOptions, "/api/config", nil)
		req.Header.Set("Origin", origin)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, req)
		return w
	}

	if got := request("https://new.example"); got.Code != http.StatusForbidden {
		t.Fatalf("new origin was allowed before reload: status=%d", got.Code)
	}
	policy.UpdateAllowedOrigins([]string{"https://new.example"})
	if got := request("https://new.example"); got.Code != http.StatusNoContent || got.Header().Get("Access-Control-Allow-Origin") != "https://new.example" {
		t.Fatalf("new origin was not allowed after reload: status=%d headers=%v", got.Code, got.Header())
	}
	if got := request("https://old.example"); got.Code != http.StatusForbidden {
		t.Fatalf("old origin remained allowed after atomic reload: status=%d", got.Code)
	}
}

func TestSecurityMiddleware_Headers(t *testing.T) {
	handler := NewSecurityPolicy(nil).Handler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/traces", nil))

	if got := rec.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") || !strings.Contains(got, "frame-ancestors 'none'") {
		t.Fatalf("missing or weak CSP: %q", got)
	}
	if got := rec.Header().Get("Permissions-Policy"); !strings.Contains(got, "camera=()") {
		t.Fatalf("missing permissions policy: %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("API response must not be cached, got %q", got)
	}
	if got := rec.Header().Get("Strict-Transport-Security"); got != "" {
		t.Fatalf("HSTS must not be sent over plain HTTP, got %q", got)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/traces", nil)
	req.Header.Set("X-Forwarded-Proto", "https")
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, req)
	if got := rec.Header().Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=31536000") {
		t.Fatalf("HSTS missing behind a TLS terminator: %q", got)
	}

	// Static assets stay cacheable.
	rec = httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", nil))
	if got := rec.Header().Get("Cache-Control"); got == "no-store" {
		t.Fatalf("static asset should not be no-store: %q", got)
	}
}
