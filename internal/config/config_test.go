package config

import "testing"

func TestLoadGeminiConfig(t *testing.T) {
	t.Setenv("HADESGATE_ADMIN_KEY", "test_admin_key")
	t.Setenv("GEMINI_BASE_URL", "")
	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("GOOGLE_API_KEY", "")

	cfg := Load()
	if cfg.GeminiBaseURL != "https://generativelanguage.googleapis.com" {
		t.Fatalf("expected default GeminiBaseURL, got %q", cfg.GeminiBaseURL)
	}
	if cfg.GeminiKey != "" {
		t.Fatalf("expected empty GeminiKey by default, got %q", cfg.GeminiKey)
	}

	// Fallback to GOOGLE_API_KEY when GEMINI_API_KEY is unset
	t.Setenv("GOOGLE_API_KEY", "google_fallback_key")
	cfg = Load()
	if cfg.GeminiKey != "google_fallback_key" {
		t.Fatalf("expected GOOGLE_API_KEY fallback, got %q", cfg.GeminiKey)
	}

	// Explicit GEMINI_API_KEY and GEMINI_BASE_URL override defaults and fallback
	t.Setenv("GEMINI_API_KEY", "gemini_primary_key")
	t.Setenv("GEMINI_BASE_URL", "https://custom-gemini.example.com")
	cfg = Load()
	if cfg.GeminiKey != "gemini_primary_key" {
		t.Fatalf("expected GEMINI_API_KEY override, got %q", cfg.GeminiKey)
	}
	if cfg.GeminiBaseURL != "https://custom-gemini.example.com" {
		t.Fatalf("expected custom GEMINI_BASE_URL, got %q", cfg.GeminiBaseURL)
	}
}

func TestLoadSeparatesAdminProxyAndLoadsBYOKSecurity(t *testing.T) {
	t.Setenv("HADESGATE_ADMIN_KEY", "same-key-must-not-be-reused")
	t.Setenv("HADESGATE_PROXY_KEY", "same-key-must-not-be-reused")
	t.Setenv("HADESGATE_FINGERPRINT_SECRET", "stable-fingerprint-secret")
	t.Setenv("HADESGATE_ALLOW_LEGACY_URL_KEYS", "true")

	cfg := Load()
	if cfg.ProxyKey == cfg.AdminKey {
		t.Fatal("proxy key must never reuse the administrative key")
	}
	if cfg.ProviderFingerprintSecret != "stable-fingerprint-secret" {
		t.Fatalf("unexpected fingerprint secret: %q", cfg.ProviderFingerprintSecret)
	}
	if !cfg.AllowLegacyURLKeys {
		t.Fatal("expected legacy URL flag to load from environment")
	}
}

func TestLoadNetworkSecurityDefaultsAndOverrides(t *testing.T) {
	t.Setenv("HADESGATE_ADMIN_KEY", "network-test-admin")
	t.Setenv("HADESGATE_BIND_ADDRESS", "")
	t.Setenv("HADESGATE_ALLOW_PRIVATE_DYNAMIC_UPSTREAM", "")
	t.Setenv("HADESGATE_PRIVATE_UPSTREAM_ALLOWED_HOSTS", "")

	cfg := Load()
	if cfg.BindAddress != "127.0.0.1" {
		t.Fatalf("expected loopback bind by default, got %q", cfg.BindAddress)
	}
	if cfg.AllowPrivateDynamicUpstream {
		t.Fatal("private dynamic upstreams must be disabled by default")
	}
	t.Setenv("HADESGATE_BIND_ADDRESS", "   ")
	if got := Load().BindAddress; got != "127.0.0.1" {
		t.Fatalf("blank bind address must not expose all interfaces, got %q", got)
	}

	t.Setenv("HADESGATE_BIND_ADDRESS", "0.0.0.0")
	t.Setenv("HADESGATE_ALLOW_PRIVATE_DYNAMIC_UPSTREAM", "true")
	t.Setenv("HADESGATE_PRIVATE_UPSTREAM_ALLOWED_HOSTS", "router.internal:20128,10.0.0.8:8080")
	cfg = Load()
	if cfg.BindAddress != "0.0.0.0" || !cfg.AllowPrivateDynamicUpstream {
		t.Fatalf("network overrides were not loaded: bind=%q private=%v", cfg.BindAddress, cfg.AllowPrivateDynamicUpstream)
	}
	if len(cfg.PrivateUpstreamAllowedHosts) != 2 {
		t.Fatalf("expected two private upstream allowlist entries, got %v", cfg.PrivateUpstreamAllowedHosts)
	}
}

func TestLoad_GeneratedKeysAreFlagged(t *testing.T) {
	t.Setenv("HADESGATE_ADMIN_KEY", "")
	t.Setenv("HADESGATE_PROXY_KEY", "")
	t.Setenv("HADESGATE_CONFIG_MASTER_KEY", "")

	cfg := Load()
	if !cfg.GeneratedAdminKey || !cfg.GeneratedProxyKey {
		t.Fatalf("expected both keys to be flagged as generated: %+v", cfg)
	}
	if len(cfg.AdminKey) <= len("hadesgate_sec_") || len(cfg.ProxyKey) <= len("hadesgate_proxy_") {
		t.Fatalf("generated keys look truncated: admin=%q proxy=%q", cfg.AdminKey, cfg.ProxyKey)
	}
	if cfg.AdminKey == ExampleAdminKey {
		t.Fatal("a generated admin key must not reuse the public example value")
	}
}

func TestLoad_PublicExampleKeyIsNotFlagged(t *testing.T) {
	t.Setenv("HADESGATE_ADMIN_KEY", ExampleAdminKey)
	t.Setenv("HADESGATE_PROXY_KEY", "distinct_proxy_key")

	cfg := Load()
	if cfg.GeneratedAdminKey {
		t.Fatal("an explicit admin key must not be flagged as generated")
	}
	if cfg.GeneratedProxyKey {
		t.Fatal("an explicit proxy key must not be flagged as generated")
	}
}
