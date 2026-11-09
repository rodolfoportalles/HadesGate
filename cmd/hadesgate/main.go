package main

import (
	"context"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/hadesgate/hadesgate/internal/anonymizer"
	"github.com/hadesgate/hadesgate/internal/anonymizer/detector"
	"github.com/hadesgate/hadesgate/internal/anonymizer/vault"
	"github.com/hadesgate/hadesgate/internal/config"
	"github.com/hadesgate/hadesgate/internal/observability"
	"github.com/hadesgate/hadesgate/internal/proxy"
	"github.com/hadesgate/hadesgate/internal/web"
	"github.com/hadesgate/hadesgate/internal/webhook"
)

func main() {
	cfg := config.Load()
	configMasterKey, keyErr := config.ParseMasterKey(cfg.ConfigMasterKey)
	if keyErr != nil {
		log.Fatalf("configuration encryption unavailable: %v", keyErr)
	}

	log.Println("==================================================")
	log.Println("   HADESGATE // TACTICAL DATA ANONYMIZATION       ")
	log.Println("   Zero-Leak PII Shield & Real-time Stream SSE    ")
	log.Println("==================================================")

	// 1. Initialize In-Memory Vault with TTL cleanup
	memVault := vault.NewMemoryVault(1 * time.Minute)
	defer memVault.Close()

	// 2. Initialize Anonymizer Engine with LGPD, International & Secret detectors
	anonCfg := anonymizer.DefaultConfig()
	anonCfg.SessionTTL = cfg.VaultTTL
	anonCfg.MinConfidence = cfg.AnonymizerMinScore
	anonCfg.Allowlist = cfg.AnonymizerAllowlist
	anonCfg.Denylist = cfg.AnonymizerDenylist
	anonCfg.CustomDetectorsFile = cfg.AnonymizerCustomFile
	anonCfg.EnablePIX = cfg.AnonymizerEnablePIX
	anonCfg.EnableRG = cfg.AnonymizerEnableRG
	anonCfg.EnableCNH = cfg.AnonymizerEnableCNH
	anonCfg.EnableBank = cfg.AnonymizerEnableBank
	anonCfg.EnableIBAN = cfg.AnonymizerEnableIBAN
	anonCfg.EnablePassport = cfg.AnonymizerEnablePass
	anonCfg.EnableIPAddress = cfg.AnonymizerEnableIP
	anonCfg.EnableAPIKey = cfg.AnonymizerEnableAPIKey
	anonCfg.EnableSecret = cfg.AnonymizerEnableSecret
	anonCfg.EnableSSN = cfg.AnonymizerEnableSSN
	anonCfg.EnableEIN = cfg.AnonymizerEnableEIN
	anonCfg.EnableNINO = cfg.AnonymizerEnableNINO
	anonCfg.EnableNHS = cfg.AnonymizerEnableNHS
	anonCfg.EnableDNI = cfg.AnonymizerEnableDNI
	anonCfg.EnableNIR = cfg.AnonymizerEnableNIR
	anonCfg.EnableCodiceFiscale = cfg.AnonymizerEnableCF
	anonCfg.EnableMedicalID = cfg.AnonymizerEnableMedical
	anonCfg.EnableSUS = cfg.AnonymizerEnableSUS
	anonCfg.EnableVehicle = cfg.AnonymizerEnableVehicle
	anonCfg.EnableLegal = cfg.AnonymizerEnableLegal
	anonCfg.EnableDevice = cfg.AnonymizerEnableDevice
	anonCfg.EnableGovernmentID = cfg.AnonymizerEnableGovID
	anonCfg.EnableCID = cfg.AnonymizerEnableCID
	anonCfg.EnableMedication = cfg.AnonymizerEnableMedication
	if cfg.SemanticDetectorEnabled {
		anonCfg.AdditionalDetectors = append(anonCfg.AdditionalDetectors,
			detector.NewSemanticDetector(cfg.SemanticDetectorURL, cfg.SemanticDetectorTimeout))
	}
	engine := anonymizer.NewEngine(anonCfg, memVault)

	// 3. Initialize SQLite Trace Logger for Zero-Leak Anonymization Telemetry
	traceLogger, err := observability.NewSQLiteTraceLogger(cfg.SQLiteDBPath, cfg.TraceBufferSize)
	if err != nil {
		log.Printf("⚠️  Could not open SQLite telemetry store at %q (%v); falling back to in-memory SQLite", cfg.SQLiteDBPath, err)
		traceLogger = observability.NewTraceLogger(cfg.TraceBufferSize)
	} else {
		log.Printf("🗄️  HadesGate SQLite Telemetry Store: %s (zero raw PII stored)\n", traceLogger.DBPath())
	}
	defer traceLogger.Close()

	// 4. Initialize Dynamic Configuration & Multitenancy Store (Phase 13)
	initialTenantNames := make(map[string]string)
	configStore, err := config.NewStore(traceLogger.DB(), configMasterKey)
	if err != nil {
		log.Fatalf("encrypted configuration store unavailable: %v", err)
	} else {
		var initialTenants []config.TenantConfig
		for id, key := range cfg.TenantProxyKeys {
			t := config.TenantConfig{
				ID:        id,
				ProxyKey:  key,
				RateLimit: cfg.TenantRateLimits[id],
			}
			if actions, ok := cfg.TenantEntityActions[id]; ok {
				t.EntityActions = actions
			}
			initialTenants = append(initialTenants, t)
		}

		_ = configStore.SeedIfEmpty(context.Background(), config.DynamicConfig{
			EntityActions:      cfg.EntityActions,
			WebhookURL:         cfg.WebhookURL,
			WebhookSecret:      cfg.WebhookSecret,
			WebhookEvents:      cfg.WebhookEvents,
			EnableEgressScan:   cfg.EnableEgressScan,
			GlobalProxyKey:     cfg.ProxyKey,
			OllamaBaseURL:      cfg.OllamaBaseURL,
			CORSAllowedOrigins: cfg.CORSAllowedOrigins,
		}, initialTenants)

		if dynCfg, err := configStore.GetDynamicConfig(context.Background()); err == nil {
			if len(dynCfg.EntityActions) > 0 {
				cfg.EntityActions = dynCfg.EntityActions
			}
			if dynCfg.GlobalProxyKey != "" {
				cfg.ProxyKey = dynCfg.GlobalProxyKey
			}
			if dynCfg.WebhookURL != "" {
				cfg.WebhookURL = dynCfg.WebhookURL
				cfg.WebhookSecret = dynCfg.WebhookSecret
				cfg.WebhookEvents = dynCfg.WebhookEvents
			}
			cfg.EnableEgressScan = dynCfg.EnableEgressScan
			if dynCfg.OllamaBaseURL != "" {
				cfg.OllamaBaseURL = dynCfg.OllamaBaseURL
			}
			if len(dynCfg.CORSAllowedOrigins) > 0 {
				cfg.CORSAllowedOrigins = dynCfg.CORSAllowedOrigins
			}
			if len(dynCfg.FamilyThresholds) > 0 || len(dynCfg.EntityThresholds) > 0 {
				engine.SetThresholds(dynCfg.FamilyThresholds, dynCfg.EntityThresholds)
			}
		}

		if activeTenants, err := configStore.ListTenants(context.Background()); err == nil && len(activeTenants) > 0 {
			tenantKeys := make(map[string]string, len(activeTenants))
			tenantActions := make(map[string]map[string]string, len(activeTenants))
			tenantRateLimits := make(map[string]int, len(activeTenants))
			for _, t := range activeTenants {
				name := strings.TrimSpace(t.Name)
				if name == "" {
					name = t.ID
				}
				initialTenantNames[t.ID] = name
				slug := strings.ToLower(strings.TrimSpace(t.Name))
				if slug != "" {
					initialTenantNames[slug] = name
				}
				tenantKeys[t.ID] = t.ProxyKey
				tenantRateLimits[t.ID] = t.RateLimit
				if len(t.EntityActions) > 0 {
					tenantActions[t.ID] = t.EntityActions
				}
			}
			cfg.TenantProxyKeys = tenantKeys
			cfg.TenantEntityActions = tenantActions
			cfg.TenantRateLimits = tenantRateLimits
		}
	}

	// 5. Initialize Webhook Alert Dispatcher
	webhookEvents := make(map[string]bool)
	for _, e := range cfg.WebhookEvents {
		webhookEvents[e] = true
	}
	webhookDisp := webhook.NewDispatcher(webhook.Config{
		URL:    cfg.WebhookURL,
		Secret: cfg.WebhookSecret,
		Events: webhookEvents,
	})
	defer webhookDisp.Close()
	if webhookDisp.Enabled() {
		log.Printf("🔔 HadesGate Security Webhooks enabled: %s\n", cfg.WebhookURL)
	}

	// 6. Initialize Upstream Dispatcher
	upstream := proxy.NewUpstreamDispatcher(proxy.UpstreamConfig{
		OpenAIBaseURL:               cfg.OpenAIBaseURL,
		OpenAIKey:                   cfg.OpenAIKey,
		AnthropicURL:                cfg.AnthropicBaseURL,
		AnthropicKey:                cfg.AnthropicKey,
		GeminiURL:                   cfg.GeminiBaseURL,
		GeminiKey:                   cfg.GeminiKey,
		OllamaBaseURL:               cfg.OllamaBaseURL,
		AdminKey:                    cfg.ProxyKey,
		AllowDynamicUpstream:        cfg.AllowDynamicUpstream,
		AllowPrivateDynamicUpstream: cfg.AllowPrivateDynamicUpstream,
		DynamicUpstreamAllowedHosts: cfg.DynamicUpstreamAllowedHosts,
		PrivateUpstreamAllowedHosts: cfg.PrivateUpstreamAllowedHosts,
		MaxResponseBytes:            cfg.MaxResponseBytes,
		MaxSSEEventBytes:            cfg.MaxSSEEventBytes,
		EnableEgressScan:            cfg.EnableEgressScan,
		Engine:                      engine,
		Webhook:                     webhookDisp,
	})
	// Webhooks leave the process too: reuse the proxy address policy so
	// private hosts stay reachable while metadata and redirects are refused.
	webhookDisp.SetTransport(upstream.EgressTransport())

	// 7. Initialize Gateway Proxy Handler
	gateway := proxy.NewGatewayWithOptions(engine, upstream, traceLogger, proxy.GatewayOptions{
		MaxConcurrent:             cfg.MaxConcurrentRequests,
		GlobalProxyKey:            cfg.ProxyKey,
		EntityActions:             cfg.EntityActions,
		TenantKeys:                cfg.TenantProxyKeys,
		TenantNames:               initialTenantNames,
		TenantEntityActions:       cfg.TenantEntityActions,
		RateLimitPerMinute:        cfg.RateLimitPerMinute,
		TenantRateLimits:          cfg.TenantRateLimits,
		ProviderFingerprintSecret: cfg.ProviderFingerprintSecret,
		AllowLegacyURLKeys:        cfg.AllowLegacyURLKeys,
		Webhook:                   webhookDisp,
	})
	if configStore != nil {
		if fingerprints, fingerprintErr := configStore.ProviderKeyFingerprints(context.Background()); fingerprintErr != nil {
			log.Printf("⚠️  Failed to load provider credential fingerprints: %v", fingerprintErr)
		} else {
			gateway.UpdateProviderKeyFingerprints(cfg.ProviderFingerprintSecret, fingerprints)
		}
	}

	// 8. Initialize Web Server and Dashboard Handlers
	webServer := web.NewServer(engine, gateway, cfg.AdminKey, web.GetStaticFS())
	webServer.SetStore(configStore)
	webServer.SetWebhook(webhookDisp)
	webServer.SetUpstream(upstream)
	webServer.SetProviderFingerprintSecret(cfg.ProviderFingerprintSecret)
	webServer.SetDefaultRateLimit(cfg.RateLimitPerMinute)
	securityPolicy := web.NewSecurityPolicy(cfg.CORSAllowedOrigins)
	webServer.SetSecurityPolicy(securityPolicy)

	mux := http.NewServeMux()

	// Register Proxy endpoints (with and without /v1 prefix for maximum router/client compatibility)
	mux.HandleFunc("/v1/chat/completions", gateway.HandleChatCompletions)
	mux.HandleFunc("/chat/completions", gateway.HandleChatCompletions)
	mux.HandleFunc("/v1/responses", gateway.HandleResponses)
	mux.HandleFunc("/responses", gateway.HandleResponses)
	mux.HandleFunc("/v1/messages", gateway.HandleAnthropicMessages)
	mux.HandleFunc("/anthropic/v1/messages", gateway.HandleAnthropicMessages)
	mux.HandleFunc("/v1beta/models/", gateway.HandleGeminiModels)
	mux.HandleFunc("/gemini/v1beta/models/", gateway.HandleGeminiModels)
	mux.HandleFunc("/v1/models", gateway.HandleModels)
	mux.HandleFunc("/models", gateway.HandleModels)

	// Register Multi-Tenant and Global Transparent Proxy Routers
	mux.HandleFunc("/t/", gateway.HandleTenantPath)
	mux.HandleFunc("/p/", gateway.HandleGlobalProxyPath)
	mux.HandleFunc("/g/", gateway.HandleGlobalProxyPath)

	// Register Dashboard & Management APIs
	webServer.RegisterRoutes(mux)

	// Wrap with Security & CORS middleware (configurable allowed origins)
	handler := securityPolicy.Handler(mux)

	server := &http.Server{
		Addr:         net.JoinHostPort(cfg.BindAddress, strconv.Itoa(cfg.Port)),
		Handler:      handler,
		ReadTimeout:  120 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Graceful shutdown listener
	stopChan := make(chan os.Signal, 1)
	signal.Notify(stopChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		log.Printf("🚀 HadesGate Gateway listening on http://%s\n", server.Addr)
		log.Printf("📊 Dashboard: http://localhost:%d/\n", cfg.Port)
		log.Printf("🔒 OpenAI Proxy: http://localhost:%d/v1/chat/completions\n", cfg.Port)
		if cfg.AdminKey == "" {
			log.Println("⚠️  Dev Mode: Running without API Key authentication")
		} else {
			log.Println("🛡️  Auth Enabled: Admin key configured")
		}
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server error: %v", err)
		}
	}()

	<-stopChan
	log.Println("\nInitiating graceful shutdown...")

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Forced shutdown error: %v\n", err)
	} else {
		log.Println("HadesGate shutdown gracefully.")
	}
}
