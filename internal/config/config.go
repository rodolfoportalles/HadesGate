package config

import (
	"crypto/rand"
	"crypto/subtle"
	"flag"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// ExampleAdminKey is the placeholder shipped in .env.example. Booting with it
// unchanged means the dashboard key is public knowledge.
const ExampleAdminKey = "hadesgate_sec_admin_key_2026"

// Config encapsulates runtime configuration for the HadesGate gateway.
type Config struct {
	BindAddress                 string
	Port                        int
	AdminKey                    string
	ProxyKey                    string
	GeneratedAdminKey           bool
	GeneratedProxyKey           bool
	ProviderFingerprintSecret   string
	ConfigMasterKey             string
	AllowLegacyURLKeys          bool
	OpenAIBaseURL               string
	OpenAIKey                   string
	AnthropicBaseURL            string
	AnthropicKey                string
	GeminiBaseURL               string
	GeminiKey                   string
	OllamaBaseURL               string
	AllowDynamicUpstream        bool
	AllowPrivateDynamicUpstream bool
	DynamicUpstreamAllowedHosts []string
	PrivateUpstreamAllowedHosts []string
	MaxConcurrentRequests       int
	MaxResponseBytes            int64
	MaxSSEEventBytes            int
	EntityActions               map[string]string
	TenantProxyKeys             map[string]string
	TenantEntityActions         map[string]map[string]string
	RateLimitPerMinute          int
	TenantRateLimits            map[string]int
	SemanticDetectorEnabled     bool
	SemanticDetectorURL         string
	SemanticDetectorTimeout     time.Duration
	VaultTTL                    time.Duration
	SQLiteDBPath                string
	TraceBufferSize             int
	AnonymizerMinScore          float64
	AnonymizerAllowlist         []string
	AnonymizerDenylist          []string
	AnonymizerCustomFile        string
	AnonymizerEnablePIX         bool
	AnonymizerEnableRG          bool
	AnonymizerEnableCNH         bool
	AnonymizerEnableBank        bool
	AnonymizerEnableIBAN        bool
	AnonymizerEnablePass        bool
	AnonymizerEnableIP          bool
	AnonymizerEnableAPIKey      bool
	AnonymizerEnableSecret      bool
	AnonymizerEnableSSN         bool
	AnonymizerEnableEIN         bool
	AnonymizerEnableNINO        bool
	AnonymizerEnableNHS         bool
	AnonymizerEnableDNI         bool
	AnonymizerEnableNIR         bool
	AnonymizerEnableCF          bool
	AnonymizerEnableMedical     bool
	AnonymizerEnableSUS         bool
	AnonymizerEnableVehicle     bool
	AnonymizerEnableLegal       bool
	AnonymizerEnableDevice      bool
	AnonymizerEnableGovID       bool
	AnonymizerEnableCID         bool
	AnonymizerEnableMedication  bool
	CORSAllowedOrigins          []string
	EnableEgressScan            bool
	WebhookURL                  string
	WebhookSecret               string
	WebhookEvents               []string
}

// Load reads configuration from command-line flags and environment variables.
func Load() *Config {
	cfg := &Config{
		BindAddress:                "127.0.0.1",
		Port:                       8080,
		AdminKey:                   "",
		ProxyKey:                   "",
		OpenAIBaseURL:              "https://api.openai.com/v1",
		OpenAIKey:                  "",
		AnthropicBaseURL:           "https://api.anthropic.com",
		AnthropicKey:               "",
		GeminiBaseURL:              "https://generativelanguage.googleapis.com",
		GeminiKey:                  "",
		OllamaBaseURL:              "http://localhost:11434/v1",
		AllowDynamicUpstream:       false,
		AllowLegacyURLKeys:         false,
		MaxConcurrentRequests:      128,
		MaxResponseBytes:           20 << 20,
		MaxSSEEventBytes:           1 << 20,
		EntityActions:              make(map[string]string),
		TenantProxyKeys:            make(map[string]string),
		TenantEntityActions:        make(map[string]map[string]string),
		TenantRateLimits:           make(map[string]int),
		SemanticDetectorEnabled:    false,
		SemanticDetectorURL:        "http://127.0.0.1:5002/analyze",
		SemanticDetectorTimeout:    250 * time.Millisecond,
		VaultTTL:                   10 * time.Minute,
		SQLiteDBPath:               "./data/hadesgate.db",
		TraceBufferSize:            1000,
		AnonymizerMinScore:         0.70,
		AnonymizerAllowlist:        nil,
		AnonymizerDenylist:         nil,
		AnonymizerCustomFile:       "",
		AnonymizerEnablePIX:        true,
		AnonymizerEnableRG:         true,
		AnonymizerEnableCNH:        true,
		AnonymizerEnableBank:       true,
		AnonymizerEnableIBAN:       true,
		AnonymizerEnablePass:       true,
		AnonymizerEnableIP:         true,
		AnonymizerEnableAPIKey:     true,
		AnonymizerEnableSecret:     true,
		AnonymizerEnableSSN:        true,
		AnonymizerEnableEIN:        true,
		AnonymizerEnableNINO:       true,
		AnonymizerEnableNHS:        true,
		AnonymizerEnableDNI:        true,
		AnonymizerEnableNIR:        true,
		AnonymizerEnableCF:         true,
		AnonymizerEnableMedical:    true,
		AnonymizerEnableSUS:        true,
		AnonymizerEnableVehicle:    true,
		AnonymizerEnableLegal:      true,
		AnonymizerEnableDevice:     true,
		AnonymizerEnableGovID:      true,
		AnonymizerEnableCID:        true,
		AnonymizerEnableMedication: true,
		CORSAllowedOrigins:         nil,
		EnableEgressScan:           false,
	}

	// Environment variable overrides (HADESGATE_* primary, PRIVAGATE_* legacy fallback)
	if val := strings.TrimSpace(getEnvAny("HADESGATE_BIND_ADDRESS", "PRIVAGATE_BIND_ADDRESS")); val != "" {
		cfg.BindAddress = val
	}
	if val := getEnvAny("HADESGATE_PORT", "PRIVAGATE_PORT", "PORT"); val != "" {
		if p, err := strconv.Atoi(val); err == nil {
			cfg.Port = p
		}
	}
	if val := getEnvAny("HADESGATE_ADMIN_KEY", "PRIVAGATE_ADMIN_KEY"); val != "" {
		cfg.AdminKey = val
	}
	if val := getEnvAny("HADESGATE_PROXY_KEY", "PRIVAGATE_PROXY_KEY"); val != "" {
		cfg.ProxyKey = val
	}
	if val := os.Getenv("HADESGATE_FINGERPRINT_SECRET"); val != "" {
		cfg.ProviderFingerprintSecret = strings.TrimSpace(val)
	}
	if val := os.Getenv("HADESGATE_CONFIG_MASTER_KEY"); val != "" {
		cfg.ConfigMasterKey = strings.TrimSpace(val)
	}
	if val := os.Getenv("HADESGATE_ALLOW_LEGACY_URL_KEYS"); val != "" {
		cfg.AllowLegacyURLKeys = strings.EqualFold(val, "true") || val == "1"
	}
	if val := os.Getenv("OPENAI_BASE_URL"); val != "" {
		cfg.OpenAIBaseURL = val
	}
	if val := os.Getenv("OPENAI_API_KEY"); val != "" {
		cfg.OpenAIKey = val
	}
	if val := os.Getenv("ANTHROPIC_BASE_URL"); val != "" {
		cfg.AnthropicBaseURL = val
	}
	if val := os.Getenv("ANTHROPIC_API_KEY"); val != "" {
		cfg.AnthropicKey = val
	}
	if val := os.Getenv("GEMINI_BASE_URL"); val != "" {
		cfg.GeminiBaseURL = val
	}
	if val := getEnvAny("GEMINI_API_KEY", "GOOGLE_API_KEY"); val != "" {
		cfg.GeminiKey = val
	}
	if val := os.Getenv("OLLAMA_BASE_URL"); val != "" {
		cfg.OllamaBaseURL = val
	}
	if val := os.Getenv("VAULT_TTL"); val != "" {
		if ttl, err := time.ParseDuration(val); err == nil && ttl > 0 {
			cfg.VaultTTL = ttl
		}
	}
	if val := os.Getenv("TRACE_BUFFER_SIZE"); val != "" {
		if size, err := strconv.Atoi(val); err == nil && size > 0 {
			cfg.TraceBufferSize = size
		}
	}
	if val := getEnvAny("HADESGATE_ALLOW_DYNAMIC_UPSTREAM", "PRIVAGATE_ALLOW_DYNAMIC_UPSTREAM"); val != "" {
		cfg.AllowDynamicUpstream = strings.EqualFold(val, "true") || val == "1"
	}
	if val := getEnvAny("HADESGATE_ALLOW_PRIVATE_DYNAMIC_UPSTREAM", "PRIVAGATE_ALLOW_PRIVATE_DYNAMIC_UPSTREAM"); val != "" {
		cfg.AllowPrivateDynamicUpstream = strings.EqualFold(val, "true") || val == "1"
	}
	if val := getEnvAny("HADESGATE_DYNAMIC_UPSTREAM_ALLOWED_HOSTS", "PRIVAGATE_DYNAMIC_UPSTREAM_ALLOWED_HOSTS"); val != "" {
		for _, host := range strings.Split(val, ",") {
			if host = strings.TrimSpace(host); host != "" {
				cfg.DynamicUpstreamAllowedHosts = append(cfg.DynamicUpstreamAllowedHosts, host)
			}
		}
	}
	if val := getEnvAny("HADESGATE_PRIVATE_UPSTREAM_ALLOWED_HOSTS", "PRIVAGATE_PRIVATE_UPSTREAM_ALLOWED_HOSTS"); val != "" {
		for _, entry := range strings.Split(val, ",") {
			if host := strings.TrimSpace(entry); host != "" {
				cfg.PrivateUpstreamAllowedHosts = append(cfg.PrivateUpstreamAllowedHosts, host)
			}
		}
	}
	if val := getEnvAny("HADESGATE_MAX_CONCURRENT_REQUESTS", "PRIVAGATE_MAX_CONCURRENT_REQUESTS"); val != "" {
		if limit, err := strconv.Atoi(val); err == nil && limit > 0 {
			cfg.MaxConcurrentRequests = limit
		}
	}
	if val := getEnvAny("HADESGATE_MAX_RESPONSE_BYTES", "PRIVAGATE_MAX_RESPONSE_BYTES"); val != "" {
		if limit, err := strconv.ParseInt(val, 10, 64); err == nil && limit > 0 {
			cfg.MaxResponseBytes = limit
		}
	}
	if val := getEnvAny("HADESGATE_MAX_SSE_EVENT_BYTES", "PRIVAGATE_MAX_SSE_EVENT_BYTES"); val != "" {
		if limit, err := strconv.Atoi(val); err == nil && limit > 0 {
			cfg.MaxSSEEventBytes = limit
		}
	}
	if val := getEnvAny("HADESGATE_ENTITY_ACTIONS", "PRIVAGATE_ENTITY_ACTIONS"); val != "" {
		for _, rule := range strings.Split(val, ",") {
			parts := strings.SplitN(rule, ":", 2)
			if len(parts) == 2 {
				cfg.EntityActions[strings.ToUpper(strings.TrimSpace(parts[0]))] = strings.ToLower(strings.TrimSpace(parts[1]))
			}
		}
	}
	if val := getEnvAny("HADESGATE_TENANT_PROXY_KEYS", "PRIVAGATE_TENANT_PROXY_KEYS"); val != "" {
		for _, entry := range strings.Split(val, ",") {
			parts := strings.SplitN(entry, ":", 2)
			if len(parts) == 2 && strings.TrimSpace(parts[0]) != "" && strings.TrimSpace(parts[1]) != "" {
				cfg.TenantProxyKeys[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
			}
		}
	}
	if val := getEnvAny("HADESGATE_TENANT_ENTITY_ACTIONS", "PRIVAGATE_TENANT_ENTITY_ACTIONS"); val != "" {
		for _, entry := range strings.Split(val, ";") {
			parts := strings.SplitN(entry, "|", 2)
			if len(parts) != 2 {
				continue
			}
			tenant := strings.TrimSpace(parts[0])
			if cfg.TenantEntityActions[tenant] == nil {
				cfg.TenantEntityActions[tenant] = make(map[string]string)
			}
			for _, rule := range strings.Split(parts[1], ",") {
				actionParts := strings.SplitN(rule, ":", 2)
				if len(actionParts) == 2 {
					cfg.TenantEntityActions[tenant][strings.ToUpper(strings.TrimSpace(actionParts[0]))] = strings.ToLower(strings.TrimSpace(actionParts[1]))
				}
			}
		}
	}
	if val := getEnvAny("HADESGATE_RATE_LIMIT_PER_MINUTE", "PRIVAGATE_RATE_LIMIT_PER_MINUTE"); val != "" {
		if limit, err := strconv.Atoi(val); err == nil && limit >= 0 {
			cfg.RateLimitPerMinute = limit
		}
	}
	if val := getEnvAny("HADESGATE_TENANT_RATE_LIMITS", "PRIVAGATE_TENANT_RATE_LIMITS"); val != "" {
		for _, entry := range strings.Split(val, ",") {
			parts := strings.SplitN(entry, ":", 2)
			if len(parts) == 2 {
				if limit, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil && limit > 0 {
					cfg.TenantRateLimits[strings.TrimSpace(parts[0])] = limit
				}
			}
		}
	}
	if val := os.Getenv("SEMANTIC_DETECTOR_ENABLED"); val != "" {
		cfg.SemanticDetectorEnabled = strings.EqualFold(val, "true") || val == "1"
	}
	if val := os.Getenv("SEMANTIC_DETECTOR_URL"); val != "" {
		cfg.SemanticDetectorURL = val
	}
	if val := os.Getenv("SEMANTIC_DETECTOR_TIMEOUT_MS"); val != "" {
		if timeout, err := strconv.Atoi(val); err == nil && timeout > 0 {
			cfg.SemanticDetectorTimeout = time.Duration(timeout) * time.Millisecond
		}
	}
	if val := getEnvAny("HADESGATE_DB_PATH", "PRIVAGATE_DB_PATH", "SQLITE_DB_PATH"); val != "" {
		cfg.SQLiteDBPath = strings.TrimSpace(val)
	}
	if val := os.Getenv("ANONYMIZER_MIN_CONFIDENCE"); val != "" {
		if s, err := strconv.ParseFloat(val, 64); err == nil && s > 0 && s <= 1.0 {
			cfg.AnonymizerMinScore = s
		}
	}
	if val := os.Getenv("ANONYMIZER_ALLOWLIST"); val != "" {
		cfg.AnonymizerAllowlist = strings.Split(val, ",")
	}
	if val := os.Getenv("ANONYMIZER_DENYLIST"); val != "" {
		cfg.AnonymizerDenylist = strings.Split(val, ",")
	}
	if val := os.Getenv("ANONYMIZER_CUSTOM_FILE"); val != "" {
		cfg.AnonymizerCustomFile = val
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_PIX"); val != "" {
		cfg.AnonymizerEnablePIX = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_RG"); val != "" {
		cfg.AnonymizerEnableRG = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_CNH"); val != "" {
		cfg.AnonymizerEnableCNH = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_BANK"); val != "" {
		cfg.AnonymizerEnableBank = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_IBAN"); val != "" {
		cfg.AnonymizerEnableIBAN = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_PASSPORT"); val != "" {
		cfg.AnonymizerEnablePass = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_IP"); val != "" {
		cfg.AnonymizerEnableIP = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_API_KEY"); val != "" {
		cfg.AnonymizerEnableAPIKey = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_SECRET"); val != "" {
		cfg.AnonymizerEnableSecret = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_SSN"); val != "" {
		cfg.AnonymizerEnableSSN = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_EIN"); val != "" {
		cfg.AnonymizerEnableEIN = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_NINO"); val != "" {
		cfg.AnonymizerEnableNINO = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_NHS"); val != "" {
		cfg.AnonymizerEnableNHS = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_DNI"); val != "" {
		cfg.AnonymizerEnableDNI = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_NIR"); val != "" {
		cfg.AnonymizerEnableNIR = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_CODICE_FISCALE"); val != "" {
		cfg.AnonymizerEnableCF = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_MEDICAL"); val != "" {
		cfg.AnonymizerEnableMedical = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_SUS"); val != "" {
		cfg.AnonymizerEnableSUS = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_VEHICLE"); val != "" {
		cfg.AnonymizerEnableVehicle = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_LEGAL"); val != "" {
		cfg.AnonymizerEnableLegal = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_DEVICE"); val != "" {
		cfg.AnonymizerEnableDevice = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_GOVERNMENT_ID"); val != "" {
		cfg.AnonymizerEnableGovID = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_CID"); val != "" {
		cfg.AnonymizerEnableCID = strings.ToLower(val) != "false" && val != "0"
	}
	if val := os.Getenv("ANONYMIZER_ENABLE_MEDICATION"); val != "" {
		cfg.AnonymizerEnableMedication = strings.ToLower(val) != "false" && val != "0"
	}
	if val := getEnvAny("HADESGATE_CORS_ALLOWED_ORIGINS", "PRIVAGATE_CORS_ALLOWED_ORIGINS", "CORS_ALLOWED_ORIGINS"); val != "" {
		var origins []string
		for _, o := range strings.Split(val, ",") {
			if trimmed := strings.TrimSpace(o); trimmed != "" {
				origins = append(origins, trimmed)
			}
		}
		if len(origins) > 0 {
			cfg.CORSAllowedOrigins = origins
		}
	}
	if val := getEnvAny("HADESGATE_ENABLE_EGRESS_SCAN", "PRIVAGATE_ENABLE_EGRESS_SCAN", "ENABLE_EGRESS_SCAN"); val != "" {
		cfg.EnableEgressScan = strings.ToLower(val) == "true" || val == "1"
	}
	if val := getEnvAny("HADESGATE_WEBHOOK_URL", "PRIVAGATE_WEBHOOK_URL", "WEBHOOK_URL"); val != "" {
		cfg.WebhookURL = strings.TrimSpace(val)
	}
	if val := getEnvAny("HADESGATE_WEBHOOK_SECRET", "PRIVAGATE_WEBHOOK_SECRET", "WEBHOOK_SECRET"); val != "" {
		cfg.WebhookSecret = strings.TrimSpace(val)
	}
	if val := getEnvAny("HADESGATE_WEBHOOK_EVENTS", "PRIVAGATE_WEBHOOK_EVENTS", "WEBHOOK_EVENTS"); val != "" {
		var events []string
		for _, e := range strings.Split(val, ",") {
			if trimmed := strings.TrimSpace(e); trimmed != "" {
				events = append(events, trimmed)
			}
		}
		cfg.WebhookEvents = events
	}

	// CLI flags (registered and parsed when invoked from CLI entrypoint)
	if !flag.Parsed() && flag.Lookup("port") == nil {
		flag.StringVar(&cfg.BindAddress, "bind-address", cfg.BindAddress, "HTTP server bind address")
		flag.IntVar(&cfg.Port, "port", cfg.Port, "HTTP server port")
		flag.StringVar(&cfg.AdminKey, "admin-key", cfg.AdminKey, "Admin API key for dashboard and proxy")
		flag.StringVar(&cfg.ProxyKey, "proxy-key", cfg.ProxyKey, "API key accepted by model proxy endpoints")
		flag.StringVar(&cfg.ProviderFingerprintSecret, "fingerprint-secret", cfg.ProviderFingerprintSecret, "HMAC secret for transparent BYOK credential fingerprints")
		flag.BoolVar(&cfg.AllowLegacyURLKeys, "allow-legacy-url-keys", cfg.AllowLegacyURLKeys, "Allow deprecated credential-bearing /p and /t URLs")
		flag.StringVar(&cfg.OpenAIBaseURL, "openai-base-url", cfg.OpenAIBaseURL, "OpenAI base URL")
		flag.StringVar(&cfg.OpenAIKey, "openai-key", cfg.OpenAIKey, "OpenAI API key")
		flag.StringVar(&cfg.AnthropicBaseURL, "anthropic-base-url", cfg.AnthropicBaseURL, "Anthropic base URL")
		flag.StringVar(&cfg.AnthropicKey, "anthropic-key", cfg.AnthropicKey, "Anthropic API key")
		flag.StringVar(&cfg.GeminiBaseURL, "gemini-base-url", cfg.GeminiBaseURL, "Google Gemini base URL")
		flag.StringVar(&cfg.GeminiKey, "gemini-key", cfg.GeminiKey, "Google Gemini API key")
		flag.StringVar(&cfg.OllamaBaseURL, "ollama-url", cfg.OllamaBaseURL, "Ollama base URL")
		flag.BoolVar(&cfg.AllowDynamicUpstream, "allow-dynamic-upstream", cfg.AllowDynamicUpstream, "Allow X-Upstream-Url for explicitly allowlisted hosts")
		flag.BoolVar(&cfg.AllowPrivateDynamicUpstream, "allow-private-dynamic-upstream", cfg.AllowPrivateDynamicUpstream, "Allow dynamic upstream allowlist entries to resolve to loopback or private networks")
		flag.IntVar(&cfg.MaxConcurrentRequests, "max-concurrent-requests", cfg.MaxConcurrentRequests, "Maximum concurrent proxy requests")
		flag.StringVar(&cfg.SQLiteDBPath, "db-path", cfg.SQLiteDBPath, "SQLite file path for non-sensitive anonymization telemetry")
		flag.Float64Var(&cfg.AnonymizerMinScore, "anonymizer-min-score", cfg.AnonymizerMinScore, "Minimum confidence score for PII detection")
		flag.BoolVar(&cfg.AnonymizerEnableAPIKey, "anonymizer-enable-apikey", cfg.AnonymizerEnableAPIKey, "Enable API Key detection")
		flag.BoolVar(&cfg.AnonymizerEnableSecret, "anonymizer-enable-secret", cfg.AnonymizerEnableSecret, "Enable secrets and credentials detection")
		flag.Parse()
	}

	// Security requirement: Ensure AdminKey is never empty.
	// A generated key is printed once at boot (see cmd/hadesgate) so a deployment
	// without configuration stays reachable instead of becoming a locked box.
	if cfg.AdminKey == "" {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err == nil {
			cfg.AdminKey = fmt.Sprintf("hadesgate_sec_%x", bytes)
			cfg.GeneratedAdminKey = true
		}
	}
	if cfg.ProxyKey == "" {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err == nil {
			cfg.ProxyKey = fmt.Sprintf("hadesgate_proxy_%x", bytes)
			cfg.GeneratedProxyKey = true
		}
	}
	if cfg.ProxyKey != "" && subtle.ConstantTimeCompare([]byte(cfg.ProxyKey), []byte(cfg.AdminKey)) == 1 {
		bytes := make([]byte, 32)
		if _, err := rand.Read(bytes); err == nil {
			cfg.ProxyKey = fmt.Sprintf("hadesgate_proxy_%x", bytes)
			cfg.GeneratedProxyKey = true
			log.Printf("⚠️  [SECURITY NOTICE] HADESGATE_PROXY_KEY matched HADESGATE_ADMIN_KEY and was replaced with an ephemeral, non-admin proxy key.\n")
		}
	}
	if cfg.AdminKey == ExampleAdminKey {
		log.Printf("⚠️  [SECURITY NOTICE] HADESGATE_ADMIN_KEY still uses the public value from .env.example. Replace it before exposing the gateway.\n")
	}
	if cfg.BindAddress = strings.TrimSpace(cfg.BindAddress); cfg.BindAddress == "" {
		cfg.BindAddress = "127.0.0.1"
	}

	return cfg
}

func getEnvAny(keys ...string) string {
	for _, k := range keys {
		if v := os.Getenv(k); v != "" {
			return v
		}
	}
	return ""
}
