package config

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

var testConfigMasterKey = []byte("0123456789abcdef0123456789abcdef")

func TestConfigStore_CRUD(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db, testConfigMasterKey)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	ctx := context.Background()

	// 1. Seed if empty
	initialCfg := DynamicConfig{
		EntityActions:    map[string]string{"CPF": "mask", "API_KEY": "block"},
		GlobalProxyKey:   "sec_HG_global_initial",
		WebhookURL:       "https://discord.com/api/webhooks/test",
		EnableEgressScan: true,
		WebhookEvents:    []string{"block", "egress_leak"},
	}
	initialTenants := []TenantConfig{
		{
			ID:            "01",
			Name:          "Financeiro",
			ProxyKey:      "acme-secret",
			RateLimit:     100,
			EntityActions: map[string]string{"CPF": "block"},
		},
	}

	if err := store.SeedIfEmpty(ctx, initialCfg, initialTenants); err != nil {
		t.Fatalf("SeedIfEmpty failed: %v", err)
	}

	// 2. Read back DynamicConfig
	cfg, err := store.GetDynamicConfig(ctx)
	if err != nil {
		t.Fatalf("GetDynamicConfig failed: %v", err)
	}
	if cfg.WebhookURL != initialCfg.WebhookURL {
		t.Errorf("got webhook URL %s, want %s", cfg.WebhookURL, initialCfg.WebhookURL)
	}
	if cfg.GlobalProxyKey != "sec_HG_global_initial" {
		t.Errorf("got GlobalProxyKey %s, want sec_HG_global_initial", cfg.GlobalProxyKey)
	}
	if !cfg.EnableEgressScan {
		t.Errorf("expected EnableEgressScan to be true")
	}
	if cfg.EntityActions["API_KEY"] != "block" {
		t.Errorf("expected API_KEY to be block, got %s", cfg.EntityActions["API_KEY"])
	}

	// 3. Update DynamicConfig with rotated global key
	cfg.WebhookURL = "https://hooks.slack.com/services/test"
	cfg.GlobalProxyKey = "sec_HG_global_rotated"
	cfg.EntityActions["SECRET"] = "block"
	if err := store.SaveDynamicConfig(ctx, cfg); err != nil {
		t.Fatalf("SaveDynamicConfig failed: %v", err)
	}
	updatedCfg, _ := store.GetDynamicConfig(ctx)
	if updatedCfg.GlobalProxyKey != "sec_HG_global_rotated" {
		t.Errorf("expected updated global proxy key, got %s", updatedCfg.GlobalProxyKey)
	}
	if updatedCfg.WebhookURL != "https://hooks.slack.com/services/test" {
		t.Errorf("expected updated webhook URL")
	}
	if updatedCfg.EntityActions["SECRET"] != "block" {
		t.Errorf("expected SECRET=block in updated config")
	}

	// 4. Test Tenants List, Upsert and Delete
	tenants, err := store.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants failed: %v", err)
	}
	if len(tenants) != 1 || tenants[0].ID != "01" || tenants[0].Name != "Financeiro" {
		t.Fatalf("expected 1 tenant '01' ('Financeiro'), got %+v", tenants)
	}

	// Add second tenant WITHOUT specifying ID -> should auto-assign "02"
	newTenant := TenantConfig{
		Name:      "Marketing",
		ProxyKey:  "mkt-secret",
		RateLimit: 50,
	}
	saved02, err := store.SaveTenant(ctx, newTenant)
	if err != nil {
		t.Fatalf("SaveTenant failed: %v", err)
	}
	if saved02.ID != "02" {
		t.Fatalf("expected auto-assigned ID '02', got %q", saved02.ID)
	}

	tenants, _ = store.ListTenants(ctx)
	if len(tenants) != 2 {
		t.Fatalf("expected 2 tenants, got %d", len(tenants))
	}

	// 5. Test UpdateTenant without changing ID (updating Name, Key, Limit, Actions)
	updated02 := TenantConfig{
		ID:            "02",
		Name:          "Marketing & Growth",
		ProxyKey:      "mkt-new-secret",
		RateLimit:     75,
		EntityActions: map[string]string{"EMAIL": "block"},
	}
	if err := store.UpdateTenant(ctx, "02", updated02); err != nil {
		t.Fatalf("UpdateTenant failed: %v", err)
	}
	tenants, _ = store.ListTenants(ctx)
	var found02 *TenantConfig
	for _, tItem := range tenants {
		if tItem.ID == "02" {
			found02 = &tItem
			break
		}
	}
	if found02 == nil || found02.Name != "Marketing & Growth" || found02.ProxyKey != "mkt-new-secret" || found02.EntityActions["EMAIL"] != "block" {
		t.Fatalf("expected updated tenant '02', got %+v", found02)
	}

	// Delete tenant 01
	if err := store.DeleteTenant(ctx, "01"); err != nil {
		t.Fatalf("DeleteTenant failed: %v", err)
	}
	tenants, _ = store.ListTenants(ctx)
	if len(tenants) != 1 || tenants[0].ID != "02" {
		t.Fatalf("expected 1 tenant '02' after delete, got %+v", tenants)
	}

	// Rename tenant ID
	renamedTenant := TenantConfig{
		ID:        "99",
		Name:      "Marketing & Growth",
		ProxyKey:  "mkt-new-secret",
		RateLimit: 75,
	}
	if err := store.UpdateTenant(ctx, "02", renamedTenant); err != nil {
		t.Fatalf("UpdateTenant with rename failed: %v", err)
	}
	tenants, _ = store.ListTenants(ctx)
	if len(tenants) != 1 || tenants[0].ID != "99" {
		t.Fatalf("expected tenant '99' after rename, got %+v", tenants)
	}
}

func TestConfigStore_SecretsAreNeverPersistedAsPlaintext(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db, testConfigMasterKey)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	ctx := context.Background()
	const globalKey = "sec_HG_global_plaintext_forbidden"
	const webhookSecret = "webhook_plaintext_forbidden"
	const webhookURL = "https://hooks.example.test/plaintext-forbidden-token"
	const tenantKey = "sec_HG_tenant_plaintext_forbidden"
	if err := store.SaveDynamicConfig(ctx, DynamicConfig{
		GlobalProxyKey: globalKey,
		WebhookURL:     webhookURL,
		WebhookSecret:  webhookSecret,
	}); err != nil {
		t.Fatalf("SaveDynamicConfig failed: %v", err)
	}
	if _, err := store.SaveTenant(ctx, TenantConfig{ID: "01", ProxyKey: tenantKey}); err != nil {
		t.Fatalf("SaveTenant failed: %v", err)
	}

	for _, key := range []string{"global_proxy_key", "webhook_url", "webhook_secret"} {
		var persisted string
		if err := db.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", key).Scan(&persisted); err != nil {
			t.Fatalf("reading persisted %s: %v", key, err)
		}
		if persisted == globalKey || persisted == webhookURL || persisted == webhookSecret || !strings.HasPrefix(persisted, "enc:v1:") {
			t.Fatalf("secret %s was not stored as a versioned encrypted envelope: %q", key, persisted)
		}
	}
	var persistedTenantKey string
	if err := db.QueryRowContext(ctx, "SELECT proxy_key FROM tenants WHERE id = '01'").Scan(&persistedTenantKey); err != nil {
		t.Fatalf("reading tenant key: %v", err)
	}
	if persistedTenantKey == tenantKey || !strings.HasPrefix(persistedTenantKey, "enc:v1:") {
		t.Fatalf("tenant key was not encrypted: %q", persistedTenantKey)
	}

	cfg, err := store.GetDynamicConfig(ctx)
	if err != nil || cfg.GlobalProxyKey != globalKey || cfg.WebhookURL != webhookURL || cfg.WebhookSecret != webhookSecret {
		t.Fatalf("encrypted dynamic secrets did not round-trip: cfg=%+v err=%v", cfg, err)
	}
	tenants, err := store.ListTenants(ctx)
	if err != nil || len(tenants) != 1 || tenants[0].ProxyKey != tenantKey {
		t.Fatalf("encrypted tenant key did not round-trip: tenants=%+v err=%v", tenants, err)
	}
}

func TestConfigStore_MigratesLegacySecretsAndRejectsWrongKey(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "legacy.db")
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	defer db.Close()
	if _, err := NewStore(db, testConfigMasterKey); err != nil {
		t.Fatalf("initializing schema: %v", err)
	}
	ctx := context.Background()
	now := time.Now().UTC()
	if _, err := db.ExecContext(ctx, `INSERT INTO system_config(key,value,updated_at) VALUES('global_proxy_key','legacy-global',?)`, now); err != nil {
		t.Fatalf("inserting legacy global key: %v", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO tenants(id,name,proxy_key,rate_limit,entity_actions,updated_at) VALUES('01','Legacy','legacy-tenant',0,'{}',?)`, now); err != nil {
		t.Fatalf("inserting legacy tenant key: %v", err)
	}

	migrated, err := NewStore(db, testConfigMasterKey)
	if err != nil {
		t.Fatalf("migrating legacy secrets: %v", err)
	}
	cfg, err := migrated.GetDynamicConfig(ctx)
	if err != nil || cfg.GlobalProxyKey != "legacy-global" {
		t.Fatalf("legacy global key did not migrate: cfg=%+v err=%v", cfg, err)
	}
	tenants, err := migrated.ListTenants(ctx)
	if err != nil || len(tenants) != 1 || tenants[0].ProxyKey != "legacy-tenant" {
		t.Fatalf("legacy tenant key did not migrate: tenants=%+v err=%v", tenants, err)
	}
	databaseBytes, err := os.ReadFile(dbPath)
	if err != nil {
		t.Fatalf("reading migrated database: %v", err)
	}
	if bytes.Contains(databaseBytes, []byte("legacy-global")) || bytes.Contains(databaseBytes, []byte("legacy-tenant")) {
		t.Fatal("legacy plaintext remained recoverable in SQLite pages after migration")
	}

	wrongKey := []byte("abcdef0123456789abcdef0123456789")
	if _, err := NewStore(db, wrongKey); err == nil {
		t.Fatal("expected encrypted store initialization to reject the wrong master key")
	}
}

func TestParseMasterKey(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString(testConfigMasterKey)
	parsed, err := ParseMasterKey(encoded)
	if err != nil || !bytes.Equal(parsed, testConfigMasterKey) {
		t.Fatalf("base64 key did not parse: parsed=%x err=%v", parsed, err)
	}
	if _, err := ParseMasterKey("short"); err == nil {
		t.Fatal("expected invalid master key length to fail")
	}
}

func TestStoreProviderCredentialsPersistOnlyFingerprint(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	defer db.Close()

	store, err := NewStore(db, testConfigMasterKey)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}
	ctx := context.Background()
	_, err = store.SaveTenant(ctx, TenantConfig{
		ID:       "financeiro",
		Name:     "Financeiro",
		ProxyKey: "legacy-proxy-key",
	})
	if err != nil {
		t.Fatalf("SaveTenant failed: %v", err)
	}

	const rawProviderKey = "sk-provider-must-never-be-persisted"
	credential, err := store.SaveProviderCredential(ctx, ProviderCredential{
		ID:          "cred-01",
		TenantID:    "financeiro",
		Provider:    "openai",
		Label:       "Produção",
		KeyHint:     "…sted",
		Fingerprint: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	})
	if err != nil {
		t.Fatalf("SaveProviderCredential failed: %v", err)
	}
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatalf("marshaling credential: %v", err)
	}
	if strings.Contains(string(encoded), credential.Fingerprint) || strings.Contains(string(encoded), rawProviderKey) {
		t.Fatalf("credential response exposed sensitive material: %s", encoded)
	}

	credentials, err := store.ListProviderCredentials(ctx, "financeiro")
	if err != nil {
		t.Fatalf("ListProviderCredentials failed: %v", err)
	}
	if len(credentials) != 1 || credentials[0].Fingerprint != credential.Fingerprint {
		t.Fatalf("unexpected stored credentials: %+v", credentials)
	}
	fingerprints, err := store.ProviderKeyFingerprints(ctx)
	if err != nil {
		t.Fatalf("ProviderKeyFingerprints failed: %v", err)
	}
	if len(fingerprints["financeiro"]) != 1 || fingerprints["financeiro"][0] != credential.Fingerprint {
		t.Fatalf("unexpected grouped fingerprints: %+v", fingerprints)
	}

	if err := store.DeleteProviderCredential(ctx, credential.ID); err != nil {
		t.Fatalf("DeleteProviderCredential failed: %v", err)
	}
	credentials, err = store.ListProviderCredentials(ctx, "")
	if err != nil || len(credentials) != 0 {
		t.Fatalf("credential was not revoked: credentials=%+v err=%v", credentials, err)
	}
}

func TestStore_ClearWebhookAndThresholdPersistence(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("opening sqlite: %v", err)
	}
	defer db.Close()

	masterKey := []byte("01234567890123456789012345678901")
	store, err := NewStore(db, masterKey)
	if err != nil {
		t.Fatalf("NewStore failed: %v", err)
	}

	ctx := context.Background()

	// 1. Save with webhook and thresholds
	cfg := DynamicConfig{
		WebhookURL:       "https://hooks.example.test/incoming",
		WebhookSecret:    "hmac-secret-123",
		FamilyThresholds: map[string]float64{"HEALTH_PHI": 0.8},
		EntityThresholds: map[string]float64{"CPF": 0.95},
	}
	if err := store.SaveDynamicConfig(ctx, cfg); err != nil {
		t.Fatalf("SaveDynamicConfig failed: %v", err)
	}

	loaded, err := store.GetDynamicConfig(ctx)
	if err != nil {
		t.Fatalf("GetDynamicConfig failed: %v", err)
	}
	if loaded.WebhookURL != "https://hooks.example.test/incoming" {
		t.Fatalf("expected webhook URL, got %q", loaded.WebhookURL)
	}
	if loaded.FamilyThresholds["HEALTH_PHI"] != 0.8 || loaded.EntityThresholds["CPF"] != 0.95 {
		t.Fatalf("thresholds not persisted: family=%v entity=%v", loaded.FamilyThresholds, loaded.EntityThresholds)
	}

	// 2. Clear webhook using __CLEAR__
	cfg.WebhookURL = "__CLEAR__"
	cfg.WebhookSecret = "__CLEAR__"
	if err := store.SaveDynamicConfig(ctx, cfg); err != nil {
		t.Fatalf("SaveDynamicConfig with __CLEAR__ failed: %v", err)
	}

	cleared, err := store.GetDynamicConfig(ctx)
	if err != nil {
		t.Fatalf("GetDynamicConfig after clear failed: %v", err)
	}
	if cleared.WebhookURL != "" {
		t.Fatalf("expected cleared webhook URL, got %q", cleared.WebhookURL)
	}
	if cleared.WebhookSecret != "" {
		t.Fatalf("expected cleared webhook secret, got %q", cleared.WebhookSecret)
	}
}

func TestTenantIDValidation(t *testing.T) {
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewStore(db, testConfigMasterKey)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, id := range []string{"financeiro", "01", "team_a-b"} {
		if _, err := store.SaveTenant(ctx, TenantConfig{ID: id, Name: id, ProxyKey: "k-" + id}); err != nil {
			t.Fatalf("valid id %q rejected: %v", id, err)
		}
	}
	for _, id := range []string{"with space", "a/b", "acentuação"} {
		if _, err := store.SaveTenant(ctx, TenantConfig{ID: id, Name: id, ProxyKey: "k"}); err == nil {
			t.Fatalf("invalid id %q accepted", id)
		}
	}
}
