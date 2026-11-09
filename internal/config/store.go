package config

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"
)

// DynamicConfig represents configurations that can be modified at runtime without server restart.
type DynamicConfig struct {
	EntityActions      map[string]string  `json:"entity_actions"`
	GlobalProxyKey     string             `json:"global_proxy_key"`
	WebhookURL         string             `json:"webhook_url"`
	WebhookSecret      string             `json:"webhook_secret"`
	WebhookEvents      []string           `json:"webhook_events"`
	EnableEgressScan   bool               `json:"enable_egress_scan"`
	OllamaBaseURL      string             `json:"ollama_base_url"`
	CORSAllowedOrigins []string           `json:"cors_allowed_origins"`
	FamilyThresholds   map[string]float64 `json:"family_thresholds,omitempty"`
	EntityThresholds   map[string]float64 `json:"entity_thresholds,omitempty"`
}

// TenantConfig represents an isolated customer or department configuration.
type TenantConfig struct {
	ID            string            `json:"id"`
	Name          string            `json:"name"`
	ProxyKey      string            `json:"proxy_key"`
	RateLimit     int               `json:"rate_limit"`
	EntityActions map[string]string `json:"entity_actions"`
	UpdatedAt     time.Time         `json:"updated_at"`
}

// ProviderCredential stores only metadata and a keyed fingerprint of a BYOK
// provider credential. The original provider key is never persisted.
type ProviderCredential struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Provider    string    `json:"provider"`
	Label       string    `json:"label"`
	KeyHint     string    `json:"key_hint"`
	Fingerprint string    `json:"-"`
	CreatedAt   time.Time `json:"created_at"`
}

// Store persists dynamic configurations in SQLite.
type Store struct {
	db      *sql.DB
	mu      sync.Mutex
	secrets *secretCipher
	authKey [32]byte
}

// NewStore initializes the store and creates necessary SQLite tables.
func NewStore(db *sql.DB, masterKey []byte) (*Store, error) {
	if db == nil {
		return nil, fmt.Errorf("database connection is nil")
	}
	secrets, err := newSecretCipher(masterKey)
	if err != nil {
		return nil, err
	}
	s := &Store{db: db, secrets: secrets, authKey: sha256.Sum256(append(append([]byte{}, masterKey...), []byte("/hadesgate/governance/v1")...))}
	if err := s.initSchema(context.Background()); err != nil {
		return nil, err
	}
	if err := s.initGovernanceSchema(context.Background()); err != nil {
		return nil, err
	}
	if err := s.migrateAndValidateSecrets(context.Background()); err != nil {
		return nil, fmt.Errorf("initializing encrypted configuration: %w", err)
	}
	return s, nil
}

func (s *Store) migrateAndValidateSecrets(ctx context.Context) error {
	if _, err := s.db.ExecContext(ctx, "PRAGMA secure_delete = ON"); err != nil {
		return fmt.Errorf("enabling secure delete for secret migration: %w", err)
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	migratedPlaintext := false

	type systemValue struct{ key, value string }
	var systemValues []systemValue
	rows, err := tx.QueryContext(ctx, "SELECT key, value FROM system_config WHERE key IN ('global_proxy_key', 'webhook_url', 'webhook_secret')")
	if err != nil {
		return err
	}
	for rows.Next() {
		var item systemValue
		if err := rows.Scan(&item.key, &item.value); err != nil {
			rows.Close()
			return err
		}
		systemValues = append(systemValues, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range systemValues {
		if item.value == "" {
			continue
		}
		if strings.HasPrefix(item.value, encryptedSecretPrefix) {
			if _, err := s.secrets.decrypt(item.value, systemSecretAAD(item.key)); err != nil {
				return fmt.Errorf("validating %s: %w", item.key, err)
			}
			continue
		}
		encrypted, err := s.secrets.encrypt(item.value, systemSecretAAD(item.key))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE system_config SET value = ? WHERE key = ?", encrypted, item.key); err != nil {
			return err
		}
		migratedPlaintext = true
	}

	type tenantValue struct{ id, value string }
	var tenantValues []tenantValue
	rows, err = tx.QueryContext(ctx, "SELECT id, proxy_key FROM tenants")
	if err != nil {
		return err
	}
	for rows.Next() {
		var item tenantValue
		if err := rows.Scan(&item.id, &item.value); err != nil {
			rows.Close()
			return err
		}
		tenantValues = append(tenantValues, item)
	}
	if err := rows.Close(); err != nil {
		return err
	}
	for _, item := range tenantValues {
		if item.value == "" {
			continue
		}
		if strings.HasPrefix(item.value, encryptedSecretPrefix) {
			if _, err := s.secrets.decrypt(item.value, tenantSecretAAD(item.id)); err != nil {
				return fmt.Errorf("validating tenant %s proxy key: %w", item.id, err)
			}
			continue
		}
		encrypted, err := s.secrets.encrypt(item.value, tenantSecretAAD(item.id))
		if err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, "UPDATE tenants SET proxy_key = ? WHERE id = ?", encrypted, item.id); err != nil {
			return err
		}
		migratedPlaintext = true
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	if migratedPlaintext {
		if _, err := s.db.ExecContext(ctx, "VACUUM"); err != nil {
			return fmt.Errorf("vacuuming legacy plaintext pages: %w", err)
		}
		if _, err := s.db.ExecContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)"); err != nil {
			return fmt.Errorf("truncating legacy plaintext WAL: %w", err)
		}
	}
	return nil
}

func (s *Store) initSchema(ctx context.Context) error {
	const ddl = `
	CREATE TABLE IF NOT EXISTS system_config (
		key TEXT PRIMARY KEY,
		value TEXT NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS tenants (
		id TEXT PRIMARY KEY,
		name TEXT NOT NULL DEFAULT '',
		proxy_key TEXT NOT NULL,
		rate_limit INTEGER NOT NULL,
		entity_actions TEXT NOT NULL,
		updated_at TIMESTAMP NOT NULL
	);

	CREATE TABLE IF NOT EXISTS provider_credentials (
		id TEXT PRIMARY KEY,
		tenant_id TEXT NOT NULL,
		provider TEXT NOT NULL,
		label TEXT NOT NULL,
		key_hint TEXT NOT NULL,
		fingerprint TEXT NOT NULL UNIQUE,
		created_at TIMESTAMP NOT NULL,
		FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON UPDATE CASCADE ON DELETE CASCADE
	);
	CREATE INDEX IF NOT EXISTS idx_provider_credentials_tenant ON provider_credentials(tenant_id);
	`
	_, err := s.db.ExecContext(ctx, ddl)
	if err != nil {
		return fmt.Errorf("creating configuration tables: %w", err)
	}

	// Schema migration: ensure 'name' column exists in existing databases
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE tenants ADD COLUMN name TEXT NOT NULL DEFAULT ''")

	return nil
}

// SeedIfEmpty loads default configurations from boot config if the tables are currently empty.
func (s *Store) SeedIfEmpty(ctx context.Context, initial DynamicConfig, initialTenants []TenantConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM system_config").Scan(&count)
	if err != nil {
		return fmt.Errorf("checking system_config count: %w", err)
	}

	if count == 0 {
		if err := s.saveDynamicConfigLocked(ctx, initial); err != nil {
			return fmt.Errorf("seeding initial dynamic config: %w", err)
		}
	}

	var tenantCount int
	err = s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tenants").Scan(&tenantCount)
	if err != nil {
		return fmt.Errorf("checking tenants count: %w", err)
	}

	if tenantCount == 0 && len(initialTenants) > 0 {
		for _, t := range initialTenants {
			if _, err := s.saveTenantLocked(ctx, t); err != nil {
				return fmt.Errorf("seeding initial tenant %s: %w", t.ID, err)
			}
		}
	}

	return nil
}

// GetDynamicConfig loads dynamic configuration from SQLite.
func (s *Store) GetDynamicConfig(ctx context.Context) (DynamicConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, "SELECT key, value FROM system_config")
	if err != nil {
		return DynamicConfig{}, fmt.Errorf("querying system_config: %w", err)
	}
	defer rows.Close()

	cfg := DynamicConfig{
		EntityActions: make(map[string]string),
	}

	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			return DynamicConfig{}, err
		}

		switch k {
		case "entity_actions":
			_ = json.Unmarshal([]byte(v), &cfg.EntityActions)
		case "global_proxy_key":
			cfg.GlobalProxyKey, err = s.secrets.decrypt(v, systemSecretAAD(k))
			if err != nil {
				return DynamicConfig{}, fmt.Errorf("decrypting global proxy key: %w", err)
			}
		case "webhook_url":
			cfg.WebhookURL, err = s.secrets.decrypt(v, systemSecretAAD(k))
			if err != nil {
				return DynamicConfig{}, fmt.Errorf("decrypting webhook URL: %w", err)
			}
		case "webhook_secret":
			cfg.WebhookSecret, err = s.secrets.decrypt(v, systemSecretAAD(k))
			if err != nil {
				return DynamicConfig{}, fmt.Errorf("decrypting webhook secret: %w", err)
			}
		case "webhook_events":
			if v != "" {
				cfg.WebhookEvents = strings.Split(v, ",")
			}
		case "enable_egress_scan":
			cfg.EnableEgressScan = (v == "true" || v == "1")
		case "ollama_base_url":
			cfg.OllamaBaseURL = v
		case "cors_allowed_origins":
			if v != "" {
				cfg.CORSAllowedOrigins = strings.Split(v, ",")
			}
		case "family_thresholds":
			if v != "" {
				_ = json.Unmarshal([]byte(v), &cfg.FamilyThresholds)
			}
		case "entity_thresholds":
			if v != "" {
				_ = json.Unmarshal([]byte(v), &cfg.EntityThresholds)
			}
		}
	}

	return cfg, rows.Err()
}

// SaveDynamicConfig updates dynamic configuration in SQLite.
func (s *Store) SaveDynamicConfig(ctx context.Context, cfg DynamicConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveDynamicConfigLocked(ctx, cfg)
}

func (s *Store) saveDynamicConfigLocked(ctx context.Context, cfg DynamicConfig) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	actionsJSON, _ := json.Marshal(cfg.EntityActions)
	familyThresholdsJSON, _ := json.Marshal(cfg.FamilyThresholds)
	entityThresholdsJSON, _ := json.Marshal(cfg.EntityThresholds)
	now := time.Now().UTC()
	globalProxyKey, err := s.encryptedSystemSecret(ctx, tx, "global_proxy_key", strings.TrimSpace(cfg.GlobalProxyKey))
	if err != nil {
		return err
	}
	webhookSecret, err := s.encryptedSystemSecret(ctx, tx, "webhook_secret", strings.TrimSpace(cfg.WebhookSecret))
	if err != nil {
		return err
	}

	webhookURL, err := s.encryptedSystemSecret(ctx, tx, "webhook_url", strings.TrimSpace(cfg.WebhookURL))
	if err != nil {
		return err
	}

	items := map[string]string{
		"entity_actions":       string(actionsJSON),
		"global_proxy_key":     globalProxyKey,
		"webhook_url":          webhookURL,
		"webhook_secret":       webhookSecret,
		"webhook_events":       strings.Join(cfg.WebhookEvents, ","),
		"enable_egress_scan":   fmt.Sprintf("%t", cfg.EnableEgressScan),
		"ollama_base_url":      cfg.OllamaBaseURL,
		"cors_allowed_origins": strings.Join(cfg.CORSAllowedOrigins, ","),
		"family_thresholds":    string(familyThresholdsJSON),
		"entity_thresholds":    string(entityThresholdsJSON),
	}

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO system_config (key, value, updated_at) 
		VALUES (?, ?, ?) 
		ON CONFLICT(key) DO UPDATE SET value = excluded.value, updated_at = excluded.updated_at
	`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for k, v := range items {
		if _, err := stmt.ExecContext(ctx, k, v, now); err != nil {
			return err
		}
	}

	return tx.Commit()
}

func (s *Store) encryptedSystemSecret(ctx context.Context, tx *sql.Tx, key, plaintext string) (string, error) {
	if plaintext == "__CLEAR__" {
		return "", nil
	}
	if plaintext != "" {
		return s.secrets.encrypt(plaintext, systemSecretAAD(key))
	}
	var existing string
	err := tx.QueryRowContext(ctx, "SELECT value FROM system_config WHERE key = ?", key).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("reading existing %s: %w", key, err)
	}
	return "", nil
}

// ListTenants retrieves all configured tenants from SQLite.
func (s *Store) ListTenants(ctx context.Context) ([]TenantConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rows, err := s.db.QueryContext(ctx, "SELECT id, name, proxy_key, rate_limit, entity_actions, updated_at FROM tenants ORDER BY id ASC")
	if err != nil {
		return nil, fmt.Errorf("querying tenants: %w", err)
	}
	defer rows.Close()

	var tenants []TenantConfig
	for rows.Next() {
		var t TenantConfig
		var actionsRaw string
		if err := rows.Scan(&t.ID, &t.Name, &t.ProxyKey, &t.RateLimit, &actionsRaw, &t.UpdatedAt); err != nil {
			return nil, err
		}
		t.ProxyKey, err = s.secrets.decrypt(t.ProxyKey, tenantSecretAAD(t.ID))
		if err != nil {
			return nil, fmt.Errorf("decrypting tenant %s proxy key: %w", t.ID, err)
		}
		t.EntityActions = make(map[string]string)
		_ = json.Unmarshal([]byte(actionsRaw), &t.EntityActions)
		tenants = append(tenants, t)
	}

	return tenants, rows.Err()
}

// tenantIDPattern keeps IDs usable in the /t/{id}/ route.
var tenantIDPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// SaveTenant creates or updates a tenant record. If tenant.ID is empty, it auto-assigns the next sequential ID.
func (s *Store) SaveTenant(ctx context.Context, tenant TenantConfig) (TenantConfig, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.saveTenantLocked(ctx, tenant)
}

// UpdateTenant updates an existing tenant, supporting updating Name, ProxyKey, RateLimit, EntityActions, and ID rename.
func (s *Store) UpdateTenant(ctx context.Context, originalID string, tenant TenantConfig) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	originalID = strings.TrimSpace(originalID)
	tenant.ID = strings.TrimSpace(tenant.ID)
	tenant.Name = strings.TrimSpace(tenant.Name)
	tenant.ProxyKey = strings.TrimSpace(tenant.ProxyKey)

	if tenant.ID == "" {
		return fmt.Errorf("tenant ID is required")
	}
	if !tenantIDPattern.MatchString(tenant.ID) {
		return fmt.Errorf("tenant ID %q must match [A-Za-z0-9_-] up to 64 characters", tenant.ID)
	}

	now := time.Now().UTC()
	tenant.UpdatedAt = now
	actionsJSON, _ := json.Marshal(tenant.EntityActions)

	if originalID == "" || originalID == tenant.ID {
		encryptedProxyKey, err := s.encryptedTenantSecret(ctx, tenant.ID, tenant.ProxyKey)
		if err != nil {
			return err
		}
		query := `
			UPDATE tenants
			SET name = ?, proxy_key = ?, rate_limit = ?, entity_actions = ?, updated_at = ?
			WHERE id = ?
		`
		res, err := s.db.ExecContext(ctx, query, tenant.Name, encryptedProxyKey, tenant.RateLimit, string(actionsJSON), now, tenant.ID)
		if err != nil {
			return fmt.Errorf("updating tenant: %w", err)
		}
		rowsAffected, _ := res.RowsAffected()
		if rowsAffected == 0 {
			_, err := s.saveTenantLocked(ctx, tenant)
			return err
		}
		return nil
	}

	// Renaming tenant ID: verify target ID does not already exist
	var count int
	err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tenants WHERE id = ?", tenant.ID).Scan(&count)
	if err != nil {
		return fmt.Errorf("checking tenant ID existence: %w", err)
	}
	if count > 0 {
		return fmt.Errorf("tenant with ID %q already exists", tenant.ID)
	}
	plaintextProxyKey := tenant.ProxyKey
	if plaintextProxyKey == "" {
		var existing string
		if err := s.db.QueryRowContext(ctx, "SELECT proxy_key FROM tenants WHERE id = ?", originalID).Scan(&existing); err != nil {
			return fmt.Errorf("reading tenant %q proxy key: %w", originalID, err)
		}
		plaintextProxyKey, err = s.secrets.decrypt(existing, tenantSecretAAD(originalID))
		if err != nil {
			return fmt.Errorf("decrypting tenant %q proxy key: %w", originalID, err)
		}
	}
	encryptedProxyKey, err := s.secrets.encrypt(plaintextProxyKey, tenantSecretAAD(tenant.ID))
	if err != nil {
		return err
	}

	query := `
		UPDATE tenants
		SET id = ?, name = ?, proxy_key = ?, rate_limit = ?, entity_actions = ?, updated_at = ?
		WHERE id = ?
	`
	res, err := s.db.ExecContext(ctx, query, tenant.ID, tenant.Name, encryptedProxyKey, tenant.RateLimit, string(actionsJSON), now, originalID)
	if err != nil {
		return fmt.Errorf("updating tenant ID: %w", err)
	}
	rowsAffected, _ := res.RowsAffected()
	if rowsAffected == 0 {
		return fmt.Errorf("tenant %q not found", originalID)
	}
	return nil
}

func (s *Store) saveTenantLocked(ctx context.Context, tenant TenantConfig) (TenantConfig, error) {
	tenant.ID = strings.TrimSpace(tenant.ID)
	tenant.Name = strings.TrimSpace(tenant.Name)
	tenant.ProxyKey = strings.TrimSpace(tenant.ProxyKey)
	if tenant.ID != "" && !tenantIDPattern.MatchString(tenant.ID) {
		return tenant, fmt.Errorf("tenant ID %q must match [A-Za-z0-9_-] up to 64 characters", tenant.ID)
	}

	// Auto-assign sequential numeric ID if empty
	if tenant.ID == "" {
		var maxID int
		rows, err := s.db.QueryContext(ctx, "SELECT id FROM tenants")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var idStr string
				if err := rows.Scan(&idStr); err == nil {
					var num int
					if _, err := fmt.Sscanf(idStr, "%d", &num); err == nil && num > maxID {
						maxID = num
					}
				}
			}
		}
		tenant.ID = fmt.Sprintf("%02d", maxID+1)
	}

	if tenant.Name == "" {
		tenant.Name = fmt.Sprintf("Tenant %s", tenant.ID)
	}

	now := time.Now().UTC()
	tenant.UpdatedAt = now
	actionsJSON, _ := json.Marshal(tenant.EntityActions)
	encryptedProxyKey, err := s.encryptedTenantSecret(ctx, tenant.ID, tenant.ProxyKey)
	if err != nil {
		return tenant, err
	}

	query := `
		INSERT INTO tenants (id, name, proxy_key, rate_limit, entity_actions, updated_at)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET
			name = excluded.name,
			proxy_key = excluded.proxy_key,
			rate_limit = excluded.rate_limit,
			entity_actions = excluded.entity_actions,
			updated_at = excluded.updated_at
	`
	_, err = s.db.ExecContext(ctx, query, tenant.ID, tenant.Name, encryptedProxyKey, tenant.RateLimit, string(actionsJSON), now)
	return tenant, err
}

func (s *Store) encryptedTenantSecret(ctx context.Context, id, plaintext string) (string, error) {
	if plaintext != "" {
		return s.secrets.encrypt(plaintext, tenantSecretAAD(id))
	}
	var existing string
	err := s.db.QueryRowContext(ctx, "SELECT proxy_key FROM tenants WHERE id = ?", id).Scan(&existing)
	if err == nil {
		return existing, nil
	}
	if err != sql.ErrNoRows {
		return "", fmt.Errorf("reading existing tenant proxy key: %w", err)
	}
	return "", fmt.Errorf("tenant proxy key is required")
}

// DeleteTenant deletes a tenant by ID.
func (s *Store) DeleteTenant(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	_, err := s.db.ExecContext(ctx, "DELETE FROM tenants WHERE id = ?", id)
	return err
}

// SaveProviderCredential persists a provider-key fingerprint and non-sensitive metadata.
func (s *Store) SaveProviderCredential(ctx context.Context, credential ProviderCredential) (ProviderCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	credential.ID = strings.TrimSpace(credential.ID)
	credential.TenantID = strings.TrimSpace(credential.TenantID)
	credential.Provider = strings.ToLower(strings.TrimSpace(credential.Provider))
	credential.Label = strings.TrimSpace(credential.Label)
	credential.KeyHint = strings.TrimSpace(credential.KeyHint)
	credential.Fingerprint = strings.ToLower(strings.TrimSpace(credential.Fingerprint))
	if credential.ID == "" || credential.TenantID == "" || credential.Fingerprint == "" {
		return credential, fmt.Errorf("credential ID, tenant ID, and fingerprint are required")
	}
	if credential.Provider == "" {
		credential.Provider = "other"
	}
	if credential.Label == "" {
		credential.Label = credential.Provider
	}
	if credential.CreatedAt.IsZero() {
		credential.CreatedAt = time.Now().UTC()
	}

	var tenantExists int
	if err := s.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM tenants WHERE id = ?", credential.TenantID).Scan(&tenantExists); err != nil {
		return credential, fmt.Errorf("checking provider credential tenant: %w", err)
	}
	if tenantExists == 0 {
		return credential, fmt.Errorf("tenant %q not found", credential.TenantID)
	}

	const query = `
		INSERT INTO provider_credentials (id, tenant_id, provider, label, key_hint, fingerprint, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?)
	`
	if _, err := s.db.ExecContext(ctx, query, credential.ID, credential.TenantID, credential.Provider, credential.Label, credential.KeyHint, credential.Fingerprint, credential.CreatedAt); err != nil {
		return credential, fmt.Errorf("saving provider credential: %w", err)
	}
	return credential, nil
}

// ListProviderCredentials returns credential metadata. Fingerprint is populated
// for trusted in-process authentication reloads but omitted from JSON responses.
func (s *Store) ListProviderCredentials(ctx context.Context, tenantID string) ([]ProviderCredential, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	tenantID = strings.TrimSpace(tenantID)
	query := `SELECT id, tenant_id, provider, label, key_hint, fingerprint, created_at FROM provider_credentials`
	var args []interface{}
	if tenantID != "" {
		query += " WHERE tenant_id = ?"
		args = append(args, tenantID)
	}
	query += " ORDER BY created_at DESC"
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("listing provider credentials: %w", err)
	}
	defer rows.Close()

	var credentials []ProviderCredential
	for rows.Next() {
		var credential ProviderCredential
		if err := rows.Scan(&credential.ID, &credential.TenantID, &credential.Provider, &credential.Label, &credential.KeyHint, &credential.Fingerprint, &credential.CreatedAt); err != nil {
			return nil, fmt.Errorf("scanning provider credential: %w", err)
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

// ProviderKeyFingerprints groups persisted fingerprints by tenant for the in-memory gateway index.
func (s *Store) ProviderKeyFingerprints(ctx context.Context) (map[string][]string, error) {
	credentials, err := s.ListProviderCredentials(ctx, "")
	if err != nil {
		return nil, err
	}
	grouped := make(map[string][]string)
	for _, credential := range credentials {
		grouped[credential.TenantID] = append(grouped[credential.TenantID], credential.Fingerprint)
	}
	return grouped, nil
}

// DeleteProviderCredential revokes one provider credential by its opaque ID.
func (s *Store) DeleteProviderCredential(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	result, err := s.db.ExecContext(ctx, "DELETE FROM provider_credentials WHERE id = ?", strings.TrimSpace(id))
	if err != nil {
		return fmt.Errorf("deleting provider credential: %w", err)
	}
	rows, err := result.RowsAffected()
	if err == nil && rows == 0 {
		return fmt.Errorf("provider credential not found")
	}
	return nil
}
