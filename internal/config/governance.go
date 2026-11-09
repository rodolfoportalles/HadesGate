package config

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const backupAAD = "hadesgate/config-backup/v1"

type AdminRole string

const (
	RoleViewer   AdminRole = "viewer"
	RoleOperator AdminRole = "operator"
	RoleAdmin    AdminRole = "admin"
)

func (r AdminRole) Valid() bool { return r == RoleViewer || r == RoleOperator || r == RoleAdmin }
func (r AdminRole) Level() int {
	switch r {
	case RoleAdmin:
		return 3
	case RoleOperator:
		return 2
	case RoleViewer:
		return 1
	default:
		return 0
	}
}

type AdminCredential struct {
	KeyID      string    `json:"key_id"`
	Label      string    `json:"label"`
	Role       AdminRole `json:"role"`
	Enabled    bool      `json:"enabled"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
	Secret     string    `json:"secret,omitempty"`
}

type AuditEvent struct {
	ID         string          `json:"id"`
	ActorKeyID string          `json:"actor_key_id"`
	ActorRole  AdminRole       `json:"actor_role"`
	Action     string          `json:"action"`
	TargetType string          `json:"target_type"`
	TargetID   string          `json:"target_id,omitempty"`
	Metadata   json.RawMessage `json:"metadata"`
	Timestamp  time.Time       `json:"timestamp"`
	Nonce      string          `json:"nonce"`
	Signature  string          `json:"signature"`
	PrevHash   string          `json:"prev_hash"`
}

func (s *Store) initGovernanceSchema(ctx context.Context) error {
	const ddl = `
CREATE TABLE IF NOT EXISTS admin_credentials (
  key_id TEXT PRIMARY KEY, label TEXT NOT NULL, role TEXT NOT NULL,
  fingerprint TEXT NOT NULL UNIQUE, enabled INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL, updated_at TIMESTAMP NOT NULL, last_used_at TIMESTAMP
);
CREATE TABLE IF NOT EXISTS governance_audit (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT NOT NULL UNIQUE,
  actor_key_id TEXT NOT NULL, actor_role TEXT NOT NULL, action TEXT NOT NULL,
  target_type TEXT NOT NULL, target_id TEXT NOT NULL DEFAULT '', metadata TEXT NOT NULL DEFAULT '{}',
  timestamp TIMESTAMP NOT NULL, nonce TEXT NOT NULL UNIQUE, signature TEXT NOT NULL,
  prev_hash TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_governance_audit_timestamp ON governance_audit(timestamp DESC);
CREATE TABLE IF NOT EXISTS telemetry_retention (
  tenant_id TEXT PRIMARY KEY, retention_days INTEGER NOT NULL DEFAULT 0,
  max_rows INTEGER NOT NULL DEFAULT 0, updated_at TIMESTAMP NOT NULL
);`
	if _, err := s.db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("creating governance tables: %w", err)
	}
	// Migration for databases created before the hash chain.
	_, _ = s.db.ExecContext(ctx, "ALTER TABLE governance_audit ADD COLUMN prev_hash TEXT NOT NULL DEFAULT ''")
	return nil
}

func (s *Store) credentialFingerprint(secret string) string {
	mac := hmac.New(sha256.New, s.authKey[:])
	_, _ = mac.Write([]byte(secret))
	return hex.EncodeToString(mac.Sum(nil))
}

func randomHex(size int) (string, error) {
	buffer := make([]byte, size)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func (s *Store) CreateAdminCredential(ctx context.Context, label string, role AdminRole) (AdminCredential, error) {
	label = strings.TrimSpace(label)
	if label == "" || !role.Valid() {
		return AdminCredential{}, fmt.Errorf("label and a valid role are required")
	}
	idPart, err := randomHex(6)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("generating credential id: %w", err)
	}
	secretPart, err := randomHex(32)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("generating credential secret: %w", err)
	}
	now := time.Now().UTC()
	credential := AdminCredential{KeyID: "adm_" + idPart, Label: label, Role: role, Enabled: true, CreatedAt: now, UpdatedAt: now, Secret: "hg_admin_" + secretPart}
	_, err = s.db.ExecContext(ctx, `INSERT INTO admin_credentials(key_id,label,role,fingerprint,enabled,created_at,updated_at) VALUES(?,?,?,?,1,?,?)`, credential.KeyID, credential.Label, credential.Role, s.credentialFingerprint(credential.Secret), now, now)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("creating admin credential: %w", err)
	}
	return credential, nil
}

// RotateAdminCredential invalidates the existing secret of an admin credential and generates a new one.
func (s *Store) RotateAdminCredential(ctx context.Context, keyID string) (AdminCredential, error) {
	keyID = strings.TrimSpace(keyID)
	if keyID == "" {
		return AdminCredential{}, fmt.Errorf("key_id is required")
	}

	var item AdminCredential
	var enabled int
	err := s.db.QueryRowContext(ctx, `SELECT key_id, label, role, enabled, created_at FROM admin_credentials WHERE key_id = ?`, keyID).
		Scan(&item.KeyID, &item.Label, &item.Role, &enabled, &item.CreatedAt)
	if err == sql.ErrNoRows {
		return AdminCredential{}, fmt.Errorf("credential not found")
	}
	if err != nil {
		return AdminCredential{}, fmt.Errorf("querying admin credential: %w", err)
	}

	secretPart, err := randomHex(32)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("generating credential secret: %w", err)
	}
	newSecret := "hg_admin_" + secretPart
	newFingerprint := s.credentialFingerprint(newSecret)
	now := time.Now().UTC()

	_, err = s.db.ExecContext(ctx, `UPDATE admin_credentials SET fingerprint = ?, updated_at = ?, last_used_at = NULL WHERE key_id = ?`,
		newFingerprint, now, keyID)
	if err != nil {
		return AdminCredential{}, fmt.Errorf("updating admin credential: %w", err)
	}

	item.Enabled = enabled == 1
	item.UpdatedAt = now
	item.Secret = newSecret
	return item, nil
}

func (s *Store) ListAdminCredentials(ctx context.Context) ([]AdminCredential, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT key_id,label,role,enabled,created_at,updated_at,last_used_at FROM admin_credentials ORDER BY created_at DESC`)
	if err != nil {
		return nil, fmt.Errorf("listing admin credentials: %w", err)
	}
	defer rows.Close()
	result := []AdminCredential{}
	for rows.Next() {
		var item AdminCredential
		var enabled int
		var lastUsed sql.NullTime
		if err := rows.Scan(&item.KeyID, &item.Label, &item.Role, &enabled, &item.CreatedAt, &item.UpdatedAt, &lastUsed); err != nil {
			return nil, err
		}
		item.Enabled = enabled == 1
		if lastUsed.Valid {
			item.LastUsedAt = lastUsed.Time
		}
		result = append(result, item)
	}
	return result, rows.Err()
}

func (s *Store) AuthenticateAdminCredential(ctx context.Context, secret string) (AdminCredential, bool) {
	if strings.TrimSpace(secret) == "" {
		return AdminCredential{}, false
	}
	fingerprint := s.credentialFingerprint(secret)
	rows, err := s.db.QueryContext(ctx, `SELECT key_id,label,role,fingerprint,created_at,updated_at FROM admin_credentials WHERE enabled = 1`)
	if err != nil {
		return AdminCredential{}, false
	}
	var matched AdminCredential
	for rows.Next() {
		var item AdminCredential
		var stored string
		if err := rows.Scan(&item.KeyID, &item.Label, &item.Role, &stored, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return AdminCredential{}, false
		}
		if len(stored) == len(fingerprint) && subtle.ConstantTimeCompare([]byte(stored), []byte(fingerprint)) == 1 {
			item.Enabled = true
			matched = item
		}
	}
	_ = rows.Close()
	if matched.KeyID == "" {
		return AdminCredential{}, false
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE admin_credentials SET last_used_at = ? WHERE key_id = ?`, time.Now().UTC(), matched.KeyID)
	return matched, true
}

func (s *Store) DeleteAdminCredential(ctx context.Context, keyID string) error {
	result, err := s.db.ExecContext(ctx, `DELETE FROM admin_credentials WHERE key_id = ?`, strings.TrimSpace(keyID))
	if err != nil {
		return fmt.Errorf("deleting admin credential: %w", err)
	}
	if count, _ := result.RowsAffected(); count == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (s *Store) auditSignature(event AuditEvent) string {
	mac := hmac.New(sha256.New, s.authKey[:])
	fmt.Fprintf(mac, "%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s\x00%s", event.PrevHash, event.ID, event.ActorKeyID, event.ActorRole, event.Action, event.TargetType, event.TargetID, event.Timestamp.UTC().Format(time.RFC3339Nano), event.Nonce)
	_, _ = mac.Write(event.Metadata)
	return hex.EncodeToString(mac.Sum(nil))
}

// lastAuditSignature returns the signature of the newest event, the chain link
// the next event must reference.
func (s *Store) lastAuditSignature(ctx context.Context) (string, error) {
	var signature string
	err := s.db.QueryRowContext(ctx, `SELECT signature FROM governance_audit ORDER BY seq DESC LIMIT 1`).Scan(&signature)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return signature, err
}

func (s *Store) RecordAuditEvent(ctx context.Context, event AuditEvent) error {
	if event.ActorKeyID == "" || !event.ActorRole.Valid() || event.Action == "" || event.TargetType == "" {
		return fmt.Errorf("incomplete audit event")
	}
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	if len(event.Metadata) == 0 {
		event.Metadata = json.RawMessage(`{}`)
	}
	var metadata interface{}
	if err := json.Unmarshal(event.Metadata, &metadata); err != nil {
		return fmt.Errorf("invalid audit metadata: %w", err)
	}
	event.Metadata, _ = json.Marshal(metadata)
	var err error
	if event.ID == "" {
		event.ID, err = randomHex(16)
		if err != nil {
			return err
		}
	}
	if event.Nonce == "" {
		event.Nonce, err = randomHex(16)
		if err != nil {
			return err
		}
	}
	// Chain the event to its predecessor so deletions are detectable, not only
	// in-place edits. Serialized by the store mutex to keep the link stable.
	s.mu.Lock()
	previous, err := s.lastAuditSignature(ctx)
	if err != nil {
		s.mu.Unlock()
		return fmt.Errorf("reading previous audit signature: %w", err)
	}
	event.PrevHash = previous
	event.Signature = s.auditSignature(event)
	_, err = s.db.ExecContext(ctx, `INSERT INTO governance_audit(id,actor_key_id,actor_role,action,target_type,target_id,metadata,timestamp,nonce,signature,prev_hash) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, event.ID, event.ActorKeyID, event.ActorRole, event.Action, event.TargetType, event.TargetID, string(event.Metadata), event.Timestamp, event.Nonce, event.Signature, event.PrevHash)
	s.mu.Unlock()
	if err != nil {
		return fmt.Errorf("recording audit event: %w", err)
	}
	return nil
}

func (s *Store) ListAuditEvents(ctx context.Context, limit int) ([]AuditEvent, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor_key_id,actor_role,action,target_type,target_id,metadata,timestamp,nonce,signature,prev_hash FROM governance_audit ORDER BY seq DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("listing audit events: %w", err)
	}
	defer rows.Close()
	result := []AuditEvent{}
	for rows.Next() {
		var item AuditEvent
		var metadata string
		if err := rows.Scan(&item.ID, &item.ActorKeyID, &item.ActorRole, &item.Action, &item.TargetType, &item.TargetID, &metadata, &item.Timestamp, &item.Nonce, &item.Signature, &item.PrevHash); err != nil {
			return nil, err
		}
		item.Metadata = json.RawMessage(metadata)
		result = append(result, item)
	}
	return result, rows.Err()
}

type backupRow map[string]interface{}
type backupPayload struct {
	Version    int                    `json:"version"`
	InstanceID string                 `json:"instance_id"`
	Created    time.Time              `json:"created_at"`
	Tables     map[string][]backupRow `json:"tables"`
}

// backupTableColumns is the contract a backup must satisfy. A payload missing a
// table or a column is rejected before anything is deleted.
var backupTableColumns = map[string][]string{
	"system_config":        {"key", "value", "updated_at"},
	"tenants":              {"id", "name", "proxy_key", "rate_limit", "entity_actions", "updated_at"},
	"provider_credentials": {"id", "tenant_id", "provider", "label", "key_hint", "fingerprint", "created_at"},
	"admin_credentials":    {"key_id", "label", "role", "fingerprint", "enabled", "created_at", "updated_at", "last_used_at"},
	"telemetry_retention":  {"tenant_id", "retention_days", "max_rows", "updated_at"},
}

// instanceID returns this installation's identifier, creating it on first use.
// It is not secret: it exists to tell backups from different installations apart.
func (s *Store) instanceID(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.instanceIDLocked(ctx)
}

func (s *Store) instanceIDLocked(ctx context.Context) (string, error) {
	var existing string
	err := s.db.QueryRowContext(ctx, `SELECT value FROM system_config WHERE key = 'instance_id'`).Scan(&existing)
	if err == nil && existing != "" {
		return existing, nil
	}
	if err != nil && err != sql.ErrNoRows {
		return "", err
	}
	generated, err := randomHex(8)
	if err != nil {
		return "", err
	}
	if _, err := s.db.ExecContext(ctx, `INSERT INTO system_config(key,value,updated_at) VALUES('instance_id',?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, generated, time.Now().UTC()); err != nil {
		return "", err
	}
	return generated, nil
}

// RestoreReport describes what a restore replaced.
type RestoreReport struct {
	SourceInstance string `json:"source_instance"`
	CrossInstance  bool   `json:"cross_instance"`
	Rows           int    `json:"rows"`
}

func validateBackupPayload(payload backupPayload) error {
	if payload.Version != 1 {
		return fmt.Errorf("unsupported backup payload")
	}
	for table, columns := range backupTableColumns {
		rows, ok := payload.Tables[table]
		if !ok {
			return fmt.Errorf("backup is missing the %s table", table)
		}
		for index, row := range rows {
			for _, column := range columns {
				if _, ok := row[column]; !ok {
					return fmt.Errorf("backup row %d of %s is missing the %s column", index, table, column)
				}
			}
		}
	}
	return nil
}

func (s *Store) ExportEncryptedBackup(ctx context.Context) (string, error) {
	tables := map[string]string{
		"system_config":        `SELECT key,value,updated_at FROM system_config`,
		"tenants":              `SELECT id,name,proxy_key,rate_limit,entity_actions,updated_at FROM tenants`,
		"provider_credentials": `SELECT id,tenant_id,provider,label,key_hint,fingerprint,created_at FROM provider_credentials`,
		"admin_credentials":    `SELECT key_id,label,role,fingerprint,enabled,created_at,updated_at,last_used_at FROM admin_credentials`,
		"telemetry_retention":  `SELECT tenant_id,retention_days,max_rows,updated_at FROM telemetry_retention`,
	}
	payload := backupPayload{Version: 1, Created: time.Now().UTC(), Tables: make(map[string][]backupRow, len(tables))}
	instance, err := s.instanceID(ctx)
	if err != nil {
		return "", fmt.Errorf("resolving instance id: %w", err)
	}
	payload.InstanceID = instance
	names := make([]string, 0, len(tables))
	for name := range tables {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		payload.Tables[name] = []backupRow{}
	}
	for _, name := range names {
		rows, err := s.db.QueryContext(ctx, tables[name])
		if err != nil {
			return "", err
		}
		columns, _ := rows.Columns()
		for rows.Next() {
			values := make([]interface{}, len(columns))
			pointers := make([]interface{}, len(columns))
			for index := range values {
				pointers[index] = &values[index]
			}
			if err := rows.Scan(pointers...); err != nil {
				rows.Close()
				return "", err
			}
			row := backupRow{}
			for index, column := range columns {
				if value, ok := values[index].([]byte); ok {
					row[column] = string(value)
				} else {
					row[column] = values[index]
				}
			}
			payload.Tables[name] = append(payload.Tables[name], row)
		}
		rows.Close()
	}
	encoded, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	return s.secrets.encrypt(string(encoded), backupAAD)
}

func (s *Store) RestoreEncryptedBackup(ctx context.Context, envelope string) (RestoreReport, error) {
	plaintext, err := s.secrets.decrypt(strings.TrimSpace(envelope), backupAAD)
	if err != nil {
		return RestoreReport{}, fmt.Errorf("decrypting backup: %w", err)
	}
	var payload backupPayload
	if err := json.Unmarshal([]byte(plaintext), &payload); err != nil {
		return RestoreReport{}, fmt.Errorf("unsupported backup payload")
	}
	if err := validateBackupPayload(payload); err != nil {
		return RestoreReport{}, err
	}

	current, err := s.instanceID(ctx)
	if err != nil {
		return RestoreReport{}, fmt.Errorf("resolving instance id: %w", err)
	}
	report := RestoreReport{SourceInstance: payload.InstanceID, CrossInstance: payload.InstanceID != "" && payload.InstanceID != current}
	for _, rows := range payload.Tables {
		report.Rows += len(rows)
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return RestoreReport{}, err
	}
	defer tx.Rollback()
	for _, table := range []string{"provider_credentials", "admin_credentials", "telemetry_retention", "tenants", "system_config"} {
		if _, err := tx.ExecContext(ctx, "DELETE FROM "+table); err != nil {
			return RestoreReport{}, err
		}
	}
	insertRows := func(table string, columns []string) error {
		query := "INSERT INTO " + table + "(" + strings.Join(columns, ",") + ") VALUES(" + strings.TrimRight(strings.Repeat("?,", len(columns)), ",") + ")"
		for _, row := range payload.Tables[table] {
			values := make([]interface{}, len(columns))
			for index, column := range columns {
				values[index] = row[column]
			}
			if _, err := tx.ExecContext(ctx, query, values...); err != nil {
				return fmt.Errorf("restoring %s: %w", table, err)
			}
		}
		return nil
	}
	if err := insertRows("system_config", []string{"key", "value", "updated_at"}); err != nil {
		return RestoreReport{}, err
	}
	// The identifier belongs to the destination: a cross-instance restore must
	// not rename this installation to the source one.
	if _, err := tx.ExecContext(ctx, `INSERT INTO system_config(key,value,updated_at) VALUES('instance_id',?,?) ON CONFLICT(key) DO UPDATE SET value = excluded.value`, current, time.Now().UTC()); err != nil {
		return RestoreReport{}, err
	}
	if err := insertRows("tenants", []string{"id", "name", "proxy_key", "rate_limit", "entity_actions", "updated_at"}); err != nil {
		return RestoreReport{}, err
	}
	if err := insertRows("provider_credentials", []string{"id", "tenant_id", "provider", "label", "key_hint", "fingerprint", "created_at"}); err != nil {
		return RestoreReport{}, err
	}
	if err := insertRows("admin_credentials", []string{"key_id", "label", "role", "fingerprint", "enabled", "created_at", "updated_at", "last_used_at"}); err != nil {
		return RestoreReport{}, err
	}
	if err := insertRows("telemetry_retention", []string{"tenant_id", "retention_days", "max_rows", "updated_at"}); err != nil {
		return RestoreReport{}, err
	}
	if err := tx.Commit(); err != nil {
		return RestoreReport{}, err
	}
	if err := s.migrateAndValidateSecrets(ctx); err != nil {
		return report, err
	}
	return report, nil
}

// AuditChainReport is the outcome of an integrity check over the audit trail.
type AuditChainReport struct {
	Valid    bool   `json:"valid"`
	Events   int    `json:"events"`
	BrokenAt string `json:"broken_at,omitempty"`
	Reason   string `json:"reason,omitempty"`
}

// VerifyAuditChain walks the trail in insertion order and reports the first
// event whose signature does not match its content or whose predecessor link
// does not point at the previous row. A deleted row breaks the chain.
func (s *Store) VerifyAuditChain(ctx context.Context) (AuditChainReport, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT id,actor_key_id,actor_role,action,target_type,target_id,metadata,timestamp,nonce,signature,prev_hash FROM governance_audit ORDER BY seq ASC`)
	if err != nil {
		return AuditChainReport{}, fmt.Errorf("reading audit chain: %w", err)
	}
	defer rows.Close()

	report := AuditChainReport{Valid: true}
	expectedPrev := ""
	for rows.Next() {
		var item AuditEvent
		var metadata string
		if err := rows.Scan(&item.ID, &item.ActorKeyID, &item.ActorRole, &item.Action, &item.TargetType, &item.TargetID, &metadata, &item.Timestamp, &item.Nonce, &item.Signature, &item.PrevHash); err != nil {
			return AuditChainReport{}, err
		}
		item.Metadata = json.RawMessage(metadata)
		report.Events++
		if item.PrevHash != expectedPrev {
			report.Valid = false
			report.BrokenAt = item.ID
			report.Reason = "missing predecessor: a row was deleted or reordered"
			return report, nil
		}
		if subtle.ConstantTimeCompare([]byte(s.auditSignature(item)), []byte(item.Signature)) != 1 {
			report.Valid = false
			report.BrokenAt = item.ID
			report.Reason = "signature mismatch: a row was edited"
			return report, nil
		}
		expectedPrev = item.Signature
	}
	return report, rows.Err()
}
