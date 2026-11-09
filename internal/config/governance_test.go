package config

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"

	_ "modernc.org/sqlite"
)

func newGovernanceTestStore(t *testing.T) *Store {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { _ = db.Close() })
	store, err := NewStore(db, []byte("0123456789abcdef0123456789abcdef"))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestAdminCredentialsAreAccountlessScopedAndOneTimeReveal(t *testing.T) {
	store := newGovernanceTestStore(t)
	ctx := context.Background()
	created, err := store.CreateAdminCredential(ctx, "NOC", RoleOperator)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(created.Secret, "hg_admin_") {
		t.Fatalf("secret was not generated: %+v", created)
	}
	if credential, ok := store.AuthenticateAdminCredential(ctx, created.Secret); !ok || credential.KeyID != created.KeyID || credential.Role != RoleOperator {
		t.Fatalf("generated credential did not authenticate: %+v, %v", credential, ok)
	}
	if _, ok := store.AuthenticateAdminCredential(ctx, "wrong-secret"); ok {
		t.Fatal("invalid secret authenticated")
	}
	listed, err := store.ListAdminCredentials(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(listed) != 1 || listed[0].Secret != "" {
		t.Fatalf("listing exposed or lost credential: %+v", listed)
	}
	if err := store.DeleteAdminCredential(ctx, created.KeyID); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.AuthenticateAdminCredential(ctx, created.Secret); ok {
		t.Fatal("revoked credential authenticated")
	}
}

func TestAdminCredentialRotationInvalidatesOldSecretAndAuthenticatesNew(t *testing.T) {
	store := newGovernanceTestStore(t)
	ctx := context.Background()

	// 1. Create initial credential
	created, err := store.CreateAdminCredential(ctx, "SecOps", RoleOperator)
	if err != nil {
		t.Fatalf("creating credential: %v", err)
	}
	oldSecret := created.Secret

	// Verify old secret works
	if _, ok := store.AuthenticateAdminCredential(ctx, oldSecret); !ok {
		t.Fatal("old secret did not authenticate before rotation")
	}

	// 2. Rotate the credential
	rotated, err := store.RotateAdminCredential(ctx, created.KeyID)
	if err != nil {
		t.Fatalf("rotating credential: %v", err)
	}
	if rotated.Secret == "" || rotated.Secret == oldSecret {
		t.Fatalf("expected new secret generated, got %q", rotated.Secret)
	}
	if rotated.KeyID != created.KeyID {
		t.Fatalf("expected same key ID %s, got %s", created.KeyID, rotated.KeyID)
	}

	// 3. Old secret MUST be invalidated
	if _, ok := store.AuthenticateAdminCredential(ctx, oldSecret); ok {
		t.Fatal("old secret still authenticated after rotation")
	}

	// 4. New secret MUST authenticate
	authenticated, ok := store.AuthenticateAdminCredential(ctx, rotated.Secret)
	if !ok {
		t.Fatal("new secret failed to authenticate")
	}
	if authenticated.KeyID != created.KeyID || authenticated.Role != RoleOperator {
		t.Fatalf("unexpected authenticated principal: %+v", authenticated)
	}
}

func TestGovernanceAuditUsesUniqueNonceAndSignature(t *testing.T) {
	store := newGovernanceTestStore(t)
	ctx := context.Background()
	for index := 0; index < 2; index++ {
		if err := store.RecordAuditEvent(ctx, AuditEvent{ActorKeyID: "bootstrap", ActorRole: RoleAdmin, Action: "policy.updated", TargetType: "tenant", TargetID: "finance"}); err != nil {
			t.Fatal(err)
		}
	}
	events, err := store.ListAuditEvents(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || events[0].Nonce == events[1].Nonce {
		t.Fatalf("audit nonces are not unique: %+v", events)
	}
	for _, event := range events {
		if event.Signature == "" || event.Signature != store.auditSignature(event) {
			t.Fatalf("invalid audit signature: %+v", event)
		}
	}
}

func TestEncryptedBackupExcludesTelemetryAndRestoresCiphertextConfiguration(t *testing.T) {
	store := newGovernanceTestStore(t)
	ctx := context.Background()
	if err := store.SaveDynamicConfig(ctx, DynamicConfig{GlobalProxyKey: "proxy-plaintext", WebhookSecret: "webhook-plaintext"}); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.ExecContext(ctx, `CREATE TABLE audit_traces(sanitized_prompt TEXT); INSERT INTO audit_traces VALUES('trace-canary')`); err != nil {
		t.Fatal(err)
	}
	credential, err := store.CreateAdminCredential(ctx, "Auditoria", RoleViewer)
	if err != nil {
		t.Fatal(err)
	}
	backup, err := store.ExportEncryptedBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(backup, "proxy-plaintext") || strings.Contains(backup, "webhook-plaintext") || strings.Contains(backup, credential.Secret) {
		t.Fatal("backup exposed plaintext secret")
	}
	decrypted, err := store.secrets.decrypt(backup, backupAAD)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(decrypted, "trace-canary") || strings.Contains(decrypted, "audit_traces") {
		t.Fatal("backup included telemetry")
	}
	if _, err := store.db.ExecContext(ctx, `DELETE FROM system_config; DELETE FROM admin_credentials`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RestoreEncryptedBackup(ctx, backup); err != nil {
		t.Fatal(err)
	}
	cfg, err := store.GetDynamicConfig(ctx)
	if err != nil || cfg.GlobalProxyKey != "proxy-plaintext" || cfg.WebhookSecret != "webhook-plaintext" {
		t.Fatalf("configuration was not restored: %+v, %v", cfg, err)
	}
	if _, ok := store.AuthenticateAdminCredential(ctx, credential.Secret); !ok {
		t.Fatal("admin credential fingerprint was not restored")
	}
}

func TestAuditChainDetectsEditionAndDeletion(t *testing.T) {
	store := newGovernanceTestStore(t)
	ctx := context.Background()

	record := func(action string) {
		t.Helper()
		if err := store.RecordAuditEvent(ctx, AuditEvent{
			ActorKeyID: "adm_test", ActorRole: RoleAdmin, Action: action, TargetType: "configuration",
		}); err != nil {
			t.Fatalf("recording %s: %v", action, err)
		}
	}
	record("configuration.updated")
	record("tenant.created")
	record("admin_credential.created")

	report, err := store.VerifyAuditChain(ctx)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !report.Valid || report.Events != 3 {
		t.Fatalf("intact chain must verify: %+v", report)
	}

	// Editing a row breaks its signature.
	if _, err := store.db.ExecContext(ctx, `UPDATE governance_audit SET action = 'tenant.deleted' WHERE action = 'tenant.created'`); err != nil {
		t.Fatal(err)
	}
	report, _ = store.VerifyAuditChain(ctx)
	if report.Valid || !strings.Contains(report.Reason, "edited") {
		t.Fatalf("edition must be detected: %+v", report)
	}

	// Rebuild the chain and delete a middle row instead.
	store2 := newGovernanceTestStore(t)
	store = store2
	record("a.first")
	record("b.middle")
	record("c.last")
	if _, err := store.db.ExecContext(ctx, `DELETE FROM governance_audit WHERE action = 'b.middle'`); err != nil {
		t.Fatal(err)
	}
	report, _ = store.VerifyAuditChain(ctx)
	if report.Valid || !strings.Contains(report.Reason, "deleted") {
		t.Fatalf("deletion must be detected: %+v", report)
	}
}

func TestRestoreRejectsIncompletePayloadWithoutTouchingData(t *testing.T) {
	store := newGovernanceTestStore(t)
	ctx := context.Background()
	if err := store.SaveDynamicConfig(ctx, DynamicConfig{GlobalProxyKey: "key-before-restore"}); err != nil {
		t.Fatal(err)
	}
	backup, err := store.ExportEncryptedBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}
	plain, err := store.secrets.decrypt(backup, backupAAD)
	if err != nil {
		t.Fatal(err)
	}
	var payload backupPayload
	if err := json.Unmarshal([]byte(plain), &payload); err != nil {
		t.Fatal(err)
	}
	delete(payload.Tables, "tenants")
	delete(payload.Tables, "admin_credentials")
	broken, _ := json.Marshal(payload)
	envelope, err := store.secrets.encrypt(string(broken), backupAAD)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.RestoreEncryptedBackup(ctx, envelope); err == nil || !strings.Contains(err.Error(), "missing the") {
		t.Fatalf("expected a missing-table error, got %v", err)
	}
	cfg, err := store.GetDynamicConfig(ctx)
	if err != nil || cfg.GlobalProxyKey != "key-before-restore" {
		t.Fatalf("rejected restore must not touch the data: %+v %v", cfg, err)
	}
}

func TestRestoreFlagsCrossInstanceBackup(t *testing.T) {
	source := newGovernanceTestStore(t)
	ctx := context.Background()
	backup, err := source.ExportEncryptedBackup(ctx)
	if err != nil {
		t.Fatal(err)
	}

	destination := newGovernanceTestStore(t)
	destinationID, err := destination.instanceID(ctx)
	if err != nil {
		t.Fatal(err)
	}
	report, err := destination.RestoreEncryptedBackup(ctx, backup)
	if err != nil {
		t.Fatal(err)
	}
	if !report.CrossInstance || report.SourceInstance == "" {
		t.Fatalf("cross-instance restore must be reported: %+v", report)
	}
	// The destination keeps its own identity.
	after, err := destination.instanceID(ctx)
	if err != nil || after != destinationID {
		t.Fatalf("destination instance id changed: %q -> %q (%v)", destinationID, after, err)
	}
}
