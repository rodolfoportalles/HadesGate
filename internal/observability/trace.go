package observability

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"

	_ "modernc.org/sqlite"

	"github.com/hadesgate/hadesgate/internal/anonymizer"
	"github.com/hadesgate/hadesgate/internal/anonymizer/detector"
)

const (
	defaultMaxRows           = 1000
	maxSanitizedPromptRunes  = 4096
	defaultDBOperationBudget = 3 * time.Second
)

// Trace represents non-sensitive anonymization telemetry for a single AI request.
// By design, raw prompts, plaintext PII, secrets, and vault token maps are NEVER stored here.
type Trace struct {
	ID              string    `json:"id"`
	Tenant          string    `json:"tenant,omitempty"`
	TenantName      string    `json:"tenant_name,omitempty"`
	UserLabel       string    `json:"user_label,omitempty"`
	UserRole        string    `json:"user_role,omitempty"`
	PolicyAction    string    `json:"policy_action,omitempty"`
	Timestamp       time.Time `json:"timestamp"`
	Provider        string    `json:"provider"`
	Model           string    `json:"model"`
	Language        string    `json:"language"`
	Stream          bool      `json:"stream"`
	StatusCode      int       `json:"status_code"`
	DurationMs      float64   `json:"duration_ms"`
	AnonDurationUs  int64     `json:"anon_duration_us"`
	EntitiesCount   int       `json:"entities_count"`
	EntityTypes     []string  `json:"entity_types"`
	PIITypes        []string  `json:"pii_types"`
	SecretTypes     []string  `json:"secret_types"`
	SanitizedPrompt string    `json:"sanitized_prompt"`
}

// Summary provides aggregated anonymization telemetry for the dashboard.
type Summary struct {
	TotalRequests        int            `json:"total_requests"`
	MaskedRequests       int            `json:"masked_requests"`
	MaskedRatePct        float64        `json:"masked_rate_pct"`
	BlockedRequests      int            `json:"blocked_requests"`
	TotalEntities        int            `json:"total_entities"`
	AvgScanUs            int64          `json:"avg_scan_us"`
	AvgScanMs            float64        `json:"avg_scan_ms"`
	AverageDurationMs    float64        `json:"avg_duration_ms"`
	RequestsLastHour     int            `json:"requests_last_hour"`
	ProviderDistribution map[string]int `json:"provider_distribution"`
	ModelDistribution    map[string]int `json:"model_distribution"`
	EntityTypeCounts     map[string]int `json:"entity_type_counts"`
	PIITypeCounts        map[string]int `json:"pii_type_counts"`
	SecretTypeCounts     map[string]int `json:"secret_type_counts"`
}

// TraceLogger persists non-sensitive anonymization telemetry in SQLite (file or :memory:).
type TraceLogger struct {
	db      *sql.DB
	dbPath  string
	maxRows int
}

// NewTraceLogger creates an in-memory SQLite TraceLogger bounded to maxCapacity rows.
func NewTraceLogger(maxCapacity int) *TraceLogger {
	logger, err := NewSQLiteTraceLogger(":memory:", maxCapacity)
	if err != nil {
		panic(fmt.Sprintf("failed to initialize in-memory sqlite trace logger: %v", err))
	}
	return logger
}

// NewSQLiteTraceLogger opens or creates a SQLite database at dbPath to store non-sensitive
// anonymization telemetry. Pass ":memory:" for ephemeral in-memory operation.
func NewSQLiteTraceLogger(dbPath string, maxRows int) (*TraceLogger, error) {
	if maxRows <= 0 {
		maxRows = defaultMaxRows
	}
	trimmedPath := strings.TrimSpace(dbPath)
	if trimmedPath == "" {
		trimmedPath = ":memory:"
	}

	if trimmedPath != ":memory:" {
		dir := filepath.Dir(trimmedPath)
		if dir != "" && dir != "." {
			if err := os.MkdirAll(dir, 0o750); err != nil {
				return nil, fmt.Errorf("creating sqlite directory %q: %w", dir, err)
			}
		}
	}

	db, err := sql.Open("sqlite", trimmedPath)
	if err != nil {
		return nil, fmt.Errorf("opening sqlite database: %w", err)
	}

	// Single-connection pool prevents SQLITE_BUSY write contention under high concurrency
	// and keeps ":memory:" databases alive across queries.
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	db.SetConnMaxLifetime(0)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := initSchema(ctx, db, trimmedPath != ":memory:"); err != nil {
		_ = db.Close()
		return nil, err
	}
	if trimmedPath != ":memory:" {
		// The database holds encrypted secrets, fingerprints and traces; keep it
		// owner-only regardless of the process umask.
		_ = os.Chmod(trimmedPath, 0o600)
	}

	return &TraceLogger{
		db:      db,
		dbPath:  trimmedPath,
		maxRows: maxRows,
	}, nil
}

func initSchema(ctx context.Context, db *sql.DB, enableWAL bool) error {
	pragmas := []string{
		"PRAGMA busy_timeout = 5000;",
		"PRAGMA synchronous = NORMAL;",
		"PRAGMA foreign_keys = ON;",
	}
	if enableWAL {
		pragmas = append([]string{"PRAGMA journal_mode = WAL;"}, pragmas...)
	}

	for _, pragma := range pragmas {
		if _, err := db.ExecContext(ctx, pragma); err != nil {
			return fmt.Errorf("applying sqlite pragma %q: %w", pragma, err)
		}
	}

	const ddl = `
CREATE TABLE IF NOT EXISTS audit_traces (
	seq              INTEGER PRIMARY KEY AUTOINCREMENT,
	id               TEXT NOT NULL UNIQUE,
	tenant           TEXT NOT NULL DEFAULT '',
	tenant_name      TEXT NOT NULL DEFAULT '',
	user_label       TEXT NOT NULL DEFAULT '',
	user_role        TEXT NOT NULL DEFAULT '',
	policy_action    TEXT NOT NULL DEFAULT 'mask',
	timestamp_unix   INTEGER NOT NULL,
	timestamp_iso    TEXT NOT NULL,
	provider         TEXT NOT NULL DEFAULT '',
	model            TEXT NOT NULL DEFAULT '',
	language         TEXT NOT NULL DEFAULT '',
	stream           INTEGER NOT NULL DEFAULT 0,
	status_code      INTEGER NOT NULL DEFAULT 200,
	duration_ms      REAL NOT NULL DEFAULT 0,
	anon_duration_us INTEGER NOT NULL DEFAULT 0,
	entities_count   INTEGER NOT NULL DEFAULT 0,
	entity_types     TEXT NOT NULL DEFAULT '[]',
	pii_types        TEXT NOT NULL DEFAULT '[]',
	secret_types     TEXT NOT NULL DEFAULT '[]',
	sanitized_prompt TEXT NOT NULL DEFAULT ''
);
CREATE INDEX IF NOT EXISTS idx_audit_traces_timestamp ON audit_traces(timestamp_unix DESC);
CREATE TABLE IF NOT EXISTS telemetry_retention (
	tenant_id TEXT PRIMARY KEY,
	retention_days INTEGER NOT NULL DEFAULT 0,
	max_rows INTEGER NOT NULL DEFAULT 0,
	updated_at TIMESTAMP NOT NULL
);
`
	if _, err := db.ExecContext(ctx, ddl); err != nil {
		return fmt.Errorf("creating audit_traces schema: %w", err)
	}

	// Migrate existing audit_traces table if new columns are missing
	for _, col := range []string{"tenant_name", "user_label", "user_role"} {
		_, _ = db.ExecContext(ctx, fmt.Sprintf("ALTER TABLE audit_traces ADD COLUMN %s TEXT NOT NULL DEFAULT '';", col))
	}
	return nil
}

// Close closes the underlying SQLite connection pool.
func (l *TraceLogger) Close() error {
	if l == nil || l.db == nil {
		return nil
	}
	return l.db.Close()
}

// DB returns the underlying sql.DB connection pool.
func (l *TraceLogger) DB() *sql.DB {
	if l == nil {
		return nil
	}
	return l.db
}

// DBPath returns the configured SQLite database path.
func (l *TraceLogger) DBPath() string {
	if l == nil {
		return ""
	}
	return l.dbPath
}

// Record stores a non-sensitive trace using a bounded background timeout.
func (l *TraceLogger) Record(t Trace) {
	if l == nil || l.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	_ = l.RecordContext(ctx, t)
}

// RecordContext inserts a non-sensitive trace into SQLite and prunes rows beyond maxRows.
func (l *TraceLogger) RecordContext(ctx context.Context, t Trace) error {
	if l == nil || l.db == nil {
		return nil
	}

	if t.Timestamp.IsZero() {
		t.Timestamp = time.Now()
	}
	if t.PolicyAction == "" {
		t.PolicyAction = "mask"
	}
	if t.Provider == "" {
		t.Provider = InferProvider("", t.Model, "", t.Model == "mock")
	}

	// Ensure PII / Secret slices are populated even if caller only passed EntityTypes
	if len(t.PIITypes) == 0 && len(t.SecretTypes) == 0 && len(t.EntityTypes) > 0 {
		t.PIITypes, t.SecretTypes = splitTypeStrings(t.EntityTypes)
	}

	entityJSON := marshalStringSlice(dedupeStrings(t.EntityTypes))
	piiJSON := marshalStringSlice(dedupeStrings(t.PIITypes))
	secretJSON := marshalStringSlice(dedupeStrings(t.SecretTypes))
	safePrompt := truncateRunes(t.SanitizedPrompt, maxSanitizedPromptRunes)

	streamInt := 0
	if t.Stream {
		streamInt = 1
	}

	const insertQuery = `
INSERT OR REPLACE INTO audit_traces (
	id, tenant, tenant_name, user_label, user_role, policy_action, timestamp_unix, timestamp_iso,
	provider, model, language, stream, status_code,
	duration_ms, anon_duration_us, entities_count,
	entity_types, pii_types, secret_types, sanitized_prompt
) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`
	_, err := l.db.ExecContext(
		ctx,
		insertQuery,
		t.ID,
		t.Tenant,
		t.TenantName,
		t.UserLabel,
		t.UserRole,
		t.PolicyAction,
		t.Timestamp.Unix(),
		t.Timestamp.UTC().Format(time.RFC3339Nano),
		t.Provider,
		t.Model,
		t.Language,
		streamInt,
		t.StatusCode,
		t.DurationMs,
		t.AnonDurationUs,
		t.EntitiesCount,
		entityJSON,
		piiJSON,
		secretJSON,
		safePrompt,
	)
	if err != nil {
		return fmt.Errorf("inserting audit trace: %w", err)
	}

	if l.maxRows > 0 {
		const pruneQuery = `
DELETE FROM audit_traces
WHERE seq <= (
	SELECT seq FROM audit_traces
	ORDER BY seq DESC
	LIMIT 1 OFFSET ?
)
`
		if _, err := l.db.ExecContext(ctx, pruneQuery, l.maxRows); err != nil {
			return fmt.Errorf("pruning old audit traces: %w", err)
		}
	}
	if err := l.applyRetention(ctx, t.Tenant); err != nil {
		return fmt.Errorf("applying telemetry retention: %w", err)
	}

	return nil
}

// GetPaged returns paginated traces and the total count.
func (l *TraceLogger) GetPaged(limit, offset int) ([]Trace, int) {
	if l == nil || l.db == nil {
		return []Trace{}, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	traces, total, err := l.GetPagedContext(ctx, limit, offset)
	if err != nil {
		return []Trace{}, 0
	}
	return traces, total
}

// GetPagedContext queries paginated audit traces and the total count.
func (l *TraceLogger) GetPagedContext(ctx context.Context, limit, offset int) ([]Trace, int, error) {
	return l.getPagedContext(ctx, limit, offset, "")
}

// GetPagedForTenant returns paginated telemetry restricted to one tenant.
func (l *TraceLogger) GetPagedForTenant(tenant string, limit, offset int) ([]Trace, int) {
	if l == nil || l.db == nil {
		return []Trace{}, 0
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	traces, total, err := l.getPagedContext(ctx, limit, offset, strings.TrimSpace(tenant))
	if err != nil {
		return []Trace{}, 0
	}
	return traces, total
}

func (l *TraceLogger) getPagedContext(ctx context.Context, limit, offset int, tenant string) ([]Trace, int, error) {
	if l == nil || l.db == nil {
		return []Trace{}, 0, nil
	}

	if limit <= 0 {
		limit = 20
	}
	if limit > 200 {
		limit = 200
	}
	if offset < 0 {
		offset = 0
	}

	countQuery := "SELECT COUNT(*) FROM audit_traces"
	var countArgs []interface{}
	if tenant != "" {
		countQuery += " WHERE tenant = ?"
		countArgs = append(countArgs, tenant)
	}
	var total int
	if err := l.db.QueryRowContext(ctx, countQuery, countArgs...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("counting audit traces: %w", err)
	}

	pagedQuery := `
SELECT
	id, tenant, tenant_name, user_label, user_role, policy_action, timestamp_iso, provider, model, language,
	stream, status_code, duration_ms, anon_duration_us, entities_count,
	entity_types, pii_types, secret_types, sanitized_prompt
FROM audit_traces
`
	args := make([]interface{}, 0, 3)
	if tenant != "" {
		pagedQuery += " WHERE tenant = ?\n"
		args = append(args, tenant)
	}
	pagedQuery += "ORDER BY seq DESC\nLIMIT ? OFFSET ?"
	args = append(args, limit, offset)
	rows, err := l.db.QueryContext(ctx, pagedQuery, args...)
	if err != nil {
		return nil, 0, fmt.Errorf("querying paged audit traces: %w", err)
	}
	defer rows.Close()

	result := make([]Trace, 0, limit)
	for rows.Next() {
		var (
			t          Trace
			tsISO      string
			streamInt  int
			entityJSON string
			piiJSON    string
			secretJSON string
		)
		if err := rows.Scan(
			&t.ID,
			&t.Tenant,
			&t.TenantName,
			&t.UserLabel,
			&t.UserRole,
			&t.PolicyAction,
			&tsISO,
			&t.Provider,
			&t.Model,
			&t.Language,
			&streamInt,
			&t.StatusCode,
			&t.DurationMs,
			&t.AnonDurationUs,
			&t.EntitiesCount,
			&entityJSON,
			&piiJSON,
			&secretJSON,
			&t.SanitizedPrompt,
		); err != nil {
			return nil, 0, fmt.Errorf("scanning audit trace row: %w", err)
		}

		if parsedTS, parseErr := time.Parse(time.RFC3339Nano, tsISO); parseErr == nil {
			t.Timestamp = parsedTS
		}
		t.Stream = streamInt == 1
		t.EntityTypes = unmarshalStringSlice(entityJSON)
		t.PIITypes = unmarshalStringSlice(piiJSON)
		t.SecretTypes = unmarshalStringSlice(secretJSON)
		result = append(result, t)
	}

	if err := rows.Err(); err != nil {
		return nil, 0, fmt.Errorf("iterating paged audit traces: %w", err)
	}

	return result, total, nil
}

// GetAll returns all recorded traces ordered newest first.
func (l *TraceLogger) GetAll() []Trace {
	if l == nil || l.db == nil {
		return []Trace{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	traces, err := l.GetAllContext(ctx)
	if err != nil {
		return []Trace{}
	}
	return traces
}

// GetAllContext reads all recorded traces from SQLite ordered newest first.
func (l *TraceLogger) GetAllContext(ctx context.Context) ([]Trace, error) {
	if l == nil || l.db == nil {
		return []Trace{}, nil
	}

	const selectQuery = `
SELECT
	id, tenant, tenant_name, user_label, user_role, policy_action, timestamp_iso, provider, model, language,
	stream, status_code, duration_ms, anon_duration_us, entities_count,
	entity_types, pii_types, secret_types, sanitized_prompt
FROM audit_traces
ORDER BY seq DESC
LIMIT ?
`
	rows, err := l.db.QueryContext(ctx, selectQuery, l.maxRows)
	if err != nil {
		return nil, fmt.Errorf("querying audit traces: %w", err)
	}
	defer rows.Close()

	result := make([]Trace, 0, 64)
	for rows.Next() {
		var (
			t          Trace
			tsISO      string
			streamInt  int
			entityJSON string
			piiJSON    string
			secretJSON string
		)
		if err := rows.Scan(
			&t.ID,
			&t.Tenant,
			&t.TenantName,
			&t.UserLabel,
			&t.UserRole,
			&t.PolicyAction,
			&tsISO,
			&t.Provider,
			&t.Model,
			&t.Language,
			&streamInt,
			&t.StatusCode,
			&t.DurationMs,
			&t.AnonDurationUs,
			&t.EntitiesCount,
			&entityJSON,
			&piiJSON,
			&secretJSON,
			&t.SanitizedPrompt,
		); err != nil {
			return nil, fmt.Errorf("scanning audit trace row: %w", err)
		}

		if parsedTS, parseErr := time.Parse(time.RFC3339Nano, tsISO); parseErr == nil {
			t.Timestamp = parsedTS
		}
		t.Stream = streamInt == 1
		t.EntityTypes = unmarshalStringSlice(entityJSON)
		t.PIITypes = unmarshalStringSlice(piiJSON)
		t.SecretTypes = unmarshalStringSlice(secretJSON)
		result = append(result, t)
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterating audit traces: %w", err)
	}

	return result, nil
}

// Clear deletes all stored traces from SQLite.
func (l *TraceLogger) Clear() {
	if l == nil || l.db == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	_ = l.ClearContext(ctx)
}

// ClearContext deletes all stored traces from SQLite.
func (l *TraceLogger) ClearContext(ctx context.Context) error {
	if l == nil || l.db == nil {
		return nil
	}
	if _, err := l.db.ExecContext(ctx, "DELETE FROM audit_traces"); err != nil {
		return fmt.Errorf("clearing audit traces: %w", err)
	}
	return nil
}

// ClearTenant deletes only telemetry owned by the selected tenant.
func (l *TraceLogger) ClearTenant(tenant string) error {
	if l == nil || l.db == nil {
		return nil
	}
	tenant = strings.TrimSpace(tenant)
	if tenant == "" {
		return fmt.Errorf("tenant is required")
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	if _, err := l.db.ExecContext(ctx, "DELETE FROM audit_traces WHERE tenant = ?", tenant); err != nil {
		return fmt.Errorf("clearing tenant audit traces: %w", err)
	}
	return nil
}

// GetSummary computes real-time anonymization statistics from SQLite.
func (l *TraceLogger) GetSummary() Summary {
	if l == nil || l.db == nil {
		return emptySummary()
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	s, err := l.GetSummaryContext(ctx)
	if err != nil {
		return emptySummary()
	}
	return s
}

// GetSummaryContext aggregates request, masking, latency, rate, provider, and entity statistics.
func (l *TraceLogger) GetSummaryContext(ctx context.Context) (Summary, error) {
	s := emptySummary()
	if l == nil || l.db == nil {
		return s, nil
	}

	traces, err := l.GetAllContext(ctx)
	if err != nil {
		return s, err
	}

	return summarizeTraces(traces), nil
}

// GetSummaryForTenant aggregates telemetry restricted to one tenant.
func (l *TraceLogger) GetSummaryForTenant(tenant string) Summary {
	if l == nil || l.db == nil {
		return emptySummary()
	}
	ctx, cancel := context.WithTimeout(context.Background(), defaultDBOperationBudget)
	defer cancel()
	tenant = strings.TrimSpace(tenant)
	traces := make([]Trace, 0)
	for offset, total := 0, 1; offset < total; {
		page, count, err := l.getPagedContext(ctx, 200, offset, tenant)
		if err != nil {
			return emptySummary()
		}
		total = count
		traces = append(traces, page...)
		if len(page) == 0 {
			break
		}
		offset += len(page)
	}
	return summarizeTraces(traces)
}

func summarizeTraces(traces []Trace) Summary {
	s := emptySummary()
	s.TotalRequests = len(traces)
	if s.TotalRequests == 0 {
		return s
	}

	oneHourAgo := time.Now().Add(-1 * time.Hour)
	var totalDurationMs float64
	var totalScanUs int64

	for _, t := range traces {
		totalDurationMs += t.DurationMs
		totalScanUs += t.AnonDurationUs
		s.TotalEntities += t.EntitiesCount

		if t.EntitiesCount > 0 {
			s.MaskedRequests++
		}
		if t.PolicyAction == "block" {
			s.BlockedRequests++
		}
		if !t.Timestamp.Before(oneHourAgo) {
			s.RequestsLastHour++
		}

		if t.Provider != "" {
			s.ProviderDistribution[t.Provider]++
		}
		if t.Model != "" {
			s.ModelDistribution[t.Model]++
		}

		for _, et := range t.EntityTypes {
			s.EntityTypeCounts[et]++
		}
		for _, pt := range t.PIITypes {
			s.PIITypeCounts[pt]++
		}
		for _, st := range t.SecretTypes {
			s.SecretTypeCounts[st]++
		}
	}

	s.MaskedRatePct = (float64(s.MaskedRequests) / float64(s.TotalRequests)) * 100.0
	s.AvgScanUs = totalScanUs / int64(s.TotalRequests)
	s.AvgScanMs = float64(totalScanUs) / float64(s.TotalRequests) / 1000.0
	s.AverageDurationMs = totalDurationMs / float64(s.TotalRequests)

	return s
}

func emptySummary() Summary {
	return Summary{
		ProviderDistribution: make(map[string]int),
		ModelDistribution:    make(map[string]int),
		EntityTypeCounts:     make(map[string]int),
		PIITypeCounts:        make(map[string]int),
		SecretTypeCounts:     make(map[string]int),
	}
}

// ClassifyEntities separates detected entities into policy types, PII badges, and Secret badges.
func ClassifyEntities(entities []anonymizer.DetectedEntity) (policyTypes, piiTypes, secretTypes []string) {
	piiSeen := make(map[string]bool)
	secretSeen := make(map[string]bool)

	for _, ent := range entities {
		rawType := string(ent.Type)
		policyTypes = append(policyTypes, rawType)

		switch ent.Type {
		case detector.EntityAPIKey:
			if !secretSeen["API_KEY"] {
				secretSeen["API_KEY"] = true
				secretTypes = append(secretTypes, "API_KEY")
			}
		case detector.EntitySecret:
			label := ent.SubType
			if label == "" {
				label = "SECRET"
			}
			if !secretSeen[label] {
				secretSeen[label] = true
				secretTypes = append(secretTypes, label)
			}
		case detector.EntityType("CONFIDENTIAL"):
			if !secretSeen["CONFIDENTIAL"] {
				secretSeen["CONFIDENTIAL"] = true
				secretTypes = append(secretTypes, "CONFIDENTIAL")
			}
		default:
			if !piiSeen[rawType] {
				piiSeen[rawType] = true
				piiTypes = append(piiTypes, rawType)
			}
		}
	}

	return policyTypes, piiTypes, secretTypes
}

func splitTypeStrings(types []string) (piiTypes, secretTypes []string) {
	piiSeen := make(map[string]bool)
	secretSeen := make(map[string]bool)

	for _, t := range types {
		switch t {
		case "API_KEY", "SECRET", "PASSWORD", "JWT", "PRIVATE_KEY", "DB_URI", "SSH_KEY", "CONFIDENTIAL":
			if !secretSeen[t] {
				secretSeen[t] = true
				secretTypes = append(secretTypes, t)
			}
		default:
			if !piiSeen[t] {
				piiSeen[t] = true
				piiTypes = append(piiTypes, t)
			}
		}
	}
	return piiTypes, secretTypes
}

// InferProvider determines the AI provider name from routing context without exposing credentials.
func InferProvider(endpoint, model, targetURL string, isMock bool) string {
	lowerModel := strings.ToLower(strings.TrimSpace(model))
	lowerURL := strings.ToLower(strings.TrimSpace(targetURL))

	if isMock || lowerModel == "mock" || strings.HasPrefix(lowerModel, "mock/") {
		return "mock"
	}
	if endpoint == "anthropic" || strings.Contains(lowerURL, "anthropic.com") || strings.HasPrefix(lowerModel, "claude") {
		return "anthropic"
	}
	if strings.HasPrefix(lowerModel, "ollama/") || strings.Contains(lowerURL, "11434") {
		return "ollama"
	}
	if strings.HasPrefix(lowerModel, "groq/") || strings.Contains(lowerURL, "groq.com") {
		return "groq"
	}
	if strings.Contains(lowerURL, "deepseek") || strings.HasPrefix(lowerModel, "deepseek") {
		return "deepseek"
	}
	if strings.Contains(lowerURL, "openrouter.ai") {
		return "openrouter"
	}
	if strings.Contains(lowerURL, "googleapis.com") || strings.HasPrefix(lowerModel, "gemini") {
		return "gemini"
	}
	if strings.Contains(lowerURL, "openai.com") ||
		strings.HasPrefix(lowerModel, "gpt-") ||
		strings.HasPrefix(lowerModel, "o1") ||
		strings.HasPrefix(lowerModel, "o3") ||
		strings.HasPrefix(lowerModel, "o4") {
		return "openai"
	}
	if lowerURL != "" {
		if parsed, err := url.Parse(targetURL); err == nil && parsed.Hostname() != "" {
			return strings.ToLower(parsed.Hostname())
		}
	}
	if idx := strings.IndexByte(lowerModel, '/'); idx > 0 {
		return lowerModel[:idx]
	}
	return "openai"
}

var (
	ptWords = map[string]int{
		"não": 3, "para": 2, "com": 1, "uma": 2, "meu": 2, "minha": 2, "dados": 2,
		"cpf": 3, "cnpj": 3, "chave": 2, "pix": 3, "cartão": 3, "fatura": 2,
		"cliente": 2, "favor": 2, "olá": 3, "ola": 2, "está": 2, "são": 3, "você": 3,
		"pelo": 2, "pela": 2, "nosso": 2, "nossa": 2, "preciso": 2, "ajuda": 2,
		"sobre": 1, "conta": 2, "senha": 3, "envie": 2, "cobrança": 3, "oi": 2,
		"bom": 2, "dia": 1, "obrigado": 3, "relatório": 3, "transferir": 2,
	}
	enWords = map[string]int{
		"the": 3, "and": 2, "for": 2, "with": 2, "from": 2, "this": 2, "that": 2,
		"please": 3, "help": 2, "respond": 2, "support": 2, "ticket": 2, "regarding": 3,
		"error": 2, "account": 2, "user": 2, "my": 2, "your": 2, "can": 2, "you": 2,
		"about": 2, "what": 2, "how": 2, "have": 2, "hello": 3, "hi": 2, "password": 2,
	}
	esWords = map[string]int{
		"hola": 3, "por": 2, "una": 1, "del": 2, "las": 2, "los": 2, "cómo": 3,
		"está": 1, "ayuda": 3, "correo": 3, "cuenta": 3, "contraseña": 3, "gracias": 3,
		"este": 1, "esta": 1, "pero": 2, "más": 2, "respuesta": 2, "cliente": 1,
	}
	frWords = map[string]int{
		"les": 2, "des": 2, "une": 2, "dans": 3, "pour": 3, "avec": 3, "sur": 2,
		"pas": 2, "plus": 2, "bonjour": 3, "merci": 3, "votre": 3, "mon": 2,
		"aide": 2, "compte": 3, "mot": 2, "passe": 2, "nous": 3, "vous": 3,
	}
	itWords = map[string]int{
		"gli": 3, "della": 3, "delle": 3, "degli": 3, "nel": 2, "nella": 3,
		"per": 2, "sono": 2, "ciao": 3, "grazie": 3, "aiuto": 3, "conto": 2,
		"utente": 3, "questo": 3, "questa": 3, "anche": 3, "più": 3, "risposta": 2,
	}
	deWords = map[string]int{
		"der": 3, "die": 3, "das": 3, "und": 3, "mit": 3, "für": 3, "von": 2,
		"auf": 2, "ist": 2, "nicht": 3, "bitte": 3, "hilfe": 3, "konto": 2,
		"passwort": 3, "ich": 3, "sie": 2, "wir": 2, "ein": 2, "eine": 2,
	}
)

// DetectLanguage performs fast, zero-allocation-light heuristic language classification
// returning an ISO-like 2-letter uppercase tag (PT, EN, ES, FR, IT, DE).
func DetectLanguage(text string) string {
	trimmed := strings.TrimSpace(text)
	if trimmed == "" {
		return "--"
	}

	scores := map[string]int{
		"PT": 0, "EN": 0, "ES": 0, "FR": 0, "IT": 0, "DE": 0,
	}

	lower := strings.ToLower(trimmed)
	for _, r := range lower {
		switch r {
		case 'ã', 'õ':
			scores["PT"] += 3
		case 'ç':
			scores["PT"] += 2
			scores["FR"] += 1
		case 'ñ', '¿', '¡':
			scores["ES"] += 4
		case 'ß', 'ä', 'ö':
			scores["DE"] += 4
		case 'ü':
			scores["DE"] += 2
		case 'œ':
			scores["FR"] += 3
		}
	}

	var wordBuf strings.Builder
	scoreWord := func(w string) {
		if w == "" {
			return
		}
		if v := ptWords[w]; v > 0 {
			scores["PT"] += v
		}
		if v := enWords[w]; v > 0 {
			scores["EN"] += v
		}
		if v := esWords[w]; v > 0 {
			scores["ES"] += v
		}
		if v := frWords[w]; v > 0 {
			scores["FR"] += v
		}
		if v := itWords[w]; v > 0 {
			scores["IT"] += v
		}
		if v := deWords[w]; v > 0 {
			scores["DE"] += v
		}
	}

	for _, r := range lower {
		if unicode.IsLetter(r) {
			wordBuf.WriteRune(r)
		} else if wordBuf.Len() > 0 {
			scoreWord(wordBuf.String())
			wordBuf.Reset()
		}
	}
	if wordBuf.Len() > 0 {
		scoreWord(wordBuf.String())
	}

	bestLang := "EN"
	bestScore := 0
	// Deterministic priority order: PT > EN > ES > FR > IT > DE
	for _, lang := range []string{"PT", "EN", "ES", "FR", "IT", "DE"} {
		if scores[lang] > bestScore {
			bestScore = scores[lang]
			bestLang = lang
		}
	}
	return bestLang
}

func dedupeStrings(items []string) []string {
	if len(items) == 0 {
		return []string{}
	}
	seen := make(map[string]bool, len(items))
	out := make([]string, 0, len(items))
	for _, item := range items {
		if item != "" && !seen[item] {
			seen[item] = true
			out = append(out, item)
		}
	}
	return out
}

func marshalStringSlice(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	b, err := json.Marshal(items)
	if err != nil {
		return "[]"
	}
	return string(b)
}

func unmarshalStringSlice(raw string) []string {
	if raw == "" || raw == "[]" {
		return []string{}
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return []string{}
	}
	return out
}

func truncateRunes(s string, maxRunes int) string {
	if maxRunes <= 0 || len(s) <= maxRunes {
		return s
	}
	count := 0
	for idx := range s {
		if count == maxRunes {
			return s[:idx] + "..."
		}
		count++
	}
	return s
}
