package detector

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/csv"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

const (
	DefaultAnvisaEndpoint = "https://dados.anvisa.gov.br/dados/DADOS_ABERTOS_MEDICAMENTOS.csv"
	// maxAnvisaCSVBytes bounds a streamed refresh so a runaway response cannot
	// exhaust memory.
	maxAnvisaCSVBytes = 256 << 20
)

// AnvisaSyncResult represents the outcome of an ANVISA catalog synchronization check.
type AnvisaSyncResult struct {
	UpToDate     bool      `json:"up_to_date"`
	Updated      bool      `json:"updated"`
	TermsCount   int       `json:"terms_count"`
	ActiveETag   string    `json:"active_etag"`
	LastModified string    `json:"last_modified"`
	CheckedAt    time.Time `json:"checked_at"`
	Message      string    `json:"message"`
}

// AnvisaSynchronizer checks and live-streams updates from the official ANVISA dataset.
type AnvisaSynchronizer struct {
	detector   *MedicationDetector
	httpClient *http.Client
	endpoint   string
}

// NewAnvisaSynchronizer creates a new AnvisaSynchronizer bound to the given MedicationDetector.
func NewAnvisaSynchronizer(detector *MedicationDetector) *AnvisaSynchronizer {
	return &AnvisaSynchronizer{
		detector: detector,
		httpClient: &http.Client{
			Timeout: 45 * time.Second,
		},
		endpoint: DefaultAnvisaEndpoint,
	}
}

// SetEndpoint overrides the ANVISA dataset URL (useful for testing or mirroring).
func (s *AnvisaSynchronizer) SetEndpoint(url string) {
	if url != "" {
		s.endpoint = url
	}
}

// CheckAndSync queries the ANVISA server via HTTP HEAD to verify if updates are available.
// If the remote ETag or Last-Modified header differs from the active catalog (or force is true),
// it streams the CSV body directly in memory, deduplicates and reloads the Aho-Corasick automaton
// without ever storing the raw 45MB CSV file on disk.
func (s *AnvisaSynchronizer) CheckAndSync(ctx context.Context, force bool) (*AnvisaSyncResult, error) {
	if s.detector == nil {
		return nil, fmt.Errorf("medication detector not initialized")
	}

	status := s.detector.Status()

	// 1. Send lightweight HEAD request to inspect remote headers
	headReq, err := http.NewRequestWithContext(ctx, http.MethodHead, s.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating head request: %w", err)
	}

	headResp, err := s.httpClient.Do(headReq)
	if err != nil {
		return nil, fmt.Errorf("anvisa server check failed: %w", err)
	}
	defer headResp.Body.Close()

	if headResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anvisa server returned HTTP status %d", headResp.StatusCode)
	}

	remoteETag := strings.Trim(headResp.Header.Get("ETag"), `" `)
	remoteLastMod := strings.TrimSpace(headResp.Header.Get("Last-Modified"))

	currentETag := strings.Trim(status.ActiveETag, `" `)

	// If remote ETag matches current and not forced, catalog is already up to date!
	if !force && remoteETag != "" && currentETag != "" && strings.EqualFold(remoteETag, currentETag) {
		return &AnvisaSyncResult{
			UpToDate:     true,
			Updated:      false,
			TermsCount:   status.TermsCount,
			ActiveETag:   status.ActiveETag,
			LastModified: status.LastModified,
			CheckedAt:    time.Now(),
			Message:      "Catálogo ANVISA já está na versão mais recente.",
		}, nil
	}

	// 2. Stream the CSV in memory
	getReq, err := http.NewRequestWithContext(ctx, http.MethodGet, s.endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating get request: %w", err)
	}

	getResp, err := s.httpClient.Do(getReq)
	if err != nil {
		return nil, fmt.Errorf("anvisa stream download failed: %w", err)
	}
	defer getResp.Body.Close()

	if getResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("anvisa stream returned HTTP status %d", getResp.StatusCode)
	}

	reader := csv.NewReader(io.LimitReader(getResp.Body, maxAnvisaCSVBytes))
	reader.Comma = ';'
	reader.LazyQuotes = true

	// Skip CSV header
	if _, err := reader.Read(); err != nil {
		return nil, fmt.Errorf("parsing csv header: %w", err)
	}

	unique := make(map[string]struct{})

	for {
		rec, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// rec[1]: NOME_PRODUTO
		if len(rec) > 1 {
			prod := normalizeMedicationText(rec[1])
			if isValidMedicationCandidate(prod) {
				unique[prod] = struct{}{}
			}
		}

		// rec[10]: PRINCIPIO_ATIVO
		if len(rec) > 10 {
			subs := strings.Split(rec[10], ",")
			for _, sub := range subs {
				sNorm := normalizeMedicationText(sub)
				if isValidMedicationCandidate(sNorm) {
					unique[sNorm] = struct{}{}
				}
			}
		}
	}

	if len(unique) == 0 {
		return nil, fmt.Errorf("no valid medication terms extracted from anvisa stream")
	}

	terms := make([]string, 0, len(unique))
	for t := range unique {
		terms = append(terms, t)
	}
	sort.Strings(terms)

	// 3. Persist compact delta cache to data/anvisa_catalog.bin if possible
	_ = persistCompactCatalog("data/anvisa_catalog.bin", terms)

	// 4. Hot-reload detector in-memory
	effectiveETag := remoteETag
	if effectiveETag == "" {
		effectiveETag = fmt.Sprintf("sync_%d", time.Now().Unix())
	}
	effectiveLastMod := remoteLastMod
	if effectiveLastMod == "" {
		effectiveLastMod = time.Now().UTC().Format(time.RFC1123)
	}

	s.detector.Reload(terms, effectiveETag, effectiveLastMod, "live_updated")

	return &AnvisaSyncResult{
		UpToDate:     false,
		Updated:      true,
		TermsCount:   len(terms),
		ActiveETag:   effectiveETag,
		LastModified: effectiveLastMod,
		CheckedAt:    time.Now(),
		Message:      fmt.Sprintf("Catálogo ANVISA sincronizado com sucesso (%d termos).", len(terms)),
	}, nil
}

func isValidMedicationCandidate(s string) bool {
	if len(s) < 3 || len(s) > 60 {
		return false
	}
	for _, r := range s {
		if unicode.IsLetter(r) {
			return true
		}
	}
	return false
}

func persistCompactCatalog(path string, terms []string) error {
	dir := filepath.Dir(path)
	if dir != "" && dir != "." {
		_ = os.MkdirAll(dir, 0o750)
	}

	var buf bytes.Buffer
	gw, err := gzip.NewWriterLevel(&buf, gzip.BestCompression)
	if err != nil {
		return err
	}

	for _, t := range terms {
		buf.WriteString(t)
		buf.WriteByte('\n')
	}

	if err := gw.Close(); err != nil {
		return err
	}

	return os.WriteFile(path, buf.Bytes(), 0o600)
}
