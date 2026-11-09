package detector

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// SemanticDetector calls an optional local sidecar. Failures always fall back
// to the deterministic detectors and never prevent gateway startup.
type SemanticDetector struct {
	url                 string
	client              *http.Client
	consecutiveFailures atomic.Int32
	openUntilUnixNano   atomic.Int64
}

type semanticEntity struct {
	Type       string  `json:"type"`
	EntityType string  `json:"entity_type"`
	Value      string  `json:"value"`
	Text       string  `json:"text"`
	Start      int     `json:"start"`
	End        int     `json:"end"`
	Score      float64 `json:"score"`
}

func NewSemanticDetector(url string, timeout time.Duration) *SemanticDetector {
	if timeout <= 0 {
		timeout = 250 * time.Millisecond
	}
	return &SemanticDetector{url: url, client: &http.Client{Timeout: timeout}}
}

func (d *SemanticDetector) Type() EntityType { return EntityType("SEMANTIC") }

func (d *SemanticDetector) Detect(text string) []Match {
	if d.url == "" || text == "" || time.Now().UnixNano() < d.openUntilUnixNano.Load() {
		return nil
	}
	payload, _ := json.Marshal(map[string]string{"text": text})
	request, err := http.NewRequest(http.MethodPost, d.url, bytes.NewReader(payload))
	if err != nil {
		d.recordFailure()
		return nil
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := d.client.Do(request)
	if err != nil {
		d.recordFailure()
		return nil
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		d.recordFailure()
		return nil
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	if err != nil {
		d.recordFailure()
		return nil
	}
	var envelope struct {
		Entities []semanticEntity `json:"entities"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		var direct []semanticEntity
		if directErr := json.Unmarshal(body, &direct); directErr != nil {
			d.recordFailure()
			return nil
		}
		envelope.Entities = direct
	}
	d.consecutiveFailures.Store(0)

	matches := make([]Match, 0, len(envelope.Entities))
	for _, entity := range envelope.Entities {
		entityType := sanitizeTokenLabel(entity.EntityType)
		if entityType == "SEMANTIC" {
			entityType = sanitizeTokenLabel(entity.Type)
		}
		value := entity.Value
		if value == "" {
			value = entity.Text
		}
		if entity.Start < 0 || entity.End <= entity.Start || entity.End > len(text) {
			continue
		}
		if value == "" {
			value = text[entity.Start:entity.End]
		}
		matches = append(matches, Match{
			Type: EntityType(entityType), Value: value, Start: entity.Start, End: entity.End,
			Score: entity.Score, ValidatorPassed: false, IsSemantic: true,
		})
	}
	return matches
}

func (d *SemanticDetector) recordFailure() {
	if d.consecutiveFailures.Add(1) >= 3 {
		d.openUntilUnixNano.Store(time.Now().Add(30 * time.Second).UnixNano())
		d.consecutiveFailures.Store(0)
	}
}

// sanitizeTokenLabel keeps the sidecar-supplied type usable as a token label
// ([HG_<ns>_<TYPE>_<n>]): upper case, A-Z 0-9 and underscore only, 32 chars.
func sanitizeTokenLabel(raw string) string {
	var b strings.Builder
	for _, r := range strings.ToUpper(strings.TrimSpace(raw)) {
		if b.Len() >= 32 {
			break
		}
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	if b.Len() == 0 {
		return "SEMANTIC"
	}
	return b.String()
}
