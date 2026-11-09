package detector

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestSemanticDetector(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"entities": []interface{}{map[string]interface{}{
				"entity_type": "ORGANIZATION", "start": 0, "end": 7, "score": 0.93,
			}},
		})
	}))
	defer server.Close()

	detector := NewSemanticDetector(server.URL, time.Second)
	matches := detector.Detect("Acme SA contratou")
	if len(matches) != 1 || matches[0].Type != "ORGANIZATION" || matches[0].Value != "Acme SA" {
		t.Fatalf("unexpected semantic matches: %+v", matches)
	}
}

func TestSemanticDetectorCircuitBreaker(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()

	detector := NewSemanticDetector(server.URL, time.Second)
	for range 4 {
		if matches := detector.Detect("Acme SA"); len(matches) != 0 {
			t.Fatalf("unexpected matches: %+v", matches)
		}
	}
	if calls.Load() != 3 {
		t.Fatalf("circuit breaker did not open after three failures, calls=%d", calls.Load())
	}
}

func TestSanitizeTokenLabel(t *testing.T) {
	cases := map[string]string{
		"CPF":         "CPF",
		"person name": "PERSONNAME",
		"cpf]":        "CPF",
		"a.b-c":       "ABC",
		"":            "SEMANTIC",
		"--":          "SEMANTIC",
		"aaaaaaaaaabbbbbbbbbbccccccccccdddddddddd": "AAAAAAAAAABBBBBBBBBBCCCCCCCCCCDD",
	}
	for input, want := range cases {
		if got := sanitizeTokenLabel(input); got != want {
			t.Fatalf("sanitizeTokenLabel(%q) = %q, want %q", input, got, want)
		}
	}
}
