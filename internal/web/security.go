package web

import (
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
)

const (
	sourceCodeURL = "https://github.com/rodolfoportalles/HadesGate"
	licenseSPDX   = "AGPL-3.0-only"
)

type securityConfig struct {
	allowedOrigins []string
}

// SecurityPolicy stores an immutable, atomically replaceable HTTP security configuration.
type SecurityPolicy struct {
	config atomic.Pointer[securityConfig]
}

func NewSecurityPolicy(allowedOrigins []string) *SecurityPolicy {
	p := &SecurityPolicy{}
	p.UpdateAllowedOrigins(allowedOrigins)
	return p
}

// UpdateAllowedOrigins publishes a cloned CORS allowlist without interrupting active requests.
func (p *SecurityPolicy) UpdateAllowedOrigins(allowedOrigins []string) {
	p.config.Store(&securityConfig{allowedOrigins: append([]string(nil), allowedOrigins...)})
}

func (p *SecurityPolicy) Handler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cfg := p.config.Load()
		p.serveHTTP(next, cfg, w, r)
	})
}

// SecurityMiddleware wraps an http.Handler with OWASP security headers and fine-grained CORS validation.
func SecurityMiddleware(next http.Handler, allowedOrigins []string) http.Handler {
	return NewSecurityPolicy(allowedOrigins).Handler(next)
}

func (p *SecurityPolicy) serveHTTP(next http.Handler, cfg *securityConfig, w http.ResponseWriter, r *http.Request) {
	isOriginAllowed := func(origin string) bool {
		parsedOrigin, err := parseOrigin(origin)
		if err != nil {
			return false
		}
		for _, allowed := range cfg.allowedOrigins {
			allowed = strings.TrimSpace(allowed)
			if allowed == "*" || strings.EqualFold(allowed, origin) {
				return true
			}
			if wildcardOriginMatches(parsedOrigin, allowed) {
				return true
			}
		}
		return false
	}

	origin := r.Header.Get("Origin")
	allowed := false
	if origin != "" {
		allowed = isOriginAllowed(origin)
		if allowed {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Vary", "Origin")
		}
	}

	if allowed {
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-Upstream-Url, X-Upstream-Key, X-API-Key, X-Goog-Api-Key, X-HadesGate-Tenant, Anthropic-Version")
		if strings.EqualFold(r.Header.Get("Access-Control-Request-Private-Network"), "true") {
			w.Header().Set("Access-Control-Allow-Private-Network", "true")
		}
	}

	// Security Headers (OWASP recommendations)
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("X-XSS-Protection", "1; mode=block")
	w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
	// AGPL section 13 source offer for browser and API users interacting remotely.
	w.Header().Set("Link", "<"+sourceCodeURL+">; rel=\"source\"")
	w.Header().Set("X-HadesGate-License", licenseSPDX)

	if r.Method == http.MethodOptions {
		if origin != "" && !allowed {
			http.Error(w, "CORS origin denied", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	next.ServeHTTP(w, r)
}

func parseOrigin(raw string) (*url.URL, error) {
	parsed, err := url.ParseRequestURI(strings.TrimSpace(raw))
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, http.ErrNotSupported
	}
	if parsed.Path != "" {
		return nil, http.ErrNotSupported
	}
	return parsed, nil
}

func wildcardOriginMatches(origin *url.URL, allowed string) bool {
	if !strings.HasSuffix(allowed, "*") {
		return false
	}
	if strings.HasSuffix(allowed, ":*") {
		base, err := url.ParseRequestURI(strings.TrimSuffix(allowed, ":*"))
		return err == nil && strings.EqualFold(origin.Scheme, base.Scheme) && strings.EqualFold(origin.Hostname(), base.Hostname())
	}
	if strings.HasSuffix(allowed, "://*") {
		return strings.EqualFold(origin.Scheme, strings.TrimSuffix(allowed, "://*")) && origin.Hostname() != ""
	}
	return false
}
