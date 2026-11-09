package proxy

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"
)

type lookupIPFunc func(context.Context, string) ([]net.IPAddr, error)

var hardBlockedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("::/128"),
	netip.MustParsePrefix("fe80::/10"),
	netip.MustParsePrefix("ff00::/8"),
}

func privateUpstreamHostSet(cfg UpstreamConfig) map[string]struct{} {
	allowed := make(map[string]struct{})
	for _, entry := range cfg.PrivateUpstreamAllowedHosts {
		addAllowedHost(allowed, entry)
	}

	// An explicitly configured literal private endpoint is an intentional local
	// target. Ollama is local by definition and may use a Docker-only hostname.
	for _, raw := range []string{cfg.OpenAIBaseURL, cfg.AnthropicURL, cfg.GeminiURL} {
		if parsed, err := url.Parse(raw); err == nil && parsed.Hostname() != "" {
			if ip, err := netip.ParseAddr(parsed.Hostname()); err == nil && isPrivateAddress(ip.Unmap()) {
				addAllowedHost(allowed, parsed.Host)
			}
		}
	}
	if parsed, err := url.Parse(cfg.OllamaBaseURL); err == nil && parsed.Hostname() != "" {
		addAllowedHost(allowed, parsed.Host)
	}
	if cfg.AllowPrivateDynamicUpstream {
		for _, entry := range cfg.DynamicUpstreamAllowedHosts {
			addAllowedHost(allowed, entry)
		}
	}
	return allowed
}

func addAllowedHost(allowed map[string]struct{}, raw string) {
	raw = strings.ToLower(strings.TrimSpace(raw))
	if raw == "" {
		return
	}
	allowed[raw] = struct{}{}
}

func (u *UpstreamDispatcher) resolveHost(ctx context.Context, host string) ([]net.IPAddr, error) {
	if parsed := net.ParseIP(host); parsed != nil {
		return []net.IPAddr{{IP: parsed}}, nil
	}
	if u.lookupIP == nil {
		return nil, fmt.Errorf("DNS resolver is not configured")
	}
	addresses, err := u.lookupIP(ctx, host)
	if err != nil {
		return nil, err
	}
	if len(addresses) == 0 {
		return nil, fmt.Errorf("host resolved without addresses")
	}
	return addresses, nil
}

func validateResolvedAddresses(addresses []net.IPAddr, allowPrivate bool) error {
	for _, address := range addresses {
		parsed, ok := netip.AddrFromSlice(address.IP)
		if !ok {
			return fmt.Errorf("upstream resolved to an invalid IP address")
		}
		parsed = parsed.Unmap()
		if isHardBlockedAddress(parsed) {
			return fmt.Errorf("upstream resolved to a prohibited network address")
		}
		if isPrivateAddress(parsed) && !allowPrivate {
			return fmt.Errorf("upstream resolved to a private network address without explicit authorization")
		}
	}
	return nil
}

func isHardBlockedAddress(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() {
		return true
	}
	for _, prefix := range hardBlockedPrefixes {
		if prefix.Contains(address) {
			return true
		}
	}
	return false
}

func isPrivateAddress(address netip.Addr) bool {
	return address.IsLoopback() || address.IsPrivate()
}

func (u *UpstreamDispatcher) isPrivateUpstreamAllowed(host, port string) bool {
	host = strings.ToLower(strings.Trim(host, "[]"))
	if _, ok := u.privateUpstreamHosts[host]; ok {
		return true
	}
	_, ok := u.privateUpstreamHosts[strings.ToLower(net.JoinHostPort(host, port))]
	return ok
}

func effectivePort(parsed *url.URL) string {
	if port := parsed.Port(); port != "" {
		return port
	}
	if strings.EqualFold(parsed.Scheme, "https") {
		return "443"
	}
	return "80"
}

func (u *UpstreamDispatcher) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, fmt.Errorf("parsing upstream address: %w", err)
	}
	return u.dialValidated(ctx, network, host, port, u.isPrivateUpstreamAllowed(host, port))
}

// dialValidated resolves the host, validates every returned address and dials
// the first one, so the socket cannot be redirected after validation.
func (u *UpstreamDispatcher) dialValidated(ctx context.Context, network, host, port string, allowPrivate bool) (net.Conn, error) {
	addresses, err := u.resolveHost(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolving upstream address: %w", err)
	}
	if err := validateResolvedAddresses(addresses, allowPrivate); err != nil {
		return nil, err
	}

	selected := addresses[0]
	ip := selected.IP.String()
	if selected.Zone != "" {
		ip += "%" + selected.Zone
	}
	dialer := &net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}
	return dialer.DialContext(ctx, network, net.JoinHostPort(ip, port))
}

// EgressTransport returns an outbound transport that applies the proxy address
// policy to arbitrary destinations: DNS validation, IP pinning against
// rebinding and permanent blocking of link-local, metadata and reserved ranges.
// Private (loopback/RFC1918) destinations stay allowed because intranet
// webhooks are a normal target; metadata stays blocked on purpose.
func (u *UpstreamDispatcher) EgressTransport() *http.Transport {
	return &http.Transport{
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, fmt.Errorf("parsing egress address: %w", err)
			}
			return u.dialValidated(ctx, network, host, port, true)
		},
		ForceAttemptHTTP2:   true,
		MaxIdleConns:        20,
		MaxIdleConnsPerHost: 4,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
	}
}

// RejectRedirects is the redirect policy used by the proxy and by webhooks:
// the redirect target is not re-validated, so it is refused.
func RejectRedirects(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}
