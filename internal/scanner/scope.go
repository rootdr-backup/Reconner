package scanner

import (
	"net"
	"net/url"
	"strings"

	"golang.org/x/net/idna"
	"golang.org/x/net/publicsuffix"
)

// SSRF / credential-exfiltration guard (P0 security). Replay/verify/workflow
// endpoints attach a captured identity's Cookie/Authorization to the request, so
// they MUST NOT be pointed at an arbitrary host — otherwise a Reconner user (or a
// CSRF/XSS against the Reconner UI) could replay to attacker.com and steal the
// target's session. A URL is in scope only when its host matches the target
// domain (or a subdomain sharing the target's registrable domain, per the Public
// Suffix List) or an identity origin. Also blocks obvious internal/metadata hosts.
//
// Hostname scope is only HALF the boundary: an in-scope hostname can still resolve
// (or be rebound) to 127.0.0.1 / 169.254.169.254 / a private IP. The DNS/IP half
// of the destination check — and the pinning that defeats rebinding/TOCTOU — lives
// in destination.go and is enforced at the transport of the credential client.

// URLInScope reports whether rawURL is a legitimate testing target for this
// engagement (hostname axis only — see destination.go for the DNS/IP axis).
func URLInScope(targetDomain string, identityOrigins []string, rawURL string) bool {
	u, err := url.Parse(rawURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return false
	}
	host := normalizeHost(u.Hostname())
	if host == "" || isBlockedHost(host) {
		return false
	}
	if td := normalizeHost(targetDomain); td != "" && hostInDomainScope(host, td) {
		return true
	}
	for _, o := range identityOrigins {
		if oh := hostOfURL(o); oh != "" && hostInDomainScope(host, oh) {
			return true
		}
	}
	return false
}

// hostInDomainScope reports whether host is in scope for a single scope host:
// an exact match, a subdomain of it, or a host sharing its registrable domain
// (eTLD+1). Using the PSL is what makes evil.co.uk correctly OUT of scope for
// example.co.uk (their registrable domains differ), which the old "last two
// labels" heuristic got wrong (both collapsed to "co.uk").
func hostInDomainScope(host, scope string) bool {
	if host == "" || scope == "" {
		return false
	}
	if host == scope || strings.HasSuffix(host, "."+scope) {
		return true
	}
	return sameRegistrable(host, scope)
}

func hostOfURL(o string) string {
	o = strings.TrimSpace(o)
	if o == "" {
		return ""
	}
	if !strings.Contains(o, "://") {
		o = "https://" + o
	}
	u, err := url.Parse(o)
	if err != nil {
		return ""
	}
	return normalizeHost(u.Hostname())
}

// normalizeHost canonicalizes a hostname for comparison: strips IPv6 brackets and
// leading/trailing dots, lowercases, and converts an IDN/unicode host to its
// ASCII (punycode) form so "münchen.example" and its xn-- form compare equal and
// no unicode-lookalike sneaks past. IPs are returned as-is (lowercased, so IPv6
// is canonical for map lookups).
func normalizeHost(host string) string {
	host = strings.TrimSpace(host)
	host = strings.TrimPrefix(host, "[")
	host = strings.TrimSuffix(host, "]")
	host = strings.Trim(host, ".")
	host = strings.ToLower(host)
	if host == "" {
		return ""
	}
	if net.ParseIP(host) != nil {
		return host
	}
	// Punycode profile: lenient normalization to ASCII; on failure keep the
	// lowercased host so an unusual-but-valid name still compares consistently.
	if ascii, err := idna.ToASCII(host); err == nil && ascii != "" {
		return strings.ToLower(ascii)
	}
	return host
}

// registrableDomain returns the eTLD+1 (registrable domain) for host per the
// Public Suffix List, or "" for an IP, a bare public suffix, or a name with no
// registrable domain. Backed by golang.org/x/net/publicsuffix (the same PSL Go's
// cookiejar uses) — no hand-rolled suffix list.
func registrableDomain(host string) string {
	host = normalizeHost(host)
	if host == "" || net.ParseIP(host) != nil {
		return ""
	}
	rd, err := publicsuffix.EffectiveTLDPlusOne(host)
	if err != nil {
		return ""
	}
	return rd
}

// sameRegistrable reports whether a and b share the same registrable domain.
func sameRegistrable(a, b string) bool {
	ra := registrableDomain(a)
	return ra != "" && ra == registrableDomain(b)
}

// isBlockedHost blocks localhost, loopback/private/link-local ranges, and cloud
// metadata endpoints for the CREDENTIAL/scope axis — a captured session must
// never be replayed at internal infrastructure. Both IPv4 and IPv6 (including
// IPv4-mapped IPv6 like ::ffff:127.0.0.1, which net's methods normalize via To4)
// are covered. Private-CIDR/IP *scanning* uses different, non-credential clients
// and is unaffected by this.
func isBlockedHost(host string) bool {
	switch host {
	case "localhost", "ip6-localhost", "ip6-loopback",
		"metadata.google.internal", "metadata":
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return isDisallowedDestIP(ip)
	}
	return false
}
