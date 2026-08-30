package scanner

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"time"
)

// Destination (DNS/IP) validation — the second half of the scope boundary
// (scope.go is the hostname half). An in-scope hostname can still resolve, or be
// rebound, to 127.0.0.1 / 169.254.169.254 / a private address; blindly connecting
// there with a replayed Cookie/Authorization is an SSRF + credential-exfiltration
// bug. This file centralizes the IP policy AND ties the validated IP to the
// actual connection (pin-dial), so the HTTP client cannot re-resolve around the
// check (DNS-rebinding / TOCTOU). It backs the credential client only; private-
// CIDR/IP scanning uses separate, non-credential clients and is unaffected.

// ErrDestinationBlocked is returned when a connection would reach an IP the
// credential/security policy forbids — including when an in-scope hostname
// resolves or is rebound to such an address.
var ErrDestinationBlocked = errors.New("destination blocked by scope/SSRF policy")

// metadataIPs are well-known cloud/link-local metadata endpoints that must never
// receive a replayed credential, regardless of hostname scope.
var metadataIPs = []net.IP{
	net.ParseIP("169.254.169.254"), // AWS/GCP/Azure/DO/OpenStack IMDS (IPv4)
	net.ParseIP("fd00:ec2::254"),   // AWS IMDS over IPv6
}

func isMetadataIP(ip net.IP) bool {
	for _, m := range metadataIPs {
		if m != nil && ip.Equal(m) {
			return true
		}
	}
	return false
}

// extraBlockedCIDRs are non-public ranges that Go's net helpers don't classify as
// private/loopback/link-local but that must never receive a replayed credential:
// carrier-grade NAT (RFC 6598) and IETF-reserved test/benchmark space that only
// ever appears on internal or lab networks.
var extraBlockedCIDRs = func() []*net.IPNet {
	var out []*net.IPNet
	for _, c := range []string{
		"100.64.0.0/10",   // RFC 6598 CGNAT
		"192.0.0.0/24",    // RFC 6890 IETF protocol assignments
		"192.0.2.0/24",    // RFC 5737 TEST-NET-1
		"198.18.0.0/15",   // RFC 2544 benchmarking
		"198.51.100.0/24", // RFC 5737 TEST-NET-2
		"203.0.113.0/24",  // RFC 5737 TEST-NET-3
		"100::/64",        // RFC 6666 IPv6 discard-only
	} {
		if _, n, err := net.ParseCIDR(c); err == nil {
			out = append(out, n)
		}
	}
	return out
}()

func inExtraBlockedCIDR(ip net.IP) bool {
	for _, n := range extraBlockedCIDRs {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

// isDisallowedDestIP is the single IP-policy predicate for the credential path.
// It rejects every non-public destination: loopback, unspecified, private
// (RFC1918 + IPv6 ULA fc00::/7), link-local unicast (incl. 169.254/16 and
// fe80::/10), all multicast, and cloud metadata. IPv4-mapped IPv6 (::ffff:a.b.c.d)
// is folded to its 4-byte form first so ::ffff:127.0.0.1 is caught as loopback and
// no address-representation trick slips through.
// testAllowLoopbackDest is an UNEXPORTED, default-false escape hatch used ONLY by
// this package's tests so they can point the credential client at an httptest
// server on 127.0.0.1. It is never settable from production code (no exported
// setter, no config, no flag) so the guard is always fully active in a real build.
var testAllowLoopbackDest = false

func isDisallowedDestIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	if testAllowLoopbackDest && (ip.IsLoopback() || ip.IsPrivate()) {
		return false // test-only: allow loopback/private httptest servers
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsPrivate() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsMulticast() || ip.IsInterfaceLocalMulticast() {
		return true
	}
	return isMetadataIP(ip) || inExtraBlockedCIDR(ip)
}

// validateResolvedIPs enforces the policy over a hostname's full resolution set.
// EVERY address must be allowed: a single internal record — the DNS-rebinding
// trick, or a split-horizon name with one private answer — fails the whole
// connection (fail closed). Returns the validated addresses (order preserved) so
// the caller can pin-dial them without a second, unvalidated lookup.
func validateResolvedIPs(host string, ips []net.IPAddr) ([]net.IPAddr, error) {
	if len(ips) == 0 {
		return nil, fmt.Errorf("%w: %s has no addresses", ErrDestinationBlocked, host)
	}
	for _, ia := range ips {
		if isDisallowedDestIP(ia.IP) {
			return nil, fmt.Errorf("%w: %s resolves to forbidden %s", ErrDestinationBlocked, host, ia.IP)
		}
	}
	return ips, nil
}

var credentialBaseDialer = &net.Dialer{
	Timeout:   10 * time.Second,
	KeepAlive: 30 * time.Second,
}

// guardedDialContext validates the destination and PINS the connection to a
// validated IP. This is what defeats DNS rebinding / TOCTOU: we resolve ONCE,
// validate the whole answer set, and dial those exact IPs — the HTTP client never
// performs a second, unvalidated resolution, so the IP that passed policy is the
// IP actually connected to.
func guardedDialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	// Literal-IP destination: validate directly (no DNS), then dial it.
	if ip := net.ParseIP(host); ip != nil {
		if isDisallowedDestIP(ip) {
			return nil, fmt.Errorf("%w: %s", ErrDestinationBlocked, host)
		}
		return credentialBaseDialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
	}
	// Hostname: resolve once, validate the entire answer set, then dial the
	// validated IPs directly (trying each in order for connectivity, never
	// re-resolving through the OS).
	resolved, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, err
	}
	ips, err := validateResolvedIPs(host, resolved)
	if err != nil {
		return nil, err
	}
	var lastErr error
	for _, ia := range ips {
		conn, e := credentialBaseDialer.DialContext(ctx, network, net.JoinHostPort(ia.IP.String(), port))
		if e == nil {
			return conn, nil
		}
		lastErr = e
	}
	return nil, lastErr
}

// guardedCredentialTransport is sharedHTTPTransport's tuning with the guarded,
// destination-validating, IP-pinning dialer, and NO env proxy (a proxy would
// resolve/route around the IP guard). It backs the credential client so every
// authenticated replay/verify request is destination-checked at connect time, for
// all callers, with no HTTP-layer path to bypass the check.
var guardedCredentialTransport = &http.Transport{
	Proxy:                 nil,
	DialContext:           guardedDialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          128,
	MaxIdleConnsPerHost:   8,
	MaxConnsPerHost:       16,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	TLSClientConfig:       sharedHTTPTransport.TLSClientConfig,
}
