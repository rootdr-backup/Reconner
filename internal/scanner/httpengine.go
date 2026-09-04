package scanner

import (
	"crypto/tls"
	"net"
	"net/http"
	"time"
)

// sharedHTTPTransport is a single, tuned transport reused by every scanner
// module. Before this, each module created its own http.Client with the default
// transport, so connections were never pooled across modules — every one of the
// tens of thousands of scan requests paid a fresh TCP + TLS handshake. Sharing
// one transport with a large idle-connection pool lets keep-alive reuse those
// connections, cutting CPU and latency dramatically without touching detection
// logic.
var baseHTTPTransport = &http.Transport{
	Proxy: http.ProxyFromEnvironment,
	DialContext: (&net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}).DialContext,
	ForceAttemptHTTP2:     true,
	MaxIdleConns:          512,
	MaxIdleConnsPerHost:   16,
	MaxConnsPerHost:       32,
	IdleConnTimeout:       90 * time.Second,
	TLSHandshakeTimeout:   10 * time.Second,
	ExpectContinueTimeout: 1 * time.Second,
	// CRITICAL for coverage: bug-bounty scopes are full of dev/staging/internal
	// hosts with self-signed, expired, or hostname-mismatched TLS certs — and
	// that's exactly where the interesting bugs live. Verifying certs would make
	// every such host fail the handshake and be silently skipped (missed bugs).
	// A scanner deliberately reaches the target regardless of cert validity.
	// MinVersion TLS 1.0 so we can still talk to legacy endpoints.
	TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, //nolint:gosec // intentional: scan targets with broken certs
		MinVersion:         tls.VersionTLS10,
	},
}

// All target-facing clients use this wrapper. It applies the effective
// per-target/global bounty-program identity at the last possible point, so even
// requests created by less common scanners cannot silently omit it.
var sharedHTTPTransport http.RoundTripper = identityRoundTripper{base: baseHTTPTransport}

// newPooledClient returns an http.Client backed by the shared pooled transport.
// followRedirects=false makes it stop at the first response (what most active
// checks want, so a 302 isn't silently followed and masked).
func newPooledClient(timeout time.Duration, followRedirects bool) *http.Client {
	c := &http.Client{
		Timeout:   timeout,
		Transport: sharedHTTPTransport,
	}
	if !followRedirects {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	return c
}
