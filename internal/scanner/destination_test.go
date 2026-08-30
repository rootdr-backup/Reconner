package scanner

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
)

// withLoopbackAllowed lets a test point the credential client at an httptest
// server on 127.0.0.1 by flipping the package's test-only escape hatch, restored
// on cleanup. Never affects production (the flag has no production setter).
func withLoopbackAllowed(t *testing.T) {
	t.Helper()
	old := testAllowLoopbackDest
	testAllowLoopbackDest = true
	t.Cleanup(func() { testAllowLoopbackDest = old })
}

func TestIsDisallowedDestIP(t *testing.T) {
	disallowed := []string{
		"127.0.0.1", "10.0.0.1", "172.16.0.1", "192.168.1.1", "169.254.169.254",
		"0.0.0.0", "100.64.0.1" /* CGNAT is private per Go */, "::1",
		"fc00::1", "fd00::1", "fe80::1", "ff02::1", // ULA, link-local, multicast
		"fd00:ec2::254",          // IPv6 metadata
		"::ffff:127.0.0.1",       // IPv4-mapped loopback
		"::ffff:169.254.169.254", // IPv4-mapped metadata
		"::ffff:10.0.0.1",        // IPv4-mapped private
	}
	for _, s := range disallowed {
		ip := net.ParseIP(s)
		if ip == nil {
			t.Fatalf("bad test IP %q", s)
		}
		if !isDisallowedDestIP(ip) {
			t.Errorf("isDisallowedDestIP(%s) = false, want true (must be blocked)", s)
		}
	}
	allowed := []string{"8.8.8.8", "1.1.1.1", "93.184.216.34", "2606:4700:4700::1111"}
	for _, s := range allowed {
		if isDisallowedDestIP(net.ParseIP(s)) {
			t.Errorf("isDisallowedDestIP(%s) = true, want false (public IP must be allowed)", s)
		}
	}
}

func TestValidateResolvedIPs(t *testing.T) {
	pub := net.IPAddr{IP: net.ParseIP("93.184.216.34")}
	loop := net.IPAddr{IP: net.ParseIP("127.0.0.1")}
	priv := net.IPAddr{IP: net.ParseIP("10.0.0.7")}

	if _, err := validateResolvedIPs("h", []net.IPAddr{pub}); err != nil {
		t.Errorf("single public IP should validate, got %v", err)
	}
	if _, err := validateResolvedIPs("h", []net.IPAddr{loop}); !errors.Is(err, ErrDestinationBlocked) {
		t.Errorf("loopback must be blocked, got %v", err)
	}
	// Multi-record / DNS-rebinding: one internal answer fails the WHOLE set.
	if _, err := validateResolvedIPs("h", []net.IPAddr{pub, priv}); !errors.Is(err, ErrDestinationBlocked) {
		t.Errorf("a resolution set containing a private IP must be blocked, got %v", err)
	}
	if _, err := validateResolvedIPs("h", nil); !errors.Is(err, ErrDestinationBlocked) {
		t.Errorf("empty resolution must be blocked, got %v", err)
	}
}

// A literal internal-IP destination is blocked at dial time even before any
// network I/O (proves the guard runs at the connection layer, not just in a
// helper the client can skip).
func TestGuardedDialBlocksLiteralInternalIP(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:80", "169.254.169.254:80", "[::1]:443", "10.0.0.1:8080"} {
		_, err := guardedDialContext(context.Background(), "tcp", addr)
		if !errors.Is(err, ErrDestinationBlocked) {
			t.Errorf("guardedDialContext(%q) err = %v, want ErrDestinationBlocked", addr, err)
		}
	}
}

// roundTripFunc lets a test stand in for a transport.
type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// The credential client must NEVER follow a redirect: a 302 is returned as-is, so
// the captured Cookie/Authorization can never reach the redirect target (in- or
// out-of-scope). This is the authenticated-redirect safety property.
func TestCredentialClientDoesNotFollowRedirect(t *testing.T) {
	var seen []string
	stub := roundTripFunc(func(r *http.Request) (*http.Response, error) {
		seen = append(seen, r.URL.String())
		h := http.Header{}
		h.Set("Location", "http://evil.example/steal")
		h.Set("Set-Cookie", "x=1")
		return &http.Response{
			StatusCode: http.StatusFound, Header: h,
			Body: io.NopCloser(strings.NewReader("")), Request: r,
		}, nil
	})
	old := identityHTTPClient.Transport
	identityHTTPClient.Transport = stub
	defer func() { identityHTTPClient.Transport = old }()

	id := &Identity{Label: "u", Headers: map[string]string{
		"Cookie": "session=secret", "Authorization": "Bearer tok",
	}}
	res := Replay(context.Background(), ReplaySpec{Method: "GET", URL: "https://target.example/"}, id)

	if res.Status != http.StatusFound {
		t.Fatalf("expected the 302 returned as-is, got status %d", res.Status)
	}
	if len(seen) != 1 {
		t.Fatalf("client made %d requests %v — it must NOT follow the redirect", len(seen), seen)
	}
	if seen[0] != "https://target.example/" {
		t.Fatalf("only the original in-scope URL may be requested, got %q", seen[0])
	}
}
