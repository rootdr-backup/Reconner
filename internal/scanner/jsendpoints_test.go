package scanner

import (
	"reflect"
	"testing"
)

// TestBuildCandidatesResolvesProtocolRelativeURLs is the regression test for
// the endpoint-resolution bug: a protocol-relative JS reference
// ("//api.example.com/v1/x", the common fetch("//host/path") pattern for an
// API/CDN host that doesn't care which scheme the page loaded under) also
// starts with "/", so it used to fall into the root-relative branch and get
// mangled into root+"//host/path" — a URL resolving to the WRONG host
// entirely (the page's own origin, with a literal "//host/path" segment as
// its path) rather than the host the JS actually referenced.
func TestBuildCandidatesResolvesProtocolRelativeURLs(t *testing.T) {
	s := &JSEndpointScanner{}
	got := s.buildCandidates(
		[]string{"//api.example.com/v1/users"},
		[]string{"https://example.com"},
		"example.com",
	)
	want := []string{"https://api.example.com/v1/users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildCandidates=%v, want %v (not a root+\"//host/path\" mangled URL)", got, want)
	}
}

// TestBuildCandidatesStillResolvesRootRelativePaths guards the adjacent,
// much more common case against a regression from reordering the switch: a
// genuine single-leading-slash path must still be resolved against every
// alive host root exactly as before.
func TestBuildCandidatesStillResolvesRootRelativePaths(t *testing.T) {
	s := &JSEndpointScanner{}
	got := s.buildCandidates(
		[]string{"/api/v1/users"},
		[]string{"https://example.com", "https://app.example.com"},
		"example.com",
	)
	want := []string{"https://example.com/api/v1/users", "https://app.example.com/api/v1/users"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("buildCandidates=%v, want %v", got, want)
	}
}

// TestBuildCandidatesRejectsProtocolRelativeOutOfScopeHost ensures the fix
// does not widen scope: a protocol-relative reference to a genuinely
// third-party host (not the target domain or a subdomain of it) must still
// be dropped, exactly like an absolute out-of-scope URL already is.
func TestBuildCandidatesRejectsProtocolRelativeOutOfScopeHost(t *testing.T) {
	s := &JSEndpointScanner{}
	got := s.buildCandidates(
		[]string{"//cdn.unrelated-thirdparty.test/lib.js"},
		[]string{"https://example.com"},
		"example.com",
	)
	if len(got) != 0 {
		t.Fatalf("buildCandidates=%v, want the out-of-scope third-party host dropped", got)
	}
}

// TestBuildCandidatesAcceptsProtocolRelativeInScopeSubdomain covers the
// realistic positive case the bug silently lost: an API host that IS a
// subdomain of the target but was referenced protocol-relatively.
func TestBuildCandidatesAcceptsProtocolRelativeInScopeSubdomain(t *testing.T) {
	s := &JSEndpointScanner{}
	got := s.buildCandidates(
		[]string{"//api.example.com/v1/users"},
		[]string{"https://example.com"},
		"example.com",
	)
	if len(got) != 1 || got[0] != "https://api.example.com/v1/users" {
		t.Fatalf("buildCandidates=%v, want the in-scope subdomain endpoint kept", got)
	}
}
