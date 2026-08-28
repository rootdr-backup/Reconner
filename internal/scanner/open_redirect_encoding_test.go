package scanner

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// FN fix: an encoded-separator payload (%2f%2fevil.com) must reach the server
// decodable. The old q.Encode() construction double-encoded the '%' (→ %252f), so
// the app decoded it back to a literal "%2f%2fevil.com" that never redirected.
// This mock filters obvious off-site markers in the RAW query (a real bypass
// class) but URL-decodes the value before building its redirect, so ONLY a
// correctly-delivered encoded payload is detected.
func TestOpenRedirectEncodedBypassDelivered(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := strings.ToLower(r.URL.RawQuery)
		w.Header().Set("Content-Type", "text/html")
		if strings.Contains(raw, "//") || strings.Contains(raw, "http") || strings.Contains(raw, `\`) {
			w.Write([]byte("<html>blocked</html>")) // raw off-site markers rejected
			return
		}
		v := r.URL.Query().Get("next") // decoded once by Go
		w.Write([]byte(`<html><meta http-equiv="refresh" content="0; url=` + v + `"></html>`))
	}))
	defer srv.Close()

	res, ok := checkOpenRedirectURL(srv.URL+"/go", "next")
	if !ok || res.class != redirectExternal {
		t.Fatalf("encoded-separator open redirect must be detected (delivered decodable); got ok=%v class=%v", ok, res.class)
	}
}

// FP control: a fixed same-origin redirect that ignores the parameter must NOT be
// reported as an external open redirect (destination is validated, not reflection).
func TestOpenRedirectSameOriginNotFlagged(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/dashboard") // always same-origin, ignores ?next
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	res, ok := checkOpenRedirectURL(srv.URL+"/go", "next")
	if ok && res.class == redirectExternal {
		t.Fatal("a fixed same-origin redirect must NOT be flagged as an external open redirect")
	}
}
