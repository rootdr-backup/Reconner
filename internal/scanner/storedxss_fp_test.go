package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// A persisted payload only matters if the page a victim loads is rendered as
// HTML. cleanFetch must reject text/plain, text/css/js and JSON responses so a
// stored payload surfacing in a non-HTML endpoint isn't reported as stored XSS.
func TestStoredXSSCleanFetchContentTypeGate(t *testing.T) {
	withLoopbackAllowed(t)
	payload := "<svg onload=alert(1)>"
	mux := http.NewServeMux()
	mux.HandleFunc("/html", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<div>" + payload + "</div>"))
	})
	mux.HandleFunc("/plain", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Write([]byte("<div>" + payload + "</div>"))
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"x":"` + payload + `"}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &VulnScanner{}
	if b := s.cleanFetch(context.Background(), srv.URL+"/html", nil); !strings.Contains(b, payload) {
		t.Fatalf("a text/html page must be fetched, got %q", b)
	}
	if b := s.cleanFetch(context.Background(), srv.URL+"/plain", nil); b != "" {
		t.Fatalf("text/plain must be rejected (payload cannot execute as markup), got %q", b)
	}
	if b := s.cleanFetch(context.Background(), srv.URL+"/json", nil); b != "" {
		t.Fatalf("application/json must be rejected, got %q", b)
	}
}
