package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

// The data-flow bug: headerChecks tested X-Forwarded-For and Referer, but
// fetchWithHeader only ever set Cookie/User-Agent, so those headers were never
// actually injected. This asserts the injection now reaches each header.
func TestSQLiFetchWithHeaderSetsAllHeaders(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Echo the header under test so the caller can confirm the injection landed.
		w.Write([]byte("XFF=" + r.Header.Get("X-Forwarded-For") +
			"|REF=" + r.Header.Get("Referer") +
			"|UA=" + r.Header.Get("User-Agent") +
			"|CK=" + r.Header.Get("Cookie") +
			"|XC=" + r.Header.Get("X-Custom")))
	}))
	defer srv.Close()
	s := &SQLiScanner{}
	ctx := context.Background()

	if b := s.fetchWithHeader(ctx, srv.URL, "X-Forwarded-For", "INJ123"); !strings.Contains(b, "XFF=127.0.0.1,INJ123") {
		t.Fatalf("X-Forwarded-For injection not sent: %q", b)
	}
	if b := s.fetchWithHeader(ctx, srv.URL, "Referer", "INJ123"); !strings.Contains(b, "REF=https://INJ123/") {
		t.Fatalf("Referer injection not sent: %q", b)
	}
	if b := s.fetchWithHeader(ctx, srv.URL, "X-Custom", "INJ123"); !strings.Contains(b, "XC=INJ123") {
		t.Fatalf("custom header injection not sent: %q", b)
	}
	if b := s.fetchWithHeader(ctx, srv.URL, "Cookie", "INJ123"); !strings.Contains(b, "CK=id=INJ123") {
		t.Fatalf("Cookie injection not sent: %q", b)
	}
}

// hasQuote reports whether the injected id value carries a quote (the error probe).
func hasQuote(v string) bool { return strings.ContainsAny(v, "'\"`") }

// Error-based must REPRODUCE: a DB error that flashes only once (transient 500)
// must NOT be reported. A consistent DB error MUST be reported.
func TestSQLiErrorBasedRequiresReproduction(t *testing.T) {
	withLoopbackAllowed(t)
	ctx := context.Background()
	dbErr := "<html>You have an error in your SQL syntax; check the manual near '1' at line 1</html>"
	normal := "<html>ok ok ok normal page stable content here</html>"

	// Transient: emit the DB error on the FIRST quote request only.
	var firstQuote int32
	transient := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuote(r.URL.Query().Get("id")) && atomic.AddInt32(&firstQuote, 1) == 1 {
			w.Write([]byte(dbErr))
			return
		}
		w.Write([]byte(normal))
	}))
	defer transient.Close()
	ip := insertionPoint{URL: transient.URL + "/?id=1", Param: "id", Method: "GET"}
	if kind, _ := (&SQLiScanner{}).quickProbe(ctx, ip, nil); kind == "error_based" {
		t.Fatal("a one-shot (transient) DB error must NOT be reported as error-based SQLi")
	}

	// Consistent: emit the DB error on EVERY quote request.
	consistent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hasQuote(r.URL.Query().Get("id")) {
			w.Write([]byte(dbErr))
			return
		}
		w.Write([]byte(normal))
	}))
	defer consistent.Close()
	ip2 := insertionPoint{URL: consistent.URL + "/?id=1", Param: "id", Method: "GET"}
	if kind, _ := (&SQLiScanner{}).quickProbe(ctx, ip2, nil); kind != "error_based" {
		t.Fatalf("a reproducible DB error must be reported as error-based SQLi, got %q", kind)
	}
}
