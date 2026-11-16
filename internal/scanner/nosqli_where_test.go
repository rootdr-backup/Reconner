package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestNosqliWhereRequestShapes is the regression test for the v4.9 $where
// NoSQLi fix: $where must be added as a TOP-LEVEL sibling key (never nested
// under the field, unlike $ne/$eq/$regex), the request's original field(s)
// must survive untouched, and whereExpr=="" must produce the exact baseline
// request with no $where key at all — the zero-injection sample the timing
// engine's noise gate depends on.
func TestNosqliWhereRequestShapes(t *testing.T) {
	ip := insertionPoint{URL: "https://x.test/search?id=1", Param: "id", Value: "1", Method: "GET", Location: "query"}
	req, err := nosqliWhereRequest(context.Background(), ip, "sleep(5000)", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := req.URL.Query().Get("$where"); got != "sleep(5000)" {
		t.Fatalf("query $where=%q, want sleep(5000)", got)
	}
	if got := req.URL.Query().Get("id"); got != "1" {
		t.Fatalf("original query param id=%q, want preserved", got)
	}

	reqBase, err := nosqliWhereRequest(context.Background(), ip, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	if reqBase.URL.Query().Has("$where") {
		t.Fatalf("baseline (whereExpr=\"\") request unexpectedly carries a $where key: %s", reqBase.URL.RawQuery)
	}

	bip := insertionPoint{URL: "https://x.test/search", Param: "id", Value: "1", Method: "POST", Location: "body",
		Siblings: map[string]string{"id": "1", "q": "shoes"}}
	breq, err := nosqliWhereRequest(context.Background(), bip, "sleep(5000)", nil)
	if err != nil {
		t.Fatal(err)
	}
	rawBody, _ := io.ReadAll(breq.Body)
	form, _ := url.ParseQuery(string(rawBody))
	if form.Get("$where") != "sleep(5000)" || form.Get("id") != "1" || form.Get("q") != "shoes" {
		t.Fatalf("body form=%q, want $where added alongside original fields untouched", string(rawBody))
	}
	if ct := breq.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Fatalf("body Content-Type=%q", ct)
	}

	jip := insertionPoint{URL: "https://x.test/api", Param: "id", Value: "1", Method: "POST", Location: "json", ContentType: "application/json",
		Siblings: map[string]string{"id": "1"}}
	jreq, err := nosqliWhereRequest(context.Background(), jip, "sleep(5000)", nil)
	if err != nil {
		t.Fatal(err)
	}
	rawJSON, _ := io.ReadAll(jreq.Body)
	var root map[string]any
	if err := json.Unmarshal(rawJSON, &root); err != nil {
		t.Fatalf("invalid JSON body %s: %v", rawJSON, err)
	}
	if root["$where"] != "sleep(5000)" {
		t.Fatalf("json body=%s, want a top-level $where key (not nested under the field)", rawJSON)
	}
	if root["id"] != "1" {
		t.Fatalf("json body=%s, want the original field preserved", rawJSON)
	}
	if ct := jreq.Header.Get("Content-Type"); ct != "application/json" {
		t.Fatalf("json Content-Type=%q", ct)
	}
}

// TestWhereTimeBasedProbeSkipsUnsupportedLocations covers the guard in
// whereTimeBasedProbe: a location $where cannot be represented in (header,
// cookie, path, multipart, xml, graphql) must never be attempted.
func TestWhereTimeBasedProbeSkipsUnsupportedLocations(t *testing.T) {
	for _, loc := range []string{"header", "cookie", "path", "multipart", "xml", "graphql:field"} {
		ip := insertionPoint{URL: "https://x.test/", Param: "id", Value: "1", Method: "GET", Location: loc}
		s := &NoSQLiScanner{}
		if _, ok := s.whereTimeBasedProbe(context.Background(), ip, nil); ok {
			t.Fatalf("location %q unexpectedly accepted for $where timing probe", loc)
		}
	}
}

// TestWhereTimeBasedProbeProvenOnRealSleep is the end-to-end proof that the
// new $where statistical timing engine is wired correctly: against a server
// that genuinely executes the injected sleep() duration (mirroring real
// MongoDB $where JS execution), detection must fire with linear-scaling
// evidence. The scaling DECISION itself (timingScalingConfirmed) is already
// covered by sqli_timing_test.go's table-driven tests; this proves the new
// request-building + sampling wiring around it is correct end-to-end.
func TestWhereTimeBasedProbeProvenOnRealSleep(t *testing.T) {
	withLoopbackAllowed(t)
	sleepRe := regexp.MustCompile(`sleep\((\d+)\)`)
	mux := http.NewServeMux()
	mux.HandleFunc("/where", func(w http.ResponseWriter, r *http.Request) {
		if m := sleepRe.FindStringSubmatch(r.URL.Query().Get("$where")); m != nil {
			if ms, err := strconv.Atoi(m[1]); err == nil {
				time.Sleep(time.Duration(ms) * time.Millisecond)
			}
		}
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/where?id=1", Param: "id", Value: "1", Method: "GET", Location: "query"}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := &NoSQLiScanner{}
	ev, ok := s.whereTimeBasedProbe(ctx, ip, nil)
	if !ok {
		t.Fatal("expected $where time-based injection to be PROVEN against a server that genuinely executes the sleep")
	}
	if !strings.Contains(ev, "$where") || !strings.Contains(ev, "PROVEN") {
		t.Fatalf("evidence missing expected content: %s", ev)
	}
}

// TestWhereTimeBasedProbeRejectsFixedNonScalingDelay proves the false-
// positive floor end-to-end: a server that adds the SAME fixed delay for
// ANY request carrying a $where key — including sleep(0) — regardless of the
// sleep() value inside it (i.e. NOT real $where execution, just unrelated
// slowness triggered by the new key's mere presence) must be rejected, not
// reported. This specifically exercises the i0 control (sleep(0) must stay
// ≈ baseline), the check added for NoSQLi precisely because adding a whole
// new top-level operator key is a bigger structural change than SQLi's own
// "append a suffix to an existing value" and deserves its own proof.
func TestWhereTimeBasedProbeRejectsFixedNonScalingDelay(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/wherefixed", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("$where") != "" {
			time.Sleep(4 * time.Second) // fixed, ignores the requested sleep duration entirely
		}
		fmt.Fprint(w, "ok")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/wherefixed?id=1", Param: "id", Value: "1", Method: "GET", Location: "query"}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	s := &NoSQLiScanner{}
	if _, ok := s.whereTimeBasedProbe(ctx, ip, nil); ok {
		t.Fatal("a fixed non-scaling delay must never be reported as proven $where injection")
	}
}
