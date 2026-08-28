package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestFingerprintDBMS(t *testing.T) {
	cases := map[string]string{
		"You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version": "mysql",
		"PostgreSQL query failed: ERROR: syntax error at or near":                                              "postgresql",
		"Unclosed quotation mark after the character string":                                                   "mssql",
		"ORA-01756: quoted string not properly terminated":                                                     "oracle",
		"sqlite3.OperationalError: near":                                                                       "sqlite",
		"a perfectly normal page with no db error":                                                             "",
	}
	for body, want := range cases {
		if got := fingerprintDBMS(body); got != want {
			t.Errorf("fingerprintDBMS(%q) = %q, want %q", body[:20], got, want)
		}
	}
}

// The MySQL extractvalue path is reflection-proof: the payload carries the marker
// only as hex, so an ASCII marker in the response proves the DB decoded it. A page
// that merely echoes the raw payload (hex) must NOT be confirmed.
func TestErrorForceReflectionProof(t *testing.T) {
	// DB evaluated it: ASCII marker appears in an XPATH error.
	dbResp := "Warning: XPATH syntax error: '~" + sqliMarker + "~5.7.44-log'"
	if ok, dbms := errorForceConfirmed(true, "baseline", dbResp); !ok || dbms != "mysql" {
		t.Fatalf("hex-marker DB error must confirm mysql, got ok=%v dbms=%q", ok, dbms)
	}
	// Pure reflection of the RAW payload: the response contains the HEX literal but
	// NOT the ASCII marker → must NOT confirm.
	reflected := "you searched for: 1 AND extractvalue(1,concat(0x7e," + sqliMarkerHex + ",0x7e,version()))"
	if strings.Contains(reflected, sqliMarker) {
		t.Fatal("test setup wrong: reflected body should not contain the ASCII marker")
	}
	if ok, _ := errorForceConfirmed(true, "baseline", reflected); ok {
		t.Fatal("a raw-payload reflection (hex only) must NOT be confirmed as extraction")
	}
	// ASCII-marker engine (PG): marker alone is not enough; needs a fresh DB error.
	if ok, _ := errorForceConfirmed(false, "baseline", "echo: "+sqliMarker); ok {
		t.Fatal("ASCII-marker match without a DB error must not confirm")
	}
	pg := "ERROR: invalid input syntax for integer: \"" + sqliMarker + "\""
	if ok, dbms := errorForceConfirmed(false, "clean baseline", pg); !ok || dbms != "postgresql" {
		t.Fatalf("ASCII marker + PG error must confirm postgresql, got ok=%v dbms=%q", ok, dbms)
	}
}

func TestExtractLeakedVersion(t *testing.T) {
	resp := "XPATH syntax error: '~" + sqliMarker + "~8.0.36-community'"
	if v := extractLeakedVersion(resp); !strings.Contains(v, "8.0.36") {
		t.Errorf("leaked version = %q, want it to contain 8.0.36", v)
	}
}

func TestTamperVariants(t *testing.T) {
	v := tamperVariants("1 AND 1=1")
	if len(v) == 0 {
		t.Fatal("expected tamper variants")
	}
	joined := strings.Join(v, "|")
	if !strings.Contains(joined, "/**/") {
		t.Error("expected an inline-comment (space-filter bypass) variant")
	}
	if !strings.Contains(joined, "%") {
		t.Error("expected a URL-encoded variant")
	}
	// case-toggle must change AND's casing somewhere
	sawCase := false
	for _, x := range v {
		if strings.Contains(x, "aNd") || strings.Contains(x, "AnD") || strings.Contains(x, "aND") {
			sawCase = true
		}
	}
	if !sawCase {
		t.Errorf("expected a mixed-case keyword variant, got %v", v)
	}
	// the original must not be duplicated in the variants
	for _, x := range v {
		if x == "1 AND 1=1" {
			t.Error("tamper variants must not include the untouched original")
		}
	}
}

// TestErrorForceProbeE2E stands up a fake MySQL-ish endpoint that, when it sees
// the extractvalue payload, returns an XPATH error echoing the ASCII marker (as a
// real MySQL would). The probe must confirm error-based SQLi + fingerprint mysql.
func TestErrorForceProbeE2E(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		// Emulate the DB: only when the extractvalue expression with our HEX marker
		// arrives do we surface the decoded ASCII marker inside an XPATH error.
		if strings.Contains(q, "extractvalue") && strings.Contains(strings.ToLower(q), strings.ToLower(sqliMarkerHex)) {
			w.WriteHeader(500)
			w.Write([]byte("Warning: XPATH syntax error: '~" + sqliMarker + "~5.7.40'"))
			return
		}
		w.Write([]byte("<html>ok</html>"))
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/?id=1", Param: "id", Method: "GET"}
	base, _ := sendInjected(context.Background(), sqliHTTPClient, ip, "1", nil)
	kind, ev := s.errorForceProbe(context.Background(), ip, nil, base)
	if kind != "error_based" {
		t.Fatalf("expected error_based, got %q", kind)
	}
	if !strings.Contains(ev, "mysql") || !strings.Contains(ev, "reflection-proof") {
		t.Errorf("evidence should name mysql and reflection-proof: %q", ev)
	}
	if !strings.Contains(ev, "5.7.40") {
		t.Errorf("evidence should include the leaked version: %q", ev)
	}
}

// TestSecondOrderProbeE2E emulates a STORED-injection app: POST /save persists the
// `comment` field; GET /feed renders the last stored comment through a query that,
// if the comment contains the extractvalue+hex-marker expression, surfaces the
// decoded ASCII marker in an XPATH error. The write request itself shows nothing —
// only the later read leaks it. secondOrderProbe must catch that.
func TestSecondOrderProbeE2E(t *testing.T) {
	var stored string
	mux := http.NewServeMux()
	mux.HandleFunc("/save", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		stored = r.Form.Get("comment")
		w.Write([]byte("<html>saved</html>")) // write reveals nothing
	})
	mux.HandleFunc("/feed", func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(stored, "extractvalue") && strings.Contains(strings.ToLower(stored), strings.ToLower(sqliMarkerHex)) {
			w.WriteHeader(500)
			w.Write([]byte("Warning: XPATH syntax error: '~" + sqliMarker + "~10.4.11-MariaDB'"))
			return
		}
		w.Write([]byte("<html>feed: " + stored + "</html>"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &SQLiScanner{}
	writeIP := insertionPoint{URL: srv.URL + "/save", Param: "comment", Method: "POST",
		ContentType: "application/x-www-form-urlencoded"}
	readURLs := []string{srv.URL + "/feed"}

	kind, ev := s.secondOrderProbe(context.Background(), writeIP, readURLs, nil)
	if kind != "error_based" {
		t.Fatalf("expected second-order confirmation, got kind=%q", kind)
	}
	if !strings.Contains(ev, "second-order") || !strings.Contains(ev, "/feed") {
		t.Errorf("evidence should describe the stored→read flow: %q", ev)
	}
}
