package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var regexpOrderBy = regexp.MustCompile(`ORDER BY (\d+)`)

// TestUnionColumnCount verifies the ORDER-BY boundary technique against a
// fake DB-backed endpoint with a KNOWN column count (3): ORDER BY 1..3 must
// succeed, ORDER BY 4+ must trigger a simulated MySQL error.
func TestUnionColumnCount(t *testing.T) {
	const realCols = 3
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("id")
		if m := regexpOrderBy.FindStringSubmatch(q); m != nil {
			n, _ := strconv.Atoi(m[1])
			if n > realCols {
				fmt.Fprint(w, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version")
				return
			}
		}
		fmt.Fprint(w, "<html>ok</html>")
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/?id=1", Param: "id", Method: "GET"}
	got := s.unionColumnCount(context.Background(), ip, nil)
	if got != realCols {
		t.Fatalf("unionColumnCount() = %d, want %d", got, realCols)
	}
}

// TestUnionMarkerColumn verifies the marker-reflection technique correctly
// identifies which UNION SELECT position a fake endpoint echoes back — here
// simulated as column 2 of 3.
func TestUnionMarkerColumn(t *testing.T) {
	const cols = 3
	const vulnPos = 2
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw, _ := url.QueryUnescape(r.URL.Query().Get("id"))
		parts := strings.Split(raw, ",")
		if len(parts) == cols {
			val := strings.Trim(parts[vulnPos-1], "'")
			fmt.Fprintf(w, "<html>Result: %s</html>", val)
			return
		}
		fmt.Fprint(w, "<html>ok</html>")
	}))
	defer srv.Close()

	s := &SQLiScanner{}
	ip := insertionPoint{URL: srv.URL + "/?id=1", Param: "id", Method: "GET"}
	pos, payload := s.unionMarkerColumn(context.Background(), ip, nil, cols)
	if pos != vulnPos {
		t.Fatalf("unionMarkerColumn() pos = %d, want %d (payload=%q)", pos, vulnPos, payload)
	}
	if !strings.Contains(payload, "UNION SELECT") {
		t.Fatalf("payload missing UNION SELECT: %q", payload)
	}
}

// TestLFINewSignatures covers the new /proc/self/environ, data://, and
// expect:// confirmation paths added to confirmLFI.
func TestLFINewSignatures(t *testing.T) {
	cases := []struct {
		name, payload, body string
		wantKind            string
	}{
		{"environ hit", "../../../../proc/self/environ", "PATH=/usr/bin\x00HTTP_USER_AGENT=curl\x00", "/proc/self/environ"},
		{"environ miss", "../../../../proc/self/environ", "<html>nothing here</html>", ""},
		{"data wrapper hit", "data://text/plain;base64,x", "rcnLFI_" + lfiMarker + " echoed back", "data:// wrapper code execution"},
		{"data wrapper miss", "data://text/plain;base64,x", "<html>404</html>", ""},
		{"expect hit", "expect://id", "uid=33(www-data) gid=33(www-data) groups=33(www-data)", "expect:// wrapper command execution"},
		{"expect miss", "expect://id", "<html>command not found</html>", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := confirmLFI(c.payload, c.body)
			if got != c.wantKind {
				t.Errorf("confirmLFI(%q, ...) = %q, want %q", c.payload, got, c.wantKind)
			}
		})
	}
}

// TestSSRFNewProviderSignatures ensures the new Azure/Alibaba/DigitalOcean/
// Oracle signatures match realistic sample bodies and don't cross-fire.
func TestSSRFNewProviderSignatures(t *testing.T) {
	samples := map[string]string{
		`{"azEnvironment":"AzurePublicCloud","subscriptionId":"abc"}`:       "azure",
		`owner-account-id: 123456`:                                          "alibaba",
		`{"droplet_id":123,"interfaces":{"public":[]}}`:                     "digitalocean",
		`{"compartmentId":"ocid1.compartment","availabilityDomain":"AD-1"}`: "oracle",
	}
	for body, provider := range samples {
		matched := false
		for _, sig := range ssrfMetadataSignatures {
			if sig.MatchString(body) {
				matched = true
				break
			}
		}
		if !matched {
			t.Errorf("no ssrfMetadataSignatures matched a real %s metadata sample: %q", provider, body)
		}
	}
	// Reflection guard: the new host/path markers must still catch payload echo.
	if !responseReflectsPayload("Redirecting to http://100.100.100.200/latest/meta-data/", "http://100.100.100.200/latest/meta-data/") {
		t.Error("responseReflectsPayload should catch Alibaba host echo")
	}
}

// TestJSScriptBreakout verifies the new deterministic <script>-breakout XSS
// confirmation: a reflection inside a <script> block whose angle brackets survive
// raw must be confirmable (close </script>, inject a new element); if the angle
// brackets are encoded, it must NOT be confirmable (needs a browser-level proof).
func TestJSScriptBreakout(t *testing.T) {
	cases := []struct {
		name       string
		a          ReflectionAnalysis
		wantOK     bool
		wantHasTag string
	}{
		{"js string, < and > survive", ReflectionAnalysis{Context: CtxJSString, Surviving: `<>"'`}, true, "</script>"},
		{"js expr, < and > survive", ReflectionAnalysis{Context: CtxJSExpr, Surviving: "<>"}, true, "</script>"},
		{"js string, angle brackets encoded", ReflectionAnalysis{Context: CtxJSString, Surviving: `'"`}, false, ""},
		{"js string, only < survives", ReflectionAnalysis{Context: CtxJSString, Surviving: "<"}, false, ""},
		{"not a js context", ReflectionAnalysis{Context: CtxHTMLText, Surviving: "<>"}, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			payload, needle, ok := jsScriptBreakout(c.a)
			if ok != c.wantOK {
				t.Fatalf("jsScriptBreakout ok = %v, want %v", ok, c.wantOK)
			}
			if ok {
				if !strings.HasPrefix(payload, c.wantHasTag) {
					t.Fatalf("payload %q missing prefix %q", payload, c.wantHasTag)
				}
				if needle == "" || !strings.Contains(payload, needle) {
					t.Fatalf("needle %q not contained in payload %q", needle, payload)
				}
			}
		})
	}

	// exploitExample must report the breakout exploit for a </script> proof and the
	// canonical per-context payload otherwise.
	if got := exploitExample(CtxJSString, "</script><rcnq2z>"); !strings.HasPrefix(got, "</script>") {
		t.Errorf("exploitExample for script-breakout = %q, want </script>… ", got)
	}
	if got := exploitExample(CtxHTMLText, "<rcnq2z>"); got != contextPayload(CtxHTMLText) {
		t.Errorf("exploitExample for html-text = %q, want %q", got, contextPayload(CtxHTMLText))
	}
}

// TestLooksLikeDBLookup covers the new DB-lookup value-shape gate that widens the
// SQLi candidate set beyond bare integers and prone names.
func TestLooksLikeDBLookup(t *testing.T) {
	hits := []string{
		"550e8400-e29b-41d4-a716-446655440000", // uuid
		"2024-01-02", "2024/1/2", "2024.01.02", // dates
		"deadbeef", "0A1B2C3D", // hex ids
		"12-34", "5,6", "7|8", // composite keys
	}
	for _, v := range hits {
		if !looksLikeDBLookup(v) {
			t.Errorf("looksLikeDBLookup(%q) = false, want true", v)
		}
	}
	misses := []string{
		"", "hello world", "search term", "en", "json", "true",
		"this-is-a-very-long-free-text-value-that-should-not-be-treated-as-a-key",
	}
	for _, v := range misses {
		if looksLikeDBLookup(v) {
			t.Errorf("looksLikeDBLookup(%q) = true, want false", v)
		}
	}
}

// TestNoSQLBooleanVectors verifies both NoSQL boolean operator vectors — the
// classic $ne/$eq and the newly-added $regex (Rocket.Chat CVE-2021-22911 class) —
// against a fake Mongo-style endpoint that returns a populated list for match-all
// operators and an empty response for match-none, and that a non-injectable
// endpoint (one that ignores the operators) is NOT flagged.
func TestNoSQLBooleanVectors(t *testing.T) {
	vulnSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		dec, _ := url.QueryUnescape(r.URL.RawQuery)
		matchAll := strings.Contains(dec, "[$ne]") || strings.Contains(dec, "[$regex]=.*")
		matchNone := strings.Contains(dec, "[$eq]") || strings.Contains(dec, "[$regex]=^")
		switch {
		case matchAll:
			fmt.Fprint(w, strings.Repeat("<li>row</li>", 400)) // populated
		case matchNone:
			fmt.Fprint(w, "no results") // empty
		default:
			fmt.Fprint(w, strings.Repeat("<li>row</li>", 200)) // baseline
		}
	}))
	defer vulnSrv.Close()

	s := &NoSQLiScanner{}
	ip := insertionPoint{URL: vulnSrv.URL + "/?param=1", Param: "param", Method: "GET"}
	vol := measureVolatility(context.Background(), nosqliClient, ip, nil, valuePlain)

	for _, v := range []struct {
		name                 string
		tVal, tOp, fVal, fOp string
	}{
		{"$ne vs $eq", "rcnnope", "$ne", "rcnnope", "$eq"},
		{"$regex all vs none", ".*", "$regex", "^rcnZZnomatch$", "$regex"},
	} {
		t.Run(v.name, func(t *testing.T) {
			_, _, ok := s.booleanOpDiff(context.Background(), ip, nil, false, vol, v.tVal, v.tOp, v.fVal, v.fOp)
			if !ok {
				t.Fatalf("expected NoSQL boolean vector %s to be detected on the vulnerable endpoint", v.name)
			}
		})
	}

	// Non-injectable endpoint: same response regardless of operator → no finding.
	staticSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, strings.Repeat("<li>row</li>", 200))
	}))
	defer staticSrv.Close()
	ip2 := insertionPoint{URL: staticSrv.URL + "/?param=1", Param: "param", Method: "GET"}
	vol2 := measureVolatility(context.Background(), nosqliClient, ip2, nil, valuePlain)
	if _, _, ok := s.booleanOpDiff(context.Background(), ip2, nil, false, vol2, ".*", "$regex", "^rcnZZnomatch$", "$regex"); ok {
		t.Fatal("static endpoint must NOT be flagged as NoSQL-injectable")
	}
}

// TestBodyLeaksSecret verifies the direct .env/config exposure gate: a body with a
// real credential is flagged, while an HTML page or a framework-default env that
// carries no secret is NOT — the property that keeps this check near-zero-FP.
func TestBodyLeaksSecret(t *testing.T) {
	leaks := map[string]string{
		"dotenv db password": "APP_ENV=production\nDB_PASSWORD=Sup3rS3cretP@ss\n",
		"aws access key":     "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n",
		"stripe live key":    "STRIPE_KEY=EXAMPLE_stripe_key_placeholder\n",
		"properties api_key": "server.port=8080\napi_key=9f8c7b6a5d4e3f2a1b0c9d8e7f6a5b4c\n",
		"private key pem":    "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n",
		"env auth token":     "REDIS_HOST=localhost\nAUTH_TOKEN=abcdef0123456789abcdef\n",
	}
	for name, body := range leaks {
		if bodyLeaksSecret(body) == "" {
			t.Errorf("bodyLeaksSecret should flag %q (%q)", name, body)
		}
	}
	clean := map[string]string{
		"html page":         "<!doctype html><html><body>Not Found</body></html>",
		"framework default": "APP_ENV=production\nAPP_DEBUG=false\nLOG_LEVEL=info\n",
		"empty":             "",
		"non-secret json":   `{"name":"app","version":"1.2.3","port":8080}`,
	}
	for name, body := range clean {
		if k := bodyLeaksSecret(body); k != "" {
			t.Errorf("bodyLeaksSecret must NOT flag %q, got %q", name, k)
		}
	}
}

// TestDemoJWTSkipped verifies the jwt.io default token (and variants) are treated
// as demo tokens and skipped, while a real-looking token is analyzed. This is the
// guard against the "weak secret your-256-bit-secret" critical FP that a bundled
// jwt.io sample would otherwise produce.
func TestDemoJWTSkipped(t *testing.T) {
	// jwt.io default token: {"sub":"1234567890","name":"John Doe","iat":1516239022}
	demo := strings.Split("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c", ".")
	if !isDemoJWT(demo) {
		t.Error("jwt.io default token must be recognized as a demo JWT and skipped")
	}
	// A real token: {"sub":"u-99f2","role":"user","iat":1735689600} — no demo markers.
	real := strings.Split("eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1LTk5ZjIiLCJyb2xlIjoidXNlciIsImlhdCI6MTczNTY4OTYwMH0.x", ".")
	if isDemoJWT(real) {
		t.Error("a real token without demo markers must NOT be skipped")
	}
}

// TestConcatenatorCatchAll200 reproduces the exact false positive reported on
// WordPress load-scripts.php: a "JWT Algorithm Confusion Attack Detection" template
// matching a 200 that returned a ClipboardJS bundle. Both guards must fire.
func TestConcatenatorCatchAll200(t *testing.T) {
	// URL guard: the WP script concatenator (no static extension in the path).
	fpURL := "https://ks.example.com/wp-admin/load-scripts.php/api/profile?ver=6.9&c=0"
	if !isConcatenatorNoiseURL(fpURL) {
		t.Errorf("isConcatenatorNoiseURL should flag the load-scripts.php concatenator URL")
	}
	if isConcatenatorNoiseURL("https://ks.example.com/api/profile") {
		t.Errorf("a real API path must NOT be treated as concatenator noise")
	}

	// Response-type guard: the JS response + the JWT/auth template class.
	jsResp := "HTTP/1.1 200 OK\r\nContent-Type: application/javascript; charset=UTF-8\r\n" +
		"Cache-Control: public\r\n\r\n/*! auto-generated */!function(t,e){}();"
	if !responseIsStaticAsset(jsResp) {
		t.Errorf("responseIsStaticAsset should detect a application/javascript response")
	}
	if !nucleiAssertsAppBehavior("jwt-algorithm-confusion", "JWT Algorithm Confusion Attack Detection", []string{"jwt", "auth"}) {
		t.Errorf("a JWT confusion template must be classed as app-behaviour asserting")
	}

	// Negative: an exposure template on the same JS response must NOT be dropped by
	// the app-behaviour gate (it doesn't assert the server processed input).
	if nucleiAssertsAppBehavior("aws-cred-exposure", "AWS Credentials Exposure", []string{"exposure", "secret"}) {
		t.Errorf("an exposure/secret template must not be classed as app-behaviour asserting")
	}
	// Negative: an HTML app response must not be treated as a static asset.
	htmlResp := "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=UTF-8\r\n\r\n<html>...</html>"
	if responseIsStaticAsset(htmlResp) {
		t.Errorf("an HTML response must NOT be treated as a static asset")
	}
	// Guard: a "content-type:" string inside the BODY must not be mistaken for the header.
	trick := "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\nconsole.log('content-type: application/javascript')"
	if responseIsStaticAsset(trick) {
		t.Errorf("a content-type token in the body must not be read as the response header")
	}
}

// TestRegroupIntoChunks covers the nuclei parallel-process splitting logic:
// small surfaces stay a single process, large ones split without dropping or
// duplicating any item, and never exceed maxChunks.
func TestRegroupIntoChunks(t *testing.T) {
	mk := func(n int) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = fmt.Sprintf("t%d", i)
		}
		return out
	}
	assertNoLossNoDup := func(t *testing.T, original []string, chunks [][]string) {
		t.Helper()
		seen := map[string]bool{}
		total := 0
		for _, c := range chunks {
			for _, item := range c {
				if seen[item] {
					t.Fatalf("duplicate item across chunks: %s", item)
				}
				seen[item] = true
				total++
			}
		}
		if total != len(original) {
			t.Fatalf("chunk item count = %d, want %d", total, len(original))
		}
	}

	t.Run("small surface stays single chunk", func(t *testing.T) {
		items := mk(10)
		chunks := regroupIntoChunks(items, 500, 4)
		if len(chunks) != 1 {
			t.Fatalf("len(chunks) = %d, want 1", len(chunks))
		}
		assertNoLossNoDup(t, items, chunks)
	})

	t.Run("large surface splits up to maxChunks", func(t *testing.T) {
		items := mk(2200) // 2200/500 = 5 chunks needed, capped at maxChunks=4
		chunks := regroupIntoChunks(items, 500, 4)
		if len(chunks) != 4 {
			t.Fatalf("len(chunks) = %d, want 4", len(chunks))
		}
		assertNoLossNoDup(t, items, chunks)
	})

	t.Run("empty input", func(t *testing.T) {
		if chunks := regroupIntoChunks(nil, 500, 4); chunks != nil {
			t.Fatalf("expected nil chunks for empty input, got %v", chunks)
		}
	})

	t.Run("exact boundary", func(t *testing.T) {
		items := mk(1000) // exactly 2 chunks at chunkSize=500
		chunks := regroupIntoChunks(items, 500, 4)
		if len(chunks) != 2 {
			t.Fatalf("len(chunks) = %d, want 2", len(chunks))
		}
		assertNoLossNoDup(t, items, chunks)
	})
}
