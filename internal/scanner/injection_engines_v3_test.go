package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func seedV3Parameter(t *testing.T, db *database.DB, targetID, rawURL, param, value, method, contentType, location string) {
	t.Helper()
	_, err := db.Exec(`INSERT INTO parameters
		(id,target_id,url,parameter,value,source,method,content_type,location)
		VALUES (?,?,?,?,?,'v3-lab',?,?,?)`, uuid.New().String(), targetID, rawURL, param, value, method, contentType, location)
	if err != nil {
		t.Fatal(err)
	}
}

func newV3ScannerDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.New(t.TempDir() + "/v3.db")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets (id,domain,priority,auth_headers) VALUES (?,?,'medium',?)`,
		targetID, "lab.local", `{"Authorization":"Bearer v3-test"}`); err != nil {
		t.Fatal(err)
	}
	return db, targetID
}

func v3FindingCount(t *testing.T, db *database.DB, targetID, typ, path string) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_findings
		WHERE target_id=? AND type=? AND url LIKE ? AND COALESCE(status,'finding')='finding'`,
		targetID, typ, "%"+path+"%").Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestLFICoversAuthenticatedFormAndJSONWithSiblingReplay(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer v3-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_ = r.ParseForm()
		if r.PostFormValue("csrf") != "tok-v3" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if strings.Contains(r.PostFormValue("file"), "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}
		fmt.Fprint(w, "document not found")
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer v3-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["tenant"] != "acme" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if strings.Contains(fmt.Sprint(body["file"]), "etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}
		fmt.Fprint(w, "document not found")
	})
	// Static documentation containing a passwd sample is a deliberate FP trap.
	mux.HandleFunc("/docs", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "Example only: root:x:0:0:root:/root:/bin/bash\n")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "file", "readme", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "csrf", "tok-v3", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "file", "readme", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "tenant", "acme", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/docs?file=readme", "file", "readme", "GET", "", "query")

	cfg := &config.Config{}
	if err := NewLFIScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if got := v3FindingCount(t, db, targetID, "lfi", "/form"); got != 1 {
		t.Fatalf("authenticated form LFI findings=%d, want 1", got)
	}
	if got := v3FindingCount(t, db, targetID, "lfi", "/json"); got != 1 {
		t.Fatalf("authenticated JSON LFI findings=%d, want 1", got)
	}
	if got := v3FindingCount(t, db, targetID, "lfi", "/docs"); got != 0 {
		t.Fatalf("static passwd documentation must not be LFI, findings=%d", got)
	}
}

var v3TemplateExpr = regexp.MustCompile(`\{\{(\d+)\*(\d+)\}\}`)

func evalV3Template(input string) string {
	return v3TemplateExpr.ReplaceAllStringFunc(input, func(expr string) string {
		m := v3TemplateExpr.FindStringSubmatch(expr)
		a, _ := strconv.Atoi(m[1])
		b, _ := strconv.Atoi(m[2])
		return strconv.Itoa(a * b)
	})
}

func TestSSTIRequiresDualEvaluationAcrossFormAndJSON(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Header.Get("Authorization") != "Bearer v3-test" || r.PostFormValue("csrf") != "tok-v3" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		fmt.Fprint(w, evalV3Template(r.PostFormValue("template")))
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("Authorization") != "Bearer v3-test" || body["tenant"] != "acme" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		fmt.Fprint(w, evalV3Template(fmt.Sprint(body["message"])))
	})
	mux.HandleFunc("/literal", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "static score=49; value="+r.URL.Query().Get("template"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "template", "hello", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "csrf", "tok-v3", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "message", "hello", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "tenant", "acme", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/literal?template=hello", "template", "hello", "GET", "", "query")

	cfg := &config.Config{}
	if err := NewSSTIScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if got := v3FindingCount(t, db, targetID, "ssti", "/form"); got != 1 {
		t.Fatalf("form SSTI findings=%d, want 1", got)
	}
	if got := v3FindingCount(t, db, targetID, "ssti", "/json"); got != 1 {
		t.Fatalf("JSON SSTI findings=%d, want 1", got)
	}
	if got := v3FindingCount(t, db, targetID, "ssti", "/literal"); got != 0 {
		t.Fatalf("literal/static-49 endpoint must not be SSTI, findings=%d", got)
	}
}

func TestSSRFCoversAuthenticatedJSONAndRejectsReflection(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("Authorization") != "Bearer v3-test" || body["tenant"] != "acme" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if strings.Contains(fmt.Sprint(body["webhook"]), "169.254.169.254") {
			fmt.Fprint(w, `{"AccessKeyId":"ASIAEXAMPLE","SecretAccessKey":"example","Token":"`+strings.Repeat("A", 48)+`"}`)
			return
		}
		fmt.Fprint(w, `{"error":"fetch failed"}`)
	})
	mux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, `{"url":`+strconv.Quote(r.URL.Query().Get("url"))+`}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "webhook", "https://allowed.example/hook", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "tenant", "acme", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/reflect?url=https://example.test", "url", "https://example.test", "GET", "", "query")

	cfg := &config.Config{}
	if err := NewSSRFScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	if got := v3FindingCount(t, db, targetID, "ssrf", "/json"); got != 1 {
		t.Fatalf("authenticated JSON SSRF findings=%d, want 1", got)
	}
	if got := v3FindingCount(t, db, targetID, "ssrf", "/reflect"); got != 0 {
		t.Fatalf("reflected URL must not be SSRF, findings=%d", got)
	}
}

func TestOOBCapabilityPreservesHTTPSOriginAndStrongToken(t *testing.T) {
	cfg := &config.Config{BlindXSSCallbackURL: "https://oob.example.test/base/path"}
	o, ok := newOOBCapability(cfg)
	if !ok {
		t.Fatal("expected valid OOB capability")
	}
	if got := o.callbackURL("rcnoob0123456789abcdef0123"); got != "https://oob.example.test/oob/rcnoob0123456789abcdef0123" {
		t.Fatalf("callback URL=%q", got)
	}
	if tok := newXSSToken("rcnoob"); len(tok) != len("rcnoob")+20 {
		t.Fatalf("OOB token has %d chars, want %d", len(tok), len("rcnoob")+20)
	}
}

func TestOpenRedirectCoversAuthenticatedFormAndJSONWithSiblingReplay(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Header.Get("Authorization") != "Bearer v3-test" || r.PostFormValue("csrf") != "tok-v3" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		http.Redirect(w, r, r.PostFormValue("next"), http.StatusFound)
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("Authorization") != "Bearer v3-test" || body["tenant"] != "acme" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		w.Header().Set("Location", fmt.Sprint(body["return_to"]))
		w.WriteHeader(http.StatusFound)
	})
	// Fixed third-party SSO redirects are not controlled by the parameter and
	// must never become verified open-redirect findings.
	mux.HandleFunc("/fixed", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Location", "https://sso.example.test/login")
		w.WriteHeader(http.StatusFound)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "next", "/home", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "csrf", "tok-v3", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "return_to", "/home", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "tenant", "acme", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/fixed?next=/home", "next", "/home", "GET", "", "query")

	cfg := &config.Config{}
	if err := NewDirScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error")).
		RunOpenRedirectDiscovery(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{"/form", "/json"} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM open_redirect_findings
			WHERE target_id=? AND url LIKE ? AND verified=1`, targetID, "%"+path+"%").Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("authenticated %s open redirect findings=%d, want 1", path, n)
		}
	}
	var fixed int
	if err := db.QueryRow(`SELECT COUNT(*) FROM open_redirect_findings
		WHERE target_id=? AND url LIKE '%/fixed%' AND verified=1`, targetID).Scan(&fixed); err != nil {
		t.Fatal(err)
	}
	if fixed != 0 {
		t.Fatalf("fixed SSO redirect must not be verified, findings=%d", fixed)
	}
}

func TestNoSQLiPreservesAuthenticatedFormAndJSONSiblings(t *testing.T) {
	withLoopbackAllowed(t)
	matchAll := strings.Repeat(`{"user":"visible"}`, 40)
	mux := http.NewServeMux()
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Header.Get("Authorization") != "Bearer v3-test" || r.PostFormValue("csrf") != "tok-v3" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if r.PostFormValue("user[$ne]") != "" || r.PostFormValue("user[$regex]") == ".*" {
			fmt.Fprint(w, matchAll)
			return
		}
		fmt.Fprint(w, `{"error":"no match"}`)
	})
	mux.HandleFunc("/json", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if r.Header.Get("Authorization") != "Bearer v3-test" || body["tenant"] != "acme" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		if op, ok := body["user"].(map[string]any); ok {
			if _, exists := op["$ne"]; exists || op["$regex"] == ".*" {
				fmt.Fprint(w, matchAll)
				return
			}
		}
		fmt.Fprint(w, `{"error":"no match"}`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "user", "alice", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/form", "csrf", "tok-v3", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "user", "alice", "POST", "application/json", "json:string")
	seedV3Parameter(t, db, targetID, srv.URL+"/json", "tenant", "acme", "POST", "application/json", "json:string")

	cfg := &config.Config{}
	if err := NewNoSQLiScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ path, method, location string }{
		{"/form", "POST", "body"}, {"/json", "POST", "json"},
	} {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='nosql_injection'
			AND url LIKE ? AND method=? AND location=?`, targetID, "%"+tc.path+"%", tc.method, tc.location).Scan(&n); err != nil {
			t.Fatal(err)
		}
		if n != 1 {
			t.Fatalf("%s NoSQLi candidates=%d, want 1 with preserved request contract", tc.path, n)
		}
	}
}

func TestXXEPreservesMethodQueryAuthAndRequiresControls(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/xml", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPut || r.URL.Query().Get("tenant") != "acme" ||
			r.Header.Get("Authorization") != "Bearer v3-test" || !strings.Contains(r.Header.Get("Content-Type"), "xml") {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		body, _ := io.ReadAll(r.Body)
		if strings.Contains(string(body), "file:///etc/passwd") {
			fmt.Fprint(w, "root:x:0:0:root:/root:/bin/bash\n")
			return
		}
		fmt.Fprint(w, "xml accepted")
	})
	// Static documentation is an FP trap: every request contains a passwd sample.
	mux.HandleFunc("/xml-static", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "documentation example root:x:0:0:root:/root:/bin/bash")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/xml?tenant=acme", "document", "<root/>", "PUT", "application/xml", "xml")
	seedV3Parameter(t, db, targetID, srv.URL+"/xml-static", "document", "<root/>", "POST", "application/xml", "xml")

	cfg := &config.Config{}
	if err := NewXXEScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var real, static int
	if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='xxe'
		AND url LIKE '%/xml?tenant=acme%' AND method='PUT' AND location='xml' AND status='CONFIRMED'`, targetID).Scan(&real); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='xxe'
		AND url LIKE '%/xml-static%'`, targetID).Scan(&static); err != nil {
		t.Fatal(err)
	}
	if real != 1 {
		t.Fatalf("method/query/auth-aware XXE findings=%d, want 1", real)
	}
	if static != 0 {
		t.Fatalf("static passwd sample XXE findings=%d, want 0", static)
	}
}

func TestCRLFCoversAuthenticatedFormWithDualRandomHeaderProof(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.Header.Get("Authorization") != "Bearer v3-test" || r.PostFormValue("csrf") != "tok-v3" {
			w.WriteHeader(http.StatusUnprocessableEntity)
			return
		}
		value := strings.ReplaceAll(r.PostFormValue("next"), "\r\n", "\n")
		if i := strings.IndexByte(value, '\n'); i >= 0 {
			parts := strings.SplitN(strings.TrimSpace(value[i+1:]), ":", 2)
			if len(parts) == 2 && strings.HasPrefix(parts[0], "X-Recon-") {
				w.Header().Set(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1]))
			}
		}
		fmt.Fprint(w, "ok")
	}))
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	seedV3Parameter(t, db, targetID, srv.URL+"/download", "next", "/home", "POST", "application/x-www-form-urlencoded", "body")
	seedV3Parameter(t, db, targetID, srv.URL+"/download", "csrf", "tok-v3", "POST", "application/x-www-form-urlencoded", "body")
	cfg := &config.Config{}
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		RunCRLF(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='crlf'
		AND url LIKE '%/download%' AND method='POST' AND location='body' AND status='CONFIRMED'`, targetID).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("authenticated form CRLF confirmed candidates=%d, want 1", n)
	}
}

func TestCSRFCrawlsAuthenticatedFormsWithoutPromotingHeuristics(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/settings", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer v3-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><form method="post" action="/settings/email"><input name="email"></form></html>`)
	})
	mux.HandleFunc("/protected", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer v3-test" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprint(w, `<html><form method="post"><input type="hidden" name="csrf_token" value="v3"><input name="email"></form></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	for _, path := range []string{"/settings", "/protected"} {
		_, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source)
			VALUES (?,?,?,200,'crawl')`, uuid.NewString(), targetID, srv.URL+path)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	if err := NewCSRFScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var candidate, protected int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='csrf' AND url LIKE '%/settings' AND status='candidate'`, targetID).Scan(&candidate)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='csrf' AND url LIKE '%/protected%'`, targetID).Scan(&protected)
	if candidate != 1 || protected != 0 {
		t.Fatalf("CSRF authenticated candidate=%d protected-form reports=%d, want 1/0", candidate, protected)
	}
}

func Test403BypassRequiresStableReplayAndSeparatesPathCandidates(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/admin", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Forwarded-For") == "127.0.0.1" {
			fmt.Fprint(w, `{"admin":true,"feature":"audit_login_events","secret":"stable-private-object"}`)
			return
		}
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "forbidden access control wall for administrators only")
	})
	mux.HandleFunc("/pathadmin", func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "forbidden access control wall for path administrators")
	})
	mux.HandleFunc("/pathadmin/", func(w http.ResponseWriter, _ *http.Request) {
		fmt.Fprint(w, "a separate public route whose content is stable and deliberately longer than thirty two bytes")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	for _, path := range []string{"/admin", "/pathadmin"} {
		_, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source)
			VALUES (?,?,?,403,'probe')`, uuid.NewString(), targetID, srv.URL+path)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		Run403Bypass(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var headerConfirmed, pathFinding, pathCandidate int
	_ = db.QueryRow(`SELECT COUNT(*) FROM candidates WHERE target_id=? AND type='403_bypass'
		AND url LIKE '%/admin' AND location='header' AND status='CONFIRMED'`, targetID).Scan(&headerConfirmed)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='403_bypass'
		AND url LIKE '%/pathadmin' AND status='finding'`, targetID).Scan(&pathFinding)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='403_bypass'
		AND url LIKE '%/pathadmin' AND status='candidate'`, targetID).Scan(&pathCandidate)
	if headerConfirmed != 1 || pathFinding != 0 || pathCandidate != 1 {
		t.Fatalf("403 header confirmed=%d path finding=%d path candidate=%d, want 1/0/1", headerConfirmed, pathFinding, pathCandidate)
	}
}

func TestHostHeaderUsesDualRandomSinksAndKeepsBodyReflectionCandidate(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.Host, "rcnhh") && strings.HasSuffix(r.Host, ".example") {
			w.Header().Set("Location", "https://"+r.Host+"/reset")
			w.WriteHeader(http.StatusFound)
			return
		}
		fmt.Fprint(w, "normal")
	})
	mux.HandleFunc("/body", func(w http.ResponseWriter, r *http.Request) {
		host := r.Header.Get("X-Forwarded-Host")
		if strings.HasPrefix(host, "rcnhh") && strings.HasSuffix(host, ".example") {
			fmt.Fprintf(w, `<html><a href="https://%s/reset">reset</a></html>`, host)
			return
		}
		fmt.Fprint(w, "<html>normal</html>")
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, targetID := newV3ScannerDB(t)
	for _, path := range []string{"/redirect", "/body"} {
		_, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source)
			VALUES (?,?,?,200,'probe')`, uuid.NewString(), targetID, srv.URL+path)
		if err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		RunHostHeaderInjection(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var redirectFinding, bodyFinding, bodyCandidate int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='host_header_injection' AND url LIKE '%/redirect' AND status='finding'`, targetID).Scan(&redirectFinding)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='host_header_injection' AND url LIKE '%/body' AND status='finding'`, targetID).Scan(&bodyFinding)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='host_header_injection' AND url LIKE '%/body' AND status='candidate'`, targetID).Scan(&bodyCandidate)
	if redirectFinding != 1 || bodyFinding != 0 || bodyCandidate != 1 {
		t.Fatalf("host-header redirect finding=%d body finding=%d body candidate=%d, want 1/0/1", redirectFinding, bodyFinding, bodyCandidate)
	}
}

func TestPrototypePollutionReflectionStaysCandidate(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"echo":%q}`, r.URL.RawQuery)
	}))
	defer srv.Close()
	db, targetID := newV3ScannerDB(t)
	_, _ = db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source)
		VALUES (?,?,?,200,'probe')`, uuid.NewString(), targetID, srv.URL+"/merge")
	cfg := &config.Config{}
	if err := NewVulnScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil).
		RunPrototypePollution(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var findings, candidates int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='prototype_pollution' AND status='finding'`, targetID).Scan(&findings)
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='prototype_pollution' AND status='candidate'`, targetID).Scan(&candidates)
	if findings != 0 || candidates != 1 {
		t.Fatalf("prototype reflection findings=%d candidates=%d, want 0/1", findings, candidates)
	}
}
