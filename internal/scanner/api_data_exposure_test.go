package scanner

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

func newAPIDataExposureTestDB(t *testing.T, targetID, domain string) *database.DB {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "api-data.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets(id,domain,priority,scan_headers) VALUES(?,?,'medium',?)`,
		targetID, domain, `{"Authorization":"Bearer target-secret","Cookie":"session=target-secret","X-Program":"authorized"}`); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func TestAPIDataExposureNegotiates405POSTAndRedactsPII(t *testing.T) {
	withLoopbackAllowed(t)
	var postCount atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
			t.Errorf("unauthenticated proof leaked configured credentials: auth=%q cookie=%q", r.Header.Get("Authorization"), r.Header.Get("Cookie"))
		}
		if r.Header.Get("X-Program") != "authorized" {
			t.Errorf("non-secret program attribution was not retained: %q", r.Header.Get("X-Program"))
		}
		if r.Method == http.MethodGet {
			w.Header().Set("Allow", "POST, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		postCount.Add(1)
		var payload map[string]string
		_ = json.NewDecoder(r.Body).Decode(&payload)
		w.Header().Set("Content-Type", "application/json")
		if payload["customer_id"] == "" {
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[` +
			`{"email":"alice@acme.dev","phone":"+1 202 555 0101","national_id":"A123456789"},` +
			`{"email":"bob@acme.dev","phone":"+1 202 555 0102","national_id":"B987654321"}` +
			`]}`))
	}))
	defer server.Close()

	targetID := uuid.New().String()
	db := newAPIDataExposureTestDB(t, targetID, "127.0.0.1")
	endpoint := server.URL + "/api/customer/export"
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type,source) VALUES(?,?,?,?,?,?)`,
		uuid.New().String(), targetID, endpoint, 405, "application/json", "js")
	_, _ = db.Exec(`INSERT INTO parameters(id,target_id,url,parameter,source,method,content_type,location) VALUES(?,?,?,?,?,?,?,?)`,
		uuid.New().String(), targetID, endpoint, "customer_id", "js-request-body", "POST", "application/json", "json")

	scanner := NewAPIDataExposureScanner(db, &config.Config{ScanHeaders: map[string]string{"Authorization": "Bearer global-secret"}}, nil, nil)
	if err := scanner.Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	if postCount.Load() < 3 {
		t.Fatalf("POST count=%d, want empty control + probe + stable replay", postCount.Load())
	}
	var severity, method, parameter, evidence, payload string
	if err := db.QueryRow(`SELECT f.severity,c.method,f.parameter,f.evidence,f.payload
		FROM vuln_findings f JOIN candidates c ON c.id=f.candidate_id
		WHERE f.target_id=? AND f.type='api_data_exposure'`, targetID).
		Scan(&severity, &method, &parameter, &evidence, &payload); err != nil {
		t.Fatal(err)
	}
	if severity != "critical" || method != "POST" || parameter != "customer_id" {
		t.Fatalf("finding=(%s,%s,%s), want critical POST customer_id", severity, method, parameter)
	}
	for _, secret := range []string{"alice@acme.dev", "A123456789", "+1 202 555 0101"} {
		if strings.Contains(evidence, secret) || strings.Contains(payload, secret) {
			t.Fatalf("raw PII leaked into persisted finding: %q", secret)
		}
	}
	for _, want := range []string{"government_id", "$.results[].national_id", "Raw response values were intentionally not persisted"} {
		if !strings.Contains(evidence, want) {
			t.Fatalf("evidence missing %q: %s", want, evidence)
		}
	}
}

func TestAPIDataExposureNeverPOSTsToStateChangingRoute(t *testing.T) {
	withLoopbackAllowed(t)
	var posts atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			posts.Add(1)
		}
		w.Header().Set("Allow", "POST")
		w.WriteHeader(http.StatusMethodNotAllowed)
	}))
	defer server.Close()

	targetID := uuid.New().String()
	db := newAPIDataExposureTestDB(t, targetID, "127.0.0.1")
	endpoint := server.URL + "/api/users/create"
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type,source) VALUES(?,?,?,?,?,?)`,
		uuid.New().String(), targetID, endpoint, 405, "application/json", "js")
	_, _ = db.Exec(`INSERT INTO parameters(id,target_id,url,parameter,source,method,content_type,location) VALUES(?,?,?,?,?,?,?,?)`,
		uuid.New().String(), targetID, endpoint, "customer_id", "js", "POST", "application/json", "json")

	scanner := NewAPIDataExposureScanner(db, &config.Config{}, nil, nil)
	if err := scanner.Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	if posts.Load() != 0 {
		t.Fatalf("state-changing route received %d POST requests; want zero", posts.Load())
	}
}

func TestAPIDataExposureNegotiatesAdvertisedPostContentType(t *testing.T) {
	withLoopbackAllowed(t)
	var formCalls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet || r.Method == http.MethodOptions {
			w.Header().Set("Allow", "POST, OPTIONS")
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
			w.Header().Set("Accept-Post", "application/x-www-form-urlencoded, application/json;q=0.5")
			w.WriteHeader(http.StatusUnsupportedMediaType)
			return
		}
		formCalls.Add(1)
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		if r.Form.Get("account_id") == "" {
			_, _ = w.Write([]byte(`{"results":[]}`))
			return
		}
		_, _ = w.Write([]byte(`[{"bank_account":"123456789","date_of_birth":"1988-04-03"},{"bank_account":"987654321","date_of_birth":"1991-09-12"}]`))
	}))
	defer server.Close()

	targetID := uuid.New().String()
	db := newAPIDataExposureTestDB(t, targetID, "127.0.0.1")
	endpoint := server.URL + "/api/account/report"
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type,source) VALUES(?,?,?,?,?,?)`,
		uuid.New().String(), targetID, endpoint, 405, "", "js")
	_, _ = db.Exec(`INSERT INTO parameters(id,target_id,url,parameter,source,method,content_type,location) VALUES(?,?,?,?,?,?,?,?)`,
		uuid.New().String(), targetID, endpoint, "account_id", "js", "POST", "", "body")

	scanner := NewAPIDataExposureScanner(db, &config.Config{}, nil, nil)
	if err := scanner.Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	if formCalls.Load() < 3 {
		t.Fatalf("form calls=%d, want control + probe + replay after Accept-Post negotiation", formCalls.Load())
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='api_data_exposure' AND severity='critical'`, targetID).Scan(&count)
	if count != 1 {
		t.Fatalf("content-type negotiation produced %d critical findings, want 1", count)
	}
}

func TestAPIDataExposureRequiresStableReplay(t *testing.T) {
	withLoopbackAllowed(t)
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if calls.Add(1) == 1 {
			_, _ = w.Write([]byte(`[{"email":"first@acme.dev","phone":"+12025550101"},{"email":"second@acme.dev","phone":"+12025550102"}]`))
			return
		}
		_, _ = w.Write([]byte(`{"results":[]}`))
	}))
	defer server.Close()

	targetID := uuid.New().String()
	db := newAPIDataExposureTestDB(t, targetID, "127.0.0.1")
	endpoint := server.URL + "/api/customer/report"
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,content_type,source) VALUES(?,?,?,?,?,?)`,
		uuid.New().String(), targetID, endpoint, 200, "application/json", "probe")

	scanner := NewAPIDataExposureScanner(db, &config.Config{}, nil, nil)
	if err := scanner.Run(context.Background(), targetID, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}
	var count int
	_ = db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='api_data_exposure'`, targetID).Scan(&count)
	if count != 0 {
		t.Fatalf("unstable one-shot response produced %d findings", count)
	}
}

func TestInspectSensitiveJSONRejectsExamplesAndWeakContactNoise(t *testing.T) {
	if _, ok := inspectSensitiveJSON([]byte(`[{"email":"dev@example.com"},{"email":"user@example.org"}]`), "application/json", "https://app.test/api/users"); ok {
		t.Fatal("placeholder emails must not qualify")
	}
	if _, ok := inspectSensitiveJSON([]byte(`{"email":"person@acme.dev"}`), "application/json", "https://app.test/api/profile"); ok {
		t.Fatal("one ordinary contact field is insufficient evidence")
	}
}

func TestInspectSensitiveJSONClassifiesUnauthenticatedSecretsWithoutPersistingValues(t *testing.T) {
	summary, ok := inspectSensitiveJSON([]byte(`{"access_token":"tok_live_1234567890abcdef","refresh_token":"ref_live_abcdef1234567890"}`),
		"application/json", "https://app.test/api/account/session")
	if !ok || summary.Severity != "critical" || summary.Classes["authentication_secret"] != 2 {
		t.Fatalf("secret response was not classified as critical: %+v ok=%v", summary, ok)
	}
	if strings.Contains(summary.Fingerprint, "tok_live") {
		t.Fatal("schema fingerprint contains a raw secret")
	}
}

func TestExtractAPIParamHintsStaysBoundToRequestPrimitives(t *testing.T) {
	content := `
		const config = { theme: "dark", locale: "en" };
		const form = new FormData(); form.append("account_id", id);
		fetch("/api/customer/export", {method:"POST", body:JSON.stringify({customer_id:id, filter:{region:"eu"}, fields:["email"]})});
		axios.get("/api/search", {params:{query:term, limit:10}});
		axios.post("/api/report", {report_id:id});
	`
	hints := extractAPIParamHints(content)
	got := map[string]bool{}
	for _, hint := range hints {
		got[hint.name] = true
	}
	for _, want := range []string{"account_id", "customer_id", "filter", "region", "fields", "query", "limit", "report_id"} {
		if !got[want] {
			t.Fatalf("missing request-bound parameter %q in %#v", want, hints)
		}
	}
	for _, noise := range []string{"theme", "locale", "method", "body"} {
		if got[noise] {
			t.Fatalf("unrelated/config key %q was extracted", noise)
		}
	}
}
