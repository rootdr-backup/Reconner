package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"testing"
)

func epByPath(eps []apiEndpoint, substr string) *apiEndpoint {
	for i := range eps {
		if strings.Contains(eps[i].URL, substr) {
			return &eps[i]
		}
	}
	return nil
}

func TestParseAPISpecSwagger2(t *testing.T) {
	spec := []byte(`{
	  "swagger":"2.0",
	  "host":"api.example.com",
	  "basePath":"/v1",
	  "schemes":["https"],
	  "paths":{
	    "/users":{
	      "get":{"parameters":[{"name":"status","in":"query"},{"name":"page","in":"query"}]},
	      "post":{"parameters":[{"name":"body","in":"body","schema":{"properties":{"email":{"type":"string"},"role":{"type":"string"}}}}]}
	    },
	    "/users/{id}":{"get":{"parameters":[{"name":"id","in":"path"}]}}
	  }
	}`)
	eps := parseAPISpec(spec, "https://api.example.com")
	if len(eps) != 3 {
		t.Fatalf("expected 3 operations, got %d", len(eps))
	}
	get := epByPath(eps, "/v1/users")
	if get == nil {
		t.Fatal("GET /v1/users not found — basePath not applied?")
	}
	// path param substituted → concrete URL
	if p := epByPath(eps, "/v1/users/1"); p == nil {
		t.Fatalf("path param not substituted to a concrete URL: %v", eps)
	} else if len(p.Path) != 1 || p.Path[0].Name != "id" || p.Path[0].Index != 2 {
		t.Fatalf("path parameter insertion contract missing/wrong: %+v", p.Path)
	}
	// find the POST body op
	var bodyFields []string
	for _, e := range eps {
		if e.Method == "POST" {
			bodyFields = e.Body
		}
	}
	sort.Strings(bodyFields)
	if strings.Join(bodyFields, ",") != "email,role" || !hasJSONBody(eps) {
		t.Fatalf("swagger 2.0 body schema properties not extracted: %v", bodyFields)
	}
}

func hasJSONBody(eps []apiEndpoint) bool {
	for _, e := range eps {
		if e.JSON {
			return true
		}
	}
	return false
}

func TestParseAPISpecOpenAPI3(t *testing.T) {
	spec := []byte(`{
	  "openapi":"3.0.1",
	  "servers":[{"url":"https://svc.example.com/api"}],
	  "components":{"schemas":{"RefBody":{"type":"object","properties":{"account":{"type":"object","properties":{"id":{"type":"integer"}}}}}}},
	  "paths":{
	    "/search":{"get":{"parameters":[{"name":"q","in":"query"},{"name":"limit","in":"query"}]}},
	    "/orders":{"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{"item":{"type":"string"},"qty":{"type":"integer"},"customer":{"type":"object","properties":{"email":{"type":"string"}}}}}}}}}},
	    "/upload":{"post":{"requestBody":{"content":{"multipart/form-data":{"schema":{"properties":{"title":{"type":"string"}}}}}}}},
	    "/legacy":{"post":{"requestBody":{"content":{"application/xml":{"schema":{"properties":{"lookup":{"type":"string"}}}}}}}},
	    "/ref":{"patch":{"requestBody":{"content":{"application/json":{"schema":{"$ref":"#/components/schemas/RefBody"}}}}}}
	  }
	}`)
	eps := parseAPISpec(spec, "https://svc.example.com")
	search := epByPath(eps, "/api/search")
	if search == nil {
		t.Fatalf("server url base not applied: %v", eps)
	}
	sort.Strings(search.Query)
	if strings.Join(search.Query, ",") != "limit,q" {
		t.Fatalf("query params not extracted: %v", search.Query)
	}
	orders := epByPath(eps, "/api/orders")
	if orders == nil || !orders.JSON {
		t.Fatalf("openapi 3 requestBody json not detected: %+v", orders)
	}
	sort.Strings(orders.Body)
	if strings.Join(orders.Body, ",") != "customer.email,item,qty" {
		t.Fatalf("requestBody properties not extracted: %v", orders.Body)
	}
	if orders.BodyTypes["qty"] != "integer" || orders.BodyTypes["customer.email"] != "string" {
		t.Fatalf("JSON schema field types not preserved: %#v", orders.BodyTypes)
	}
	upload := epByPath(eps, "/api/upload")
	if upload == nil || upload.ContentType != "multipart/form-data" || strings.Join(upload.Body, ",") != "title" {
		t.Fatalf("multipart request body contract not extracted: %+v", upload)
	}
	legacy := epByPath(eps, "/api/legacy")
	if legacy == nil || legacy.ContentType != "application/xml" || strings.Join(legacy.Body, ",") != "lookup" {
		t.Fatalf("XML request body contract not extracted: %+v", legacy)
	}
	ref := epByPath(eps, "/api/ref")
	if ref == nil || strings.Join(ref.Body, ",") != "account.id" || ref.BodyTypes["account.id"] != "integer" {
		t.Fatalf("local OpenAPI $ref body schema not resolved: %+v", ref)
	}
}

// TestParseAPISpecExtractsHeaderAndCookieParameters proves the fix for a real
// gap: "in":"header" and "in":"cookie" are legal in both Swagger 2.0 and
// OpenAPI 3.x, but the ingestion switch used to match no case for them at
// all — a documented, operator-known insertion point (e.g. a per-tenant
// X-Tenant-Id header consumed straight into a SQL WHERE clause) was silently
// dropped and never became a `parameters` row for any downstream detector.
func TestParseAPISpecExtractsHeaderAndCookieParameters(t *testing.T) {
	spec := []byte(`{
	  "openapi":"3.0.1",
	  "servers":[{"url":"https://api.example.com"}],
	  "paths":{
	    "/widgets":{"get":{"parameters":[
	      {"name":"X-Tenant-Id","in":"header"},
	      {"name":"session","in":"cookie"},
	      {"name":"q","in":"query"}
	    ]}}
	  }
	}`)
	eps := parseAPISpec(spec, "https://api.example.com")
	ep := epByPath(eps, "/widgets")
	if ep == nil {
		t.Fatalf("endpoint not found: %v", eps)
	}
	if strings.Join(ep.Header, ",") != "X-Tenant-Id" {
		t.Fatalf("header parameter not extracted: %+v", ep.Header)
	}
	if strings.Join(ep.Cookie, ",") != "session" {
		t.Fatalf("cookie parameter not extracted: %+v", ep.Cookie)
	}
	if strings.Join(ep.Query, ",") != "q" {
		t.Fatalf("query parameter extraction regressed: %+v", ep.Query)
	}
}

// TestHarvestAPISpecsStoresHeaderAndCookieLocations proves the documented
// header/cookie parameters reach the `parameters` table with the correct
// Location — which insertion.go already treats as first-class — so they feed
// the SAME generic SQLi/XSS/etc ladder as query/body params instead of being
// invisible to every detector.
func TestHarvestAPISpecsStoresHeaderAndCookieLocations(t *testing.T) {
	withLoopbackAllowed(t)
	db, tid := testDB(t)
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"openapi":"3.0.0","paths":{"/widgets":{"get":{"parameters":[
			{"name":"X-Tenant-Id","in":"header"},
			{"name":"session","in":"cookie"}
		]}}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &ParamScanner{db: db}
	n := s.harvestAPISpecs(context.Background(), tid, []string{srv.URL}, func(_, _, _ string) {})
	if n != 1 {
		t.Fatalf("expected 1 endpoint ingested, got %d", n)
	}

	rows, _ := db.Query(`SELECT parameter, location FROM parameters WHERE target_id=? ORDER BY parameter`, tid)
	defer rows.Close()
	locByParam := map[string]string{}
	for rows.Next() {
		var p, loc string
		if rows.Scan(&p, &loc) == nil {
			locByParam[p] = loc
		}
	}
	if locByParam["X-Tenant-Id"] != "header" {
		t.Fatalf("expected X-Tenant-Id stored with location=header, got %v", locByParam)
	}
	if locByParam["session"] != "cookie" {
		t.Fatalf("expected session stored with location=cookie, got %v", locByParam)
	}

	// And the generic SQLi candidate loader — which filters by NEITHER source
	// NOR location — must actually see them.
	sqli := &SQLiScanner{db: db}
	candidates := sqli.selectCandidates(context.Background(), tid)
	var sawHeader, sawCookie bool
	for _, c := range candidates {
		if c.Param == "X-Tenant-Id" && c.Location == "header" {
			sawHeader = true
		}
		if c.Param == "session" && c.Location == "cookie" {
			sawCookie = true
		}
	}
	if !sawHeader {
		t.Error("expected the documented header parameter to reach SQLi's own insertion-point loader")
	}
	if !sawCookie {
		t.Error("expected the documented cookie parameter to reach SQLi's own insertion-point loader")
	}
}

func TestFetchSpecRejectsNonSpec(t *testing.T) {
	// An HTML catch-all must not be mistaken for a spec.
	if got := parseAPISpec([]byte(`<html><body>not a spec</body></html>`), "https://x.com"); got != nil {
		t.Fatal("HTML must not parse as an API spec")
	}
	// JSON without a spec marker / paths must yield nothing.
	if got := parseAPISpec([]byte(`{"hello":"world"}`), "https://x.com"); got != nil {
		t.Fatal("arbitrary JSON must not parse as an API spec")
	}
}

func TestHarvestAPISpecsEndToEnd(t *testing.T) {
	withLoopbackAllowed(t)
	db, tid := testDB(t)
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/openapi.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"openapi":"3.0.0","paths":{"/pay":{"post":{"parameters":[{"name":"token","in":"query"}],"requestBody":{"content":{"application/json":{"schema":{"properties":{"amount":{"type":"number"}}}}}}}}}}`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &ParamScanner{db: db}
	n := s.harvestAPISpecs(context.Background(), tid, []string{srv.URL}, func(_, _, _ string) {})
	if n != 1 {
		t.Fatalf("expected 1 endpoint ingested, got %d", n)
	}
	var params []string
	rows, _ := db.Query(`SELECT parameter FROM parameters WHERE target_id=? ORDER BY parameter`, tid)
	defer rows.Close()
	for rows.Next() {
		var p string
		rows.Scan(&p)
		params = append(params, p)
	}
	joined := strings.Join(params, ",")
	if !strings.Contains(joined, "token") || !strings.Contains(joined, "amount") {
		t.Fatalf("expected query param 'token' and body param 'amount' stored, got %v", params)
	}
}
