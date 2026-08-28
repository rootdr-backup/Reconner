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
	  "paths":{
	    "/search":{"get":{"parameters":[{"name":"q","in":"query"},{"name":"limit","in":"query"}]}},
	    "/orders":{"post":{"requestBody":{"content":{"application/json":{"schema":{"properties":{"item":{"type":"string"},"qty":{"type":"integer"}}}}}}}}
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
	if strings.Join(orders.Body, ",") != "item,qty" {
		t.Fatalf("requestBody properties not extracted: %v", orders.Body)
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
