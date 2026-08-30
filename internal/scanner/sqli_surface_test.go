package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
)

func newSQLiSurfaceDB(t *testing.T) (*database.DB, string) {
	t.Helper()
	db, err := database.New(filepath.Join(t.TempDir(), "sqli-surface.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RunMigrations(db); err != nil {
		db.Close()
		t.Fatal(err)
	}
	tid := uuid.New().String()
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES (?,?)`, tid, "127.0.0.1"); err != nil {
		db.Close()
		t.Fatal(err)
	}
	return db, tid
}

func TestSQLiSurfaceIncludesUnknownStringJSONAndPath(t *testing.T) {
	withLoopbackAllowed(t)
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer srv.Close()
	db, tid := newSQLiSurfaceDB(t)
	defer db.Close()

	rows := []struct{ url, param, value, method, ct, loc string }{
		{srv.URL + "/search?opaque_name=blue", "opaque_name", "blue", "GET", "", "query"},
		{srv.URL + "/api", "opaque_name", "uuid-value", "POST", "application/json", "query"},
		{srv.URL + "/api", "tenant", "acme", "POST", "application/json", "query"},
		{srv.URL + "/orders/847/items", "path1", "847", "GET", "", "path:1"},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,value,method,content_type,location,source) VALUES (?,?,?,?,?,?,?,?, 'test')`,
			uuid.New().String(), tid, r.url, r.param, r.value, r.method, r.ct, r.loc); err != nil {
			t.Fatal(err)
		}
	}

	s := &SQLiScanner{db: db, cfg: &config.Config{}}
	got := s.selectCandidates(context.Background(), tid)
	if len(got) != 4 {
		t.Fatalf("all distinct SQLi surfaces must survive selection; got %d: %+v", len(got), got)
	}
	seen := map[string]insertionPoint{}
	for _, ip := range got {
		seen[insertionLocation(ip)] = ip
	}
	if seen["query"].Value != "blue" {
		t.Errorf("unknown string GET parameter or its baseline value was lost: %+v", seen["query"])
	}
	jsonFound := false
	for _, ip := range got {
		if ip.Param == "opaque_name" && ip.Value == "uuid-value" && ip.Method == "POST" && ip.Siblings["tenant"] == "acme" {
			jsonFound = true
		}
	}
	if !jsonFound {
		t.Errorf("JSON placement/value/siblings were not preserved: %+v", got)
	}
	if seen["path:1"].Value != "847" {
		t.Errorf("path placement/value was not preserved: %+v", seen["path:1"])
	}
}

func TestSQLiStorePreservesJSONCandidateContract(t *testing.T) {
	db, tid := newSQLiSurfaceDB(t)
	defer db.Close()
	s := &SQLiScanner{db: db}
	ip := insertionPoint{URL: "https://api.example.test/search", Param: "filter", Value: "blue", Method: "POST", ContentType: "application/json", Location: "query"}
	s.store(tid, "sqli", "high", ip, "error_based", "reproduced database error")

	var method, location, parameter, payload string
	if err := db.QueryRow(`SELECT method,location,parameter,payload FROM candidates WHERE target_id=? AND type='sqli'`, tid).
		Scan(&method, &location, &parameter, &payload); err != nil {
		t.Fatal(err)
	}
	if method != "POST" || location != "json" || parameter != "filter" {
		t.Fatalf("candidate request contract was corrupted: method=%q location=%q parameter=%q", method, location, parameter)
	}
	if payload == "error_based" {
		t.Fatal("detector subtype must not be stored as if it were a replayable request body")
	}
}
