package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/recon-platform/internal/config"
)

// TestCheckInsertionReflectionDetectsBodyFormReflection is the regression
// test for the location-awareness fix: a form-body parameter must actually
// be sent as a POST body field and detected there — checkParamReflection
// (the old, still-existing query-only prober) could never see this, since it
// always sends a bodyless GET with the canary added as an unrelated query key.
func TestCheckInsertionReflectionDetectsBodyFormReflection(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>echo: %s</body></html>", r.FormValue("name"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/submit", Param: "name", Method: "POST", ContentType: "application/x-www-form-urlencoded", Location: "body"}
	reflected, htmlSink := checkInsertionReflection(context.Background(), ip, nil)
	if !reflected || !htmlSink {
		t.Fatalf("reflected=%v htmlSink=%v, want both true for a body field echoed into HTML", reflected, htmlSink)
	}
}

// TestCheckInsertionReflectionDetectsJSONReflection covers the JSON-body
// shape specifically (a different encoding path through buildInjectedRequest
// than form-urlencoded).
func TestCheckInsertionReflectionDetectsJSONReflection(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/api", func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>echo: %v</body></html>", body["q"])
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ip := insertionPoint{URL: srv.URL + "/api", Param: "q", Method: "POST", ContentType: "application/json", Location: "json"}
	reflected, htmlSink := checkInsertionReflection(context.Background(), ip, nil)
	if !reflected || !htmlSink {
		t.Fatalf("reflected=%v htmlSink=%v, want both true for a JSON field echoed into HTML", reflected, htmlSink)
	}
}

// TestCheckInsertionReflectionPreservesSiblingFields proves the sibling-
// preservation half of the fix: a server that 400s unless BOTH required
// fields are present must still see both — dropping a sibling would corrupt
// the request shape and the probed field would never reach the echo.
func TestCheckInsertionReflectionPreservesSiblingFields(t *testing.T) {
	withLoopbackAllowed(t)
	mux := http.NewServeMux()
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		if r.FormValue("token") == "" {
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "missing required field: token")
			return
		}
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>echo: %s</body></html>", r.FormValue("name"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ip := insertionPoint{
		URL: srv.URL + "/submit", Param: "name", Method: "POST", ContentType: "application/x-www-form-urlencoded", Location: "body",
		Siblings: map[string]string{"token": "abc123"},
	}
	reflected, _ := checkInsertionReflection(context.Background(), ip, nil)
	if !reflected {
		t.Fatal("expected reflection to be detected with the required sibling field preserved")
	}

	// Without the sibling, the same probe must fail (proves the test fixture
	// itself actually enforces the required field, not a false pass).
	ipNoSibling := insertionPoint{URL: srv.URL + "/submit", Param: "name", Method: "POST", ContentType: "application/x-www-form-urlencoded", Location: "body"}
	if reflected, _ := checkInsertionReflection(context.Background(), ipNoSibling, nil); reflected {
		t.Fatal("expected no reflection once the sibling is dropped and the server 400s")
	}
}

// TestLoadSiblingsForPointMatchesExactRequestShape is the DB-backed
// regression test for loadSiblingsForPoint: it must return only the
// parameter rows sharing the exact same method+url+content-type+location-
// group as the probed point, never a different GraphQL operation (or any
// other differently-shaped row) stored under the same URL.
func TestLoadSiblingsForPointMatchesExactRequestShape(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	const url = "https://example.test/api"
	rows := []struct{ param, value, method, ct, loc string }{
		{"name", "alice", "POST", "application/x-www-form-urlencoded", "body"},
		{"token", "abc123", "POST", "application/x-www-form-urlencoded", "body"},
		// Same URL, but a GraphQL operation — a different request shape entirely.
		{"id", "1", "POST", "application/json", "graphql:q1:getUser:id"},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,value,method,content_type,location) VALUES (?,?,?,?,?,?,?,?)`,
			r.param+"-id", tid, url, r.param, r.value, r.method, r.ct, r.loc); err != nil {
			t.Fatal(err)
		}
	}

	ip := insertionPoint{URL: url, Param: "name", Method: "POST", ContentType: "application/x-www-form-urlencoded", Location: "body"}
	siblings, _ := loadSiblingsForPoint(context.Background(), db, tid, ip)
	if siblings["token"] != "abc123" {
		t.Fatalf("siblings=%v, want token=abc123 from the matching-shape row", siblings)
	}
	if _, ok := siblings["id"]; ok {
		t.Fatalf("siblings=%v, must not include the GraphQL-shaped row under the same URL", siblings)
	}
}

// TestCheckReflectionMarksBodyLocatedParameterReflected is the end-to-end
// regression test for the actual production bug: ParamScanner.CheckReflection
// must correctly mark a body-located parameter as reflected. Before this fix,
// every parameter regardless of location went through the query-only prober,
// so this row would have stayed is_reflected=0 forever.
func TestCheckReflectionMarksBodyLocatedParameterReflected(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	mux := http.NewServeMux()
	mux.HandleFunc("/submit", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><body>echo: %s</body></html>", r.FormValue("name"))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	if _, err := db.Exec(`INSERT INTO parameters (id,target_id,url,parameter,value,method,content_type,location,is_reflected)
		VALUES ('p1',?,?, 'name','seed','POST','application/x-www-form-urlencoded','body',0)`, tid, srv.URL+"/submit"); err != nil {
		t.Fatal(err)
	}

	s := &ParamScanner{db: db, cfg: &config.Config{}}
	if err := s.CheckReflection(context.Background(), tid, func(string, string, string) {}); err != nil {
		t.Fatal(err)
	}

	var isReflected int
	if err := db.QueryRow(`SELECT is_reflected FROM parameters WHERE id='p1'`).Scan(&isReflected); err != nil {
		t.Fatal(err)
	}
	if isReflected != 1 {
		t.Fatalf("is_reflected=%d, want 1 — the body-located parameter genuinely reflects and must be marked", isReflected)
	}
}
