package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// Stylesheet change tracking: the monitor harvests <link rel="stylesheet">
// hrefs from every fetched page into css_files, then diffs CONTENT. A version
// bump with unchanged bytes is silence; a real change yields ONE css_change
// row whose old_body rolls the previous capture — the material the Changes
// tab's diff drawer renders.
func TestStylesheetBaselineThenContentChange(t *testing.T) {
	var mu sync.Mutex
	state := struct {
		css     string
		pageVer string
	}{css: "body{color:blue}", pageVer: "0"}
	renderPage := func(ver string) string {
		return `<html><link rel="stylesheet" href="/style.css?ver=` + ver + `"><body>hi</body></html>`
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		pv, cs := state.pageVer, state.css
		mu.Unlock()
		switch {
		case strings.HasSuffix(r.URL.Path, "/style.css"):
			w.Header().Set("Content-Type", "text/css")
			_, _ = w.Write([]byte(cs))
		default:
			w.Header().Set("Content-Type", "text/html")
			_, _ = w.Write([]byte(renderPage(pv)))
		}
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	_, _ = db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, srv.URL)
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,security_snapshot,server) VALUES(?,?,?,?,?,'','')`,
		uuid.NewString(), targetID, srv.URL+"/", 200, "")

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}

	// Pass 1 establishes the baseline: URL harvested, content captured, zero rows.
	mu.Lock()
	state.pageVer = "1"
	mu.Unlock()
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}
	var baselineHash, baselineBody string
	if err := db.QueryRow(`SELECT hash, COALESCE(body,'') FROM css_files WHERE target_id=?`, targetID).Scan(&baselineHash, &baselineBody); err != nil {
		t.Fatalf("stylesheet was not harvested into css_files: %v", err)
	}
	if baselineHash == "" || baselineBody == "" {
		t.Fatal("first pass did not capture stylesheet content baseline")
	}
	var rows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=?`, targetID).Scan(&rows)
	if rows != 0 {
		t.Fatalf("baseline pass raised %d change rows, want 0", rows)
	}

	// Pass 2 with a REAL content change → exactly one css_change row with the
	// previous capture rolled into old_*.
	mu.Lock()
	state.pageVer = "2"
	state.css = "body{color:red}"
	mu.Unlock()
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}
	var oldHash, oldBody, curBody string
	if err := db.QueryRow(`SELECT old_hash, old_body, body FROM css_files WHERE target_id=?`, targetID).Scan(&oldHash, &oldBody, &curBody); err != nil {
		t.Fatal(err)
	}
	if oldHash != baselineHash || oldBody != "body{color:blue}" || !strings.Contains(curBody, "color:red") {
		t.Fatalf("diff material not rolled: old_hash=%q old_body=%q body=%q", oldHash, oldBody, curBody)
	}
	var cssTotal int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='css_change'`, targetID).Scan(&cssTotal); err != nil {
		t.Fatal(err)
	}
	if cssTotal != 1 {
		t.Fatalf("content-change pass produced %d css_change rows, want 1 (a relative link never raises security: rows)", cssTotal)
	}

	// Pass 3: cache-buster bump with UNCHANGED bytes → silence (no extra rows).
	mu.Lock()
	state.pageVer = "3"
	mu.Unlock()
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='css_change'`, targetID).Scan(&cssTotal)
	if cssTotal != 1 {
		t.Fatalf("no-op version bump produced extra css rows: %d css_change rows, want still 1", cssTotal)
	}
	var attrRows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type LIKE 'security:stylesheet%'`, targetID).Scan(&attrRows)
	if attrRows != 0 {
		t.Fatalf("relative stylesheets raised %d security: rows, want 0", attrRows)
	}
}

// A cache-busted bump on an EXTERNAL stylesheet must not spam the Changes tab
// with add/remove pairs when the bytes are identical — snapshot keys are
// path-based (stripResourceQuery), and unchanged content yields no css_change.
func TestExternalStylesheetVerBumpIsSilent(t *testing.T) {
	pageVer := "1"
	renderPage := func(ver string) string {
		return `<html><link rel="stylesheet" href="https://cdn.example.test/style.css?ver=` + ver + `"><body>x</body></html>`
	}

	pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(renderPage(pageVer)))
	}))
	defer pageSrv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	_, _ = db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, pageSrv.URL)
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,security_snapshot) VALUES(?,?,?,?,?,'')`,
		uuid.NewString(), targetID, pageSrv.URL+"/", 200, "x")

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}
	pageVer = "2"
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}

	var attrRows, cssRows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type LIKE 'security:stylesheet%'`, targetID).Scan(&attrRows)
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='css_change'`, targetID).Scan(&cssRows)
	if attrRows != 0 || cssRows != 0 {
		t.Fatalf("ver-bump with unchanged bytes is not silent: %d security: rows, %d css_change rows", attrRows, cssRows)
	}
}

// Adding a genuinely NEW stylesheet path still alerts, at info severity.
func TestNewExternalStylesheetPathStillAlerts(t *testing.T) {
	extraEnabled := false
	renderPage := func(withExtra bool) string {
		base := `<html><link rel="stylesheet" href="https://cdn.example.test/a.css"><body>x</body></html>`
		if withExtra {
			return `<html><link rel="stylesheet" href="https://cdn.example.test/a.css">` +
				`<link rel="stylesheet" href="https://cdn.example.test/b.css"><body>x</body></html>`
		}
		return base
	}

	pageSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte(renderPage(extraEnabled)))
	}))
	defer pageSrv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	_, _ = db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, pageSrv.URL)
	_, _ = db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,security_snapshot) VALUES(?,?,?,?,?,'')`,
		uuid.NewString(), targetID, pageSrv.URL+"/", 200, "x")

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}
	extraEnabled = true
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}

	var addedRows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='security:stylesheet_added'`, targetID).Scan(&addedRows); err != nil {
		t.Fatal(err)
	}
	if addedRows != 1 {
		t.Fatalf("new stylesheet path produced %d security:stylesheet_added rows, want exactly 1", addedRows)
	}
	var sev string
	_ = db.QueryRow(`SELECT severity FROM monitoring_changes WHERE target_id=? AND change_type='security:stylesheet_added'`, targetID).Scan(&sev)
	if sev != "info" {
		t.Fatalf("new stylesheet severity = %q, want info", sev)
	}
	var removedRows int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='security:stylesheet_removed'`, targetID).Scan(&removedRows)
	if removedRows != 0 {
		t.Fatalf("adding a path produced %d removed rows, want 0", removedRows)
	}
}

// js_change rows carry the same diff material: the previous capture rolls into
// old_body at detection time.
func TestJSChangeCapturesBodies(t *testing.T) {
	var mu sync.Mutex
	js := "console.log('v1')"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		body := js
		mu.Unlock()
		w.Header().Set("Content-Type", "application/javascript")
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	_, _ = db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, srv.URL)
	_, _ = db.Exec(`INSERT INTO js_files(id,target_id,url,hash) VALUES(?,?,?,'')`, uuid.NewString(), targetID, srv.URL+"/app.js")

	s := &MonitorScanner{db: db}
	logFn := func(string, string, string) {}
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}

	mu.Lock()
	js = "console.log('v2')"
	mu.Unlock()
	if err := s.Run(context.Background(), targetID, logFn); err != nil {
		t.Fatal(err)
	}

	var oldBody, curBody string
	if err := db.QueryRow(`SELECT old_body, body FROM js_files WHERE target_id=?`, targetID).Scan(&oldBody, &curBody); err != nil {
		t.Fatal(err)
	}
	if oldBody != "console.log('v1')" || curBody != "console.log('v2')" {
		t.Fatalf("js bodies not rolled: old_body=%q body=%q", oldBody, curBody)
	}
	var changes int
	_ = db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND change_type='js_change'`, targetID).Scan(&changes)
	if changes != 1 {
		t.Fatalf("changed javascript produced %d js_change rows, want 1", changes)
	}
}

// ── pure-unit tests ──────────────────────────────────────────────────────────

func TestStripResourceQuery(t *testing.T) {
	cases := map[string]string{
		"https://cdn.t/app.css?ver=8&x=1": "https://cdn.t/app.css",
		"https://cdn.t/app.css":           "https://cdn.t/app.css",
		"/app.css?ver=1":                  "/app.css?ver=1", // no host: leave untouched
		"":                                "",
	}
	for in, want := range cases {
		if got := stripResourceQuery(in); got != want {
			t.Errorf("stripResourceQuery(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSecuritySnapshotSuppressesVerBumpButNotNewPath(t *testing.T) {
	page := func(path string) string {
		return `<html><link rel="stylesheet" href="https://cdn.example.com` + path + `"></html>`
	}
	base := extractSecuritySnapshot(page("/x.css?ver=1"), "app.test")
	bumped := extractSecuritySnapshot(page("/x.css?ver=2"), "app.test")
	if base.toJSON() != bumped.toJSON() {
		t.Fatal("ver bump on the same stylesheet path must not alter the security snapshot")
	}
	newPath := extractSecuritySnapshot(page("/y.css"), "app.test")
	if newPath.toJSON() == bumped.toJSON() {
		t.Fatal("a genuinely new stylesheet path must alter the security snapshot")
	}
	withScript := extractSecuritySnapshot(page("/x.css?ver=2\")></link><script src=\"https://evil.example.com/x.js\"></script>"), "app.test")
	if withScript.toJSON() == bumped.toJSON() {
		t.Fatal("a new external script must alter the security snapshot")
	}
}

func TestSecurityChangeSeverityStylesheetIsInfo(t *testing.T) {
	cases := []struct {
		change securityChange
		want   string
	}{
		{securityChange{action: "added", attr: securityAttr{Kind: "script", Value: "https://x/e.js"}}, "high"},
		{securityChange{action: "added", attr: securityAttr{Kind: "stylesheet", Value: "https://x/e.css"}}, "info"},
		{securityChange{action: "added", attr: securityAttr{Kind: "hidden", Value: "csrf_seen"}}, "medium"},
		{securityChange{action: "removed", attr: securityAttr{Kind: "form", Value: "/login"}}, "medium"},
	}
	for _, tc := range cases {
		if got := securityChangeSeverity(tc.change); got != tc.want {
			t.Errorf("severity(%s %s) = %q, want %q", tc.change.action, tc.change.attr.Kind, got, tc.want)
		}
	}
}

// Legacy snapshots (recorded before extraction started stripping ?ver=) must
// not unleash a one-time add+remove pair per stylesheet on the first diff
// after an upgrade: the diff key normalizes stylesheet values on both sides.
// Non-stylesheet kinds keep exact-match keys (script bump → added + removed).
func TestSecuritySnapshotLegacyQueryKeysDiffSilently(t *testing.T) {
	old := securitySnapshot{Attrs: []securityAttr{
		{Kind: "stylesheet", Value: "https://cdn.example.test/s/a.css?ver=1"},
		{Kind: "script", Value: "https://x.example.test/y.js?h=1"},
	}}
	cur := securitySnapshot{Attrs: []securityAttr{
		{Kind: "stylesheet", Value: "https://cdn.example.test/s/a.css?ver=2"},
		{Kind: "script", Value: "https://x.example.test/y.js?h=2"},
	}}
	got := diffSecuritySnapshots(old, cur)
	sheetChanges := 0
	for _, c := range got {
		if c.attr.Kind == "stylesheet" {
			sheetChanges++
		}
	}
	if sheetChanges != 0 {
		t.Fatalf("stylesheet ver-bump diffed as %d change(s), want 0", sheetChanges)
	}
	if len(got) != 2 {
		t.Fatalf("script hash bump produced %d change(s), want exactly 2 (added+removed)", len(got))
	}
}
