package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestChallengedCandidatesSelectsOnlyWAFLookingHosts is the regression test
// for the candidate-selection contract: a host whose stored title/status
// already carries a specific CDN/WAF vendor signature (see waf.go's
// looksLikeWAFBlock) is selected for a browser retry; an ordinary host, and
// a host that merely returned a generic 403 with no vendor signature, must
// NEVER be — the whole point is to touch only hosts that actually look
// challenged, never to re-render everything "just in case".
func TestChallengedCandidatesSelectsOnlyWAFLookingHosts(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	rows := []struct {
		url, title string
		status     int
	}{
		{"https://challenged.example.test/", "Just a moment...", 403},
		{"https://normal.example.test/", "Acme Dashboard", 200},
		{"https://genericforbidden.example.test/", "403 Forbidden", 403},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,source) VALUES (?,?,?,?,?,'probe')`,
			"id-"+r.url, tid, r.url, r.status, r.title); err != nil {
			t.Fatal(err)
		}
	}

	s := &HTTPScanner{db: db}
	got := s.challengedCandidates(context.Background(), tid)
	if len(got) != 1 || got[0].url != "https://challenged.example.test/" {
		t.Fatalf("challengedCandidates=%+v, want only the Cloudflare-challenge-looking host", got)
	}
}

// TestChallengedCandidatesCapsAtMax bounds the per-scan cost: a target that
// is challenge-protected on every host still only ever retries up to
// maxChallengeRescueHosts of them.
func TestChallengedCandidatesCapsAtMax(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	for i := 0; i < maxChallengeRescueHosts+5; i++ {
		u := fmt.Sprintf("https://host%d.example.test/", i)
		if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,source) VALUES (?,?,?,403,'Just a moment...','probe')`,
			u, tid, u); err != nil {
			t.Fatal(err)
		}
	}

	s := &HTTPScanner{db: db}
	got := s.challengedCandidates(context.Background(), tid)
	if len(got) != maxChallengeRescueHosts {
		t.Fatalf("len(challengedCandidates)=%d, want capped at %d", len(got), maxChallengeRescueHosts)
	}
}

// TestChallengedCandidatesRespectsHostScope ensures a per-asset scoped task
// never retries a challenge-looking host outside its own scope, matching
// the exact filterURLsByHostScope contract fingerprintHosts already relies
// on for the same table.
func TestChallengedCandidatesRespectsHostScope(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	for _, u := range []string{"https://a.example.test/", "https://b.example.test/"} {
		if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,source) VALUES (?,?,?,403,'Just a moment...','probe')`,
			u, tid, u); err != nil {
			t.Fatal(err)
		}
	}

	ctx := WithHostScope(context.Background(), []string{"a.example.test"})
	s := &HTTPScanner{db: db}
	got := s.challengedCandidates(ctx, tid)
	if len(got) != 1 || got[0].url != "https://a.example.test/" {
		t.Fatalf("challengedCandidates with host scope=%+v, want only a.example.test", got)
	}
}

// TestRescueChallengedHostsNoopsWithoutChrome is the safety-floor test: on a
// deployment with no headless Chromium at all (the common case outside the
// shipped Docker image), the rescue step must be a clean, silent no-op —
// never a panic, never a half-applied DB write.
func TestRescueChallengedHostsNoopsWithoutChrome(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()

	const u = "https://challenged.example.test/"
	if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,source) VALUES (?,?,?,403,'Just a moment...','probe')`,
		u, tid, u); err != nil {
		t.Fatal(err)
	}

	savedLookPath, savedAbsPaths := chromeLookPath, chromeAbsolutePaths
	chromeLookPath = func(string) (string, error) { return "", exec.ErrNotFound }
	chromeAbsolutePaths = nil
	t.Cleanup(func() { chromeLookPath, chromeAbsolutePaths = savedLookPath, savedAbsPaths })
	t.Setenv("RECONNER_CHROME", filepath.Join(t.TempDir(), "no-such-chrome"))

	logged := []string{}
	logFn := func(level, source, msg string) { logged = append(logged, msg) }

	s := &HTTPScanner{db: db}
	s.rescueChallengedHosts(context.Background(), tid, logFn)

	var title string
	if err := db.QueryRow(`SELECT title FROM http_services WHERE target_id=? AND url=?`, tid, u).Scan(&title); err != nil {
		t.Fatal(err)
	}
	if title != "Just a moment..." {
		t.Fatalf("title changed to %q without any browser available", title)
	}
}

// TestRescueChallengedHostsLive proves the real mechanism end-to-end with an
// actual headless browser against a local HTTP server: a page whose initial
// HTML looks exactly like a Cloudflare challenge (the plain response httpx
// would see) but whose own JavaScript replaces the title/body shortly after
// load — exactly how a real "I'm Under Attack Mode" challenge clears for any
// browser that executes JS. Opt-in only, mirroring every other real-browser
// test in this package (see xss_browser_live_test.go).
func TestRescueChallengedHostsLive(t *testing.T) {
	if os.Getenv("RECONNER_BROWSER_TEST") == "" {
		t.Skip("browser E2E disabled; set RECONNER_BROWSER_TEST=1 and RECONNER_CHROME")
	}
	if findChromePath() == "" {
		t.Fatal("browser bot-challenge rescue coverage was explicitly required but no Chrome/Chromium binary is available")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/challenged", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<html><head><title>Just a moment...</title></head><body>
			<p>Checking your browser before accessing the site. cf-ray: deadbeef</p>
			<script>
				setTimeout(function () {
					document.title = 'Acme Corp Dashboard';
					document.body.innerHTML = '<h1>Welcome to Acme Corp</h1><p>real content</p>';
				}, 500);
			</script>
		</body></html>`)
	})
	mux.HandleFunc("/hardchallenge", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `<html><head><title>Just a moment...</title></head><body>
			<p>Checking your browser before accessing the site. cf-ray: deadbeef</p>
		</body></html>`)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	db, tid := testDB(t)
	defer db.Close()

	easyURL := srv.URL + "/challenged"
	hardURL := srv.URL + "/hardchallenge"
	for _, u := range []string{easyURL, hardURL} {
		if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,title,source) VALUES (?,?,?,403,'Just a moment...','probe')`,
			u, tid, u); err != nil {
			t.Fatal(err)
		}
	}

	var logged []string
	logFn := func(level, source, msg string) { logged = append(logged, msg) }

	s := &HTTPScanner{db: db}
	s.rescueChallengedHosts(context.Background(), tid, logFn)

	var easyTitle string
	if err := db.QueryRow(`SELECT title FROM http_services WHERE target_id=? AND url=?`, tid, easyURL).Scan(&easyTitle); err != nil {
		t.Fatal(err)
	}
	if easyTitle != "Acme Corp Dashboard" {
		t.Fatalf("easy challenge: title=%q, want the JS-revealed real title (log: %v)", easyTitle, logged)
	}

	var hardTitle string
	if err := db.QueryRow(`SELECT title FROM http_services WHERE target_id=? AND url=?`, tid, hardURL).Scan(&hardTitle); err != nil {
		t.Fatal(err)
	}
	if hardTitle != "Just a moment..." {
		t.Fatalf("hard challenge: title=%q, want it left untouched (never fabricate a bypass)", hardTitle)
	}
}
