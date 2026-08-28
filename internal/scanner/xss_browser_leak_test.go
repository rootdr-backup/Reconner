package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestBrowserXSSNoTempDirLeak is the regression test for the disk-filling bug: the
// old design spawned a browser (and a /tmp/chromedp-runner* user-data-dir) PER
// payload PER candidate and only removed it on a graceful browser exit, so a real
// scan left thousands behind until the host ran out of disk/inodes. The rewrite
// uses ONE browser with an explicit user-data-dir we own, reused across every
// candidate, so:
//   - Chromium creates NO chromedp-runner* auto temp dirs at all, and
//   - after Close() our single profile dir is gone too.
//
// Guarded: needs a real Chromium. Set RECONNER_BROWSER_TEST=1 and RECONNER_CHROME.
func TestBrowserXSSNoTempDirLeak(t *testing.T) {
	if os.Getenv("RECONNER_BROWSER_TEST") != "1" {
		t.Skip("set RECONNER_BROWSER_TEST=1 (and RECONNER_CHROME) to run the live browser leak test")
	}
	chrome := os.Getenv("RECONNER_CHROME")
	if chrome == "" {
		t.Skip("set RECONNER_CHROME to the chromium binary")
	}

	// A safe endpoint that never executes the payload — so Confirm burns through ALL
	// payloads for every candidate, i.e. the maximum number of navigations.
	safe := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte("<html><body>you searched for a value</body></html>"))
	}))
	defer safe.Close()

	count := func(glob string) int {
		m, _ := filepath.Glob(filepath.Join(os.TempDir(), glob))
		return len(m)
	}
	runnersBefore := count("chromedp-runner*")

	dir := filepath.Join(t.TempDir(), "prof")
	b := &browserXSSConfirmer{chromePath: chrome, dataDir: dir, navGate: make(chan struct{}, 1)}

	// Confirm many candidates; each runs the full payload list against the safe
	// endpoint and finds nothing — 20*7 = 140 navigations on the single tab.
	for i := 0; i < 20; i++ {
		if _, ok := b.Confirm(context.Background(), safe.URL+"/p?q=1", "q"); ok {
			t.Fatal("safe endpoint must not confirm XSS")
		}
	}

	// While running, Chromium must NOT have created any auto temp profile.
	if got := count("chromedp-runner*") - runnersBefore; got != 0 {
		t.Fatalf("explicit user-data-dir must prevent chromedp-runner* dirs, got %d new", got)
	}
	// Our own profile dir exists while the browser is up...
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("expected our profile dir to exist during the run: %v", err)
	}
	// ...and is removed by Close().
	b.Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("Close() must remove the profile dir, stat err=%v", err)
	}
	t.Logf("140 confirmations: 0 chromedp-runner dirs, single profile cleaned on Close — leak closed")
}
