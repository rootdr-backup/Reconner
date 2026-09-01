package scanner

import (
	"context"
	"fmt"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// runVhostScan seeds one IP (the test server's host:port) and runs vhostScan,
// returning the hostnames stored as source='vhost'. domain uses the reserved
// .invalid TLD so every wordlist candidate is a guaranteed NXDOMAIN (never a
// real DNS name) — vhostScan only probes names that don't resolve.
func runVhostScan(t *testing.T, serverURL, domain string) []string {
	t.Helper()
	db, tid := testDB(t)
	defer db.Close()

	ipPort := strings.TrimPrefix(serverURL, "http://")
	if _, err := db.Exec(
		`INSERT INTO subdomains (id, target_id, subdomain, ip, source, last_seen)
		 VALUES (?, ?, ?, ?, 'dns', CURRENT_TIMESTAMP)`,
		uuid.New().String(), tid, "seed."+domain, ipPort); err != nil {
		t.Fatal(err)
	}

	s := &SubdomainScanner{db: db}
	var mu sync.Mutex
	found := map[string]bool{}
	s.vhostScan(context.Background(), tid, domain, found, &mu, nil, func(_, _, _ string) {})

	rows, err := db.Query(`SELECT subdomain FROM subdomains WHERE target_id=? AND source='vhost'`, tid)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var h string
		if rows.Scan(&h) == nil {
			out = append(out, h)
		}
	}
	return out
}

// A catch-all that reflects the Host and fluctuates its length wildly on every
// request — the shape that flagged an entire wordlist on one AWS IP for ewa.bh.
// The multi-sample baseline band must detect the instability and skip the IP.
func TestVhostCatchAllFluctuating(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	var rmu sync.Mutex
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		rmu.Lock()
		n := 2000 + rng.Intn(8000) // huge per-request variance
		rmu.Unlock()
		fmt.Fprintf(w, "<html><title>%s</title>%s</html>", r.Host, strings.Repeat("x", n))
	}))
	defer srv.Close()

	got := runVhostScan(t, srv.URL, "recontest.invalid")
	if len(got) != 0 {
		t.Fatalf("fluctuating catch-all must yield ZERO vhosts, got %d: %v", len(got), got)
	}
}

// A stable catch-all that ONLY reflects the Host (identical template otherwise).
// Raw length differs by len(host), but the host-neutralised normLen is constant,
// so no candidate is distinct → zero false positives.
func TestVhostCatchAllHostReflectionOnly(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, "<html><title>%s</title>%s</html>", r.Host, strings.Repeat("x", 4000))
	}))
	defer srv.Close()

	got := runVhostScan(t, srv.URL, "recontest.invalid")
	if len(got) != 0 {
		t.Fatalf("host-reflection-only catch-all must yield ZERO vhosts, got %d: %v", len(got), got)
	}
}

// Control: a genuine per-host app — one candidate serves a clearly different
// template, everyone else gets the stable default. The fix must NOT suppress the
// real vhost.
func TestVhostRealHostStillDetected(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if strings.HasPrefix(strings.ToLower(r.Host), "admin.") {
			fmt.Fprintf(w, "<html>ADMIN CONSOLE%s</html>", strings.Repeat("A", 9000))
			return
		}
		fmt.Fprintf(w, "<html>default page%s</html>", strings.Repeat("x", 4000))
	}))
	defer srv.Close()

	got := runVhostScan(t, srv.URL, "recontest.invalid")
	if len(got) != 1 || got[0] != "admin.recontest.invalid" {
		t.Fatalf("expected exactly [admin.recontest.invalid], got %v", got)
	}
}
