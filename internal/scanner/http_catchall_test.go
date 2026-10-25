package scanner

import (
	"context"
	"fmt"
	"testing"
)

func TestHostFromServiceURL(t *testing.T) {
	cases := map[string]string{
		"https://junk.realestate.com.au":            "junk.realestate.com.au",
		"http://junk.realestate.com.au/login":       "junk.realestate.com.au",
		"https://junk.realestate.com.au:8443/":      "junk.realestate.com.au",
		"https://user:pass@junk.realestate.com.au/": "junk.realestate.com.au",
		"JUNK.REALESTATE.com.au.":                   "junk.realestate.com.au",
		"":                                          "",
		"/only/path":                                "",
	}
	for raw, want := range cases {
		if got := hostFromServiceURL(raw); got != want {
			t.Fatalf("hostFromServiceURL(%q) = %q, want %q", raw, got, want)
		}
	}
}

func TestSortedTechnologies(t *testing.T) {
	if got := sortedTechnologies(`["nginx","WordPress"]`); got != "wordpress,nginx" {
		t.Fatalf("mixed order/case must normalize (sort is byte-order, lowercase after): %q", got)
	}
	if got := sortedTechnologies(`[]`); got != "" {
		t.Fatalf("empty list must be an empty string, got %q", got)
	}
	if got := sortedTechnologies(`not-json`); got != "not-json" {
		t.Fatalf("non-JSON rows must stay comparable: %q", got)
	}
}

func TestQualifiesCatchallGroups(t *testing.T) {
	apexTargets := catchallApexTargets("realestate.com.au")

	// Redirect fleet: 3 junk members, all funneling into the apex → marked;
	// an apex/www member must never be marked.
	redirect := []catchallRow{
		{host: "a.realestate.com.au", contentFP: "FP", redirectHost: "realestate.com.au"},
		{host: "b.realestate.com.au", contentFP: "FP", redirectHost: "www.realestate.com.au"},
		{host: "asdf-garbage.git.realestate.com.au", contentFP: "FP", redirectHost: "realestate.com.au"},
	}
	marked, kind := qualifiesCatchallGroup(redirect, apexTargets)
	if kind != "redirect" || len(marked) != 3 {
		t.Fatalf("3-member redirect fleet must be marked (kind=%q n=%d)", kind, len(marked))
	}
	mixed := append(append([]catchallRow{}, redirect...), catchallRow{host: "realestate.com.au", contentFP: "FP"})
	marked, kind = qualifiesCatchallGroup(mixed, apexTargets)
	if kind != "redirect" || len(marked) != 3 {
		t.Fatalf("fleet+apex group must mark only junk members (kind=%q n=%d)", kind, len(marked))
	}
	for _, row := range marked {
		if apexTargets[row.host] {
			t.Fatalf("apex/www host marked as catch-all: %q", row.host)
		}
	}

	// Same fingerprint with members split across redirect targets → not a fleet.
	half := []catchallRow{
		{host: "a.realestate.com.au", contentFP: "FP", redirectHost: "realestate.com.au"},
		{host: "b.realestate.com.au", contentFP: "FP", redirectHost: "realestate.com.au"},
		{host: "c.realestate.com.au", contentFP: "FP", redirectHost: "elsewhere.example"},
	}
	if _, kind = qualifiesCatchallGroup(half, apexTargets); kind != "" {
		t.Fatalf("partial redirect agreement must not mark (kind=%q)", kind)
	}

	// Homepage clones: apex row anchors a group of >=5 identical fingerprints.
	home := []catchallRow{{host: "realestate.com.au", contentFP: "HOMEFP"}}
	for i := 0; i < 5; i++ {
		home = append(home, catchallRow{host: fmt.Sprintf("clone%d.git.realestate.com.au", i), contentFP: "HOMEFP"})
	}
	marked, kind = qualifiesCatchallGroup(home, apexTargets)
	if kind != "homepage" || len(marked) != 5 {
		t.Fatalf("apex-anchored clone group must mark the 5 junk rows (kind=%q n=%d)", kind, len(marked))
	}

	// 4 identical members without the apex row must NOT mark (a legit twin
	// pair fleet is not catch-all evidence on its own).
	twins := make([]catchallRow, 0, 4)
	for i := 0; i < 4; i++ {
		twins = append(twins, catchallRow{host: fmt.Sprintf("twin%d.realestate.com.au", i), contentFP: "TW"})
	}
	if _, kind = qualifiesCatchallGroup(twins, apexTargets); kind != "" {
		t.Fatalf("4 identical hosts without the apex must stay unmarked (kind=%q)", kind)
	}

	// With the apex but only 3 members → below the content threshold (4 total).
	short := []catchallRow{
		catchallRow{host: "realestate.com.au", contentFP: "TW"},
		catchallRow{host: "twin0.realestate.com.au", contentFP: "TW"},
		catchallRow{host: "twin1.realestate.com.au", contentFP: "TW"},
		catchallRow{host: "twin2.realestate.com.au", contentFP: "TW"},
	}
	if _, kind = qualifiesCatchallGroup(short, apexTargets); kind != "" {
		t.Fatalf("3 members + apex is below the content threshold (kind=%q)", kind)
	}
}

func TestRunCatchallPassEndToEnd(t *testing.T) {
	db, tid := testDB(t)
	ctx := context.Background()

	seed := func(host string, statusCode int, title string, redirect string, source string) {
		if _, err := db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, ip, source, catchall, is_alive)
			VALUES (?, ?, ?, '10.0.0.1', ?, 0, 1)`, "ct-"+host, tid, host, source); err != nil {
			t.Fatalf("seed subdomain %s: %v", host, err)
		}
		if _, err := db.Exec(`INSERT INTO http_services (id, target_id, url, status_code, title, server, redirect_url, technologies)
			VALUES (?, ?, ?, ?, ?, 'nginx', ?, '[]')`,
			"ct-svc-"+host, tid, "https://"+host, statusCode, title, redirect); err != nil {
			t.Fatalf("seed service %s: %v", host, err)
		}
	}

	// The wildcard homepage fleet: apex + 5 junk clones with identical title.
	seed("m.local", 200, "Real Estate Portal", "", "dns")
	for i := 0; i < 5; i++ {
		seed(fmt.Sprintf("junk%d.git.m.local", i), 200, "Real Estate Portal", "", "dns")
	}
	// An auth wall that legitimately shares a shell across hosts: 401s are
	// outside the 2xx window and must never group.
	seed("portal.m.local", 401, "Sign in", "", "dns")
	// An operator-vouched seed that shares the homepage content: seed/vhost
	// rows are never re-marked by the pass.
	seed("operator-host.m.local", 200, "Real Estate Portal", "", "seed")

	scanner := &HTTPScanner{db: db}
	logFn := func(_ string, _, _ string) {}
	if err := scanner.runCatchallPass(ctx, tid, logFn); err != nil {
		t.Fatalf("runCatchallPass: %v", err)
	}

	var junk int
	if err := db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE catchall=1 AND target_id=?`, tid).Scan(&junk); err != nil {
		t.Fatalf("count marked: %v", err)
	}
	if junk != 5 {
		t.Fatalf("expected the 5 junk clones marked, got %d", junk)
	}
	var apex int
	if err := db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=? AND subdomain='m.local' AND catchall=1`, tid).Scan(&apex); err != nil {
		t.Fatalf("count apex: %v", err)
	}
	if apex != 0 {
		t.Fatalf("the apex itself must never be marked")
	}
	var services int
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id=? AND url LIKE 'https://junk%'`, tid).Scan(&services); err != nil {
		t.Fatalf("count junk services: %v", err)
	}
	if services != 0 {
		t.Fatalf("junk http_services rows must be dropped so web modules skip them, got %d", services)
	}
	var left int
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id=?`, tid).Scan(&left); err != nil {
		t.Fatalf("count left services: %v", err)
	}
	if left != 3 { // apex + operator seed stay; the 401 auth wall is never marked, so it stays too
		t.Fatalf("apex + seed + 401 services must survive, got %d", left)
	}

	// Idempotency: a second pass (next scan) must not change anything — the
	// junk services are already gone and the marks already exist.
	if err := scanner.runCatchallPass(ctx, tid, logFn); err != nil {
		t.Fatalf("second runCatchallPass: %v", err)
	}
	var junkAgain int
	if err := db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE catchall=1 AND target_id=?`, tid).Scan(&junkAgain); err != nil {
		t.Fatalf("count marked after rerun: %v", err)
	}
	if junkAgain != 5 {
		t.Fatalf("second pass must be idempotent, marked=%d", junkAgain)
	}
	var leftAgain int
	if err := db.QueryRow(`SELECT COUNT(*) FROM http_services WHERE target_id=?`, tid).Scan(&leftAgain); err != nil {
		t.Fatalf("count left services after rerun: %v", err)
	}
	if leftAgain != 3 {
		t.Fatalf("second pass must not delete surviving services, got %d", leftAgain)
	}
}
