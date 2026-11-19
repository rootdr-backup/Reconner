package scanner

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

// A single missed resolve pass must not delete a previously known row. The
// second CONSECUTIVE miss does. This guards against one dnsx/resolver hiccup
// wiping a target's DNS history and its recursion-frontier seeds.
func TestPruneRejectedSubdomainsRequiresTwoConsecutiveMisses(t *testing.T) {
	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "example.test"); err != nil {
		t.Fatal(err)
	}
	ins := func(name, ip, source string, alive int) {
		if _, err := db.Exec(`INSERT INTO subdomains(id,target_id,subdomain,ip,source,is_alive) VALUES(?,?,?,?,?,?)`,
			uuid.NewString(), targetID, name, ip, source, alive); err != nil {
			t.Fatal(err)
		}
	}
	ins("dns.example.test", "1.2.3.4", "dns", 0)
	ins("alive.example.test", "1.2.3.5", "dns", 1)
	ins("seed.example.test", "1.2.3.6", "seed", 0)

	s := &SubdomainScanner{db: db}
	rejected := map[string]bool{
		"dns.example.test":   true,
		"alive.example.test": true,
		"seed.example.test":  true,
	}
	count := func(name string) int {
		var n int
		if err := db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=? AND subdomain=?`, targetID, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	misses := func(name string) int {
		var n int
		if err := db.QueryRow(`SELECT COALESCE(miss_count,0) FROM subdomains WHERE target_id=? AND subdomain=?`, targetID, name).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}

	s.pruneRejectedSubdomains(context.Background(), targetID, rejected)
	if count("dns.example.test") != 1 || misses("dns.example.test") != 1 {
		t.Fatalf("first miss deleted the row (count=%d misses=%d)", count("dns.example.test"), misses("dns.example.test"))
	}
	s.pruneRejectedSubdomains(context.Background(), targetID, rejected)
	if count("dns.example.test") != 0 {
		t.Fatal("second consecutive miss did not prune the stale DNS row")
	}
	if count("alive.example.test") != 1 || count("seed.example.test") != 1 {
		t.Fatal("prune must never touch alive or operator-seeded rows")
	}
}

// A pass that resolves the name resets the miss counter, so two flakes years
// apart can never accumulate into a deletion without two CONSECUTIVE misses.
func TestResolvingUpsertResetsMissCount(t *testing.T) {
	db := newMonitorTestDB(t)
	targetID := uuid.NewString()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, targetID, "example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO subdomains(id,target_id,subdomain,ip,source,is_alive,miss_count) VALUES(?,?,?,?,?,0,1)`,
		uuid.NewString(), targetID, "back.example.test", "1.2.3.4", "dns"); err != nil {
		t.Fatal(err)
	}
	// The exact upsert resolveAll runs when a name is admitted this pass.
	if _, err := db.Exec(`
		INSERT INTO subdomains (id, target_id, subdomain, ip, source, last_seen)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, subdomain) DO UPDATE SET
			ip = excluded.ip,
			source = CASE WHEN COALESCE(subdomains.source,'dns') IN ('seed','vhost')
				THEN subdomains.source ELSE excluded.source END,
			last_seen = CURRENT_TIMESTAMP,
			miss_count = 0`,
		uuid.NewString(), targetID, "back.example.test", "5.6.7.8", "dns"); err != nil {
		t.Fatal(err)
	}
	var misses int
	if err := db.QueryRow(`SELECT COALESCE(miss_count,0) FROM subdomains WHERE target_id=? AND subdomain='back.example.test'`, targetID).Scan(&misses); err != nil {
		t.Fatal(err)
	}
	if misses != 0 {
		t.Fatalf("resolving pass left miss_count=%d, want 0", misses)
	}
}

func TestEscapeLike(t *testing.T) {
	cases := map[string]string{
		"plain.test":  "plain.test",
		`back\slash`:  `back\\slash`,
		"pct%name":    `pct\%name`,
		"under_score": `under\_score`,
	}
	for in, want := range cases {
		if got := escapeLike(in); got != want {
			t.Errorf("escapeLike(%q) = %q, want %q", in, got, want)
		}
	}
}
