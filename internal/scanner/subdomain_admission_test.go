package scanner

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
)

func TestStrictSubdomainSyntaxAndAdaptiveWords(t *testing.T) {
	for _, good := range []string{"api.example.com", "api-2.dev.example.com", "xn--bcher-kva.example.com"} {
		if !isValidSubdomain(good, "example.com") {
			t.Errorf("valid hostname rejected: %s", good)
		}
	}
	for _, bad := range []string{
		"evil-example.com", "*.example.com", "bad_.example.com", "-api.example.com",
		"api-.example.com", "api..example.com", "api.example.com.evil.test",
	} {
		if isValidSubdomain(bad, "example.com") {
			t.Errorf("invalid hostname admitted: %s", bad)
		}
	}

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "my-subdomains.txt"), []byte("custom-tool\n# comment\ninvalid_name\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	s := &SubdomainScanner{cfg: &config.Config{WordlistsDir: dir}}
	words := s.deepDNSWords(context.Background(), "example.com", []string{"payments.example.com"})
	for _, want := range []string{"argocd", "argocd-staging", "custom-tool", "payments-dev", "dev.payments"} {
		if !containsString(words, want) {
			t.Errorf("adaptive DNS word %q missing", want)
		}
	}
	if containsString(words, "invalid_name") {
		t.Fatal("invalid custom word entered DNS candidate set")
	}
}

func TestASNDiscoveryRequiresExplicitScopeOptIn(t *testing.T) {
	if asnDiscoveryEnabled(context.Background()) {
		t.Fatal("ASN/CIDR sweep must be off when the scan did not explicitly opt in")
	}
	if !asnDiscoveryEnabled(WithASNDiscovery(context.Background(), true)) {
		t.Fatal("verified-scope ASN opt-in was not carried to the scanner")
	}
}

func TestRejectedAdmissionPrunesOnlyUnverifiedDNSRows(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	insert := func(name, source string, alive int) {
		if _, err := db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,source,is_alive)
			VALUES (?,?,?,?,?)`, uuid.New().String(), tid, name, source, alive); err != nil {
			t.Fatal(err)
		}
	}
	insert("junk.m.local", "dns", 0)
	insert("historically-live.m.local", "dns", 1)
	insert("seed.m.local", "seed", 0)
	insert("cname.m.local", "dns-cname", 0)
	insert("vhost.m.local", "vhost", 0)

	s := &SubdomainScanner{db: db}
	rejected := map[string]bool{
		"junk.m.local": true, "historically-live.m.local": true, "seed.m.local": true,
		"cname.m.local": true, "vhost.m.local": true,
	}
	// One missed resolve pass must never delete: transient resolver failures are
	// common. The never-live eager DNS row survives the first pass at miss_count=1.
	s.pruneRejectedSubdomains(context.Background(), tid, rejected)
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=?`, tid).Scan(&n)
	if n != 5 {
		t.Fatalf("a single missed pass pruned rows early: rows=%d", n)
	}
	// The second CONSECUTIVE miss prunes only that never-live eager DNS row.
	s.pruneRejectedSubdomains(context.Background(), tid, rejected)
	_ = db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=?`, tid).Scan(&n)
	if n != 4 {
		t.Fatalf("expected only the never-live eager DNS row to be pruned, rows=%d", n)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=? AND subdomain='junk.m.local'`, tid).Scan(&n)
	if n != 0 {
		t.Fatal("unverified junk DNS row survived two consecutive missed passes")
	}
}

// TestDistinctCNAMETargetsDeduplicates proves the extra A/AAAA pass runs once
// per target. Many aliases share one CDN name, and dnsx can emit several
// response lines for the same target.
func TestDistinctCNAMETargetsDeduplicates(t *testing.T) {
	got := distinctCNAMETargets(map[string]string{
		"a.example.com": "D27QWT9HEEZ1ET.CloudFront.Net.",
		"b.example.com": "d27qwt9heez1et.cloudfront.net",
		"c.example.com": "other.example.net",
		"d.example.com": "",
	})
	want := []string{"d27qwt9heez1et.cloudfront.net", "other.example.net"}
	if len(got) != len(want) {
		t.Fatalf("distinct targets = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("distinct targets = %v, want %v", got, want)
		}
	}
}

// TestClassifyCNAMEAliasCopiesTargetIP covers the Merck case. dnsx reports the
// CloudFront A records under the CNAME target, so the alias has no A/AAAA of
// its own. The target IP must be copied onto the alias for the HTTP probe.
func TestClassifyCNAMEAliasCopiesTargetIP(t *testing.T) {
	const target = "d27qwt9heez1et.cloudfront.net"
	targetIPs := map[string][]string{
		target: {"108.157.60.59", "108.157.60.86"},
	}
	resolve := func(name string) []string {
		return targetIPs[normalizeSubdomainName(name)]
	}

	ip, live := classifyCNAMEAlias("account.merck.com", target+".", resolve, nil)
	if !live || ip != "108.157.60.59" {
		t.Fatalf("live CNAME alias = (%q, %v), want (108.157.60.59, true)", ip, live)
	}

	// A dangling target keeps an empty IP and stays in takeover only.
	ip, live = classifyCNAMEAlias("dangling.example.com", "missing.example.net", resolve, nil)
	if live || ip != "" {
		t.Fatalf("dangling CNAME alias = (%q, %v), want (\"\", false)", ip, live)
	}

	// A wildcard answer pool is never copied onto an alias.
	profile := &wildcardProfile{apex: wildcardZone{ips: map[string]bool{"108.157.60.59": true}}}
	ip, live = classifyCNAMEAlias("account.merck.com", target, resolve, profile)
	if live || ip != "" {
		t.Fatalf("wildcard CNAME target = (%q, %v), want (\"\", false)", ip, live)
	}

	// A wildcard CNAME target is rejected before the IP lookup.
	profile = &wildcardProfile{apex: wildcardZone{cnames: map[string]bool{target: true}}}
	ip, live = classifyCNAMEAlias("account.merck.com", target, resolve, profile)
	if live || ip != "" {
		t.Fatalf("wildcard CNAME record = (%q, %v), want (\"\", false)", ip, live)
	}
}

// TestResolvingSubdomainsUnderScoping proves the recursive-enum frontier picks
// only RESOLVING (has an IP) names strictly under the apex, excludes the apex
// itself and anything already visited, and rejects out-of-scope rows.
func TestResolvingSubdomainsUnderScoping(t *testing.T) {
	db, tid := testDB(t)
	defer db.Close()
	ins := func(name, ip string) {
		if _, err := db.Exec(`INSERT INTO subdomains (id,target_id,subdomain,ip,source)
			VALUES (?,?,?,?, 'dns')`, uuid.New().String(), tid, name, ip); err != nil {
			t.Fatal(err)
		}
	}
	ins("api.m.local", "1.2.3.4")      // resolving, in scope → included
	ins("deep.api.m.local", "1.2.3.5") // resolving, deeper → included
	ins("dead.m.local", "")            // no IP → excluded
	ins("visited.m.local", "9.9.9.9")  // resolving but visited → excluded
	ins("m.local", "1.1.1.1")          // the apex itself → excluded

	s := &SubdomainScanner{db: db}
	got := s.resolvingSubdomainsUnder(context.Background(), tid, "m.local",
		map[string]bool{"visited.m.local": true})

	want := map[string]bool{"api.m.local": true, "deep.api.m.local": true}
	if len(got) != len(want) {
		t.Fatalf("frontier=%v, want exactly %v", got, want)
	}
	for _, n := range got {
		if !want[n] {
			t.Errorf("unexpected name in recursion frontier: %q", n)
		}
	}
}

// TestSubdomainRecursionDepthDefault proves the depth helper falls back to 4 and
// honors an explicit override.
func TestSubdomainRecursionDepthDefault(t *testing.T) {
	if d := (&SubdomainScanner{cfg: &config.Config{}}).subdomainRecursionDepth(); d != 4 {
		t.Fatalf("default recursion depth = %d, want 4", d)
	}
	if d := (&SubdomainScanner{cfg: &config.Config{SubdomainRecursionDepth: 7}}).subdomainRecursionDepth(); d != 7 {
		t.Fatalf("configured recursion depth = %d, want 7", d)
	}
	if d := (&SubdomainScanner{cfg: nil}).subdomainRecursionDepth(); d != 4 {
		t.Fatalf("nil-cfg recursion depth = %d, want 4", d)
	}
}
