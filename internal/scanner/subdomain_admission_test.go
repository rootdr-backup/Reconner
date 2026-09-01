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
	s.pruneRejectedSubdomains(context.Background(), tid, map[string]bool{
		"junk.m.local": true, "historically-live.m.local": true, "seed.m.local": true,
		"cname.m.local": true, "vhost.m.local": true,
	})
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=?`, tid).Scan(&n)
	if n != 4 {
		t.Fatalf("expected only the never-live eager DNS row to be pruned, rows=%d", n)
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM subdomains WHERE target_id=? AND subdomain='junk.m.local'`, tid).Scan(&n)
	if n != 0 {
		t.Fatal("unverified junk DNS row survived admission cleanup")
	}
}
