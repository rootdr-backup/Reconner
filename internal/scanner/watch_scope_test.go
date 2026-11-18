package scanner

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/database"
)

func TestNormalizeScopeIdentifier(t *testing.T) {
	cases := []struct {
		raw  string
		want string
		ok   bool
	}{
		{"Example.COM.", "example.com", true},
		{"https://Example.com/", "example.com", true},
		{"*.Example.COM", "example.com", true},
		{"example.com:8443", "example.com", true},  // port stripped for matching
		{"https://example.com/api/v1/", "", false}, // path-scoped: not landable
		{"example.com/api", "", false},
		{"*example.com", "", false},      // missing dot
		{"sub.*.example.com", "", false}, // mid-domain glob
		{"", "", false},
	}
	for _, tc := range cases {
		got, ok := normalizeScopeIdentifier(tc.raw)
		if ok != tc.ok || got != tc.want {
			t.Errorf("normalizeScopeIdentifier(%q) = (%q,%v), want (%q,%v)", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNormalizeWatchHost(t *testing.T) {
	cases := []struct {
		raw       string
		wantValue string
		wantHost  string
		wantPort  string
		ok        bool
	}{
		{"Sub.Example.COM.", "sub.example.com", "sub.example.com", "", true},
		{"https://sub.example.com/", "sub.example.com", "sub.example.com", "", true},
		{"example.com:80", "example.com", "example.com", "80", true},
		{"example.com:8443", "example.com:8443", "example.com", "8443", true},
		{"example.com:443", "example.com", "example.com", "443", true},
	}
	for _, tc := range cases {
		got, ok := normalizeWatchHost(tc.raw)
		if ok != tc.ok || got.Value != tc.wantValue || got.Host != tc.wantHost || got.Port != tc.wantPort {
			t.Errorf("normalizeWatchHost(%q) = (%+v,%v), want value=%q host=%q port=%q ok=%v",
				tc.raw, got, ok, tc.wantValue, tc.wantHost, tc.wantPort, tc.ok)
		}
	}
}

func TestMatchWatchHost(t *testing.T) {
	entries := []WatchScopeEntry{
		{Identifier: "*.example.com", IsWildcard: true, host: "example.com"},
		{Identifier: "exact.test", host: "exact.test"},
	}
	host := func(s string) WatchScopeHost { h, _ := normalizeWatchHost(s); return h }

	cases := []struct {
		name  string
		query string
		want  string // matched identifier, "" for no match
	}{
		{"wildcard one level", "a.example.com", "*.example.com"},
		{"wildcard two levels", "a.b.example.com", "*.example.com"},
		{"wildcard does not match apex", "example.com", ""},
		{"wildcard does not match other base", "a.notexample.com", ""},
		{"exact match", "exact.test", "exact.test"},
		{"exact wins over wildcard", "exact.example.com", "*.example.com"},
		{"port does not block match", "a.example.com:8443", "*.example.com"},
		{"unmatched", "random.org", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := matchWatchHost(entries, host(tc.query))
			if tc.want == "" {
				if ok {
					t.Fatalf("unexpected match: %+v", got)
				}
				return
			}
			if !ok || got.Identifier != tc.want {
				t.Fatalf("matchWatchHost(%q) = (%+v,%v), want identifier %q", tc.query, got, ok, tc.want)
			}
		})
	}
}

func TestNormalizeScopeIdentifierRejectsPunycodeHost(t *testing.T) {
	got, ok := normalizeScopeIdentifier("BÜCHER.example")
	if !ok || got != "xn--bcher-kva.example" {
		t.Fatalf("punycode = (%q,%v), want xn--bcher-kva.example", got, ok)
	}
}

func TestLoadWatchEligibleScopeSkipsNonWebAssets(t *testing.T) {
	db, err := database.New(filepath.Join(t.TempDir(), "watch-scope.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO targets(id,domain) VALUES('target-1','acme.test')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO bounty_programs(id,provider,external_id,handle,name) VALUES('program-1','hackerone','p1','acme','Acme')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO project_programs(target_id,program_id) VALUES('target-1','program-1')`); err != nil {
		t.Fatal(err)
	}
	assets := []struct{ id, identifier, assetType string }{
		{"a-store", "https://play.google.com/store/apps/details?id=com.example", "app_store"},
		{"a-android", "com.example.app", "android"},
		{"a-note", "Third Party Marketplace Apps", "other"},
		{"a-ip", "192.0.2.10", "ip"},
		{"a-web", "*.acme.test", "wildcard"},
	}
	for _, a := range assets {
		if _, err := db.Exec(`INSERT INTO bounty_program_assets(id,program_id,external_id,identifier,asset_type) VALUES(?,?,'ext-?' || ?,?,?)`,
			a.id, "program-1", a.id, a.identifier, a.assetType); err != nil {
			t.Fatal(err)
		}
	}
	entries, linked, err := LoadWatchEligibleScope(ctx, db, "target-1")
	if err != nil {
		t.Fatal(err)
	}
	if !linked {
		t.Fatal("project must report a linked program")
	}
	if len(entries) != 1 || entries[0].Identifier != "*.acme.test" {
		t.Fatalf("eligible scope=%+v, want only *.acme.test", entries)
	}
}
