package scheduler

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

func TestIssue7SubdomainRootsCoverEveryManagedAsset(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES ('issue7','stale.example.org')`); err != nil {
		t.Fatal(err)
	}
	assets := []struct{ id, value string }{
		{"a", "https://alpha.example.com:8443/app?q=1"},
		{"b", "*.beta.example.net"},
		{"c", "alpha.example.com"}, // duplicate root in another representation
		{"d", "10.0.0.0/24"},       // network assets are not DNS-enumerable roots
		{"e", "192.0.2.10"},
	}
	for _, asset := range assets {
		if _, err := s.db.Exec(`INSERT INTO assets (id,target_id,name,value,kind) VALUES (?,'issue7','',?,'web')`, asset.id, asset.value); err != nil {
			t.Fatal(err)
		}
	}

	got := s.loadSubdomainRoots(context.Background(), "issue7", "stale.example.org", "")
	want := []string{"alpha.example.com", "beta.example.net"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("target-level roots=%v, want every managed domain asset %v", got, want)
	}

	// A per-asset task remains pinned and must never leak into sibling assets.
	got = s.loadSubdomainRoots(context.Background(), "issue7", "stale.example.org", "https://only.example.io/path")
	want = []string{"only.example.io"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("scoped roots=%v, want %v", got, want)
	}
}

func TestIssue7SubdomainFanoutContinuesAfterOneAssetFails(t *testing.T) {
	roots := []string{"one.example", "two.example", "three.example"}
	var called []string
	err := runSubdomainRootFanout(context.Background(), roots, func(string, string, string) {}, func(root string) error {
		called = append(called, root)
		if root == "two.example" {
			return errors.New("provider timeout")
		}
		return nil
	})
	if err == nil {
		t.Fatal("aggregate run must preserve an asset error")
	}
	if !reflect.DeepEqual(called, roots) {
		t.Fatalf("fan-out called=%v, want all roots %v", called, roots)
	}
}
