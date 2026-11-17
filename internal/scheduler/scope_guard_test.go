package scheduler

import (
	"context"
	"reflect"
	"testing"
)

func TestStoreAssetsAreNotScannableRoots(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES ('sg1','fallback.example.org')`); err != nil {
		t.Fatal(err)
	}
	assets := []struct{ id, value string }{
		{"g1", "https://play.google.com/store/apps/details?id=com.example"},
		{"g2", "https://apps.apple.com/us/app/example/id123456789"},
		{"g3", "example.com"},
	}
	for _, a := range assets {
		if _, err := s.db.Exec(`INSERT INTO assets (id,target_id,name,value,kind,approval_status) VALUES (?,'sg1','',?,'web','approved')`, a.id, a.value); err != nil {
			t.Fatal(err)
		}
	}

	seeds := s.loadProjectWebSeeds(context.Background(), "sg1")
	if want := []string{"example.com"}; !reflect.DeepEqual(seeds, want) {
		t.Fatalf("web seeds=%v, want %v", seeds, want)
	}

	roots := s.loadSubdomainRoots(context.Background(), "sg1", "fallback.example.org", "")
	if want := []string{"example.com"}; !reflect.DeepEqual(roots, want) {
		t.Fatalf("subdomain roots=%v, want %v", roots, want)
	}
}

func TestNormalizeSubdomainRootsDropsStoreValues(t *testing.T) {
	got := normalizeSubdomainRoots([]string{
		"https://play.google.com/store/apps/details?id=com.example",
		"apps.apple.com",
		"apple.com",
		"example.com",
	})
	want := []string{"apple.com", "example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("normalizeSubdomainRoots=%v, want %v", got, want)
	}
}

func TestStoreOnlyFallbackScopeReturnsNoRoots(t *testing.T) {
	s := newTestScheduler(t)
	if _, err := s.db.Exec(`INSERT INTO targets (id,domain) VALUES ('sg2','play.google.com')`); err != nil {
		t.Fatal(err)
	}
	roots := s.loadSubdomainRoots(context.Background(), "sg2", "play.google.com", "")
	if len(roots) != 0 {
		t.Fatalf("store-only fallback roots=%v, want empty", roots)
	}
}
