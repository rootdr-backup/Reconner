package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
)

func TestSemverGreater(t *testing.T) {
	t.Parallel()
	tests := []struct {
		a, b string
		want bool
	}{
		{"1.1.0", "1.0.9", true},
		{"2.0.0", "1.99.99", true},
		{"1.0.0", "1.0.0", false},
		{"1.0.0-rc.2", "1.0.0-rc.1", true},
		{"1.0.0", "1.0.0-rc.9", true},
		{"1.0.0-rc.1", "1.0.0", false},
		{"v1.2.3+build.4", "1.2.2", true},
		{"dev", "1.0.0", false},
		{"1.2", "1.1.9", false},
		{"01.2.3", "1.2.2", false},
	}
	for _, tt := range tests {
		if got := semverGreater(tt.a, tt.b); got != tt.want {
			t.Errorf("semverGreater(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
		}
	}
}

func TestReleaseCheckerCachesAndRevalidatesWithETag(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-GitHub-Api-Version") != "2022-11-28" {
			t.Errorf("missing GitHub API version header")
		}
		if r.Header.Get("If-None-Match") == `"release-1"` {
			w.Header().Set("ETag", `"release-1"`)
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"release-1"`)
		_, _ = w.Write([]byte(`{
			"tag_name":"v1.1.0","name":"Reconner 1.1.0",
			"html_url":"https://github.com/rootdr-backup/Reconner/releases/tag/v1.1.0",
			"body":"Faster and sharper.","published_at":"2026-08-30T10:00:00Z"
		}`))
	}))
	defer server.Close()

	c := newReleaseChecker()
	c.apiBase = server.URL
	cfg := &config.Config{GitHubRepo: "rootdr-backup/Reconner"}

	first := c.check(context.Background(), cfg, false)
	if first.Latest != "1.1.0" {
		t.Fatalf("unexpected first result: %+v", first)
	}
	second := c.check(context.Background(), cfg, false)
	if calls.Load() != 1 {
		t.Fatalf("fresh cache made %d upstream calls, want 1", calls.Load())
	}
	if second.Latest != first.Latest {
		t.Fatalf("cached latest = %q, want %q", second.Latest, first.Latest)
	}

	c.mu.Lock()
	c.checked = time.Now().Add(-updateTTL - time.Minute)
	c.mu.Unlock()
	revalidated := c.check(context.Background(), cfg, false)
	if calls.Load() != 2 {
		t.Fatalf("ETag refresh made %d upstream calls, want 2", calls.Load())
	}
	if revalidated.Latest != "1.1.0" || revalidated.Stale || revalidated.Error != "" {
		t.Fatalf("unexpected revalidated result: %+v", revalidated)
	}
}

func TestReleaseCheckerCoalescesConcurrentRequests(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		_, _ = w.Write([]byte(`{"tag_name":"v1.1.0"}`))
	}))
	defer server.Close()

	c := newReleaseChecker()
	c.apiBase = server.URL
	cfg := &config.Config{GitHubRepo: "rootdr-backup/Reconner"}
	done := make(chan struct{}, 12)
	for i := 0; i < cap(done); i++ {
		go func() {
			_ = c.check(context.Background(), cfg, false)
			done <- struct{}{}
		}()
	}
	for i := 0; i < cap(done); i++ {
		<-done
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent checks made %d upstream calls, want 1", calls.Load())
	}
}
