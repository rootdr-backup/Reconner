package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func TestDirectoryRedirectsStayOnOriginalHost(t *testing.T) {
	start, _ := http.NewRequest("GET", "https://app.example.com/start", nil)
	external, _ := http.NewRequest("GET", "https://outside.example.net/next", nil)
	if err := dirHTTPClient.CheckRedirect(external, []*http.Request{start}); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("cross-host redirect was not stopped: %v", err)
	}
	sameHost, _ := http.NewRequest("GET", "https://app.example.com/next", nil)
	if err := dirHTTPClient.CheckRedirect(sameHost, []*http.Request{start}); err != nil {
		t.Fatalf("same-host redirect was unexpectedly stopped: %v", err)
	}
}

func TestDirectoryToolConcurrencyRespectsGlobalBudget(t *testing.T) {
	tests := []struct {
		rate, hosts, want int
	}{
		{150, 6, 12},
		{20, 10, 1},
		{2000, 1, 20},
	}
	for _, tt := range tests {
		s := &DirScanner{cfg: &config.Config{
			Workers: config.WorkerConfig{DirectoryDiscovery: tt.hosts},
			Limits:  config.ResourceLimits{HTTPRateLimit: tt.rate},
		}}
		if got := s.directoryToolThreads(); got != tt.want {
			t.Errorf("rate=%d hosts=%d: threads=%d want %d", tt.rate, tt.hosts, got, tt.want)
		}
	}
	if isDirectoryFindingStatus(500) || isDirectoryFindingStatus(429) {
		t.Fatal("server/rate-limit errors must not become directory findings")
	}
	if sameDirectoryServiceHost("https://app.example.com", "https://evil.example.net/path") {
		t.Fatal("external tool output must not redirect revalidation to another host")
	}
	if !sameDirectoryServiceHost("http://app.example.com:80", "https://APP.example.com/path") {
		t.Fatal("same hostname across an HTTP-to-HTTPS service redirect should remain valid")
	}
	for _, status := range []int{200, 204, 301, 401, 403, 405} {
		if !isDirectoryFindingStatus(status) {
			t.Errorf("legitimate discovery status %d was rejected", status)
		}
	}
}

func TestExternalDirectoryHitsPassSharedSoft404Gate(t *testing.T) {
	shell := []byte(`<html><head><title>Catch All</title></head><body>same shell</body></html>`)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		if r.URL.Path == "/real" {
			_, _ = io.WriteString(w, `<html><head><title>Real Admin</title></head><body>distinct endpoint</body></html>`)
			return
		}
		_, _ = w.Write(shell)
	}))
	defer srv.Close()

	db, targetID := testDB(t)
	defer db.Close()
	toolDir := t.TempDir()
	cfg := &config.Config{
		ToolsDir: toolDir,
		Workers:  config.WorkerConfig{DirectoryDiscovery: 1},
		Limits:   config.ResourceLimits{HTTPRateLimit: 40, MaxToolExecutions: 2},
	}
	log := logger.NewWithWriter("error", io.Discard)
	exec := tools.NewExecutor(cfg, log)
	s := NewDirScanner(db, exec, cfg, log)
	baseline := soft404Baseline(context.Background(), srv.URL)

	dirsearch := "#!/bin/sh\nprintf '[00:00:00] 200 - 100B - /ghost\\n'\nprintf '[00:00:01] 200 - 100B - /real\\n'\nprintf '[00:00:02] 500 - 100B - /error\\n'\n"
	if err := os.WriteFile(filepath.Join(toolDir, "dirsearch"), []byte(dirsearch), 0o700); err != nil {
		t.Fatal(err)
	}
	ferox := fmt.Sprintf("#!/bin/sh\nprintf '200 GET 100 1 1 %s/ghost\\n'\nprintf '200 GET 100 1 1 %s/real\\n'\nprintf '500 GET 100 1 1 %s/error\\n'\n", srv.URL, srv.URL, srv.URL)
	if err := os.WriteFile(filepath.Join(toolDir, "feroxbuster"), []byte(ferox), 0o700); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	s.runDirsearch(ctx, targetID, srv.URL, baseline, func(string, string, string) {})
	s.runFeroxbuster(ctx, targetID, srv.URL, baseline, func(string, string, string) {})

	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM directory_findings WHERE target_id=?`, targetID).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("external hits bypassed soft-404/status gate: rows=%d want 1", count)
	}
	var foundURL string
	if err := db.QueryRow(`SELECT url FROM directory_findings WHERE target_id=?`, targetID).Scan(&foundURL); err != nil {
		t.Fatal(err)
	}
	if foundURL != srv.URL+"/real" {
		t.Fatalf("stored URL=%q want real endpoint", foundURL)
	}
}
