package scanner

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

func TestValidVCSMetadataRejectsLengthOnlyNoise(t *testing.T) {
	tests := []struct {
		vcs, path, body string
		want            bool
	}{
		{"git", "/.git/HEAD", "ref: refs/heads/main\n", true},
		{"git", "/.git/HEAD", "ok", false},
		{"git", "/.git/config", "[core]\nrepositoryformatversion = 0\nfilemode = true\n", true},
		{"git", "/.git/config", "[core] documentation example", false},
		{"svn", "/.svn/wc.db", "SQLite format 3\x00rest", true},
		{"svn", "/.svn/entries", "12\ndir\n", true},
		{"svn", "/.svn/entries", "dir", false},
		{"svn", "/.svn/entries", "ok", false},
		{"hg", "/.hg/requires", "revlogv1\nstore\nfncache\n", true},
		{"hg", "/.hg/requires", "ok", false},
		{"bzr", "/.bzr/branch-format", "Bazaar-NG branch format 7\n", true},
		{"bzr", "/.bzr/branch-format", "Bazaar documentation", false},
		{"hg", "/.hg/requires", "<!doctype html><html>revlogv1</html>", false},
	}
	for _, tc := range tests {
		if got := validVCSMetadata(tc.vcs, tc.path, []byte(tc.body)); got != tc.want {
			t.Errorf("validVCSMetadata(%s,%s,%q)=%v, want %v", tc.vcs, tc.path, tc.body, got, tc.want)
		}
	}
}

func TestGitExposureUsesNativeSignatureAndSoft404Baseline(t *testing.T) {
	withLoopbackAllowed(t)
	catchAll := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer catchAll.Close()

	realGit := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		if r.URL.Path == "/.git/HEAD" {
			_, _ = w.Write([]byte("ref: refs/heads/main\n"))
			return
		}
		w.WriteHeader(http.StatusNotFound)
		_, _ = w.Write([]byte("not found"))
	}))
	defer realGit.Close()

	db, targetID := newV3ScannerDB(t)
	for _, base := range []string{catchAll.URL, realGit.URL} {
		if _, err := db.Exec(`INSERT INTO http_services (id,target_id,url,status_code,source)
			VALUES (?,?,?,200,'v3-lab')`, uuid.NewString(), targetID, base); err != nil {
			t.Fatal(err)
		}
	}
	cfg := &config.Config{}
	s := NewExposureScanner(db, tools.NewExecutor(cfg, logger.New("error")), cfg, logger.New("error"), nil)
	if err := s.runGitExposure(context.Background(), targetID, func(_, _, _ string) {}); err != nil {
		t.Fatal(err)
	}
	var realCount, noiseCount int
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type='exposed_git' AND url LIKE ?`, targetID, realGit.URL+"%").Scan(&realCount); err != nil {
		t.Fatal(err)
	}
	if err := db.QueryRow(`SELECT COUNT(*) FROM vuln_findings WHERE target_id=? AND type LIKE 'exposed_%' AND url LIKE ?`, targetID, catchAll.URL+"%").Scan(&noiseCount); err != nil {
		t.Fatal(err)
	}
	if realCount != 1 {
		t.Fatalf("native .git HEAD findings=%d, want 1", realCount)
	}
	if noiseCount != 0 {
		t.Fatalf("tiny 200 catch-all VCS findings=%d, want 0", noiseCount)
	}
}
