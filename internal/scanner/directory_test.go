package scanner

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/recon-platform/internal/database"
)

func TestRealSizeUsesContentLength(t *testing.T) {
	// server reports a 5 MB file but we only read 64 KB → real size must be 5 MB.
	resp := &http.Response{ContentLength: 5 * 1024 * 1024, Header: http.Header{}}
	if got := realSize(resp, 64*1024); got != 5*1024*1024 {
		t.Fatalf("must use Content-Length: got %d", got)
	}
	// header-based Content-Length when ContentLength field is -1 (unknown)
	resp2 := &http.Response{ContentLength: -1, Header: http.Header{"Content-Length": {"1048576"}}}
	if got := realSize(resp2, 1000); got != 1048576 {
		t.Fatalf("must parse Content-Length header: got %d", got)
	}
	// no header → fall back to body length
	resp3 := &http.Response{ContentLength: -1, Header: http.Header{}}
	if got := realSize(resp3, 4321); got != 4321 {
		t.Fatalf("fallback to body len: got %d", got)
	}
}

func TestShortNestedEnvIsCredibleWithoutMinimumSizeHeuristic(t *testing.T) {
	body := []byte("DB_PASSWORD=s3cr3t\nAPI_KEY=0123456789abcdef\n")
	if len(body) >= 100 {
		t.Fatal("fixture must exercise the former short-body false negative")
	}
	if got := detectFileType("/back/.env", body); got != "env_file" {
		t.Fatalf("file type=%q", got)
	}
	if !credibleSensitiveBackup("env_file", body, "") {
		t.Fatal("short, high-signal .env content was rejected")
	}
	if credibleSensitiveBackup("env_file", []byte("hello from the app"), "") {
		t.Fatal("generic text must not be accepted only because the path ends in .env")
	}
	if credibleSensitiveBackup("archive", []byte("not really a zip"), "") {
		t.Fatal("archive extension without a file signature must be rejected")
	}
}

func TestBackupDiscoveryFindsBackDotEnv(t *testing.T) {
	withLoopbackAllowed(t)
	body := "DB_PASSWORD=s3cr3t\nAPI_KEY=0123456789abcdef\n"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/back/.env" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, body)
	}))
	defer srv.Close()

	db, err := database.New(filepath.Join(t.TempDir(), "backup.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO targets (id,domain) VALUES ('target','example.test')`); err != nil {
		t.Fatal(err)
	}
	if found := scanBackupCandidatesWithCorpus(context.Background(), db, "target", []string{srv.URL}, "example.test", []string{"/back/.env"}); found < 1 {
		t.Fatal("/back/.env was not discovered")
	}
	var fileType string
	if err := db.QueryRow(`SELECT file_type FROM backup_findings WHERE target_id='target' AND url=?`, srv.URL+"/back/.env").Scan(&fileType); err != nil {
		t.Fatal(err)
	}
	if fileType != "env_file" {
		t.Fatalf("stored file type=%q", fileType)
	}
}

func TestTrueSizeStreamCountsChunked(t *testing.T) {
	// chunked response: NO Content-Length, ContentLength == -1. We already read
	// 64 KB into the body; the remaining bytes must be stream-counted, so the
	// reported size is the FULL resource, not the 64 KB read cap.
	total := 5 * 1024 * 1024
	already := 64 * 1024
	remainder := total - already
	resp := &http.Response{
		ContentLength: -1,
		Header:        http.Header{},
		Body:          io.NopCloser(bytes.NewReader(make([]byte, remainder))),
	}
	if got := trueSize(resp, already); got != total {
		t.Fatalf("chunked size must stream-count to full size: got %d want %d", got, total)
	}
	// Content-Length present → use it directly, never drain.
	resp2 := &http.Response{ContentLength: 9 * 1024 * 1024, Header: http.Header{}}
	if got := trueSize(resp2, already); got != 9*1024*1024 {
		t.Fatalf("must trust Content-Length: got %d", got)
	}
}

func TestSensitiveBackupTypeFPGuard(t *testing.T) {
	// genuinely sensitive → allowed as a backup finding
	for _, ft := range []string{"sql_dump", "archive", "env_file", "git_repo", "backup", "log_file", "config"} {
		if !sensitiveBackupType(ft) {
			t.Errorf("%s must be treated as sensitive", ft)
		}
	}
	// noisy web assets → NOT backups (the false-positive class)
	for _, ft := range []string{"json", "xml", "yaml", "unknown"} {
		if sensitiveBackupType(ft) {
			t.Errorf("%s must NOT be reported as a backup (false positive)", ft)
		}
	}
}
