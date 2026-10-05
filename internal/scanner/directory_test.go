package scanner

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
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

// TestCredibleSensitiveBackupCatchesSecretsByContentNotExtension proves the
// false negative this fix closes: detectFileType has no case for .json/.yaml/
// .xml/no-extension (they become "json"/"yaml"/"xml"/"unknown"), and the
// switch in credibleSensitiveBackup has no case for any of those either — so
// a real leaked-secret dump served as /secrets.json, /serviceaccount.json,
// /kubeconfig, /id_rsa etc. (all already requested by backupPatterns/
// backup_magic.go) could never become a finding no matter what it contained.
// A genuine credential-shaped body must now be credible regardless of
// extension, while an ordinary JSON/YAML response at the same path types must
// still be rejected (the false positive credibleSensitiveBackup exists to
// kill).
func TestCredibleSensitiveBackupCatchesSecretsByContentNotExtension(t *testing.T) {
	awsCreds := []byte(`{"aws_access_key_id":"AKIAIOSFODNN7EXAMPLE","aws_secret_access_key":"x"}`)
	if got := detectFileType("/secrets.json", awsCreds); got != "json" {
		t.Fatalf("expected detectFileType to classify a .json path as json, got %q", got)
	}
	if !credibleSensitiveBackup("json", awsCreds, "") {
		t.Fatal("a real AWS access key in a .json response must be credible regardless of extension")
	}

	serviceAccountKey := []byte(`{"type":"service_account","project_id":"x"}`)
	if !credibleSensitiveBackup("json", serviceAccountKey, "") {
		t.Fatal("a GCP service-account JSON dump must be credible")
	}

	privateKey := []byte("-----BEGIN RSA PRIVATE KEY-----\nMIIBOgIBAAJBAK...\n-----END RSA PRIVATE KEY-----")
	if got := detectFileType("/id_rsa", privateKey); got != "unknown" {
		t.Fatalf("expected a no-extension path to classify as unknown, got %q", got)
	}
	if !credibleSensitiveBackup("unknown", privateKey, "") {
		t.Fatal("a real private key at a no-extension path (e.g. /id_rsa) must be credible")
	}

	kubeconfigSecret := []byte("apiVersion: v1\nkind: Config\nusers:\n- user:\n    token: eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ4In0.abc123def456")
	if !credibleSensitiveBackup("yaml", kubeconfigSecret, "") {
		t.Fatal("a kubeconfig-shaped YAML body carrying a real JWT must be credible")
	}

	// Negative controls: an ORDINARY API/JSON response at the same path types
	// must still be rejected — the whole point is content, not extension.
	ordinaryJSON := []byte(`{"status":"ok","items":[1,2,3],"page":1}`)
	if credibleSensitiveBackup("json", ordinaryJSON, "") {
		t.Fatal("an ordinary JSON API response must NOT be reported as a leaked secret")
	}
	ordinaryYAML := []byte("name: my-app\nversion: 1.2.3\ndescription: a normal service\n")
	if credibleSensitiveBackup("yaml", ordinaryYAML, "") {
		t.Fatal("an ordinary YAML manifest must NOT be reported as a leaked secret")
	}
	shortJunk := []byte(`{"ok":true}`)
	if credibleSensitiveBackup("json", shortJunk, "") {
		t.Fatal("trivially short JSON must NOT be reported as a leaked secret")
	}
}

// TestCheckMagicBytesRecognizesJKS proves a leaked Java KeyStore (already
// requested by backupPatterns as /keystore.jks) is magic-confirmed — before
// this fix it had neither a magic signature nor a detectFileType/
// credibleSensitiveBackup case, so a real hit could never be reported despite
// carrying TLS/signing private keys.
func TestCheckMagicBytesRecognizesJKS(t *testing.T) {
	jks := append([]byte("\xfe\xed\xfe\xed\x00\x00\x00\x02"), bytes.Repeat([]byte{0}, 32)...)
	if got := checkMagicBytes(jks); got != "Java KeyStore (JKS)" {
		t.Fatalf("checkMagicBytes(JKS) = %q, want %q", got, "Java KeyStore (JKS)")
	}
	if got := checkMagicBytes([]byte("not a keystore at all")); got != "" {
		t.Fatalf("checkMagicBytes(plain text) = %q, want empty", got)
	}
}

func TestBackupDiscoveryFindsBackDotEnv(t *testing.T) {
	withLoopbackAllowed(t)
	body := "DB_PASSWORD=s3cr3t\nAPI_KEY=0123456789abcdef\n"
	var requestOrdinal atomic.Int64
	var findingOrdinal atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ordinal := requestOrdinal.Add(1)
		if r.URL.Path != "/back/.env" {
			http.NotFound(w, r)
			return
		}
		findingOrdinal.CompareAndSwap(0, ordinal)
		if got := r.Header.Get("Range"); got != "bytes=0-262143" {
			t.Errorf("backup probe Range=%q", got)
		}
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Content-Range", fmt.Sprintf("bytes 0-%d/%d", len(body)-1, len(body)))
		w.WriteHeader(http.StatusPartialContent)
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
	// No injected corpus entry: this proves the default contextual plan itself
	// covers /back/.env, instead of merely testing a caller-provided exact path.
	if found := scanBackupCandidatesWithCorpus(context.Background(), db, "target", []string{srv.URL}, "example.test", nil, nil); found < 1 {
		t.Fatal("/back/.env was not discovered by the default plan")
	}
	// Two requests establish the soft-404 baseline; /back/.env is then in the
	// first high-signal batch rather than behind thousands of generic candidates.
	if got := findingOrdinal.Load(); got == 0 || got > 42 {
		t.Fatalf("/back/.env scheduled too late: request ordinal=%d", got)
	}
	var fileType string
	var status, size int
	if err := db.QueryRow(`SELECT file_type,status_code,content_length FROM backup_findings WHERE target_id='target' AND url=?`, srv.URL+"/back/.env").Scan(&fileType, &status, &size); err != nil {
		t.Fatal(err)
	}
	if fileType != "env_file" {
		t.Fatalf("stored file type=%q", fileType)
	}
	if status != http.StatusPartialContent || size != len(body) {
		t.Fatalf("stored status/size=%d/%d", status, size)
	}
}

func TestBackupResponseSizeUsesContentRangeWithoutDraining(t *testing.T) {
	resp := &http.Response{
		StatusCode:    http.StatusPartialContent,
		ContentLength: 256 * 1024,
		Header:        http.Header{"Content-Range": {"bytes 0-262143/987654321"}},
		Body:          io.NopCloser(bytes.NewReader(make([]byte, 1024*1024))),
	}
	if got := backupResponseSize(resp, 256*1024); got != 987654321 {
		t.Fatalf("size=%d", got)
	}
	remaining, _ := io.ReadAll(resp.Body)
	if len(remaining) != 1024*1024 {
		t.Fatal("backupResponseSize drained the response body")
	}

	unknown := &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Header: http.Header{}}
	if got := backupResponseSize(unknown, 12345); got != 12345 {
		t.Fatalf("unknown size=%d", got)
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
