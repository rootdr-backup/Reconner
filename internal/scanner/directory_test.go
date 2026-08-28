package scanner

import (
	"bytes"
	"io"
	"net/http"
	"testing"
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
