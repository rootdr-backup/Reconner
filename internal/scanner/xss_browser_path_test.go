package scanner

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestBrowserBinaryWorksRejectsStaleWrapper(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("shell fixture is Unix-only")
	}
	dir := t.TempDir()
	good := filepath.Join(dir, "good-chrome")
	bad := filepath.Join(dir, "stale-chromium")
	if err := os.WriteFile(good, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(bad, []byte("#!/bin/sh\nexec /definitely/missing/chromium \"$@\"\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if !browserBinaryWorks(good) {
		t.Fatal("working browser command was rejected")
	}
	if browserBinaryWorks(bad) {
		t.Fatal("stale browser wrapper was accepted")
	}
}
