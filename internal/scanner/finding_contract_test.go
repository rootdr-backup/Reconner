package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A detector writing vuln_findings directly bypasses candidate identity,
// verification states, transition audit and sticky terminal guards. Keep this as
// an architectural invariant so future modules cannot silently reintroduce the
// split lifecycle.
func TestProductionDetectorsCannotWriteFindingProjectionDirectly(t *testing.T) {
	for _, dir := range []string{".", "../api"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatal(err)
		}
		for _, entry := range entries {
			name := entry.Name()
			if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") || (dir == "." && name == "finding_lifecycle.go") {
				continue
			}
			path := filepath.Join(dir, name)
			body, err := os.ReadFile(filepath.Clean(path))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(strings.ToLower(string(body)), "insert into vuln_findings") {
				t.Fatalf("%s bypasses the canonical candidate/finding lifecycle", path)
			}
		}
	}
}
