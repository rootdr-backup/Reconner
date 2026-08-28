package scanner

import (
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"io/fs"
	"os"
	"path/filepath"
)

// Reconner ships its OWN curated nuclei template pack (high-signal exposure /
// misconfiguration checks) embedded in the binary. They are materialized to
// disk once and passed to nuclei via an extra -t so they ALWAYS run alongside
// whatever official/community templates the operator has — no network, no git,
// no separate install step. Every template is authored + reviewed here (not an
// unvetted third-party repo), so the supply-chain surface is just this folder.

//go:embed nucleitemplates/*.yaml
var reconnerTemplateFS embed.FS

// materializeReconnerTemplates writes the embedded pack into
// <dataDir>/nuclei-reconner-pack and returns that directory. A file is only
// rewritten when its content changed (checked by hash), so repeated scans don't
// churn the disk. Returns "" if nothing could be written.
func materializeReconnerTemplates(dataDir string) string {
	if dataDir == "" {
		dataDir = os.TempDir()
	}
	dir := filepath.Join(dataDir, "nuclei-reconner-pack")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return ""
	}
	entries, err := reconnerTemplateFS.ReadDir("nucleitemplates")
	if err != nil {
		return ""
	}
	wrote := 0
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := reconnerTemplateFS.ReadFile("nucleitemplates/" + e.Name())
		if err != nil {
			continue
		}
		dst := filepath.Join(dir, e.Name())
		if sameFileContent(dst, data) {
			wrote++
			continue
		}
		if os.WriteFile(dst, data, 0o644) == nil {
			wrote++
		}
	}
	if wrote == 0 {
		return ""
	}
	return dir
}

// sameFileContent reports whether the file at path already holds exactly data.
func sameFileContent(path string, data []byte) bool {
	existing, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	h1 := sha256.Sum256(existing)
	h2 := sha256.Sum256(data)
	return hex.EncodeToString(h1[:]) == hex.EncodeToString(h2[:])
}

// reconnerTemplateCount reports how many templates are embedded (for logging).
func reconnerTemplateCount() int {
	n := 0
	_ = fs.WalkDir(reconnerTemplateFS, "nucleitemplates", func(_ string, d fs.DirEntry, err error) error {
		if err == nil && !d.IsDir() {
			n++
		}
		return nil
	})
	return n
}
