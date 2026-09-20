package api

import (
	"archive/zip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTargetArtifactArchiveIncludesDatasetsAndJavaScript(t *testing.T) {
	h, adminID := newIsoHandler(t)
	if _, err := h.db.Exec(`INSERT INTO targets(id,domain,owner_id) VALUES('artifact-target','example.test',?)`, adminID); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO backup_findings(id,target_id,url,file_type,status_code,content_length)
		VALUES('backup','artifact-target','https://example.test/back/.env','env',200,42)`); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO js_files(id,target_id,url,size,hash,analyzed)
		VALUES('js','artifact-target','https://example.test/assets/chunk.123.js',21,'old-hash',1)`); err != nil {
		t.Fatal(err)
	}
	screenshotRoot := t.TempDir()
	screenshotPath := filepath.Join(screenshotRoot, "page.png")
	if err := os.WriteFile(screenshotPath, []byte("fake-png"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := h.db.Exec(`INSERT INTO screenshots(id,target_id,url,file_path,width,height)
		VALUES('shot','artifact-target','https://example.test/',?,1280,720)`, screenshotPath); err != nil {
		t.Fatal(err)
	}

	dst := filepath.Join(t.TempDir(), "artifacts.zip")
	fetch := func(_ context.Context, scope, rawURL string) ([]byte, string, error) {
		if scope != "example.test" || rawURL != "https://example.test/assets/chunk.123.js" {
			t.Fatalf("unexpected fetch scope=%q url=%q", scope, rawURL)
		}
		return []byte(`window.reconner=true;`), rawURL, nil
	}
	if err := writeTargetArtifactArchive(context.Background(), h.db, dst, "artifact-target", "example.test", screenshotRoot, fetch); err != nil {
		t.Fatal(err)
	}

	reader, err := zip.OpenReader(dst)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	entries := make(map[string][]byte)
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatal(err)
		}
		data, err := io.ReadAll(rc)
		if err != nil {
			rc.Close()
			t.Fatal(err)
		}
		rc.Close()
		entries[file.Name] = data
	}
	if !strings.Contains(string(entries["data/backup_findings.json"]), "/back/.env") {
		t.Fatalf("backup dataset missing nested .env: %s", entries["data/backup_findings.json"])
	}
	if !strings.Contains(string(entries["javascript/index.json"]), "chunk.123.js") {
		t.Fatalf("JavaScript index missing source URL: %s", entries["javascript/index.json"])
	}
	var manifest artifactManifest
	if err := json.Unmarshal(entries["manifest.json"], &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.JavaScript.Included != 1 || manifest.JavaScript.Failed != 0 || manifest.DatasetCounts["backup_findings"] != 1 {
		t.Fatalf("unexpected manifest: %+v", manifest)
	}
	if manifest.Screenshots.Included != 1 || len(manifest.Screenshots.Files) != 1 || string(entries[manifest.Screenshots.Files[0].ArchivePath]) != "fake-png" {
		t.Fatalf("screenshot artifact missing: %+v", manifest.Screenshots)
	}
	var foundJS bool
	for name, body := range entries {
		if strings.HasPrefix(name, "javascript/") && name != "javascript/index.json" && string(body) == `window.reconner=true;` {
			foundJS = true
		}
	}
	if !foundJS {
		t.Fatal("archive did not include fetched JavaScript content")
	}
}
