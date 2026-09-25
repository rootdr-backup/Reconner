package api

import (
	"archive/zip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/scanner"
)

const (
	artifactExportTimeout  = 3 * time.Minute
	artifactJSWorkers      = 6
	artifactMaxJSFiles     = 2000
	artifactMaxJSTotalSize = 256 << 20
	artifactMaxScreenshot  = 20 << 20
	artifactMaxScreenshots = 128 << 20
)

type artifactJSFetcher func(context.Context, string, string) ([]byte, string, error)

type artifactDataset struct {
	Name  string
	Query string
	Args  []any
}

type artifactJSFile struct {
	URL         string `json:"url"`
	FinalURL    string `json:"final_url,omitempty"`
	ArchivePath string `json:"archive_path,omitempty"`
	Hash        string `json:"sha256,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Error       string `json:"error,omitempty"`
	tempPath    string
}

type artifactManifest struct {
	FormatVersion int                  `json:"format_version"`
	GeneratedAt   time.Time            `json:"generated_at"`
	TargetID      string               `json:"target_id"`
	Target        string               `json:"target"`
	DatasetCounts map[string]int       `json:"dataset_counts"`
	JavaScript    artifactJSManifest   `json:"javascript"`
	Screenshots   artifactFileManifest `json:"screenshots"`
}

type artifactJSManifest struct {
	Discovered int              `json:"discovered"`
	Included   int              `json:"included"`
	Failed     int              `json:"failed"`
	Omitted    int              `json:"omitted"`
	Files      []artifactJSFile `json:"files"`
}

type artifactFileManifest struct {
	Discovered int                `json:"discovered"`
	Included   int                `json:"included"`
	Failed     int                `json:"failed"`
	Files      []artifactFileItem `json:"files"`
}

type artifactFileItem struct {
	ID          string `json:"id"`
	Kind        string `json:"kind"`
	Name        string `json:"name,omitempty"`
	ArchivePath string `json:"archive_path,omitempty"`
	Size        int64  `json:"size,omitempty"`
	Error       string `json:"error,omitempty"`
}

var artifactNameCleaner = regexp.MustCompile(`[^a-zA-Z0-9._-]+`)

func (h *Handler) handleTargetArtifacts(w http.ResponseWriter, r *http.Request) {
	targetID := mux.Vars(r)["id"]
	var domain string
	if err := h.db.QueryRowContext(r.Context(), `SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			h.writeError(w, http.StatusNotFound, "target not found")
			return
		}
		h.writeError(w, http.StatusInternalServerError, "failed to load target")
		return
	}

	tmp, err := os.CreateTemp("", "reconner-artifacts-*.zip")
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to prepare artifact bundle")
		return
	}
	tmpName := tmp.Name()
	_ = tmp.Close()
	defer os.Remove(tmpName)

	ctx, cancel := context.WithTimeout(r.Context(), artifactExportTimeout)
	defer cancel()
	ctx = scanner.WithTargetRequestIdentity(ctx, h.db, h.cfg, targetID)
	if err := writeTargetArtifactArchive(ctx, h.db, tmpName, targetID, domain, h.cfg.ScreenshotsDir, scanner.FetchJSArtifact); err != nil {
		h.logger.Error("Target artifact export failed", "target_id", targetID, "error", err)
		h.writeError(w, http.StatusInternalServerError, "failed to build artifact bundle")
		return
	}

	f, err := os.Open(tmpName) // #nosec G304 -- tmpName was created above and never accepts user input.
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to open artifact bundle")
		return
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		h.writeError(w, http.StatusInternalServerError, "failed to read artifact bundle")
		return
	}
	filename := "reconner-" + safeArtifactName(domain) + "-artifacts.zip"
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, filename))
	w.Header().Set("Cache-Control", "no-store")
	http.ServeContent(w, r, filename, info.ModTime(), f)
}

func writeTargetArtifactArchive(ctx context.Context, db *database.DB, dst, targetID, domain, screenshotRoot string, fetch artifactJSFetcher) (retErr error) {
	f, err := os.OpenFile(dst, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600) // #nosec G304 -- caller supplies a server-created temporary path.
	if err != nil {
		return err
	}
	defer func() {
		if err := f.Close(); retErr == nil && err != nil {
			retErr = err
		}
	}()
	zw := zip.NewWriter(f)
	defer func() {
		if err := zw.Close(); retErr == nil && err != nil {
			retErr = err
		}
	}()

	manifest := artifactManifest{
		FormatVersion: 1,
		GeneratedAt:   time.Now().UTC(),
		TargetID:      targetID,
		Target:        domain,
		DatasetCounts: make(map[string]int),
	}
	for _, dataset := range targetArtifactDatasets(targetID) {
		count, err := writeQueryJSON(ctx, zw, "data/"+dataset.Name+".json", db, dataset.Query, dataset.Args...)
		if err != nil {
			return fmt.Errorf("export %s: %w", dataset.Name, err)
		}
		manifest.DatasetCounts[dataset.Name] = count
	}
	screenshotManifest, err := exportScreenshotArtifacts(ctx, zw, db, targetID, screenshotRoot)
	if err != nil {
		return err
	}
	manifest.Screenshots = screenshotManifest

	jsManifest, err := exportJavaScriptArtifacts(ctx, zw, db, targetID, domain, fetch)
	if err != nil {
		return err
	}
	manifest.JavaScript = jsManifest
	if err := writeZipJSON(zw, "manifest.json", manifest); err != nil {
		return err
	}
	readme := "Reconner target artifact bundle\n\n" +
		"manifest.json maps included JavaScript and screenshot artifacts and records individual failures.\n" +
		"data/ contains the target's structured scan records. javascript/ contains bounded, in-scope snapshots fetched at export time.\n" +
		"screenshots/ contains bounded copies of screenshot files already owned by this target in configured storage.\n" +
		"This archive can contain vulnerability evidence and secrets discovered in target assets. Store it securely.\n"
	w, err := zw.Create("README.txt")
	if err != nil {
		return err
	}
	_, err = io.WriteString(w, readme)
	return err
}

func targetArtifactDatasets(targetID string) []artifactDataset {
	byTarget := []string{
		"assets", "network_hosts", "network_services", "evidence", "http_interactions",
		"objects", "actions", "object_relationships", "workflow_variables", "authorization_observations",
		"hypotheses", "state_snapshots", "capture_sessions", "request_templates",
		"candidates", "candidate_transitions", "subdomains", "http_services", "js_files", "js_findings",
		"parameters", "directory_findings", "admin_panel_findings", "backup_findings", "open_redirect_findings", "nuclei_findings",
		"monitoring_changes", "vuln_findings", "blind_xss_probes", "oob_probes", "open_ports",
	}
	datasets := make([]artifactDataset, 0, len(byTarget)+5)
	datasets = append(datasets, artifactDataset{
		Name: "target",
		Query: `SELECT id,domain,name,kind,description,tags,priority,notes,status,scan_status,
			enabled_modules,exclude_scope,scope,last_scan_at,created_at,updated_at,subdomain_count,
			alive_host_count,finding_count,monitor_enabled,monitor_interval_hours,monitor_last_run
			FROM targets WHERE id=?`,
		Args: []any{targetID},
	})
	for _, table := range byTarget {
		datasets = append(datasets, artifactDataset{
			Name:  table,
			Query: `SELECT * FROM ` + table + ` WHERE target_id=? ORDER BY rowid`, // #nosec G202 -- table comes only from the fixed list above.
			Args:  []any{targetID},
		})
	}
	datasets = append(datasets,
		artifactDataset{Name: "screenshots", Query: `SELECT id,target_id,url,width,height,created_at FROM screenshots WHERE target_id=? ORDER BY created_at`, Args: []any{targetID}},
		artifactDataset{Name: "captured_responses", Query: `SELECT r.* FROM captured_responses r JOIN request_templates q ON q.id=r.request_template_id WHERE q.target_id=? ORDER BY r.created_at`, Args: []any{targetID}},
		artifactDataset{Name: "tasks", Query: `SELECT * FROM tasks WHERE target_id=? ORDER BY created_at`, Args: []any{targetID}},
		artifactDataset{Name: "task_logs", Query: `SELECT l.* FROM task_logs l JOIN tasks t ON t.id=l.task_id WHERE t.target_id=? ORDER BY l.id`, Args: []any{targetID}},
		artifactDataset{Name: "task_phases", Query: `SELECT p.* FROM task_phases p JOIN tasks t ON t.id=p.task_id WHERE t.target_id=? ORDER BY p.task_id,p.phase_index`, Args: []any{targetID}},
		artifactDataset{Name: "browser_states", Query: `SELECT * FROM browser_states WHERE target_id=? ORDER BY url,sequence`, Args: []any{targetID}},
		artifactDataset{Name: "notifications", Query: `SELECT * FROM notifications WHERE target_id=? ORDER BY created_at`, Args: []any{targetID}},
	)
	return datasets
}

func exportScreenshotArtifacts(ctx context.Context, zw *zip.Writer, db *database.DB, targetID, root string) (artifactFileManifest, error) {
	rows, err := db.QueryContext(ctx, `SELECT id,file_path,thumbnail_path FROM screenshots WHERE target_id=? ORDER BY created_at`, targetID)
	if err != nil {
		return artifactFileManifest{}, err
	}
	defer rows.Close()
	type candidate struct{ id, kind, source string }
	var candidates []candidate
	for rows.Next() {
		var id, filePath, thumbnailPath string
		if err := rows.Scan(&id, &filePath, &thumbnailPath); err != nil {
			return artifactFileManifest{}, err
		}
		candidates = append(candidates, candidate{id: id, kind: "full", source: filePath})
		if strings.TrimSpace(thumbnailPath) != "" && thumbnailPath != filePath {
			candidates = append(candidates, candidate{id: id, kind: "thumbnail", source: thumbnailPath})
		}
	}
	if err := rows.Err(); err != nil {
		return artifactFileManifest{}, err
	}
	manifest := artifactFileManifest{Discovered: len(candidates), Files: make([]artifactFileItem, 0, len(candidates))}
	var totalSize int64
	for index, candidate := range candidates {
		item := artifactFileItem{ID: candidate.id, Kind: candidate.kind, Name: safeArtifactName(filepath.Base(candidate.source))}
		if err := ctx.Err(); err != nil {
			item.Error = compactArtifactError(err)
			manifest.Failed++
			manifest.Files = append(manifest.Files, item)
			continue
		}
		resolved, info, err := safeScreenshotArtifact(root, candidate.source)
		if err != nil {
			item.Error = compactArtifactError(err)
			manifest.Failed++
			manifest.Files = append(manifest.Files, item)
			continue
		}
		item.Size = info.Size()
		if totalSize+item.Size > artifactMaxScreenshots {
			item.Error = "bundle screenshot size limit reached"
			manifest.Failed++
			manifest.Files = append(manifest.Files, item)
			continue
		}
		item.ArchivePath = fmt.Sprintf("screenshots/%04d-%s-%s", index+1, candidate.kind, item.Name)
		if err := addFileToZip(zw, item.ArchivePath, resolved); err != nil {
			item.Error = compactArtifactError(err)
			item.ArchivePath = ""
			manifest.Failed++
		} else {
			totalSize += item.Size
			manifest.Included++
		}
		manifest.Files = append(manifest.Files, item)
	}
	return manifest, writeZipJSON(zw, "screenshots/index.json", manifest.Files)
}

func safeScreenshotArtifact(root, source string) (string, os.FileInfo, error) {
	if strings.TrimSpace(root) == "" || strings.TrimSpace(source) == "" {
		return "", nil, fmt.Errorf("screenshot storage path is unavailable")
	}
	rootPath, err := filepath.EvalSymlinks(root)
	if err != nil {
		return "", nil, fmt.Errorf("screenshot root unavailable")
	}
	sourcePath, err := filepath.EvalSymlinks(source)
	if err != nil {
		return "", nil, fmt.Errorf("screenshot file unavailable")
	}
	rel, err := filepath.Rel(rootPath, sourcePath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) || filepath.IsAbs(rel) {
		return "", nil, fmt.Errorf("screenshot path left configured storage")
	}
	info, err := os.Stat(sourcePath)
	if err != nil || !info.Mode().IsRegular() {
		return "", nil, fmt.Errorf("screenshot is not a regular file")
	}
	if info.Size() > artifactMaxScreenshot {
		return "", nil, fmt.Errorf("screenshot exceeds 20 MiB limit")
	}
	return sourcePath, info, nil
}

func writeQueryJSON(ctx context.Context, zw *zip.Writer, name string, db *database.DB, query string, args ...any) (int, error) {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		return 0, err
	}
	w, err := zw.Create(name)
	if err != nil {
		return 0, err
	}
	if _, err := io.WriteString(w, "[\n"); err != nil {
		return 0, err
	}
	count := 0
	for rows.Next() {
		values := make([]any, len(columns))
		dests := make([]any, len(columns))
		for i := range values {
			dests[i] = &values[i]
		}
		if err := rows.Scan(dests...); err != nil {
			return count, err
		}
		record := make(map[string]any, len(columns))
		for i, column := range columns {
			if raw, ok := values[i].([]byte); ok {
				record[column] = string(raw)
			} else {
				record[column] = values[i]
			}
		}
		encoded, err := json.Marshal(record)
		if err != nil {
			return count, err
		}
		if count > 0 {
			if _, err := io.WriteString(w, ",\n"); err != nil {
				return count, err
			}
		}
		if _, err := w.Write(encoded); err != nil {
			return count, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, err
	}
	_, err = io.WriteString(w, "\n]\n")
	return count, err
}

func exportJavaScriptArtifacts(ctx context.Context, zw *zip.Writer, db *database.DB, targetID, domain string, fetch artifactJSFetcher) (artifactJSManifest, error) {
	rows, err := db.QueryContext(ctx, `SELECT url FROM js_files WHERE target_id=? ORDER BY url`, targetID)
	if err != nil {
		return artifactJSManifest{}, err
	}
	var urls []string
	for rows.Next() {
		var rawURL string
		if err := rows.Scan(&rawURL); err != nil {
			rows.Close()
			return artifactJSManifest{}, err
		}
		urls = append(urls, rawURL)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return artifactJSManifest{}, err
	}

	manifest := artifactJSManifest{Discovered: len(urls)}
	if len(urls) > artifactMaxJSFiles {
		manifest.Omitted = len(urls) - artifactMaxJSFiles
		urls = urls[:artifactMaxJSFiles]
	}
	manifest.Files = make([]artifactJSFile, len(urls))
	tempDir, err := os.MkdirTemp("", "reconner-js-artifacts-*")
	if err != nil {
		return manifest, err
	}
	defer os.RemoveAll(tempDir)

	jobs := make(chan int)
	var wg sync.WaitGroup
	var sizeMu sync.Mutex
	var totalSize int64
	workers := artifactJSWorkers
	if len(urls) < workers {
		workers = len(urls)
	}
	for worker := 0; worker < workers; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				entry := artifactJSFile{URL: urls[i]}
				content, finalURL, fetchErr := fetch(ctx, domain, urls[i])
				if fetchErr != nil {
					entry.Error = compactArtifactError(fetchErr)
					manifest.Files[i] = entry
					continue
				}
				sizeMu.Lock()
				if totalSize+int64(len(content)) > artifactMaxJSTotalSize {
					sizeMu.Unlock()
					entry.Error = "bundle JavaScript size limit reached"
					manifest.Files[i] = entry
					continue
				}
				totalSize += int64(len(content))
				sizeMu.Unlock()

				digest := sha256.Sum256(content)
				entry.FinalURL = finalURL
				entry.Hash = hex.EncodeToString(digest[:])
				entry.Size = int64(len(content))
				entry.ArchivePath = artifactJSArchivePath(i, finalURL, digest)
				entry.tempPath = filepath.Join(tempDir, fmt.Sprintf("%04d.js", i))
				if err := os.WriteFile(entry.tempPath, content, 0o600); err != nil {
					entry.Error = compactArtifactError(err)
					entry.ArchivePath = ""
					entry.tempPath = ""
				}
				manifest.Files[i] = entry
			}
		}()
	}
	for i := range urls {
		select {
		case jobs <- i:
		case <-ctx.Done():
			manifest.Files[i] = artifactJSFile{URL: urls[i], Error: compactArtifactError(ctx.Err())}
		}
	}
	close(jobs)
	wg.Wait()

	for i := range manifest.Files {
		entry := &manifest.Files[i]
		if entry.tempPath == "" {
			manifest.Failed++
			continue
		}
		if err := addFileToZip(zw, entry.ArchivePath, entry.tempPath); err != nil {
			return manifest, err
		}
		entry.tempPath = ""
		manifest.Included++
	}
	return manifest, writeZipJSON(zw, "javascript/index.json", manifest.Files)
}

func addFileToZip(zw *zip.Writer, name, source string) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	f, err := os.Open(source) // #nosec G304 -- source is created in the private export temp directory.
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = io.Copy(w, f)
	return err
}

func writeZipJSON(zw *zip.Writer, name string, value any) error {
	w, err := zw.Create(name)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(value)
}

func artifactJSArchivePath(index int, rawURL string, digest [32]byte) string {
	name := "script.js"
	if parsed, err := url.Parse(rawURL); err == nil {
		if candidate := safeArtifactName(path.Base(parsed.Path)); candidate != "file" {
			name = candidate
		}
	}
	if !strings.HasSuffix(strings.ToLower(name), ".js") && !strings.HasSuffix(strings.ToLower(name), ".mjs") {
		name += ".js"
	}
	return fmt.Sprintf("javascript/%04d-%s-%s", index+1, hex.EncodeToString(digest[:6]), name)
}

func safeArtifactName(value string) string {
	value = strings.Trim(artifactNameCleaner.ReplaceAllString(strings.TrimSpace(value), "-"), ".-")
	if value == "" || value == "." || value == ".." {
		return "file"
	}
	if len(value) > 96 {
		value = value[:96]
	}
	return value
}

func compactArtifactError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 240 {
		message = message[:240]
	}
	return message
}
