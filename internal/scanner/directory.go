package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type DirScanner struct {
	db     *database.DB
	exec   *tools.Executor
	cfg    *config.Config
	logger *logger.Logger
}

func NewDirScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger) *DirScanner {
	return &DirScanner{db: db, exec: exec, cfg: cfg, logger: log}
}

var dirHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   8 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// soft404 captures how a host responds to a guaranteed-nonexistent path so we
// can recognise (and discard) catch-all 200 pages during content discovery.
type soft404 struct {
	active      bool
	statusCode  int
	bodyLen     int
	noise       int    // observed size wobble of the catch-all across probes
	contentType string // catch-all's Content-Type family (html/json/…)
	title       string // catch-all's <title>, if any
}

// matches reports whether a response looks like the soft-404 baseline — i.e. the
// host's catch-all page rather than a real discovered resource. Classification
// now uses THREE signals, not just length:
//  1. Identical <title>: an SPA/custom error page that echoes the same shell for
//     every route matches by title regardless of body length (the length check
//     alone missed these — a top false-positive source for dir/backup discovery).
//  2. Length similarity, but ONLY within the same Content-Type family, so a real
//     file (application/zip, sql, json) is never discarded just for happening to
//     match the HTML shell's size.
func (b soft404) matches(status int, body []byte, contentType string) bool {
	if !b.active || status != b.statusCode {
		return false
	}
	if b.title != "" && extractTitle(string(body)) == b.title {
		return true // same catch-all shell, any length
	}
	if b.contentType != "" && contentType != "" && ctFamily(b.contentType) != ctFamily(contentType) {
		return false // different content type → genuine content, keep it
	}
	tol := b.bodyLen / 20
	if tol < 128 {
		tol = 128
	}
	// A dynamic catch-all (timestamps, rotating content) wobbles in size between
	// requests. Widen the tolerance to cover TWICE the observed wobble so those
	// varying catch-all pages are still recognised and discarded instead of being
	// reported as discovered files (a content-discovery false positive).
	if b.noise*2 > tol {
		tol = b.noise * 2
	}
	d := len(body) - b.bodyLen
	if d < 0 {
		d = -d
	}
	return d <= tol
}

// ctFamily maps a Content-Type to a coarse family for same-kind comparison.
func ctFamily(ct string) string {
	ct = strings.ToLower(ct)
	switch {
	case strings.Contains(ct, "html"):
		return "html"
	case strings.Contains(ct, "json"):
		return "json"
	case strings.Contains(ct, "xml"):
		return "xml"
	case strings.Contains(ct, "javascript"), strings.Contains(ct, "ecmascript"):
		return "js"
	case strings.Contains(ct, "text/"):
		return "text"
	default:
		return "other"
	}
}

// soft404Baseline probes a couple of random paths and, if the host returns 200
// for them, records that as the catch-all baseline. Package-level (not a
// DirScanner method) because it touches no DirScanner state — shared with
// NetworkScanner.RunBackupDiscovery (network_backup.go).
func soft404Baseline(ctx context.Context, base string) soft404 {
	probes := []string{"/x9k2j7q1zNope404check", "/this_should_not_exist_" + uuid.New().String()[:8]}
	out := soft404{}
	var lens []int
	for _, p := range probes {
		req, err := http.NewRequestWithContext(ctx, "GET", base+p, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
		resp, err := dirHTTPClient.Do(req)
		if err != nil {
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		// Only a 200 to a bogus path is a soft-404 (a proper 404/403 is fine).
		if resp.StatusCode == 200 {
			lens = append(lens, len(body))
			out = soft404{
				active: true, statusCode: resp.StatusCode, bodyLen: len(body),
				contentType: resp.Header.Get("Content-Type"), title: extractTitle(string(body)),
			}
		}
	}
	// Both bogus probes answered 200 → measure the catch-all's own size wobble and
	// anchor the baseline at the LARGER sample, so `matches` tolerates a dynamic
	// catch-all instead of leaking its varying pages as findings.
	if len(lens) >= 2 {
		mn, mx := lens[0], lens[0]
		for _, l := range lens {
			if l < mn {
				mn = l
			}
			if l > mx {
				mx = l
			}
		}
		out.bodyLen = mx
		out.noise = mx - mn
	}
	return out
}

// dirDiscoveryHostCap returns the per-scan host cap for content-discovery
// (dir/backup/open-redirect) — intentionally capped because content-discovery
// is memory-heavy per host, but configurable (was a silent hardcoded 150 with
// no way to raise it and no warning when it bit a large target).
func (s *DirScanner) dirDiscoveryHostCap() int {
	if s.cfg != nil && s.cfg.DirDiscoveryMaxHosts > 0 {
		return s.cfg.DirDiscoveryMaxHosts
	}
	return 150
}

// loadHTTPServices returns the capped host list plus how many alive hosts
// existed in total, so callers can tell the operator when the cap actually
// dropped hosts instead of staying silent about it.
func (s *DirScanner) loadHTTPServices(ctx context.Context, targetID string) (services []string, totalAlive int) {
	_ = s.db.QueryRowContext(ctx, `
		SELECT COUNT(*) FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403 AND COALESCE(source,'probe') = 'probe'
	`, targetID).Scan(&totalAlive)

	hostCap := s.dirDiscoveryHostCap()
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403 AND COALESCE(source,'probe') = 'probe'
		ORDER BY url LIMIT ?
	`, targetID, hostCap)
	if err != nil {
		return nil, totalAlive
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			services = append(services, u)
		}
	}
	// Per-asset host scope
	if hostScopeSet(ctx) != nil {
		kept := services[:0]
		for _, u := range services {
			if urlHostInScope(ctx, u) {
				kept = append(kept, u)
			}
		}
		services = kept
	}
	return services, totalAlive
}

func (s *DirScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "dir_discovery", "Starting directory discovery...")

	services, totalAlive := s.loadHTTPServices(ctx, targetID)
	if len(services) == 0 {
		logFn("info", "dir_discovery", "No HTTP services to scan")
		return nil
	}
	if totalAlive > len(services) {
		logFn("warn", "dir_discovery", fmt.Sprintf(
			"host cap hit: scanning %d of %d alive hosts (content-discovery is memory-heavy) — raise dir_discovery_max_hosts in config.json to cover the rest",
			len(services), totalAlive))
	}

	// ALWAYS run the built-in prober: it's fast, bounded, and guarantees the
	// Directory section is populated even if dirsearch/feroxbuster are missing
	// or their output format changed between versions (the old code only fell
	// back to built-in when NO tool was installed, so a dirsearch whose output
	// we couldn't parse left the section permanently empty).
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var found atomic.Int64
	logFn("info", "dir_discovery", fmt.Sprintf("Probing common paths on %d services...", len(services)))
	for _, svcURL := range services {
		if ctx.Err() != nil {
			break
		}
		base := strings.TrimRight(svcURL, "/")
		bl := soft404Baseline(ctx, base) // discard catch-all 200 pages
		for _, path := range builtinWordlist {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(b, p string, baseline soft404) {
				defer wg.Done()
				defer func() { <-sem }()
				if s.probeAndStore(ctx, targetID, b+p, baseline) {
					found.Add(1)
				}
			}(base, path, bl)
		}
	}
	wg.Wait()
	logFn("info", "dir_discovery", fmt.Sprintf("Built-in prober found %d paths", found.Load()))

	// ADDITIONALLY use dirsearch or feroxbuster when present — deeper wordlists,
	// more coverage. Their failure no longer matters: the built-in results stand.
	if s.exec.IsToolAvailable("dirsearch") {
		logFn("info", "dir_discovery", fmt.Sprintf("Augmenting with dirsearch on %d services...", len(services)))
		dsem := make(chan struct{}, s.cfg.Workers.DirectoryDiscovery)
		var dwg sync.WaitGroup
		for _, svcURL := range services {
			if ctx.Err() != nil {
				break
			}
			dwg.Add(1)
			dsem <- struct{}{}
			go func(u string) {
				defer dwg.Done()
				defer func() { <-dsem }()
				s.runDirsearch(ctx, targetID, u, logFn)
			}(svcURL)
		}
		dwg.Wait()
	} else if s.exec.IsToolAvailable("feroxbuster") {
		logFn("info", "dir_discovery", fmt.Sprintf("Augmenting with feroxbuster on %d services...", len(services)))
		for _, svcURL := range services {
			if ctx.Err() != nil {
				break
			}
			s.runFeroxbuster(ctx, targetID, svcURL, logFn)
		}
	} else {
		logFn("info", "dir_discovery", "dirsearch/feroxbuster not installed — built-in prober only")
	}

	logFn("info", "dir_discovery", "Directory discovery complete")
	return nil
}

func (s *DirScanner) runDirsearch(ctx context.Context, targetID, svcURL string, logFn LogFunc) {
	// dirsearch output format: [HH:MM:SS] STATUS - SIZE - /path
	// or with full URL: [HH:MM:SS] STATUS - SIZE - https://host/path
	base := strings.TrimRight(svcURL, "/")
	// Hard per-service ceiling so one slow/huge host can't stall the whole module
	// (previously --crawl + --max-time 300 let a single host burn 5+ minutes, and
	// 12 hosts serialised into ~16 min). Cap each host and let the rest proceed.
	dctx, dcancel := context.WithTimeout(ctx, 150*time.Second)
	defer dcancel()

	callback := func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Target:") ||
			strings.HasPrefix(line, "Error") || strings.HasPrefix(line, "[!]") ||
			strings.HasPrefix(line, "[i]") || strings.HasPrefix(line, "Extensions:") ||
			strings.HasPrefix(line, "Threads:") || strings.HasPrefix(line, "Wordlist:") ||
			strings.HasPrefix(line, "Output:") || strings.HasPrefix(line, "Starting:") ||
			strings.HasPrefix(line, "Task Completed") {
			return
		}
		// Strip ANSI escape codes
		for strings.Contains(line, "\x1b[") {
			start := strings.Index(line, "\x1b[")
			end := strings.IndexAny(line[start:], "ABCDEFGHJKSTfmnsulh")
			if end < 0 {
				break
			}
			line = line[:start] + line[start+end+1:]
		}
		// Format: [HH:MM:SS] 200 -   10KB - /path
		parts := strings.Fields(line)
		if len(parts) < 4 {
			return
		}
		var statusCode int
		fmt.Sscanf(parts[1], "%d", &statusCode)
		if statusCode == 0 {
			return
		}
		size := 0
		if len(parts) >= 4 {
			size = humanSizeToBytes(parts[3])
		}
		pathOrURL := parts[len(parts)-1]
		var foundURL string
		if strings.HasPrefix(pathOrURL, "http") {
			foundURL = pathOrURL
		} else if strings.HasPrefix(pathOrURL, "/") {
			foundURL = base + pathOrURL
		} else {
			return
		}
		s.storeDirFinding(targetID, foundURL, statusCode, size, "")
	}

	args := []string{
		"-u", svcURL, "--no-color", "-q",
		"-e", "php,asp,aspx,jsp,html,txt,bak,zip,sql,tar,gz,rar,xml,json,yaml,env,js,pdf,cfg,conf,old,swp,inc",
		"-i", "200,204,301,302,307,401,403,405,500",
		"--timeout", "6", "--full-url", "-t", "60", "--max-time", "120",
	}
	args = append(args, ToolRequestIdentityArgs(ctx, "dirsearch")...)
	err := s.exec.RunWithCallback(dctx, targetID, callback, "dirsearch", args...)
	if err != nil && strings.Contains(err.Error(), "no such file or directory") {
		// venv shebang/interpreter broken → fall back to python -m
		pyArgs := append([]string{"-m", "dirsearch"}, args...)
		err = s.exec.RunWithCallback(dctx, targetID, callback, "python3", pyArgs...)
	}
	if err != nil && ctx.Err() == nil && dctx.Err() != context.DeadlineExceeded {
		logFn("warn", "dir_discovery", fmt.Sprintf("dirsearch error for %s: %v", svcURL, err))
	}
}

// humanSizeToBytes parses dirsearch-style sizes ("260B", "10KB", "3MB") to bytes.
func humanSizeToBytes(s string) int {
	s = strings.TrimSpace(strings.ToUpper(s))
	if s == "" || s == "-" {
		return 0
	}
	mult := 1.0
	switch {
	case strings.HasSuffix(s, "KB"):
		mult, s = 1024, strings.TrimSuffix(s, "KB")
	case strings.HasSuffix(s, "MB"):
		mult, s = 1024*1024, strings.TrimSuffix(s, "MB")
	case strings.HasSuffix(s, "GB"):
		mult, s = 1024*1024*1024, strings.TrimSuffix(s, "GB")
	case strings.HasSuffix(s, "B"):
		s = strings.TrimSuffix(s, "B")
	}
	var v float64
	if _, err := fmt.Sscanf(strings.TrimSpace(s), "%f", &v); err != nil {
		return 0
	}
	return int(v * mult)
}

func (s *DirScanner) runFeroxbuster(ctx context.Context, targetID, svcURL string, logFn LogFunc) {
	// feroxbuster output: STATUS METHOD SIZE WORDS LINES URL
	args := []string{"-u", svcURL, "-q", "-t", "20", "--timeout", "8", "-x", "php,asp,aspx,jsp,html,txt,bak,zip", "--no-state"}
	args = append(args, ToolRequestIdentityArgs(ctx, "feroxbuster")...)
	err := s.exec.RunWithCallback(ctx, targetID, func(line string) {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ">") {
			return
		}
		parts := strings.Fields(line)
		if len(parts) < 2 {
			return
		}
		var statusCode int
		fmt.Sscanf(parts[0], "%d", &statusCode)
		if statusCode == 0 {
			return
		}
		foundURL := ""
		for _, p := range parts {
			if strings.HasPrefix(p, "http") {
				foundURL = p
				break
			}
		}
		if foundURL != "" {
			s.storeDirFinding(targetID, foundURL, statusCode, 0, "")
		}
	}, "feroxbuster", args...)
	if err != nil && ctx.Err() == nil {
		logFn("warn", "dir_discovery", fmt.Sprintf("feroxbuster error for %s: %v", svcURL, err))
	}
}

func (s *DirScanner) probeAndStore(ctx context.Context, targetID, targetURL string, baseline soft404) bool {
	req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
	if err != nil {
		return false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")

	resp, err := dirHTTPClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))

	if resp.StatusCode == 404 || resp.StatusCode == 400 {
		return false
	}
	// Discard soft-404 catch-all responses.
	if baseline.matches(resp.StatusCode, body, resp.Header.Get("Content-Type")) {
		return false
	}

	redirect := resp.Header.Get("Location")
	s.storeDirFinding(targetID, targetURL, resp.StatusCode, trueSize(resp, len(body)), redirect)
	return true
}

// realSize returns the TRUE resource size: the Content-Length header when the
// server reports it, else the (possibly LimitReader-truncated) body length. Fixes
// large files being recorded as the 64KB/256KB read cap.
func realSize(resp *http.Response, bodyLen int) int {
	if resp.ContentLength > 0 {
		return int(resp.ContentLength)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(cl)); err == nil && n >= 0 {
			return n
		}
	}
	return bodyLen
}

// maxMeasureBytes caps how much of a body we'll stream-count (protects memory/
// bandwidth against an endless stream while still measuring real backup sizes).
const maxMeasureBytes = 200 * 1024 * 1024

// trueSize returns the real resource size even when the server uses chunked
// transfer with NO Content-Length: it counts the bytes ALREADY read (alreadyRead)
// plus the remainder streamed straight to io.Discard (never held in memory). This
// is what fixes "every result shows 64KB" for large real files on chunked servers.
func trueSize(resp *http.Response, alreadyRead int) int {
	if resp.ContentLength > 0 {
		return int(resp.ContentLength)
	}
	if cl := resp.Header.Get("Content-Length"); cl != "" {
		if n, err := strconv.Atoi(strings.TrimSpace(cl)); err == nil && n >= 0 {
			return n
		}
	}
	// drain the rest, counting, up to a sane cap
	n, _ := io.Copy(io.Discard, io.LimitReader(resp.Body, maxMeasureBytes))
	return alreadyRead + int(n)
}

// sensitiveBackupType reports whether a detected file type is a genuinely
// sensitive backup/secret (vs a normal web asset). Only these — or a magic-byte
// confirmation — become backup findings, killing the "any non-HTML 200 = backup"
// false positives (JSON APIs, JS/CSS, images, generic XML/YAML).
func sensitiveBackupType(fileType string) bool {
	switch fileType {
	case "sql_dump", "archive", "env_file", "git_repo", "backup", "log_file", "config":
		return true
	}
	return false
}

func (s *DirScanner) storeDirFinding(targetID, foundURL string, statusCode, contentLength int, redirectURL string) {
	id := uuid.New().String()
	_, _ = s.db.Exec(`
		INSERT INTO directory_findings (id, target_id, url, status_code, content_length, redirect_url)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(target_id, url) DO UPDATE SET
			status_code = excluded.status_code,
			content_length = excluded.content_length,
			redirect_url = excluded.redirect_url
	`, id, targetID, foundURL, statusCode, contentLength, redirectURL)
}

func (s *DirScanner) RunBackupDiscovery(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "backup_discovery", "Scanning for backup and sensitive files...")

	services, totalAlive := s.loadHTTPServices(ctx, targetID)
	if len(services) == 0 {
		logFn("info", "backup_discovery", "No HTTP services found")
		return nil
	}
	if totalAlive > len(services) {
		logFn("warn", "backup_discovery", fmt.Sprintf(
			"host cap hit: scanning %d of %d alive hosts — raise dir_discovery_max_hosts in config.json to cover the rest",
			len(services), totalAlive))
	}

	var domain string
	_ = s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id = ?`, targetID).Scan(&domain)

	found := scanBackupCandidates(ctx, s.db, targetID, services, domain)
	logFn("info", "backup_discovery", fmt.Sprintf("Backup discovery done. Found %d files.", found))
	return nil
}

// scanBackupCandidates is the shared backup/config-file discovery core: soft-404
// baselining, magic-byte confirmation, HTML/catch-all rejection, DB write, and
// the high-severity vuln_findings promotion for a confirmed archive/dump. Used
// by BOTH the web backup_discovery module above and NetworkScanner's own
// backup phase (network_backup.go) — a network target's discovered web
// endpoints never flowed through this at all before (they live in
// network_services, not http_services, so RunBackupDiscovery above never saw
// them), which is the gap this shared extraction closes.
func scanBackupCandidates(ctx context.Context, db *database.DB, targetID string, services []string, domain string) int {
	// Curated high-signal patterns + generated candidates (domain-derived names,
	// config files with backup suffixes, dated variants, bounded wordlist).
	patterns := append([]string{}, backupPatterns...)
	patterns = append(patterns, generateBackupCandidates(domain)...)

	// Raised from 20: the wordlist merge (backup_magic.go) roughly 5x'd the
	// per-host candidate count, so more concurrency keeps wall-clock time sane.
	sem := make(chan struct{}, 40)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, svcURL := range services {
		if ctx.Err() != nil {
			break
		}
		base := strings.TrimRight(svcURL, "/")

		// Soft-404 baseline: many sites (SPAs, custom error pages) return 200
		// with the same page for ANY path. Establish what a bogus path looks
		// like so we can discard those instead of reporting hundreds of fakes.
		bl := soft404Baseline(ctx, base)

		for _, pattern := range patterns {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(b, p string, base soft404) {
				defer wg.Done()
				defer func() { <-sem }()
				targetURL := b + p
				req, err := http.NewRequestWithContext(ctx, "GET", targetURL, nil)
				if err != nil {
					return
				}
				req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
				resp, err := dirHTTPClient.Do(req)
				if err != nil {
					return
				}
				defer resp.Body.Close()
				body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))

				// Reject the SPA / catch-all: a real backup/config file
				// (.json/.yml/.bak/.env/.sql/.config…) is NEVER served as an HTML
				// page. Many hosts return index.html (200, text/html) for ANY path,
				// producing dozens of identical fake "backups". If the body looks
				// like HTML, it's the catch-all, not a config file.
				ct := strings.ToLower(resp.Header.Get("Content-Type"))
				if strings.Contains(ct, "text/html") || looksLikeHTML(body) {
					return
				}

				if resp.StatusCode == 200 && len(body) > 100 && !base.matches(resp.StatusCode, body, resp.Header.Get("Content-Type")) {
					magic := checkMagicBytes(body)
					fileType := detectFileType(p, body)

					// Reject noisy non-secrets: a real backup/secret is either
					// magic-byte-confirmed (archive/DB dump) OR a genuinely
					// sensitive type (.sql/.env/.bak/.git/.log/.config). A plain
					// non-HTML 200 (JSON API, JS/CSS, image, generic xml/yaml) is
					// NOT a backup — skip it to kill the false positives.
					if magic == "" && !sensitiveBackupType(fileType) {
						return
					}
					if magic != "" {
						fileType = magic + " (confirmed)"
					}
					size := trueSize(resp, len(body))
					id := uuid.New().String()
					_, _ = db.Exec(`
						INSERT INTO backup_findings (id, target_id, url, status_code, content_length, file_type)
						VALUES (?, ?, ?, ?, ?, ?)
						ON CONFLICT(target_id, url) DO NOTHING
					`, id, targetID, targetURL, resp.StatusCode, size, fileType)
					found.Add(1)
					if magic != "" {
						storeExposedBackup(db, targetID, targetURL, magic, size)
					}
				}
			}(base, pattern, bl)
		}
	}

	wg.Wait()
	return int(found.Load())
}

// storeExposedBackup raises a high-severity finding for a magic-byte-CONFIRMED
// backup/dump so it shows up in the vulnerabilities list and the report with a
// ready PoC (a downloadable production backup is a real, high-impact issue).
// Package-level (not a DirScanner method) — shared with scanBackupCandidates.
func storeExposedBackup(db *database.DB, targetID, url, fileType string, size int) {
	evidence := fmt.Sprintf("Confirmed %s backup/dump downloadable (%d bytes) — verified by file signature, not just status/size.", fileType, size)
	_, _ = RecordDetectorObservation(context.Background(), db, DetectorObservation{
		TargetID: targetID, Type: "exposed_backup", Subtype: fileType, Severity: "high",
		URL: url, Method: "GET", Location: "response", Evidence: evidence,
		Source: "directory", DetectionMethod: "magic-bytes", Confidence: 95,
		Priority: 380, Verdict: VerifyVerified,
	})
}

func (s *DirScanner) RunOpenRedirectDiscovery(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "open_redirect", "Scanning for open redirects...")

	limit := 150
	if s.cfg != nil {
		limit = s.cfg.URLLimit()
	}
	// Route by tokenized name OR URL-shaped value, keep unfamiliar fallbacks, and
	// preserve the real method/body/auth/sibling request contract. The historical
	// SQL LIKE prefilter silently dropped opaque URL-valued names and every POST or
	// JSON redirect sink before the verifier saw them.
	items := loadRoutedInsertionPoints(ctx, s.db, targetID, ClassRedirect, limit, 32)
	auth := loadAuthHeaders(ctx, s.db, targetID)

	logFn("info", "open_redirect", fmt.Sprintf("Testing %d potential redirect parameters...", len(items)))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, item := range items {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()

			if res, ok := checkOpenRedirectPoint(ctx, ip, auth); ok {
				id := uuid.New().String()
				verified := 0
				status := StatusCandidate
				if res.class == redirectExternal {
					verified = 1
					status = StatusFinding
					found.Add(1)
				}
				desc := fmt.Sprintf("%s -> %s", res.testURL, res.finalLoc)
				_, _ = s.db.Exec(`
					INSERT INTO open_redirect_findings (id, target_id, url, redirect_to, parameter, verified, status, provenance)
					VALUES (?, ?, ?, ?, ?, ?, ?, ?)
					ON CONFLICT(target_id, url) DO UPDATE SET
						redirect_to = excluded.redirect_to,
						verified = excluded.verified,
						status = excluded.status,
						provenance = excluded.provenance
				`, id, targetID, ip.URL, desc, ip.Param, verified, status, res.chain)
			}
		}(item)
	}
	wg.Wait()
	logFn("info", "open_redirect", fmt.Sprintf("Open redirect scan done. Found %d verified redirects.", found.Load()))
	return nil
}

// looksLikeHTML reports whether a body is an HTML document — used to reject the
// SPA/catch-all page that many hosts return for every path. It looks only for
// HTML markers (not a bare '<'), so real XML backups (which start with <?xml)
// are not mistaken for HTML.
func looksLikeHTML(body []byte) bool {
	n := len(body)
	if n > 2048 {
		n = 2048
	}
	head := strings.ToLower(strings.TrimSpace(string(body[:n])))
	for _, m := range []string{"<!doctype html", "<html", "<head", "<body", "<title", "<meta", "<script"} {
		if strings.Contains(head, m) {
			return true
		}
	}
	return false
}

func detectFileType(path string, body []byte) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".sql"):
		return "sql_dump"
	case strings.HasSuffix(lower, ".zip") || strings.HasSuffix(lower, ".tar") || strings.HasSuffix(lower, ".gz") || strings.HasSuffix(lower, ".rar"):
		return "archive"
	case strings.HasSuffix(lower, ".env"):
		return "env_file"
	case strings.HasSuffix(lower, ".git") || strings.Contains(lower, ".git/"):
		return "git_repo"
	case strings.HasSuffix(lower, ".bak") || strings.HasSuffix(lower, ".backup") || strings.HasSuffix(lower, ".old"):
		return "backup"
	case strings.HasSuffix(lower, ".log"):
		return "log_file"
	case strings.HasSuffix(lower, ".conf") || strings.HasSuffix(lower, ".config") || strings.HasSuffix(lower, ".cfg"):
		return "config"
	case strings.HasSuffix(lower, ".xml"):
		return "xml"
	case strings.HasSuffix(lower, ".json"):
		return "json"
	case strings.HasSuffix(lower, ".yaml") || strings.HasSuffix(lower, ".yml"):
		return "yaml"
	default:
		if len(body) >= 4 {
			if body[0] == 0x50 && body[1] == 0x4B {
				return "archive"
			}
		}
		return "unknown"
	}
}

var builtinWordlist = func() []string {
	paths := []string{
		"/admin", "/admin/", "/administrator", "/login", "/wp-admin", "/wp-login.php",
		"/dashboard", "/panel", "/manage", "/management", "/backend",
		"/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/swagger", "/swagger-ui",
		"/swagger.json", "/openapi.json", "/api-docs",
		"/.env", "/.env.local", "/.env.production", "/.env.backup",
		"/.git", "/.git/HEAD", "/.git/config", "/.svn", "/.svn/entries",
		"/config", "/config.php", "/config.json", "/config.yml", "/config.yaml",
		"/backup", "/backup.zip", "/backup.sql", "/backup.tar.gz",
		"/db.sql", "/database.sql", "/dump.sql",
		"/phpinfo.php", "/info.php", "/test.php", "/debug.php",
		"/robots.txt", "/sitemap.xml", "/security.txt", "/.well-known/security.txt",
		"/crossdomain.xml", "/clientaccesspolicy.xml",
		"/server-status", "/server-info", "/_profiler", "/actuator", "/actuator/health",
		"/actuator/env", "/actuator/mappings", "/metrics", "/health",
		"/console", "/phpmyadmin", "/adminer", "/adminer.php",
		"/wp-content/uploads", "/uploads", "/files", "/static", "/assets",
		"/logs", "/log", "/error_log", "/access_log",
		"/readme.txt", "/readme.md", "/CHANGELOG.md", "/CHANGELOG.txt",
		"/.DS_Store", "/Thumbs.db",
		"/composer.json", "/package.json", "/yarn.lock", "/package-lock.json",
		"/Gemfile", "/requirements.txt",
		// ── extended high-signal surface (admin panels, APIs, dashboards) ──
		"/admin/login", "/admin/index.php", "/admin.php", "/administrator/index.php",
		"/user/login", "/users/sign_in", "/auth/login", "/account/login", "/signin",
		"/cms", "/cpanel", "/webadmin", "/siteadmin", "/adminpanel", "/admin-console",
		"/portal", "/portal/", "/secure", "/internal", "/private", "/staff", "/staff/",
		"/api/v1/", "/api/v2/", "/api/docs", "/api/swagger", "/api/graphql",
		"/graphiql", "/playground", "/altair", "/v1", "/v2", "/rest", "/soap", "/wsdl",
		"/swagger-ui.html", "/swagger-ui/index.html", "/swagger/index.html", "/redoc",
		"/actuator/beans", "/actuator/configprops", "/actuator/heapdump", "/actuator/threaddump",
		"/actuator/loggers", "/actuator/httptrace", "/actuator/prometheus", "/actuator/metrics",
		"/env", "/debug", "/debug/pprof/", "/debug/vars", "/status", "/stats", "/trace", "/traces",
		"/telescope", "/horizon", "/_ignition/health-check", "/nova", "/laravel-websockets",
		"/rails/info/properties", "/sidekiq", "/flower", "/rq", "/bull",
		// framework / build leaks
		"/.git/logs/HEAD", "/.git/index", "/.gitignore", "/.hg", "/.bzr",
		"/webpack.config.js", "/vite.config.js", "/gulpfile.js", "/Gruntfile.js",
		"/tsconfig.json", "/.babelrc", "/.eslintrc", "/.prettierrc", "/nuxt.config.js", "/next.config.js",
		"/main.js.map", "/app.js.map", "/bundle.js.map", "/index.js.map",
		// storage / uploads / exports
		"/storage", "/storage/logs", "/tmp", "/temp", "/cache", "/data", "/media",
		"/export", "/exports", "/download", "/downloads", "/reports", "/invoices",
		"/wp-json", "/wp-json/wp/v2/users", "/xmlrpc.php", "/wp-content/debug.log",
		// devops / infra panels
		"/grafana", "/kibana", "/prometheus", "/consul", "/vault", "/rabbitmq", "/traefik",
		"/kubelet", "/metrics/", "/healthz", "/readyz", "/livez", "/version", "/actuator/",
		"/jenkins", "/gitlab", "/gitea", "/sonar", "/nexus", "/artifactory", "/harbor",
		"/.well-known/openid-configuration", "/.well-known/oauth-authorization-server",
		"/oauth/authorize", "/oauth/token", "/saml/metadata", "/sso",
	}
	seen := make(map[string]bool)
	unique := make([]string, 0, len(paths))
	for _, p := range paths {
		if !seen[p] {
			seen[p] = true
			unique = append(unique, p)
		}
	}
	return unique
}()

var backupPatterns = []string{
	"/.env", "/.env.local", "/.env.backup", "/.env.old", "/.env.bak",
	"/.env.production", "/.env.staging", "/.env.development",
	"/.git/HEAD", "/.git/config", "/.git/COMMIT_EDITMSG",
	"/.svn/entries", "/.svn/format",
	"/backup.zip", "/backup.tar.gz", "/backup.sql", "/backup.sql.gz",
	"/db.sql", "/db.sql.gz", "/database.sql", "/database.sql.gz",
	"/dump.sql", "/site.sql", "/data.sql",
	"/config.php.bak", "/config.php.old", "/config.bak", "/config.old",
	"/wp-config.php.bak", "/wp-config.bak",
	"/web.config.bak", "/web.config.old",
	"/application.properties.bak", "/application.yml.bak",
	"/composer.json", "/composer.lock",
	"/package.json", "/package-lock.json", "/yarn.lock",
	"/Gemfile", "/Gemfile.lock",
	"/requirements.txt", "/Pipfile", "/Pipfile.lock",
	"/id_rsa", "/id_dsa", "/.ssh/id_rsa", "/.ssh/authorized_keys",
	"/server.key", "/private.key", "/private.pem",
	"/phpinfo.php", "/info.php", "/test.php",
	"/_phpinfo.php", "/php-info.php",
	"/logs/error.log", "/logs/access.log", "/var/log/error.log",
	"/.DS_Store",
	"/crossdomain.xml", "/clientaccesspolicy.xml",
	"/swagger.json", "/swagger.yaml", "/openapi.json", "/openapi.yaml",
	"/api-docs", "/api-docs.json",
	// extended sensitive/config/backup surface
	"/.env.dev", "/.env.test", "/.env.example", "/env.js", "/config.js.map",
	"/.aws/credentials", "/.aws/config", "/.npmrc", "/.dockercfg", "/.docker/config.json",
	"/docker-compose.yml", "/docker-compose.yaml", "/Dockerfile", "/.dockerignore",
	"/.gitlab-ci.yml", "/.github/workflows/", "/.travis.yml", "/circle.yml", "/.circleci/config.yml",
	"/settings.py", "/local_settings.py", "/wp-config.php", "/configuration.php",
	"/config.inc.php", "/database.yml", "/secrets.yml", "/credentials.yml",
	"/.htpasswd", "/.htaccess", "/nginx.conf", "/httpd.conf",
	"/server-status", "/server-info", "/.well-known/security.txt",
	"/actuator", "/actuator/health", "/actuator/env", "/actuator/heapdump", "/actuator/mappings",
	"/.vscode/settings.json", "/.idea/workspace.xml",
	"/backup.tar", "/www.zip", "/site.zip", "/web.zip", "/public.zip", "/backup.rar",
	"/dump.rdb", "/.bash_history", "/.ssh/known_hosts",
	"/phpunit.xml", "/composer.phar", "/.terraform/terraform.tfstate", "/terraform.tfstate",
	"/.env.bak", "/config.json.bak", "/appsettings.json", "/appsettings.Development.json",
	"/web.config",
	// ── extended secret/backup/config surface (high-signal for bug bounty) ──
	// env & secret variants
	"/.env.prod", "/.env.production.local", "/.env.local.php", "/.environment", "/env.bak",
	"/.env.save", "/.env~", "/.env.swp", "/.env.default", "/.envrc",
	// cloud & IaC state / creds
	"/terraform.tfstate.backup", "/.terraform.lock.hcl", "/ansible.cfg", "/hosts.ini",
	"/kubeconfig", "/.kube/config", "/.gcloud/credentials.db", "/gcloud/credentials.json",
	"/serviceaccount.json", "/service-account.json", "/firebase.json", "/.firebaserc",
	"/cloud-config.yml", "/user-data", "/meta-data",
	// git/vcs deep leaks
	"/.git/refs/heads/master", "/.git/refs/heads/main", "/.git/packed-refs",
	"/.git/logs/refs/heads/master", "/.gitconfig", "/.git-credentials",
	// DB dumps / archives (more extensions & names)
	"/backup.7z", "/backup.bak", "/backup.old", "/backup/db.sql", "/sql.sql",
	"/mysql.sql", "/users.sql", "/prod.sql", "/staging.sql", "/backup-latest.sql",
	"/www.tar.gz", "/html.tar.gz", "/app.tar.gz", "/release.tar.gz", "/source.zip", "/src.zip",
	"/archive.zip", "/old.zip", "/new.zip", "/test.zip", "/upload.zip", "/files.zip",
	// language/framework configs & secrets
	"/wp-config.php.save", "/wp-config.php~", "/wp-config.php.txt", "/wp-config.old.php",
	"/config/database.yml", "/config/secrets.yml", "/config/master.key", "/config/credentials.yml.enc",
	"/.rails-secret", "/settings.local.py", "/config.dev.js", "/config.prod.js",
	"/parameters.yml", "/app/etc/env.php", "/sites/default/settings.php",
	// keys & certs
	"/id_ecdsa", "/id_ed25519", "/.ssh/id_ed25519", "/server.pem", "/cert.pem", "/key.pem",
	"/ssl.key", "/ssl.crt", "/certificate.pfx", "/keystore.jks", "/.pypirc",
	// logs & debug dumps
	"/debug.log", "/laravel.log", "/storage/logs/laravel.log", "/npm-debug.log",
	"/error.log", "/access.log", "/app.log", "/production.log", "/development.log",
	// CI/CD & container extras
	"/Jenkinsfile", "/.drone.yml", "/bitbucket-pipelines.yml", "/azure-pipelines.yml",
	"/docker-compose.override.yml", "/docker-compose.prod.yml", "/.env.docker",
	// misc high-value
	"/.well-known/apple-app-site-association", "/graphql.schema.json", "/schema.graphql",
	"/backup.json", "/users.json", "/data.json", "/secrets.json", "/credentials.json",
	"/aws.json", "/gcp.json", "/.mysql_history", "/.psql_history", "/.rediscli_history",
	// robots.txt / sitemap.xml are normal public files — NOT backups/sensitive.
}
