package scanner

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type HTTPScanner struct {
	db     *database.DB
	exec   *tools.Executor
	cfg    *config.Config
	logger *logger.Logger
}

func NewHTTPScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger) *HTTPScanner {
	return &HTTPScanner{db: db, exec: exec, cfg: cfg, logger: log}
}

type httpxOutput struct {
	URL           string   `json:"url"`
	Input         string   `json:"input"` // original subdomain input
	Host          string   `json:"host"`  // resolved IP (not the subdomain)
	StatusCode    int      `json:"status_code"`
	Title         string   `json:"title"`
	WebServer     string   `json:"webserver"`
	ContentType   string   `json:"content_type"`
	ContentLength int      `json:"content_length"`
	RedirectURL   string   `json:"final_url"`
	Technologies  []string `json:"tech"`
	ResponseTime  string   `json:"response_time"`
}

func (o *httpxOutput) subdomain() string {
	if o.Input != "" {
		return o.Input
	}
	return o.Host
}

func (s *HTTPScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "http_probe", "Loading subdomains for HTTP probing...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT subdomain FROM subdomains 
		WHERE target_id = ? 
		ORDER BY subdomain
	`, targetID)
	if err != nil {
		return fmt.Errorf("query subdomains: %w", err)
	}

	var hosts []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err != nil {
			continue
		}
		hosts = append(hosts, sub)
	}
	rows.Close()

	// Out-of-scope exclusions (bug-bounty): drop excluded hosts BEFORE probing, so
	// nothing excluded ever becomes an http_service — the whole web pipeline reads
	// from http_services, so this one filter keeps every downstream module
	// (js, params, dast, nuclei…) off the excluded assets. This is the single
	// enforcement choke point for exclude_scope on the web side.
	if excl := LoadExclusions(ctx, s.db, targetID); !excl.Empty() {
		kept := hosts[:0]
		var dropped int
		for _, h := range hosts {
			if excl.Excludes(h) {
				dropped++
				continue
			}
			kept = append(kept, h)
		}
		hosts = kept
		if dropped > 0 {
			logFn("info", "http_probe", fmt.Sprintf("Excluded %d out-of-scope host(s) from probing (exclude_scope)", dropped))
		}
	}

	if len(hosts) == 0 {
		logFn("info", "http_probe", "No subdomains found to probe")
		return nil
	}

	logFn("info", "http_probe", fmt.Sprintf("Probing %d hosts with httpx...", len(hosts)))

	// Write hosts to a temp file — httpx stdin mode is unreliable across versions
	tmpFile, err := os.CreateTemp("", "httpx-hosts-*.txt")
	if err != nil {
		logFn("warn", "http_probe", "Failed to create temp file, falling back to basic probe")
		return s.basicHTTPProbe(ctx, targetID, hosts, logFn)
	}
	defer os.Remove(tmpFile.Name())
	if _, err := tmpFile.WriteString(strings.Join(hosts, "\n")); err != nil {
		tmpFile.Close()
		return s.basicHTTPProbe(ctx, targetID, hosts, logFn)
	}
	tmpFile.Close()

	args := []string{
		"-l", tmpFile.Name(),
		"-silent",
		"-json",
		"-title",
		"-web-server",
		"-tech-detect",
		"-status-code",
		"-content-length",
		"-follow-redirects",
		"-timeout", "10",
		"-threads", fmt.Sprintf("%d", s.cfg.Workers.HTTPProbing),
		"-retries", "1",
	}
	// Rate-limit to avoid WAF bans (which cause false negatives) and respect
	// program policy.
	if s.cfg.Limits.HTTPRateLimit > 0 {
		args = append(args, "-rate-limit", fmt.Sprintf("%d", s.cfg.Limits.HTTPRateLimit))
	}

	if s.exec.IsToolAvailable("httpx") {
		var mu sync.Mutex
		probed := 0

		err = s.exec.RunWithCallback(ctx, targetID, func(line string) {
			var out httpxOutput
			if err := json.Unmarshal([]byte(line), &out); err != nil {
				return
			}

			if err := s.storeHTTPService(targetID, out); err != nil {
				s.logger.Error("Failed to store HTTP service", "error", err)
			}

			if err := s.updateSubdomainAlive(targetID, out.subdomain(), out.StatusCode, out.Technologies, out.WebServer); err != nil {
				s.logger.Error("Failed to update subdomain", "error", err)
			}

			mu.Lock()
			probed++
			if probed%20 == 0 {
				logFn("info", "http_probe", fmt.Sprintf("Probed %d hosts...", probed))
			}
			mu.Unlock()
		}, "httpx", args...)

		if err != nil && ctx.Err() == nil {
			logFn("warn", "http_probe", fmt.Sprintf("httpx error: %v", err))
		}
	} else {
		logFn("info", "http_probe", "httpx not available, using basic HTTP probing...")
		if err := s.basicHTTPProbe(ctx, targetID, hosts, logFn); err != nil {
			return err
		}
	}

	// Fingerprint the WAF/edge AND the CMS on each live host: the WAF name shows in
	// the HTTP tab, and a WordPress/Joomla/Drupal verdict lets the injection modules
	// skip a stock-CMS host (see loadCMSSkipHosts) instead of wasting time / raising
	// false positives on it.
	s.fingerprintHosts(ctx, targetID, logFn)

	logFn("info", "http_probe", "HTTP probing complete")
	return nil
}

// fingerprintHosts runs the native WAF and CMS fingerprinters over every live
// HTTP service of a target (bounded concurrency) and stores the results.
func (s *HTTPScanner) fingerprintHosts(ctx context.Context, targetID string, logFn LogFunc) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code > 0 AND COALESCE(source,'probe')='probe'`, targetID)
	if err != nil {
		return
	}
	var urls []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil && u != "" {
			urls = append(urls, u)
		}
	}
	rows.Close()
	if len(urls) == 0 {
		return
	}

	logFn("info", "http_probe", fmt.Sprintf("Fingerprinting WAF/edge + CMS on %d host(s)...", len(urls)))
	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var wafN, cmsN atomic.Int64
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			if waf := detectWAF(ctx, u); waf != "" {
				_, _ = s.db.Exec(`UPDATE http_services SET waf=? WHERE target_id=? AND url=?`, waf, targetID, u)
				wafN.Add(1)
			}
			if cms := detectCMS(ctx, u); cms != "" {
				_, _ = s.db.Exec(`UPDATE http_services SET cms=? WHERE target_id=? AND url=?`, cms, targetID, u)
				cmsN.Add(1)
			}
		}(u)
	}
	wg.Wait()
	if n := wafN.Load(); n > 0 {
		logFn("info", "http_probe", fmt.Sprintf("WAF/edge fingerprinted on %d host(s).", n))
	}
	if n := cmsN.Load(); n > 0 {
		logFn("info", "http_probe", fmt.Sprintf("CMS fingerprinted on %d host(s) — stock WP/Joomla/Drupal hosts will skip active injection scans.", n))
	}
}

func (s *HTTPScanner) storeHTTPService(targetID string, out httpxOutput) error {
	id := uuid.New().String()
	techs := models.StringSliceToJSON(out.Technologies)

	var subID string
	_ = s.db.QueryRow("SELECT id FROM subdomains WHERE target_id = ? AND subdomain = ?",
		targetID, out.subdomain()).Scan(&subID)

	_, err := s.db.Exec(`
		INSERT INTO http_services 
			(id, target_id, subdomain_id, url, status_code, title, server, content_type, content_length, redirect_url, technologies, response_time_ms, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, url) DO UPDATE SET
			status_code = excluded.status_code,
			title = excluded.title,
			server = excluded.server,
			content_type = excluded.content_type,
			content_length = excluded.content_length,
			redirect_url = excluded.redirect_url,
			technologies = excluded.technologies,
			last_seen = CURRENT_TIMESTAMP
	`, id, targetID, subID, out.URL, out.StatusCode, out.Title, out.WebServer,
		out.ContentType, out.ContentLength, out.RedirectURL, techs, 0)

	return err
}

func (s *HTTPScanner) updateSubdomainAlive(targetID, host string, statusCode int, techs []string, server string) error {
	hasHTTPS := 0
	hasHTTP := 0

	var rows *dbRow
	// Match the exact host (scheme + host, optional port/path) instead of a
	// loose substring, so `api` no longer matches `myapi.example.com`.
	r := s.db.QueryRow(`
		SELECT
			SUM(CASE WHEN url LIKE 'https://%' THEN 1 ELSE 0 END),
			SUM(CASE WHEN url LIKE 'http://%' THEN 1 ELSE 0 END)
		FROM http_services
		WHERE target_id = ? AND (
			url = 'https://' || ? OR url LIKE 'https://' || ? || '/%' OR url LIKE 'https://' || ? || ':%' OR
			url = 'http://'  || ? OR url LIKE 'http://'  || ? || '/%' OR url LIKE 'http://'  || ? || ':%'
		)
	`, targetID, host, host, host, host, host, host)

	var httpsCount, httpCount *int
	r.Scan(&httpsCount, &httpCount)
	if httpsCount != nil && *httpsCount > 0 {
		hasHTTPS = 1
	}
	if httpCount != nil && *httpCount > 0 {
		hasHTTP = 1
	}

	techsJSON := models.StringSliceToJSON(techs)
	_, err := s.db.Exec(`
		UPDATE subdomains SET 
			is_alive = 1,
			status_code = ?,
			technologies = ?,
			server = ?,
			has_https = ?,
			has_http = ?
		WHERE target_id = ? AND subdomain = ?
	`, statusCode, techsJSON, server, hasHTTPS, hasHTTP, targetID, host)

	_ = rows
	return err
}

type dbRow = interface{}

func (s *HTTPScanner) basicHTTPProbe(ctx context.Context, targetID string, hosts []string, logFn LogFunc) error {
	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(h string) {
			defer wg.Done()
			defer func() { <-sem }()

			for _, scheme := range []string{"https", "http"} {
				url := fmt.Sprintf("%s://%s", scheme, h)
				svc := probeURL(url)
				if svc != nil {
					svc.ID = uuid.New().String()
					svc.TargetID = targetID
					if err := s.storeBasicService(svc); err != nil {
						s.logger.Error("Store basic service failed", "error", err)
					}
				}
			}
		}(host)
	}

	wg.Wait()
	return nil
}

func (s *HTTPScanner) storeBasicService(svc *models.HTTPService) error {
	_, err := s.db.Exec(`
		INSERT INTO http_services (id, target_id, url, status_code, title, server, content_type, content_length, last_seen)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, url) DO UPDATE SET
			status_code = excluded.status_code,
			title = excluded.title,
			last_seen = CURRENT_TIMESTAMP
	`, svc.ID, svc.TargetID, svc.URL, svc.StatusCode, svc.Title, svc.Server, svc.ContentType, svc.ContentLength)
	return err
}

func (s *HTTPScanner) RunWithCallback(ctx context.Context, taskID string, callback func(line string), args ...string) error {
	return s.exec.RunWithCallback(ctx, taskID, callback, "httpx", args...)
}

func (s *HTTPScanner) ProbeURL(ctx context.Context, targetID, url string) error {
	if !s.exec.IsToolAvailable("httpx") {
		return nil
	}
	_, err := s.exec.Run(ctx, "httpx",
		"-u", url,
		"-silent",
		"-json",
		"-title",
		"-web-server",
		"-tech-detect",
	)
	return err
}

// RunWithInput probes an explicit newline-separated list of hosts via httpx.
// It correctly feeds the list through stdin (previously it used a plain
// RunWithCallback with `-l /dev/stdin`, which — like the old nuclei bug — read
// EOF and scanned nothing).
func (s *HTTPScanner) RunWithInput(ctx context.Context, taskID string, input string, logFn LogFunc) error {
	if !s.exec.IsToolAvailable("httpx") {
		return nil
	}

	return s.exec.RunWithInputCallback(ctx, strings.NewReader(input), taskID, func(line string) {
		var out httpxOutput
		if err := json.Unmarshal([]byte(line), &out); err != nil {
			return
		}
		if err := s.storeHTTPService(taskID, out); err != nil {
			s.logger.Error("Failed to store HTTP service from input run", "error", err)
		}
	}, "httpx",
		"-l", "/dev/stdin",
		"-silent",
		"-json",
		"-title",
		"-web-server",
		"-tech-detect",
		"-status-code",
		"-content-length",
		"-follow-redirects",
		"-timeout", "10",
	)
}
