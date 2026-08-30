package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
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

// JSEndpointScanner closes the loop on JavaScript analysis. js_analysis extracts
// endpoints/routes from bundles but never scans them — so an API only referenced
// inside a webpack chunk is invisible to every active check. This module takes
// those extracted paths, resolves them to absolute in-scope URLs, probes which
// actually exist, and feeds the live ones back into http_services + parameters.
// After this runs, the whole active pipeline (XSS/SQLi/SSRF/… + nuclei) reaches
// endpoints that are only reachable through JS.
type JSEndpointScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewJSEndpointScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *JSEndpointScanner {
	return &JSEndpointScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var jsEndpointClient = newPooledClient(12*time.Second, false)

func (s *JSEndpointScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "js_endpoints", "Resolving & probing endpoints extracted from JavaScript...")

	var domain string
	_ = s.db.QueryRowContext(ctx, `SELECT domain FROM targets WHERE id = ?`, targetID).Scan(&domain)

	// Extracted endpoint-ish JS findings.
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT value FROM js_findings
		WHERE target_id = ? AND type IN ('endpoint','api_url','graphql','debug_endpoint','auth_endpoint','config')
		LIMIT 4000
	`, targetID)
	if err != nil {
		return err
	}
	var raw []string
	for rows.Next() {
		var v string
		if err := rows.Scan(&v); err == nil {
			raw = append(raw, v)
		}
	}
	rows.Close()

	// Alive host roots to resolve relative paths against.
	hostRoots := s.aliveHostRoots(ctx, targetID)
	if len(hostRoots) == 0 {
		return nil
	}

	// Build the candidate absolute-URL set (deduped, in-scope only).
	candidates := s.buildCandidates(raw, hostRoots, domain)
	if len(candidates) == 0 {
		logFn("info", "js_endpoints", "No resolvable endpoints found in JS")
		return nil
	}
	logFn("info", "js_endpoints", fmt.Sprintf("Probing %d JS-derived endpoint candidates...", len(candidates)))

	auth := loadAuthHeaders(ctx, s.db, targetID)
	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var live, params atomic.Int64

	for _, u := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(candidate string) {
			defer wg.Done()
			defer func() { <-sem }()

			status, title := s.probe(ctx, candidate, auth)
			if status == 0 || status == 404 {
				return
			}
			// Store as a scannable service.
			if s.storeService(targetID, candidate, status, title) {
				live.Add(1)
			}
			// Harvest any query params for the active modules.
			if p := storeQueryParams(s.db, targetID, candidate); p > 0 {
				params.Add(int64(p))
			}
		}(u)
	}
	wg.Wait()

	logFn("info", "js_endpoints", fmt.Sprintf("JS endpoints done. %d live endpoints added, %d params harvested.", live.Load(), params.Load()))
	return nil
}

func (s *JSEndpointScanner) aliveHostRoots(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT 200
	`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) != nil {
			continue
		}
		if b := hostBaseScan(u); b != "" && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}

// buildCandidates turns raw JS strings into absolute, in-scope, deduped URLs.
func (s *JSEndpointScanner) buildCandidates(raw, hostRoots []string, domain string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(u string) {
		if u == "" || seen[u] || len(out) >= 3000 {
			return
		}
		// scope: must be on the target domain (or a subdomain).
		if domain != "" {
			p, err := url.Parse(u)
			if err != nil {
				return
			}
			h := strings.ToLower(p.Hostname())
			d := strings.ToLower(domain)
			if h != d && !strings.HasSuffix(h, "."+d) {
				return
			}
		}
		seen[u] = true
		out = append(out, u)
	}

	for _, v := range raw {
		v = strings.TrimSpace(v)
		if v == "" || len(v) > 512 {
			continue
		}
		switch {
		case strings.HasPrefix(v, "http://") || strings.HasPrefix(v, "https://"):
			add(v)
		case strings.HasPrefix(v, "/"):
			// relative path — resolve against every alive host root
			for _, root := range hostRoots {
				add(strings.TrimRight(root, "/") + v)
			}
		}
	}
	return out
}

func (s *JSEndpointScanner) probe(ctx context.Context, u string, auth map[string]string) (int, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return 0, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := jsEndpointClient.Do(req)
	if err != nil {
		return 0, ""
	}
	resp.Body.Close()
	return resp.StatusCode, resp.Header.Get("Content-Type")
}

func (s *JSEndpointScanner) storeService(targetID, u string, status int, ctype string) bool {
	id := uuid.New().String()
	res, err := s.db.Exec(`
		INSERT INTO http_services (id, target_id, url, status_code, content_type, last_seen, source)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, 'js')
		ON CONFLICT(target_id, url) DO NOTHING
	`, id, targetID, u, status, ctype)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// storeQueryParams extracts ?a=b params from a URL into the parameters table.
func storeQueryParams(db *database.DB, targetID, rawURL string) int {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}
	n := 0
	for name, vals := range parsed.Query() {
		val := ""
		if len(vals) > 0 {
			val = vals[0]
		}
		id := uuid.New().String()
		res, err := db.Exec(`
			INSERT INTO parameters (id,target_id,url,parameter,value,source,method,content_type,location)
			VALUES (?,?,?,?,?,'js','GET','','query')
			ON CONFLICT(target_id,url,parameter,method,location,content_type) DO NOTHING
		`, id, targetID, rawURL, name, val)
		if err == nil {
			if a, _ := res.RowsAffected(); a > 0 {
				n++
			}
		}
	}
	return n
}

// hostBaseScan reduces a URL to scheme://host[:port] (scanner-package copy).
func hostBaseScan(rawURL string) string {
	i := strings.Index(rawURL, "://")
	if i < 0 {
		return ""
	}
	rest := rawURL[i+3:]
	if j := strings.IndexAny(rest, "/?#"); j >= 0 {
		rest = rest[:j]
	}
	if rest == "" {
		return ""
	}
	return rawURL[:i+3] + rest
}
