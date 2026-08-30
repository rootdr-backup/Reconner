package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// TimeMachineScanner ports the core of anmolksachan/TheTimeMachine: mine the
// Wayback Machine's archive for a domain, pull every parameterised URL ever
// seen, and bucket the parameters by the vulnerability class their NAME hints at
// (redirect/SSRF, LFI, SQLi/IDOR, XSS, RCE, SSRF). The harvested params are fed
// straight into the `parameters` table so the active injection modules test
// endpoints that may not be linked anywhere on the live site anymore — a classic
// source of forgotten, still-exploitable bugs.
type TimeMachineScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewTimeMachineScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *TimeMachineScanner {
	return &TimeMachineScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var tmHTTPClient = &http.Client{Timeout: 90 * time.Second}

// vuln-prone parameter-name heuristics (lowercased substrings). Mirrors the
// "juicy param" lists TheTimeMachine ships, condensed and de-duplicated.
var tmBuckets = map[string][]string{
	"redirect/SSRF": {"url", "uri", "redirect", "redir", "return", "returnurl", "next", "continue", "dest", "destination", "callback", "redirect_uri", "out", "view", "go", "link", "target"},
	"LFI/path":      {"file", "path", "page", "folder", "dir", "document", "root", "pg", "template", "php_path", "doc", "download", "read", "load", "include"},
	"SQLi/IDOR":     {"id", "user", "userid", "uid", "account", "number", "order", "no", "item", "cat", "category", "product", "pid", "select", "report", "row", "search_id"},
	"XSS":           {"q", "s", "search", "query", "keyword", "kw", "term", "text", "message", "msg", "name", "comment", "content", "title", "email", "lang", "redirect_url"},
	"RCE/cmd":       {"cmd", "exec", "command", "run", "ping", "query_string", "func", "code", "do", "action", "proc", "shell", "system"},
}

// Run harvests archived parameterised URLs and classifies them.
func (s *TimeMachineScanner) Run(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	logFn("info", "timemachine", "TimeMachine: mining Wayback archive for forgotten parameterised URLs...")

	urls, err := s.fetchWayback(ctx, domain)
	if err != nil {
		logFn("warn", "timemachine", fmt.Sprintf("Wayback fetch failed: %v", err))
		return nil // non-fatal: it's an enrichment source
	}
	logFn("info", "timemachine", fmt.Sprintf("TimeMachine: %d archived URLs retrieved", len(urls)))

	bucketCounts := map[string]int{}
	seen := map[string]bool{} // url|param dedupe
	stored := 0

	for _, raw := range urls {
		if ctx.Err() != nil {
			break
		}
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			continue
		}
		q := u.Query()
		if len(q) == 0 {
			continue
		}
		// strip the query for a clean base URL we store per-param
		base := u.Scheme + "://" + u.Host + u.Path
		for param, vals := range q {
			key := base + "|" + param
			if seen[key] {
				continue
			}
			seen[key] = true
			val := ""
			if len(vals) > 0 {
				val = vals[0]
			}
			if s.store(targetID, base, param, val) {
				stored++
			}
			if cat := tmClassify(param); cat != "" {
				bucketCounts[cat]++
			}
		}
	}

	if stored > 0 {
		logFn("info", "timemachine", fmt.Sprintf("TimeMachine: injected %d unique archived parameters for active testing", stored))
	}
	// Report the vuln-class breakdown so the operator sees what's worth watching.
	if len(bucketCounts) > 0 {
		type kv struct {
			k string
			v int
		}
		var order []kv
		for k, v := range bucketCounts {
			order = append(order, kv{k, v})
		}
		sort.Slice(order, func(i, j int) bool { return order[i].v > order[j].v })
		var parts []string
		for _, o := range order {
			parts = append(parts, fmt.Sprintf("%s=%d", o.k, o.v))
		}
		logFn("info", "timemachine", "TimeMachine vuln-class buckets → "+strings.Join(parts, ", "))
	}
	logFn("info", "timemachine", "TimeMachine complete.")
	return nil
}

// fetchWayback pulls the domain's archived original URLs from the CDX API. It
// collapses duplicates server-side and caps the volume so a huge domain can't
// blow up memory.
func (s *TimeMachineScanner) fetchWayback(ctx context.Context, domain string) ([]string, error) {
	api := fmt.Sprintf(
		"http://web.archive.org/cdx/search/cdx?url=*.%s/*&output=text&fl=original&collapse=urlkey&limit=50000",
		url.QueryEscape(domain))
	req, err := http.NewRequestWithContext(ctx, "GET", api, nil)
	if err != nil {
		return nil, err
	}
	resp, err := tmHTTPClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("cdx status %d", resp.StatusCode)
	}

	var out []string
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line != "" && strings.Contains(line, "?") {
			out = append(out, line)
		}
	}
	return out, sc.Err()
}

// tmClassify returns the vuln bucket a parameter name hints at (empty if none).
func tmClassify(param string) string {
	p := strings.ToLower(param)
	for cat, names := range tmBuckets {
		for _, n := range names {
			if p == n {
				return cat
			}
		}
	}
	return ""
}

func (s *TimeMachineScanner) store(targetID, rawURL, param, value string) bool {
	id := uuid.New().String()
	res, err := s.db.Exec(`
		INSERT INTO parameters (id,target_id,url,parameter,value,source,method,content_type,location)
		VALUES (?,?,?,?,?,'timemachine','GET','','query')
		ON CONFLICT(target_id,url,parameter,method,location,content_type) DO NOTHING
	`, id, targetID, rawURL, param, value)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}
