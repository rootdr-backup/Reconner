package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
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

// IntelScanner is the intelligence layer: it fingerprints the technology of
// each live host and then launches TECHNOLOGY-SPECIFIC checks that generic
// scanners never run. This is where the highest-value bounty classes live —
// Spring actuator heapdumps (leaked creds), Laravel Ignition RCE, Next.js image
// SSRF, WordPress user enumeration. Instead of blindly probing every path on
// every host, it only runs a stack's checks when that stack is detected, so it
// is both faster and far more accurate than a flat wordlist.
type IntelScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewIntelScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *IntelScanner {
	return &IntelScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var intelClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   12 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 2 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

func (s *IntelScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "intel", "Fingerprinting technologies and running stack-specific checks...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	seen := make(map[string]bool)
	var hosts []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			base := hostBase(u)
			if base != "" && !seen[base] {
				seen[base] = true
				hosts = append(hosts, base)
			}
		}
	}
	rows.Close()
	if len(hosts) == 0 {
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	logFn("info", "intel", fmt.Sprintf("Analyzing %d hosts for technology-specific weaknesses...", len(hosts)))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, host := range hosts {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(base string) {
			defer wg.Done()
			defer func() { <-sem }()
			found.Add(int64(s.analyzeHost(ctx, targetID, base, auth, logFn)))
		}(host)
	}
	wg.Wait()

	logFn("info", "intel", fmt.Sprintf("Intelligence checks done. Found %d issues.", found.Load()))
	return nil
}

func (s *IntelScanner) analyzeHost(ctx context.Context, targetID, base string, auth map[string]string, logFn LogFunc) int {
	status, hdr, body := s.get(ctx, base, auth)
	if status == 0 {
		return 0
	}
	techs := fingerprint(hdr, body)
	n := 0
	report := func(typ, sev, url, evidence string) {
		s.store(targetID, typ, sev, url, evidence)
		n++
		logFn("warn", "intel", fmt.Sprintf("[%s] %s — %s", sev, typ, url))
		if sev == "high" || sev == "critical" {
			if s.broadcast != nil {
				s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": typ, "url": url})
			}
		}
	}

	if techs["spring"] {
		s.checkSpring(ctx, base, auth, report)
	}
	if techs["laravel"] {
		s.checkLaravel(ctx, base, auth, report)
	}
	if techs["nextjs"] {
		s.checkNextjs(ctx, base, auth, report)
	}
	if techs["wordpress"] {
		s.checkWordPress(ctx, base, auth, report)
	}
	if techs["django"] {
		s.checkDjango(ctx, base, auth, report)
	}
	if techs["rails"] {
		s.checkRails(ctx, base, auth, report)
	}
	return n
}

// ── fingerprinting ────────────────────────────────────────────────────────────

func fingerprint(hdr http.Header, body string) map[string]bool {
	t := map[string]bool{}
	server := strings.ToLower(hdr.Get("Server"))
	powered := strings.ToLower(hdr.Get("X-Powered-By"))
	setCookie := strings.ToLower(strings.Join(hdr["Set-Cookie"], " "))
	lb := strings.ToLower(body)

	if strings.Contains(setCookie, "laravel_session") || strings.Contains(setCookie, "xsrf-token") ||
		strings.Contains(lb, "laravel") {
		t["laravel"] = true
	}
	if strings.Contains(setCookie, "jsessionid") || strings.Contains(lb, "whitelabel error page") ||
		hdr.Get("X-Application-Context") != "" || strings.Contains(lb, "org.springframework") {
		t["spring"] = true
	}
	if strings.Contains(lb, "__next_data__") || strings.Contains(lb, "/_next/static") ||
		hdr.Get("X-Powered-By") == "Next.js" {
		t["nextjs"] = true
	}
	if strings.Contains(lb, "/wp-content/") || strings.Contains(lb, "/wp-includes/") ||
		strings.Contains(lb, "wp-json") {
		t["wordpress"] = true
	}
	if strings.Contains(lb, "csrfmiddlewaretoken") || strings.Contains(setCookie, "csrftoken") ||
		strings.Contains(lb, "__admin_media_prefix__") {
		t["django"] = true
	}
	if strings.Contains(setCookie, "_rails") || strings.Contains(powered, "phusion passenger") ||
		strings.Contains(lb, "content-security-policy-report-only") && strings.Contains(server, "puma") {
		t["rails"] = true
	}
	return t
}

// ── Spring Boot ───────────────────────────────────────────────────────────────

func (s *IntelScanner) checkSpring(ctx context.Context, base string, auth map[string]string, report func(t, sev, url, ev string)) {
	for _, c := range []struct{ path, sig, typ, sev string }{
		{"/actuator", `"_links"`, "spring_actuator_open", "medium"},
		{"/actuator/env", "propertySources", "spring_actuator_env", "high"},
		{"/actuator/mappings", "dispatcherServlet", "spring_actuator_mappings", "medium"},
		{"/actuator/configprops", "contexts", "spring_actuator_configprops", "medium"},
		{"/actuator/gateway/routes", "route_id", "spring_gateway_routes", "high"},
		{"/env", "propertySources", "spring_env_legacy", "high"},
	} {
		st, _, b := s.get(ctx, base+c.path, auth)
		if st == 200 && strings.Contains(b, c.sig) {
			report(c.typ, c.sev, base+c.path, "Spring Boot endpoint exposed (matched: "+c.sig+")")
		}
	}
	// Heapdump — a full memory dump, frequently containing credentials/tokens.
	st, hdr, _ := s.get(ctx, base+"/actuator/heapdump", auth)
	if st == 200 && (strings.Contains(strings.ToLower(hdr.Get("Content-Type")), "octet-stream") || strings.Contains(strings.ToLower(hdr.Get("Content-Disposition")), "heapdump")) {
		report("spring_heapdump_exposed", "critical", base+"/actuator/heapdump", "Heap dump downloadable — likely leaks in-memory secrets/creds")
	}
}

// ── Laravel ───────────────────────────────────────────────────────────────────

func (s *IntelScanner) checkLaravel(ctx context.Context, base string, auth map[string]string, report func(t, sev, url, ev string)) {
	if st, _, b := s.get(ctx, base+"/.env", auth); st == 200 && strings.Contains(b, "APP_KEY") {
		report("laravel_env_exposed", "critical", base+"/.env", "Laravel .env exposed (APP_KEY, DB creds)")
	}
	if st, _, b := s.get(ctx, base+"/telescope/requests", auth); st == 200 && strings.Contains(b, "Telescope") {
		report("laravel_telescope_open", "high", base+"/telescope", "Laravel Telescope debug dashboard exposed")
	}
	// Ignition (Laravel debug page) — historically RCE (CVE-2021-3129).
	if st, _, b := s.postJSON(ctx, base+"/_ignition/execute-solution", `{"solution":"x","parameters":{}}`, auth); st != 0 &&
		(strings.Contains(b, "MakeViewVariableOptionalSolution") || strings.Contains(b, "solution") || st == 500) {
		report("laravel_ignition_exposed", "high", base+"/_ignition/execute-solution", "Laravel Ignition endpoint reachable — check CVE-2021-3129 RCE")
	}
	if st, _, b := s.get(ctx, base+"/storage/logs/laravel.log", auth); st == 200 && strings.Contains(b, "stack trace") {
		report("laravel_log_exposed", "high", base+"/storage/logs/laravel.log", "Laravel log file exposed")
	}
}

// ── Next.js ───────────────────────────────────────────────────────────────────

func (s *IntelScanner) checkNextjs(ctx context.Context, base string, auth map[string]string, report func(t, sev, url, ev string)) {
	// Image optimizer SSRF — /_next/image?url= can be abused to fetch internal
	// resources on misconfigured deployments.
	u := base + "/_next/image?url=http://169.254.169.254/latest/meta-data/&w=64&q=75"
	if st, _, b := s.get(ctx, u, auth); st == 200 {
		for _, sig := range ssrfMetadataSignatures {
			if sig.MatchString(b) {
				report("nextjs_image_ssrf", "critical", u, "Next.js image optimizer proxied cloud metadata (SSRF)")
				break
			}
		}
	}
	if st, _, b := s.get(ctx, base+"/_next/static/", auth); st == 200 && strings.Contains(b, "Index of") {
		report("nextjs_static_listing", "low", base+"/_next/static/", "Next.js static directory listing")
	}
}

// ── WordPress ─────────────────────────────────────────────────────────────────

func (s *IntelScanner) checkWordPress(ctx context.Context, base string, auth map[string]string, report func(t, sev, url, ev string)) {
	if st, _, b := s.get(ctx, base+"/wp-json/wp/v2/users", auth); st == 200 && strings.Contains(b, `"slug"`) {
		report("wordpress_user_enum", "medium", base+"/wp-json/wp/v2/users", "WordPress REST user enumeration (usernames leaked)")
	}
	if st, _, b := s.get(ctx, base+"/xmlrpc.php", auth); st == 405 || (st == 200 && strings.Contains(b, "XML-RPC server accepts POST")) {
		report("wordpress_xmlrpc_open", "low", base+"/xmlrpc.php", "WordPress XML-RPC enabled (brute-force / pingback SSRF vector)")
	}
	if st, _, b := s.get(ctx, base+"/wp-content/debug.log", auth); st == 200 && (strings.Contains(b, "PHP") || strings.Contains(b, "stack trace")) {
		report("wordpress_debug_log", "high", base+"/wp-content/debug.log", "WordPress debug.log exposed")
	}
}

// ── Django ────────────────────────────────────────────────────────────────────

func (s *IntelScanner) checkDjango(ctx context.Context, base string, auth map[string]string, report func(t, sev, url, ev string)) {
	// Trigger a 404 to reveal a DEBUG=True page (leaks settings, paths, versions).
	if st, _, b := s.get(ctx, base+"/rcn-nonexistent-"+pfCanary, auth); st == 404 &&
		(strings.Contains(b, "You're seeing this error because you have") || strings.Contains(b, "URLconf")) {
		report("django_debug_enabled", "high", base, "Django DEBUG=True — settings/paths disclosed on errors")
	}
}

// ── Rails ─────────────────────────────────────────────────────────────────────

func (s *IntelScanner) checkRails(ctx context.Context, base string, auth map[string]string, report func(t, sev, url, ev string)) {
	if st, _, b := s.get(ctx, base+"/rails/info/routes", auth); st == 200 && strings.Contains(b, "Helper") {
		report("rails_routes_exposed", "medium", base+"/rails/info/routes", "Rails routes info page exposed (dev mode)")
	}
}

// ── low-level helpers ─────────────────────────────────────────────────────────

func (s *IntelScanner) get(ctx context.Context, u string, auth map[string]string) (int, http.Header, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", u, nil)
	if err != nil {
		return 0, nil, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := intelClient.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return resp.StatusCode, resp.Header, string(body)
}

func (s *IntelScanner) postJSON(ctx context.Context, u, payload string, auth map[string]string) (int, http.Header, string) {
	reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "POST", u, strings.NewReader(payload))
	if err != nil {
		return 0, nil, ""
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	req.Header.Set("Content-Type", "application/json")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := intelClient.Do(req)
	if err != nil {
		return 0, nil, ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	resp.Body.Close()
	return resp.StatusCode, resp.Header, string(body)
}

func (s *IntelScanner) store(targetID, vulnType, severity, rawURL, evidence string) {
	id := uuid.New().String()
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence)
		VALUES (?, ?, ?, ?, ?, '', '', ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity = excluded.severity, evidence = excluded.evidence
	`, id, targetID, vulnType, severity, rawURL, evidence)
}

// hostBase reduces a URL to scheme://host[:port].
func hostBase(rawURL string) string {
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
