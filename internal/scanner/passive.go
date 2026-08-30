package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// PassiveScanner inspects every live response without sending attack payloads —
// the same discipline Burp's passive scanner uses, which is where a large share
// of real, low-noise findings come from (missing headers, cookie flags, info
// disclosure, stack traces, secrets echoed in responses).
type PassiveScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
	// hdrSeen deduplicates host-level hygiene findings (missing CSP/HSTS/…, tech
	// disclosure) to ONE per (target, host, type). These are a property of the
	// server/host, not of a specific endpoint, so raising them on every one of a
	// site's thousands of URLs is pure noise that buries real findings. Key:
	// targetID|host|type.
	hdrSeen sync.Map
}

// perDomainHygieneTypes are finding types that describe the HOST's security
// posture (a header/tech-stack property), not an endpoint-specific bug. They are
// reported ONCE per domain instead of once per URL.
var perDomainHygieneTypes = map[string]bool{
	"missing_csp":               true,
	"missing_xfo":               true,
	"missing_xcto":              true,
	"missing_hsts":              true,
	"server_version_disclosure": true,
	"tech_disclosure":           true,
}

func NewPassiveScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *PassiveScanner {
	return &PassiveScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var passiveHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// Server-side error / stack-trace signatures (verbose error disclosure).
var stackTraceSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)Fatal error:.*on line \d+`),            // PHP
	regexp.MustCompile(`(?i)Warning: .*? in .*? on line \d+`),      // PHP
	regexp.MustCompile(`(?i)Traceback \(most recent call last\)`),  // Python
	regexp.MustCompile(`(?i)at [\w.$]+\([\w.]+\.java:\d+\)`),       // Java
	regexp.MustCompile(`(?i)System\.[\w.]+Exception`),              // .NET
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider`),            // ASP/DB
	regexp.MustCompile(`(?i)org\.springframework\.`),               // Spring
	regexp.MustCompile(`(?i)Whitelabel Error Page`),                // Spring Boot
	regexp.MustCompile(`(?i)Ruby.*?\.rb:\d+:in`),                   // Ruby
	regexp.MustCompile(`(?i)Exception in thread`),                  // Java
	regexp.MustCompile(`(?i)ORA-\d{5}`),                            // Oracle
	regexp.MustCompile(`(?i)You have an error in your SQL syntax`), // MySQL
}

var privateIPRe = regexp.MustCompile(`\b(?:10\.(?:\d{1,3})\.(?:\d{1,3})\.(?:\d{1,3})|192\.168\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3})\b`)
var emailRe = regexp.MustCompile(`[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}`)

// Precompiled once. Previously these were compiled inside analyze() — i.e. on
// every single response, thousands of redundant regex compilations per scan.
var (
	serverHasDigitRe  = regexp.MustCompile(`\d`)
	passwordFieldRe   = regexp.MustCompile(`(?i)<input[^>]+type=["']?password["']?[^>]*>`)
	autocompleteOffRe = regexp.MustCompile(`(?i)autocomplete=["']?off`)
	mixedContentRe    = regexp.MustCompile(`(?i)(src|href)=["']http://`)
)

func (s *PassiveScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "passive", "Running passive analysis on live responses...")

	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 499
		ORDER BY url LIMIT ?
	`, targetID, s.cfg.URLLimit())
	if err != nil {
		return err
	}
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	if len(urls) == 0 {
		return nil
	}

	// Per-host cap (performance): passive findings are overwhelmingly host-level
	// (security headers, tech disclosure) or saturate after a handful of pages
	// (directory listing, stack traces, cookie flags). Re-fetching all 20,000 URLs
	// of one host to re-derive the same handful of observations is a huge, pointless
	// cost on big targets. Sample a generous slice per host instead — full coverage
	// of DISTINCT hosts, bounded work per host. Opt out with a very high URLLimit.
	const passivePerHostCap = 60
	if capped := capURLsPerHost(urls, passivePerHostCap); len(capped) < len(urls) {
		logFn("info", "passive", fmt.Sprintf("Sampling %d of %d URL(s) (≤%d per host) — passive findings are host-level.",
			len(capped), len(urls), passivePerHostCap))
		urls = capped
	}
	logFn("info", "passive", fmt.Sprintf("Analyzing %d responses...", len(urls)))

	sem := make(chan struct{}, 15)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			found.Add(int64(s.analyze(ctx, targetID, target)))
		}(u)
	}
	wg.Wait()

	logFn("info", "passive", fmt.Sprintf("Passive analysis done. Raised %d observations.", found.Load()))
	return nil
}

func (s *PassiveScanner) analyze(ctx context.Context, targetID, target string) int {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", target, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
	resp, err := passiveHTTPClient.Do(req)
	if err != nil {
		return 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	bodyStr := string(body)
	h := resp.Header
	isHTTPS := strings.HasPrefix(target, "https://")
	n := 0

	add := func(typ, sev, evidence string) {
		s.store(targetID, typ, sev, target, evidence)
		n++
	}
	// addDomain records a host-level hygiene finding ONCE per (target, host, type),
	// keyed against the host root (scheme://host/) rather than this endpoint — so a
	// missing CSP/HSTS/… on a 10,000-URL site is one finding, not ten thousand.
	host := hostRootOf(target)
	addDomain := func(typ, sev, evidence string) {
		key := targetID + "|" + host + "|" + typ
		if _, dup := s.hdrSeen.LoadOrStore(key, true); dup {
			return
		}
		s.store(targetID, typ, sev, host, evidence)
		n++
	}

	// ── Security headers (host-level → one per domain) ─────────────────────────
	ct := strings.ToLower(h.Get("Content-Type"))
	isHTML := strings.Contains(ct, "html")
	if isHTML {
		if h.Get("Content-Security-Policy") == "" {
			addDomain("missing_csp", "low", "No Content-Security-Policy header (host-level; reported once per domain)")
		}
		if h.Get("X-Frame-Options") == "" && !strings.Contains(strings.ToLower(h.Get("Content-Security-Policy")), "frame-ancestors") {
			addDomain("missing_xfo", "low", "No X-Frame-Options / frame-ancestors — clickjacking exposure (host-level)")
		}
		if h.Get("X-Content-Type-Options") == "" {
			addDomain("missing_xcto", "info", "No X-Content-Type-Options: nosniff (host-level)")
		}
	}
	if isHTTPS && h.Get("Strict-Transport-Security") == "" {
		addDomain("missing_hsts", "low", "HTTPS response without Strict-Transport-Security (host-level)")
	}

	// ── Cookie flags ──────────────────────────────────────────────────────────
	for _, c := range resp.Cookies() {
		low := strings.ToLower(c.Name)
		sessionish := strings.Contains(low, "sess") || strings.Contains(low, "token") ||
			strings.Contains(low, "auth") || strings.Contains(low, "sid") || strings.Contains(low, "jwt")
		if isHTTPS && !c.Secure {
			sev := "low"
			if sessionish {
				sev = "medium"
			}
			add("cookie_no_secure", sev, fmt.Sprintf("Cookie %q set without Secure flag", c.Name))
		}
		if !c.HttpOnly && sessionish {
			add("cookie_no_httponly", "medium", fmt.Sprintf("Session cookie %q without HttpOnly", c.Name))
		}
		if c.SameSite == http.SameSiteDefaultMode && sessionish {
			add("cookie_no_samesite", "low", fmt.Sprintf("Session cookie %q without SameSite", c.Name))
		}
	}

	// ── Version / tech disclosure (host-level → one per domain) ────────────────
	if srv := h.Get("Server"); srv != "" && serverHasDigitRe.MatchString(srv) {
		addDomain("server_version_disclosure", "info", "Server header discloses version: "+srv)
	}
	if xp := h.Get("X-Powered-By"); xp != "" {
		addDomain("tech_disclosure", "info", "X-Powered-By reveals stack: "+xp)
	}
	for _, hn := range []string{"X-AspNet-Version", "X-AspNetMvc-Version", "X-Generator", "X-Drupal-Cache"} {
		if v := h.Get(hn); v != "" {
			addDomain("tech_disclosure", "info", hn+": "+v)
		}
	}

	// ── Directory listing ─────────────────────────────────────────────────────
	if strings.Contains(bodyStr, "<title>Index of /") || strings.Contains(bodyStr, "Directory listing for") {
		add("directory_listing", "medium", "Directory listing enabled")
	}

	// ── Verbose errors / stack traces ─────────────────────────────────────────
	for _, sig := range stackTraceSignatures {
		if sig.MatchString(bodyStr) {
			add("verbose_error", "medium", "Server error / stack trace disclosed: "+sig.String())
			break
		}
	}

	// ── Internal IP disclosure ────────────────────────────────────────────────
	if m := privateIPRe.FindString(bodyStr); m != "" {
		add("internal_ip_disclosure", "low", "Private IP disclosed in response: "+m)
	}

	// ── Secrets echoed in HTML/headers (high value) ───────────────────────────
	for _, pat := range jsPatterns {
		if !isSecretType(pat.Type) {
			continue
		}
		if m := pat.Pattern.FindString(bodyStr); m != "" && !isPlaceholderSecret(m) && shannonEntropy(m) >= 3.0 {
			add("secret_in_response_"+pat.Type, "high", "Possible "+pat.Type+" exposed in HTML response")
			break
		}
	}

	// ── Autocomplete on password field ────────────────────────────────────────
	if isHTML && passwordFieldRe.MatchString(bodyStr) {
		if !autocompleteOffRe.MatchString(bodyStr) {
			add("password_autocomplete", "info", "Password field without autocomplete=off")
		}
	}

	// ── Mixed content ─────────────────────────────────────────────────────────
	if isHTTPS && isHTML && mixedContentRe.MatchString(bodyStr) {
		add("mixed_content", "low", "HTTPS page loads resources over http://")
	}

	// (Open redirect via the Location header is handled — with exploitability
	// confirmation — by the active RunOpenRedirectDiscovery module, not here; a
	// passive "Location points off-site" note would be pure noise without the
	// injected-payload proof that module provides.)

	return n
}

// capURLsPerHost returns at most `perHost` URLs for each host, preserving the
// original order. Distinct hosts are all kept; only the long tail of same-host
// URLs is trimmed.
func capURLsPerHost(urls []string, perHost int) []string {
	if perHost <= 0 {
		return urls
	}
	counts := make(map[string]int)
	out := make([]string, 0, len(urls))
	for _, u := range urls {
		h := ""
		if pu, err := url.Parse(u); err == nil {
			h = pu.Host
		}
		if counts[h] >= perHost {
			continue
		}
		counts[h]++
		out = append(out, u)
	}
	return out
}

// hostRootOf reduces a URL to its scheme://host/ root, the canonical anchor for a
// host-level finding. Falls back to the input on a parse error.
func hostRootOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return rawURL
	}
	scheme := u.Scheme
	if scheme == "" {
		scheme = "https"
	}
	return scheme + "://" + u.Host + "/"
}

func (s *PassiveScanner) store(targetID, vulnType, severity, rawURL, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL, Method: "PASSIVE",
		Location: "response", Evidence: evidence, Source: "passive",
		DetectionMethod: "passive-signature", Confidence: ConfEvidence, Verdict: VerifyVerified,
	})
	// high-severity passive findings (exposed secrets) are worth a push
	if s.broadcast != nil && (severity == "high" || severity == "critical") {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": vulnType, "url": rawURL,
		})
	}
	_ = emailRe // reserved for an opt-in email-harvest check
}
