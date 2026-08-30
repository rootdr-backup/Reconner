package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
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

// CSRFScanner detects likely Cross-Site Request Forgery on state-changing forms
// — the #11 class in the HackerOne top-20 that Reconner only touched passively
// (cookie SameSite flag). It finds POST <form>s that carry NO anti-CSRF token
// and whose page's session cookie is NOT SameSite-protected. Because CSRF
// protection can also live server-side (header tokens, per-request checks we
// can't observe), every hit is a CANDIDATE, never a confirmed finding — keeping
// the zero-false-positive guarantee for the Findings view.
type CSRFScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewCSRFScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *CSRFScanner {
	return &CSRFScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var csrfClient = &http.Client{Timeout: 12 * time.Second, Transport: sharedHTTPTransport}

// csrfTokenName matches hidden-input names that are anti-CSRF tokens.
var csrfTokenName = regexp.MustCompile(`(?i)csrf|xsrf|_token|authenticity_token|nonce|request[_-]?verification|anti[_-]?forgery`)

// reHiddenInput pulls hidden input fields (name + value) from a form.
var reHiddenInput = regexp.MustCompile(`(?is)<input[^>]*type\s*=\s*["']?hidden["']?[^>]*>`)
var reInputName = regexp.MustCompile(`(?i)\bname\s*=\s*["']([^"']+)["']`)

func (s *CSRFScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "csrf", "Checking state-changing forms for missing CSRF protection...")

	pages := s.loadPages(ctx, targetID)
	if len(pages) == 0 {
		logFn("info", "csrf", "No pages to check")
		return nil
	}

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64
	for _, p := range pages {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(page string) {
			defer wg.Done()
			defer func() { <-sem }()
			found.Add(int64(s.checkPage(ctx, targetID, page, logFn)))
		}(p)
	}
	wg.Wait()

	logFn("info", "csrf", fmt.Sprintf("CSRF check done. Found %d candidate(s).", found.Load()))
	return nil
}

func (s *CSRFScanner) loadPages(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services
		WHERE target_id=? AND COALESCE(source,'probe')='probe' AND status_code BETWEEN 200 AND 399
		LIMIT ?`, targetID, s.cfg.URLLimit())
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			out = append(out, u)
		}
	}
	return filterURLsByHostScope(ctx, out)
}

func (s *CSRFScanner) checkPage(ctx context.Context, targetID, page string, logFn LogFunc) int {
	reqCtx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", page, nil)
	if err != nil {
		return 0
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
	resp, err := csrfClient.Do(req)
	if err != nil {
		return 0
	}
	ct := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.Contains(ct, "html") {
		resp.Body.Close()
		return 0
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	sameSiteProtected := sessionCookieSameSiteProtected(resp.Cookies())
	resp.Body.Close()

	count := 0
	for _, form := range formRE.FindAllString(string(body), -1) {
		// Only POST (state-changing) forms; GET forms aren't CSRF-relevant.
		m := methodRE.FindStringSubmatch(form)
		if len(m) < 2 || !strings.EqualFold(m[1], "post") {
			continue
		}
		if formHasCSRFToken(form) {
			continue // protected by a token field
		}
		// A SameSite=Lax/Strict session cookie already blocks cross-site POSTs
		// for the common case — don't cry wolf when the app relies on that.
		if sameSiteProtected {
			continue
		}
		action := page
		if a := actionRE.FindStringSubmatch(form); len(a) > 1 && a[1] != "" {
			action = resolveURL(page, a[1])
		}
		s.store(targetID, page, action)
		count++
		logFn("warn", "csrf", fmt.Sprintf("CSRF candidate: POST form with no anti-CSRF token at %s (action %s)", page, action))
	}
	return count
}

func (s *CSRFScanner) store(targetID, page, action string) {
	evidence := "POST form has no anti-CSRF token field and the page's session cookie is not SameSite-protected — likely CSRF. Confirm manually (server may validate a header token). Action: " + action
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "csrf", Severity: "medium", URL: page, Method: "POST",
		Location: "form", Payload: action, Evidence: evidence, Source: "csrf",
		DetectionMethod: "form-heuristic", Confidence: 72, Verdict: CandDetected,
		Provenance: "form_action=" + action + "\nno_csrf_token=true\nsamesite_protected=false",
	})
}

// formHasCSRFToken reports whether a form contains a hidden input whose name
// looks like an anti-CSRF token.
func formHasCSRFToken(form string) bool {
	for _, in := range reHiddenInput.FindAllString(form, -1) {
		if nm := reInputName.FindStringSubmatch(in); len(nm) > 1 && csrfTokenName.MatchString(nm[1]) {
			return true
		}
	}
	// Some frameworks embed the token in a <meta> tag read by JS.
	return csrfTokenName.MatchString(form) && strings.Contains(strings.ToLower(form), "meta")
}

// sessionCookieSameSiteProtected reports whether a session-ish cookie is set
// with SameSite=Lax or Strict (which mitigates cross-site POST CSRF).
func sessionCookieSameSiteProtected(cookies []*http.Cookie) bool {
	for _, c := range cookies {
		low := strings.ToLower(c.Name)
		sessionish := strings.Contains(low, "sess") || strings.Contains(low, "token") ||
			strings.Contains(low, "auth") || strings.Contains(low, "sid") || strings.Contains(low, "jwt")
		if sessionish && (c.SameSite == http.SameSiteLaxMode || c.SameSite == http.SameSiteStrictMode) {
			return true
		}
	}
	return false
}
