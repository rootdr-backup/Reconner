package scanner

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// AccountTakeoverEngine chains individually-modest findings into account-takeover
// (ATO) attack paths — the way a real bug-bounty report is built. It is
// deliberately COOKIE- and TOKEN-aware: an XSS only becomes ATO if the session
// cookie is JS-readable; an open redirect only leaks a session if it sits on an
// auth flow or carries a code/token; an OAuth misconfig only escalates if the
// redirect target is attacker-influenceable.
//
// It runs LATE (after xss / oauth / jwt / open_redirect / passive), reads their
// stored primitives, adds a live cookie probe, and emits high-severity
// `account_takeover` findings whose evidence spells out the full chain and the
// repro. Every chain requires a concrete, stored primitive on each link — no
// speculative "could be chained" noise.
type AccountTakeoverEngine struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewAccountTakeoverEngine(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *AccountTakeoverEngine {
	return &AccountTakeoverEngine{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var atoClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   10 * time.Second,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse // capture the FIRST response's Set-Cookie
	},
}

// atoSensitivePathRe matches URL paths where a redirect/leak hands over an auth
// secret (OAuth code, SSO assertion, session, reset token).
var atoSensitivePathRe = regexp.MustCompile(`(?i)(login|sign-?in|logout|sso|saml|oauth|openid|authoriz|/connect/|callback|/auth|/token|session|reset|forgot|recover|verif|confirm|activate|magic-?link|password)`)

// atoRedirectParams: parameter names that carry the post-auth landing URL — an
// open redirect here leaks the auth code/token to the attacker's host.
var atoRedirectParams = map[string]bool{
	"redirect_uri": true, "redirecturi": true, "redirect_url": true, "redirect": true,
	"returnurl": true, "return_url": true, "return": true, "next": true, "continue": true,
	"callback": true, "callback_url": true, "goto": true, "dest": true, "destination": true,
	"relaystate": true, "target": true, "url": true, "returnto": true, "back": true, "forward": true,
}

// atoAuthTokenParams: parameter names that ARE an auth secret. Present in a URL,
// they leak via Referer / browser history / proxy logs.
var atoAuthTokenParams = map[string]bool{
	"token": true, "code": true, "access_token": true, "id_token": true, "refresh_token": true,
	"reset_token": true, "reset": true, "ticket": true, "jwt": true, "session": true, "sid": true,
	"sessionid": true, "auth": true, "otp": true, "samlresponse": true, "assertion": true,
	"api_key": true, "apikey": true, "secret": true, "activation": true, "confirmation": true,
}

func normParam(p string) string {
	return strings.ToLower(strings.TrimSpace(p))
}

// isSensitiveAuthURL reports whether a redirect at (rawURL, param) sits on an
// authentication flow (path or landing-URL parameter).
func isSensitiveAuthURL(rawURL, param string) bool {
	if atoRedirectParams[normParam(param)] {
		return true
	}
	return atoSensitivePathRe.MatchString(rawURL)
}

func atoHost(rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return strings.ToLower(strings.TrimPrefix(u.Host, "www."))
	}
	return ""
}

var cookieNameRe = regexp.MustCompile(`"([^"]+)"`)

func (s *AccountTakeoverEngine) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "ato", "Correlating findings into account-takeover chains...")

	xssHosts := s.hostsForTypes(ctx, targetID, []string{"xss", "dom_xss", "stored_xss"})
	oauthHosts := s.hostsForTypes(ctx, targetID, []string{"oauth"})
	// JS-readable session cookies (no HttpOnly) — the exact primitive that turns
	// XSS into session theft. Merge passive findings with a live cookie probe.
	jsCookies := s.jsReadableCookies(ctx, targetID)
	for h, cs := range s.probeSessionCookies(ctx, targetID) {
		jsCookies[h] = append(jsCookies[h], cs...)
	}
	redirectHosts, redirects := s.openRedirects(ctx, targetID)

	chains := 0
	emit := func(sev, url, param, evidence string, conf int) {
		s.store(targetID, "account_takeover", sev, url, param, evidence, conf)
		chains++
		logFn("warn", "ato", fmt.Sprintf("ATO chain [%s %d%%]: %s", sev, conf, url))
	}

	// ── Chain 1: XSS + JS-readable session cookie → session hijack ──
	for host, xurl := range xssHosts {
		if cookies := dedupeStrings(jsCookies[host]); len(cookies) > 0 {
			emit("critical", xurl, "xss+cookie",
				fmt.Sprintf("ACCOUNT TAKEOVER chain — XSS → session theft. A confirmed XSS on %s can run document.cookie; the session cookie(s) %s are set WITHOUT HttpOnly, so JavaScript reads them directly. Payload exfiltrates the cookie to an attacker host and replays it → full session hijack. Fix: HttpOnly on session cookies AND fix the XSS. Repro: %s with a cookie-stealing payload.",
					host, strings.Join(cookies, ", "), xurl), ConfEvidence)
		}
	}

	// ── Chain 2: open redirect on an auth flow → code/token leak ──
	for _, r := range redirects {
		if !isSensitiveAuthURL(r.url, r.param) {
			continue
		}
		conf := ConfCandidateHi
		sev := "high"
		if r.verified {
			conf = ConfEvidence
		}
		emit(sev, r.url, r.param,
			fmt.Sprintf("ACCOUNT TAKEOVER chain — open redirect on an authentication flow. The %s parameter redirects off-origin (→ %s). On a login / OAuth / SSO / password-reset flow this hands the auth code, SSO assertion, or reset token to an attacker-controlled host (via the Location target and the Referer). Fix: strict allow-list of redirect targets. Repro: set %s to an attacker URL and complete the flow.",
				r.param, r.redirectTo, r.param), conf)
	}

	// ── Chain 3: OAuth misconfig + open redirect on same host → code interception ──
	for host := range oauthHosts {
		if redirectHosts[host] {
			emit("critical", oauthHosts[host], "oauth+redirect",
				fmt.Sprintf("ACCOUNT TAKEOVER chain — OAuth authorization-code/token interception. %s has an OAuth flow with a weak posture (missing state / implicit flow) AND an open redirect on the same host. An attacker crafts an authorize request with a redirect_uri that bounces through the open redirect to their server, capturing the victim's code/token → account takeover. Fix: exact-match redirect_uri allow-list + state + auth-code flow with PKCE.",
					host), ConfCandidateHi)
		}
	}

	// ── Chain 4: auth token/secret transmitted in a URL ──
	for host, hits := range s.authTokensInURL(ctx, targetID) {
		sev, conf := "medium", ConfCandidateLo
		vector := "leaks via Referer, browser history, and proxy/server logs"
		if redirectHosts[host] {
			sev, conf = "high", ConfCandidateHi
			vector = "leaks via Referer/history AND can be exfiltrated through the open redirect on this host"
		} else if _, x := xssHosts[host]; x {
			sev, conf = "high", ConfCandidateHi
			vector = "leaks via Referer/history AND is readable by the XSS on this host"
		}
		emit(sev, hits[0].url, hits[0].param,
			fmt.Sprintf("ACCOUNT TAKEOVER risk — sensitive auth token in URL. Parameter %q on %s carries an authentication secret in the query string, which %s. Fix: move the token to a POST body or a short-lived, single-use exchange.",
				hits[0].param, host, vector), conf)
	}

	logFn("info", "ato", fmt.Sprintf("Account-takeover correlation done. %d chain(s).", chains))
	return nil
}

// hostsForTypes returns host → one representative finding URL for the given
// vuln_findings types (findings only, not rejected candidates).
func (s *AccountTakeoverEngine) hostsForTypes(ctx context.Context, targetID string, types []string) map[string]string {
	out := map[string]string{}
	if len(types) == 0 {
		return out
	}
	ph := strings.TrimRight(strings.Repeat("?,", len(types)), ",")
	args := []any{targetID}
	for _, t := range types {
		args = append(args, t)
	}
	rows, err := s.db.QueryContext(ctx,
		`SELECT url FROM vuln_findings WHERE target_id=? AND type IN (`+ph+`) AND COALESCE(status,'finding') != 'rejected'`, args...)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			if h := atoHost(u); h != "" && out[h] == "" {
				out[h] = u
			}
		}
	}
	return out
}

// jsReadableCookies maps host → JS-readable session cookie names, from passive's
// stored cookie_no_httponly findings.
func (s *AccountTakeoverEngine) jsReadableCookies(ctx context.Context, targetID string) map[string][]string {
	out := map[string][]string{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT url, evidence FROM vuln_findings WHERE target_id=? AND type='cookie_no_httponly'`, targetID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var u, ev string
		if rows.Scan(&u, &ev) != nil {
			continue
		}
		h := atoHost(u)
		if h == "" {
			continue
		}
		name := "session cookie"
		if m := cookieNameRe.FindStringSubmatch(ev); m != nil {
			name = m[1]
		}
		out[h] = append(out[h], name)
	}
	return out
}

// probeSessionCookies actively fetches a few alive hosts and returns host →
// session cookies that are set WITHOUT HttpOnly (JS-readable). This makes the
// engine self-sufficient even if the passive module didn't run.
func (s *AccountTakeoverEngine) probeSessionCookies(ctx context.Context, targetID string) map[string][]string {
	out := map[string][]string{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT url FROM http_services WHERE target_id=? AND status_code BETWEEN 200 AND 399 ORDER BY url LIMIT 15`, targetID)
	if err != nil {
		return out
	}
	var urls []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()

	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		req, err := http.NewRequestWithContext(ctx, "GET", u, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; ReconBot/1.0)")
		resp, err := atoClient.Do(req)
		if err != nil {
			continue
		}
		h := atoHost(u)
		for _, c := range resp.Cookies() {
			if isSessionCookie(c.Name) && !c.HttpOnly {
				out[h] = append(out[h], c.Name)
			}
		}
		resp.Body.Close()
	}
	return out
}

// isSessionCookie reports whether a cookie name looks session/auth-bearing.
func isSessionCookie(name string) bool {
	l := strings.ToLower(name)
	for _, k := range []string{"sess", "token", "auth", "jwt", "sid", "login", "csrf", "access", "id_token", "remember"} {
		if strings.Contains(l, k) {
			return true
		}
	}
	return false
}

type redirectFinding struct {
	url, redirectTo, param string
	verified               bool
}

// openRedirects returns the set of hosts with a verified open redirect plus the
// raw list. Redirect ANALYSIS is a shared capability ATO owns INTERNALLY: it runs
// the same destination-validated open-redirect check the Open Redirect detector
// uses (checkOpenRedirectURL) directly over redirect-prone parameters. So ATO
// never depends on the Open Redirect DETECTOR module having run, and — because
// checkOpenRedirectURL only analyses and returns a verdict, writing nothing to
// open_redirect_findings — an ATO-only scan never emits an independent
// open_redirect finding as a side effect. ATO's own findings are stored as
// type "account_takeover" only.
func (s *AccountTakeoverEngine) openRedirects(ctx context.Context, targetID string) (map[string]bool, []redirectFinding) {
	hosts := map[string]bool{}
	var out []redirectFinding

	// Collect redirect-prone (url, param) candidates first, then close the cursor
	// before the (HTTP-bound) analysis loop so a slow probe never holds the row set.
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT url, parameter, COALESCE(value,'') FROM parameters WHERE target_id=? LIMIT 3000`, targetID)
	if err != nil {
		return hosts, out
	}
	type cand struct{ url, param string }
	var cands []cand
	for rows.Next() {
		var u, p, v string
		if rows.Scan(&u, &p, &v) != nil {
			continue
		}
		if paramProneTo(ClassRedirect, p, v) {
			cands = append(cands, cand{u, p})
		}
	}
	rows.Close()

	for _, c := range cands {
		if ctx.Err() != nil {
			break
		}
		// Only a destination-validated EXTERNAL redirect counts (same bar as the
		// Open Redirect detector) — never a mere reflection or same-origin bounce.
		if res, ok := checkOpenRedirectURL(c.url, c.param); ok && res.class == redirectExternal {
			out = append(out, redirectFinding{url: c.url, redirectTo: res.finalLoc, param: c.param, verified: true})
			if h := atoHost(c.url); h != "" {
				hosts[h] = true
			}
		}
	}
	return hosts, out
}

type paramHit struct{ url, param string }

// authTokensInURL finds parameters that carry an auth secret in the query string.
func (s *AccountTakeoverEngine) authTokensInURL(ctx context.Context, targetID string) map[string][]paramHit {
	out := map[string][]paramHit{}
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT url, parameter FROM parameters WHERE target_id=? LIMIT 5000`, targetID)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var u, p string
		if rows.Scan(&u, &p) != nil {
			continue
		}
		if !atoAuthTokenParams[normParam(p)] {
			continue
		}
		h := atoHost(u)
		if h == "" {
			continue
		}
		out[h] = append(out[h], paramHit{u, p})
	}
	return out
}

func (s *AccountTakeoverEngine) store(targetID, typ, sev, rawURL, param, evidence string, confidence int) {
	weight := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 1}[sev]
	if weight == 0 {
		weight = 1
	}
	verdict := CandDetected
	if confidence >= ConfEvidence {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: typ, Severity: sev, URL: rawURL, Method: "GET",
		Parameter: param, Location: "query", Evidence: evidence, Source: "account-takeover",
		DetectionMethod: "workflow-correlation", Confidence: confidence,
		Priority: confidence * weight, Verdict: verdict,
	})
	if s.broadcast != nil && verdict == VerifyVerified {
		s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": typ, "url": rawURL})
	}
}
