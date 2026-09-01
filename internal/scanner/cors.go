package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// CORSScanner detects exploitable Cross-Origin Resource Sharing (CORS)
// misconfigurations — a class Burp/ZAP flag structurally but frequently
// mis-triage (they report "ACAO: *" as high even though browsers ignore "*"
// with credentials). This module confirms only the combinations that are
// ACTUALLY exploitable in a browser, so a hit is real:
//
//  1. Reflected arbitrary Origin + Access-Control-Allow-Credentials: true
//     → CRITICAL. Any attacker origin can read authenticated responses.
//  2. Origin "null" allowed + credentials → HIGH. Exploitable from a
//     sandboxed iframe (data:/about:blank documents send Origin: null).
//  3. Trusted-suffix reflection (server does substring/endsWith on the allowed
//     origin) e.g. reflects https://victimhost.attacker.com → HIGH.
//  4. Reflected arbitrary Origin WITHOUT credentials → MEDIUM candidate
//     (readable cross-origin, but no session data leaks by itself).
//
// Deliberately NOT reported (the biggest CORS false-positive source): "ACAO: *"
// with or without credentials — browsers forbid "*" + credentials, and a bare
// "*" on a public, unauthenticated endpoint is by design, not a vulnerability.
type CORSScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewCORSScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *CORSScanner {
	return &CORSScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

// corsClient does NOT follow redirects — CORS headers must be read from the
// endpoint's own response, not wherever it redirects to.
var corsClient = &http.Client{
	Timeout:   12 * time.Second,
	Transport: sharedHTTPTransport,
	CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

const corsMaxHosts = 300

func (s *CORSScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "cors", "Checking endpoints for exploitable CORS misconfigurations...")

	urls := s.loadURLs(ctx, targetID)
	if len(urls) == 0 {
		logFn("info", "cors", "No probed HTTP endpoints to check")
		return nil
	}
	logFn("info", "cors", fmt.Sprintf("Testing %d endpoint(s) for CORS misconfig...", len(urls)))
	auth := loadAuthHeaders(ctx, s.db, targetID)

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(u string) {
			defer wg.Done()
			defer func() { <-sem }()
			if sev, ev, cred, proven, ok := s.checkWithAuth(ctx, u, auth); ok {
				s.store(targetID, u, sev, ev, cred, proven)
				found.Add(1)
				logFn("warn", "cors", fmt.Sprintf("CORS misconfig (%s): %s", sev, u))
				if s.broadcast != nil && proven {
					s.broadcast("new_vuln_finding", map[string]any{"target_id": targetID, "type": "cors_misconfig", "url": u, "parameter": "Origin"})
				}
			}
		}(u)
	}
	wg.Wait()

	logFn("info", "cors", fmt.Sprintf("CORS check done. Found %d.", found.Load()))
	return nil
}

func (s *CORSScanner) loadURLs(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 405
		ORDER BY url LIMIT ?`, targetID, corsMaxHosts)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) == nil {
			if u = strings.TrimSpace(u); u != "" {
				out = append(out, u)
			}
		}
	}
	return filterURLsByHostScope(ctx, out)
}

// check runs the CORS probes against one URL and returns the most severe
// confirmed misconfiguration (checked most-severe first). Every positive is
// re-probed once to drop transient/proxy flukes before it is reported.
func (s *CORSScanner) check(ctx context.Context, target string) (severity, evidence string, credentialed, ok bool) {
	severity, evidence, credentialed, _, ok = s.checkWithAuth(ctx, target, nil)
	return
}

func (s *CORSScanner) checkWithAuth(ctx context.Context, target string, auth map[string]string) (severity, evidence string, credentialed, proven, ok bool) {
	host := ""
	if p, err := url.Parse(target); err == nil {
		host = p.Hostname()
	}
	if host == "" {
		return "", "", false, false, false
	}

	const evil = "https://recon-cors-probe.example"
	suffixEvil := "https://" + host + ".recon-cors-probe.example"

	// 1) Reflected arbitrary origin (+ credentials → critical).
	if first := s.probeWithAuth(ctx, target, evil, auth); first.acao == evil {
		if strings.EqualFold(first.acac, "true") {
			if s.reconfirmWithAuth(ctx, target, evil, true, auth) {
				proof := s.sensitiveCredentialedProof(ctx, target, evil, auth, first)
				sev := "high"
				detail := "Credentialed arbitrary-Origin reflection is reproducible, but this endpoint's cookie-authenticated sensitive response was not independently proven; retained as a candidate."
				if proof {
					sev = "critical"
					detail = "Cookie-authenticated response differs from the unauthenticated response and is readable from the reflected attacker Origin; cross-origin data theft is proven."
				}
				return sev, fmt.Sprintf(
						"Endpoint reflects arbitrary Origin %s and returns Access-Control-Allow-Credentials: true. %s", evil, detail),
					true, proof, true
			}
		} else if s.reconfirmWithAuth(ctx, target, evil, false, auth) {
			// Reflected without credentials → medium candidate.
			return "medium", fmt.Sprintf(
					"Endpoint reflects an arbitrary Origin (%s) in Access-Control-Allow-Origin (no credentials). Cross-origin sites can read its responses; impact depends on whether it serves sensitive data without cookies.", evil),
				false, false, true
		}
	}

	// 2) null origin + credentials → high.
	if first := s.probeWithAuth(ctx, target, "null", auth); first.acao == "null" && strings.EqualFold(first.acac, "true") {
		if s.reconfirmWithAuth(ctx, target, "null", true, auth) {
			proof := s.sensitiveCredentialedProof(ctx, target, "null", auth, first)
			sev := "medium"
			if proof {
				sev = "high"
			}
			return sev, "Endpoint reproducibly allows Origin: null with credentials. A cookie-authenticated data differential is required for a confirmed sandboxed-iframe data leak.", true, proof, true
		}
	}

	// 3) Trusted-suffix reflection (server matches the allowed origin as a
	// substring/prefix, so victimhost.attacker.com passes) → high if creds.
	if first := s.probeWithAuth(ctx, target, suffixEvil, auth); first.acao == suffixEvil {
		cred := strings.EqualFold(first.acac, "true")
		sev := "medium"
		proof := cred && s.sensitiveCredentialedProof(ctx, target, suffixEvil, auth, first)
		if proof {
			sev = "high"
		}
		if s.reconfirmWithAuth(ctx, target, suffixEvil, cred, auth) {
			return sev, fmt.Sprintf(
					"Endpoint reflects an attacker-controlled Origin that merely CONTAINS the target host (%s), indicating a weak substring/suffix origin check. An attacker registers that domain to bypass the allow-list%s.",
					suffixEvil, map[bool]string{true: " and read credentialed responses", false: ""}[cred]),
				cred, proof, true
		}
	}

	return "", "", false, false, false
}

type corsProbeResult struct {
	status     int
	acao, acac string
	body       string
}

// probe sends one GET with the given Origin and returns the endpoint's
// Access-Control-Allow-Origin and Access-Control-Allow-Credentials response
// headers (empty when absent).
func (s *CORSScanner) probe(ctx context.Context, target, origin string) (acao, acac string) {
	r := s.probeWithAuth(ctx, target, origin, nil)
	return r.acao, r.acac
}

func (s *CORSScanner) probeWithAuth(ctx context.Context, target, origin string, auth map[string]string) corsProbeResult {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, "GET", target, nil)
	if err != nil {
		return corsProbeResult{}
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner-CORS)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	resp, err := corsClient.Do(req)
	if err != nil {
		return corsProbeResult{}
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return corsProbeResult{status: resp.StatusCode, body: string(body),
		acao: strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin")),
		acac: strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))}
}

func (s *CORSScanner) reconfirm(ctx context.Context, target, origin string, wantCred bool) bool {
	return s.reconfirmWithAuth(ctx, target, origin, wantCred, nil)
}

func (s *CORSScanner) reconfirmWithAuth(ctx context.Context, target, origin string, wantCred bool, auth map[string]string) bool {
	r := s.probeWithAuth(ctx, target, origin, auth)
	if r.acao != origin {
		return false
	}
	if wantCred {
		return strings.EqualFold(r.acac, "true")
	}
	return true
}

func (s *CORSScanner) reconfirmNull(ctx context.Context, target string) bool {
	return s.reconfirmWithAuth(ctx, target, "null", true, nil)
}

func hasCookieAuth(auth map[string]string) bool {
	for k, v := range auth {
		if strings.EqualFold(strings.TrimSpace(k), "cookie") && strings.TrimSpace(v) != "" {
			return true
		}
	}
	return false
}

func (s *CORSScanner) sensitiveCredentialedProof(ctx context.Context, target, origin string, auth map[string]string, authed corsProbeResult) bool {
	if !hasCookieAuth(auth) || authed.status < 200 || authed.status >= 400 || len(strings.TrimSpace(authed.body)) < 8 {
		return false
	}
	unauth := s.probeWithAuth(ctx, target, origin, nil)
	if unauth.status == http.StatusUnauthorized || unauth.status == http.StatusForbidden {
		return true
	}
	return unauth.status != authed.status || !bodiesSameObject(authed.body, unauth.body)
}

// store writes a CORS finding. Credentialed reflections are confirmed findings
// (browser-exploitable); the no-credentials medium case is a candidate.
func (s *CORSScanner) store(targetID, target, severity, evidence string, credentialed, proven bool) {
	verdict := CandDetected
	conf := 75
	if credentialed {
		conf = ConfCandidateHi
	}
	if proven {
		verdict = VerifyVerified
		conf = ConfMultiTool
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "cors_misconfig", Severity: severity, URL: target,
		Method: "GET", Parameter: "Origin", Location: "header", Payload: "Origin: reflected attacker value",
		Evidence: evidence, Source: "cors", DetectionMethod: "origin-replay",
		Confidence: conf, Verdict: verdict,
	})
}
