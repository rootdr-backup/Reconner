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
			if sev, ev, cred, ok := s.check(ctx, u); ok {
				s.store(targetID, u, sev, ev, cred)
				found.Add(1)
				logFn("warn", "cors", fmt.Sprintf("CORS misconfig (%s): %s", sev, u))
				if s.broadcast != nil {
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
		WHERE target_id = ? AND COALESCE(source,'probe') = 'probe'
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
	host := ""
	if p, err := url.Parse(target); err == nil {
		host = p.Hostname()
	}
	if host == "" {
		return "", "", false, false
	}

	const evil = "https://recon-cors-probe.example"
	suffixEvil := "https://" + host + ".recon-cors-probe.example"

	// 1) Reflected arbitrary origin (+ credentials → critical).
	if acao, acac := s.probe(ctx, target, evil); acao == evil {
		if strings.EqualFold(acac, "true") {
			if s.reconfirm(ctx, target, evil, true) {
				return "critical", fmt.Sprintf(
						"Endpoint reflects an arbitrary Origin (%s) in Access-Control-Allow-Origin AND returns Access-Control-Allow-Credentials: true. Any attacker-controlled site can read this endpoint's authenticated responses (session-scoped data theft).", evil),
					true, true
			}
		} else if s.reconfirm(ctx, target, evil, false) {
			// Reflected without credentials → medium candidate.
			return "medium", fmt.Sprintf(
					"Endpoint reflects an arbitrary Origin (%s) in Access-Control-Allow-Origin (no credentials). Cross-origin sites can read its responses; impact depends on whether it serves sensitive data without cookies.", evil),
				false, true
		}
	}

	// 2) null origin + credentials → high.
	if acao, acac := s.probe(ctx, target, "null"); acao == "null" && strings.EqualFold(acac, "true") {
		if s.reconfirmNull(ctx, target) {
			return "high", "Endpoint allows Origin: null with Access-Control-Allow-Credentials: true. Exploitable from a sandboxed iframe (documents loaded via data:/srcdoc send Origin: null), letting an attacker page read authenticated responses.", true, true
		}
	}

	// 3) Trusted-suffix reflection (server matches the allowed origin as a
	// substring/prefix, so victimhost.attacker.com passes) → high if creds.
	if acao, acac := s.probe(ctx, target, suffixEvil); acao == suffixEvil {
		cred := strings.EqualFold(acac, "true")
		sev := "medium"
		if cred {
			sev = "high"
		}
		if s.reconfirm(ctx, target, suffixEvil, cred) {
			return sev, fmt.Sprintf(
					"Endpoint reflects an attacker-controlled Origin that merely CONTAINS the target host (%s), indicating a weak substring/suffix origin check. An attacker registers that domain to bypass the allow-list%s.",
					suffixEvil, map[bool]string{true: " and read credentialed responses", false: ""}[cred]),
				cred, true
		}
	}

	return "", "", false, false
}

// probe sends one GET with the given Origin and returns the endpoint's
// Access-Control-Allow-Origin and Access-Control-Allow-Credentials response
// headers (empty when absent).
func (s *CORSScanner) probe(ctx context.Context, target, origin string) (acao, acac string) {
	rctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(rctx, "GET", target, nil)
	if err != nil {
		return "", ""
	}
	req.Header.Set("Origin", origin)
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner-CORS)")
	resp, err := corsClient.Do(req)
	if err != nil {
		return "", ""
	}
	resp.Body.Close()
	return strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Origin")),
		strings.TrimSpace(resp.Header.Get("Access-Control-Allow-Credentials"))
}

func (s *CORSScanner) reconfirm(ctx context.Context, target, origin string, wantCred bool) bool {
	acao, acac := s.probe(ctx, target, origin)
	if acao != origin {
		return false
	}
	if wantCred {
		return strings.EqualFold(acac, "true")
	}
	return true
}

func (s *CORSScanner) reconfirmNull(ctx context.Context, target string) bool {
	acao, acac := s.probe(ctx, target, "null")
	return acao == "null" && strings.EqualFold(acac, "true")
}

// store writes a CORS finding. Credentialed reflections are confirmed findings
// (browser-exploitable); the no-credentials medium case is a candidate.
func (s *CORSScanner) store(targetID, target, severity, evidence string, credentialed bool) {
	status := StatusFinding
	conf := 90
	if !credentialed {
		status = StatusCandidate
		conf = 65
	}
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, status)
		VALUES (?, ?, 'cors_misconfig', ?, ?, 'Origin', ?, ?, ?, ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity=excluded.severity, payload=excluded.payload, evidence=excluded.evidence,
			confidence=excluded.confidence, status=excluded.status`,
		uuid.New().String(), targetID, severity, target,
		"Origin: reflected attacker value", evidence, conf, status)
}
