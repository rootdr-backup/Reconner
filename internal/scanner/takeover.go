package scanner

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type TakeoverScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewTakeoverScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *TakeoverScanner {
	return &TakeoverScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var takeoverHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// takeoverFingerprint maps a dangling-CNAME provider to the body signature it
// returns when the resource is unclaimed. Curated from EdOverflow/can-i-take-over-xyz.
type takeoverFingerprint struct {
	service   string
	cnames    []string
	signature string
	severity  string
}

var takeoverFingerprints = []takeoverFingerprint{
	{"GitHub Pages", []string{"github.io", "github.map.fastly.net"}, "There isn't a GitHub Pages site here", "high"},
	// S3 patterns must be PRECISE. The old catch-all "amazonaws.com" swallowed every
	// AWS hostname — ELB/ALB, CloudFront, EC2, RDS — and mislabeled a live load
	// balancer (…-alb-….elb.amazonaws.com) as a dangling S3 bucket. These match only
	// real object-storage / S3-website endpoints.
	{"AWS S3", []string{"s3.amazonaws.com", ".s3.", "s3-website", "s3.dualstack", "s3-external"}, "NoSuchBucket", "high"},
	{"Heroku", []string{"herokuapp.com", "herokudns.com", "herokussl.com"}, "No such app", "high"},
	{"Shopify", []string{"myshopify.com"}, "Sorry, this shop is currently unavailable", "high"},
	{"Fastly", []string{"fastly.net"}, "Fastly error: unknown domain", "medium"},
	{"Unbounce", []string{"unbouncepages.com"}, "The requested URL was not found on this server", "medium"},
	{"Tumblr", []string{"domains.tumblr.com"}, "Whatever you were looking for doesn't currently exist at this address", "medium"},
	{"Ghost", []string{"ghost.io"}, "The thing you were looking for is no longer here", "medium"},
	{"Surge.sh", []string{"surge.sh"}, "project not found", "medium"},
	{"Bitbucket", []string{"bitbucket.io"}, "Repository not found", "high"},
	{"Cargo", []string{"cargocollective.com"}, "404 Not Found", "low"},
	{"Webflow", []string{"proxy.webflow.com", "proxy-ssl.webflow.com"}, "The page you are looking for doesn't exist or has been moved", "medium"},
	{"Wordpress", []string{"wordpress.com"}, "Do you want to register", "medium"},
	{"Pantheon", []string{"pantheonsite.io"}, "404 error unknown site", "medium"},
	{"Azure", []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net"}, "404 Web Site not found", "high"},
	{"Readme.io", []string{"readme.io"}, "Project doesnt exist... yet!", "medium"},
	{"Zendesk", []string{"zendesk.com"}, "Help Center Closed", "low"},
	{"Netlify", []string{"netlify.app", "netlify.com"}, "Not Found - Request ID", "medium"},
}

type subjackalScore struct {
	CNAMEMatch     int `json:"CNAMEMatch"`
	NXDOMAINBack   int `json:"NXDOMAINBack"`
	HTTPMatch      int `json:"HTTPMatch"`
	NSUnregistered int `json:"NSUnregistered"`
}

func (s subjackalScore) Total() int {
	return s.CNAMEMatch + s.NXDOMAINBack + s.HTTPMatch + s.NSUnregistered
}

func (s subjackalScore) Level() string {
	t := s.Total()
	switch {
	case t >= 120:
		return "high"
	case t >= 50:
		return "medium"
	default:
		return "low"
	}
}


type subjackalSubdomain struct {
	Domain           string         `json:"Domain"`
	Root             string         `json:"Root"`
	RecordType       string         `json:"RecordType"`
	IPs              []string       `json:"IPs"`
	CNAMEChain       []string       `json:"CNAMEChain"`
	NSRecords        []string       `json:"NSRecords"`
	IsWildcard       bool           `json:"IsWildcard"`
	CNAMETarget      string         `json:"CNAMETarget"`
	ServiceProvider  string         `json:"ServiceProvider"`
	TakeoverPossible bool           `json:"TakeoverPossible"`
	Confidence       string         `json:"Confidence"`
	Score            subjackalScore `json:"Score"`
	Fingerprint      string         `json:"Fingerprint"`
	Status           string         `json:"Status"` // vulnerable | suspicious | dismissed | alive | nxdomain
	Note             string         `json:"Note"`
}

func parseSubjackalJSON(r io.Reader) ([]subjackalSubdomain, error) {
	var results []subjackalSubdomain
	dec := json.NewDecoder(r)
	for dec.More() {
		var s subjackalSubdomain
		if err := dec.Decode(&s); err != nil {
			return results, err
		}
		results = append(results, s)
	}
	return results, nil
}

// Run resolves CNAMEs for every subdomain and flags any that point at an
// unclaimed third-party service (subdomain takeover). If Subjackal is installed,
// it validates the entire set in batch; otherwise it uses the native CNAME fallback.
func (s *TakeoverScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "takeover", "Checking for subdomain takeovers...")

	rows, err := s.db.QueryContext(ctx, `SELECT subdomain FROM subdomains WHERE target_id = ?`, targetID)
	if err != nil {
		return fmt.Errorf("query subdomains: %w", err)
	}
	var subs []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err == nil {
			subs = append(subs, sub)
		}
	}
	rows.Close()
	subs = filterHostsByHostScope(ctx, subs)

	if len(subs) == 0 {
		logFn("info", "takeover", "No subdomains to check")
		return nil
	}

	if s.exec != nil && s.exec.IsToolAvailable("subjackal") {
		return s.runSubjackalBatch(ctx, targetID, subs, logFn)
	}

	return s.runNativeFallback(ctx, targetID, subs, logFn)
}

func (s *TakeoverScanner) runSubjackalBatch(ctx context.Context, targetID string, subs []string, logFn LogFunc) error {
	logFn("info", "takeover", fmt.Sprintf("Validating %d subdomains with Subjackal batch engine...", len(subs)))

	var validSubs []string
	for _, sub := range subs {
		sub = strings.TrimSpace(sub)
		if sub != "" && !strings.ContainsAny(sub, "\r\n\t ;|") {
			validSubs = append(validSubs, sub)
		}
	}
	if len(validSubs) == 0 {
		return nil
	}

	tmpIn, err := os.CreateTemp("", "subjackal-subs-*.txt")
	if err != nil {
		return fmt.Errorf("create subjackal temp input: %w", err)
	}
	defer os.Remove(tmpIn.Name())

	if _, err := tmpIn.WriteString(strings.Join(validSubs, "\n") + "\n"); err != nil {
		_ = tmpIn.Close()
		return fmt.Errorf("write subjackal input: %w", err)
	}
	_ = tmpIn.Close()

	tmpOut, err := os.CreateTemp("", "subjackal-out-*.json")
	if err != nil {
		return fmt.Errorf("create subjackal temp output: %w", err)
	}
	defer os.Remove(tmpOut.Name())
	_ = tmpOut.Close()

	workers := 50
	if s.cfg != nil && s.cfg.Limits.MaxToolExecutions > 0 && s.cfg.Limits.MaxToolExecutions < workers {
		workers = s.cfg.Limits.MaxToolExecutions
	}

	args := []string{
		"--subs", tmpIn.Name(),
		"-o", tmpOut.Name(),
		"--silent",
		"--threads", fmt.Sprintf("%d", workers),
		"--timeout", "3000",
		"--http-timeout", "5000",
	}

	execRes, err := s.exec.Run(ctx, "subjackal", args...)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		s.logger.Warn("Subjackal execution error; falling back to native scanner", "error", err)
		return s.runNativeFallback(ctx, targetID, subs, logFn)
	}
	if execRes != nil && execRes.ExitCode != 0 && s.logger != nil {
		s.logger.Warn("Subjackal non-zero exit code", "code", execRes.ExitCode, "stderr", execRes.Stderr)
	}

	outFile, err := os.Open(tmpOut.Name())
	if err != nil {
		return fmt.Errorf("open subjackal output: %w", err)
	}
	defer outFile.Close()

	parsed, err := parseSubjackalJSON(outFile)
	if err != nil && s.logger != nil {
		s.logger.Warn("Partial error reading subjackal output stream", "error", err)
	}

	var found atomic.Int64
	for _, res := range parsed {
		if ctx.Err() != nil {
			break
		}
		s.recordSubjackalResult(targetID, res, &found, logFn)
	}

	logFn("info", "takeover", fmt.Sprintf("Subjackal analysis complete: processed %d subdomains, found %d confirmed takeover(s).", len(parsed), found.Load()))
	return nil
}

func (s *TakeoverScanner) recordSubjackalResult(targetID string, sub subjackalSubdomain, found *atomic.Int64, logFn LogFunc) {
	service := sub.ServiceProvider
	if service == "" {
		service = "Unknown Provider"
	}
	severity := "high"
	for _, fp := range takeoverFingerprints {
		if strings.EqualFold(fp.service, service) && fp.severity != "" {
			severity = fp.severity
			break
		}
	}

	rawURL := "https://" + sub.Domain
	cname := sub.CNAMETarget
	if cname == "" && len(sub.CNAMEChain) > 0 {
		cname = sub.CNAMEChain[len(sub.CNAMEChain)-1]
	}

	switch strings.ToLower(sub.Status) {
	case "vulnerable":
		// Confirmed takeover proven by Subjackal
		conf := ConfMultiTool // 95
		status := StatusFinding
		evidence := fmt.Sprintf("Subjackal VALIDATED takeover: %s → %s (%s) — %s [%d%%]",
			sub.Domain, cname, service, sub.Note, conf)
		provenance := fmt.Sprintf("subjackal: status=vulnerable service=%s score=%d cname=%s note=%s",
			service, sub.Score.Total(),
			cname, sub.Note)

		s.storeVulnClassified(targetID, "subdomain_takeover", severity, rawURL, "", cname, evidence, conf, status, provenance)
		if found != nil {
			found.Add(1)
		}
		s.logSubjackalFinding(sub, service, logFn)
		if s.broadcast != nil {
			s.broadcast("new_vuln_finding", map[string]any{
				"target_id": targetID,
				"type":      "subdomain_takeover",
				"url":       rawURL,
			})
		}

	case "suspicious":
		// Suspicious/dangling infrastructure, but not yet verified as reclaimable
		conf := ConfCandidateHi // 85
		status := StatusCandidate
		evidence := fmt.Sprintf("Subjackal SUSPICIOUS candidate: %s → %s (%s) — %s [%d%%]",
			sub.Domain, cname, service, sub.Note, conf)
		provenance := fmt.Sprintf("subjackal: status=suspicious service=%s score=%d cname=%s note=%s",
			service, sub.Score.Total(),
			cname, sub.Note)

		s.storeVulnClassified(targetID, "subdomain_takeover", severity, rawURL, "", cname, evidence, conf, status, provenance)

		confidence := strings.ToLower(sub.Confidence)
		if confidence == "" {
			confidence = sub.Score.Level()
		}
		if confidence == "" {
			confidence = "medium"
		}
		logFn("info", "takeover", fmt.Sprintf("[TK] [SUSPICIOUS] %s — CNAME → %s (%s confidence, score: %d)",
			sub.Domain, service, confidence, sub.Score.Total()))

	case "dismissed":
		// Dismissed: CNAME chain resolves to live IP. Suppressed completely (Issue #21 fix).
		if s.logger != nil {
			s.logger.Debug("Subjackal dismissed takeover candidate", "domain", sub.Domain, "note", sub.Note)
		}

	case "alive", "nxdomain":
		// Live site or standard NXDOMAIN - no finding
	}
}

func (s *TakeoverScanner) logSubjackalFinding(sub subjackalSubdomain, service string, logFn LogFunc) {
	serviceWithStatus := service
	if !strings.Contains(serviceWithStatus, "[") {
		serviceWithStatus = fmt.Sprintf("%s [vulnerable]", serviceWithStatus)
	}

	confidence := strings.ToLower(sub.Confidence)
	if confidence == "" {
		confidence = sub.Score.Level()
	}
	if confidence == "" {
		confidence = "high"
	}

	logFn("warn", "takeover", fmt.Sprintf("[TK] [VULNERABLE] %s", sub.Domain))
	logFn("warn", "takeover", fmt.Sprintf("[TK]              service    : %s", serviceWithStatus))
	logFn("warn", "takeover", fmt.Sprintf("[TK]              confidence : %s (score: %d)", confidence, sub.Score.Total()))
	if sub.Note != "" {
		logFn("warn", "takeover", fmt.Sprintf("[TK]              note       : %s", sub.Note))
	}

	finalTarget := sub.CNAMETarget
	if finalTarget == "" && len(sub.CNAMEChain) > 0 {
		finalTarget = sub.CNAMEChain[len(sub.CNAMEChain)-1]
	}

	if len(sub.CNAMEChain) > 0 || finalTarget != "" {
		logFn("warn", "takeover", fmt.Sprintf("[TK] [VALIDATE] %s", sub.Domain))
		logFn("warn", "takeover", "[TK]   │")
		logFn("warn", "takeover", "[TK]   ├── CNAME chain")
		for _, hop := range sub.CNAMEChain {
			logFn("warn", "takeover", fmt.Sprintf("[TK]   │   → %s", hop))
		}
		if finalTarget != "" {
			if len(sub.IPs) > 0 {
				logFn("warn", "takeover", fmt.Sprintf("[TK]   │   → final: %s (✓ %s)", finalTarget, strings.Join(sub.IPs, ", ")))
			} else {
				logFn("warn", "takeover", fmt.Sprintf("[TK]   │   → final: %s (NXDOMAIN — dangling)", finalTarget))
			}
		}
		logFn("warn", "takeover", "[TK]   │")
	}
}


func (s *TakeoverScanner) runNativeFallback(ctx context.Context, targetID string, subs []string, logFn LogFunc) error {
	logFn("info", "takeover", fmt.Sprintf("Checking %d subdomains for dangling CNAMEs (native fallback)...", len(subs)))

	sem := make(chan struct{}, 20)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, sub := range subs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			cname, err := lookupCNAME(ctx, host)
			if err != nil || cname == "" {
				return
			}

			fp := matchTakeoverFingerprint(cname)
			if fp == nil {
				return
			}

			// Defense in depth: never flag AWS load-balancer / compute infrastructure.
			// A CNAME to a *live* ELB/ALB/NLB or EC2 host is not a subdomain takeover
			// (can-i-take-over-xyz lists AWS ELB as "Not vulnerable"); only a deleted
			// backend is, and that path is covered by the NXDOMAIN signal on real
			// claimable services. This guards against a broad fingerprint ever again
			// swallowing an ELB name (the services.ewa.bh false positive).
			if awsNonTakeoverableInfra(cname) {
				return
			}

			// Assess the claim: confidence + provenance + status (finding vs
			// candidate). Below the surfacing cutoff → drop silently.
			conf, provenance := s.assessTakeover(ctx, host, cname, fp)
			status, ok := ClassifyStatus(conf)
			if !ok {
				return
			}

			evidence := fmt.Sprintf("CNAME %s → %s (%s) — unclaimed resource [%d%%]", host, cname, fp.service, conf)
			s.storeVulnClassified(targetID, "subdomain_takeover", fp.severity, "https://"+host, "", cname, evidence, conf, status, provenance)
			if status == StatusFinding {
				found.Add(1)
			}
			logFn("warn", "takeover", fmt.Sprintf("TAKEOVER %s [%s %d%%]: %s → %s (%s)", strings.ToUpper(status), fp.severity, conf, host, cname, fp.service))
			if s.broadcast != nil && status == StatusFinding {
				s.broadcast("new_vuln_finding", map[string]any{
					"target_id": targetID,
					"type":      "subdomain_takeover",
					"url":       "https://" + host,
				})
			}
		}(sub)
	}
	wg.Wait()

	logFn("info", "takeover", fmt.Sprintf("Native takeover check done. Found %d potential takeovers.", found.Load()))
	return nil
}

func lookupCNAME(ctx context.Context, host string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := net.Resolver{}
	cname, err := r.LookupCNAME(c, host)
	if err != nil {
		return "", err
	}
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	if cname == strings.ToLower(host) {
		return "", nil // no real CNAME
	}
	return cname, nil
}

func matchTakeoverFingerprint(cname string) *takeoverFingerprint {
	for i := range takeoverFingerprints {
		for _, c := range takeoverFingerprints[i].cnames {
			if strings.Contains(cname, c) {
				return &takeoverFingerprints[i]
			}
		}
	}
	return nil
}

// assessTakeover decides how confident we are that `host` is takeover-able and
// returns a confidence score (see classify.go bands) plus provenance. The rule
// set is intentionally conservative — an uncertain result is a *candidate*, not
// a finding, so we never cry wolf:
//
//   - Azure: only a takeover if DNS is NXDOMAIN *or* HTTP returns the
//     "404 Web Site not found" body on *.azurewebsites.net. A 403 with
//     x-ms-forbidden-ip (or any other response) means the site IS claimed →
//     NOT a takeover.
//   - Signature body match (via Host-header request)      → evidence (90).
//   - + CNAME target is NXDOMAIN                           → strong.
//   - + a second tool (subzy) agrees                       → multi-tool (95).
//   - Only a dangling CNAME to a known service, nothing
//     else confirmed                                       → candidate (75).
func (s *TakeoverScanner) assessTakeover(ctx context.Context, host, cname string, fp *takeoverFingerprint) (int, string) {
	var prov strings.Builder
	fmt.Fprintf(&prov, "CNAME: %s -> %s (%s)\n", host, cname, fp.service)

	nx := cnameTargetNXDOMAIN(ctx, cname)
	fmt.Fprintf(&prov, "DNS: CNAME target NXDOMAIN=%v\n", nx)

	status, hdrs, body := s.fetchWithHostHeader(ctx, host)
	sigMatch := strings.Contains(body, fp.signature)
	fmt.Fprintf(&prov, "HTTP(Host:%s): status=%d signature_match=%v\n", host, status, sigMatch)

	// ── Azure-specific guard (spec) ──
	if fp.service == "Azure" {
		if forbiddenIP := hdrs["x-ms-forbidden-ip"]; forbiddenIP != "" || status == 403 {
			fmt.Fprintf(&prov, "Azure: 403/x-ms-forbidden-ip present -> site is CLAIMED, NOT takeover\n")
			return 0, prov.String() // definitively not a takeover
		}
		if !nx && !sigMatch {
			fmt.Fprintf(&prov, "Azure: neither NXDOMAIN nor 404-body -> not takeover\n")
			return 0, prov.String()
		}
	}

	// Second tool: subzy (if installed) as an independent confirmation.
	subzyConfirms, subzyRan := s.subzyConfirms(ctx, host)
	if subzyRan {
		fmt.Fprintf(&prov, "subzy: vulnerable=%v\n", subzyConfirms)
	}

	conf := takeoverConfidence(sigMatch, nx, subzyConfirms)
	if conf == 0 {
		fmt.Fprintf(&prov, "verdict: CNAME target resolves, no unclaimed signature, subzy negative -> CLAIMED resource, not a takeover\n")
	}
	return conf, prov.String()
}

// takeoverConfidence maps the three independent takeover signals to a confidence
// score. The critical rule: with NONE of them positive — no unclaimed-body
// signature, the CNAME target still resolves, and subzy disagrees — the resource
// is LIVE and CLAIMED, so the score is 0 (dropped). Merely pointing a CNAME at a
// known provider is normal for every working site hosted there and must never, on
// its own, surface a takeover (the services.ewa.bh live-ALB false positive).
func takeoverConfidence(sigMatch, nx, subzyConfirms bool) int {
	switch {
	case sigMatch && subzyConfirms:
		return ConfMultiTool // 95 — two tools agree
	case sigMatch && nx:
		return ConfMultiTool // 95 — body + DNS both prove it
	case sigMatch:
		return ConfEvidence // 90 — solid single evidence
	case subzyConfirms:
		return ConfEvidence // 90 — dedicated tool confirms
	case nx:
		return ConfCandidateHi // 85 — DNS says dangling, body unconfirmed
	default:
		return 0 // claimed / live → not a takeover
	}
}

// awsNonTakeoverableInfra matches AWS hostnames that are load balancers or compute
// endpoints — NOT claimable object-storage / website resources. A CNAME to a live
// ELB/ALB/NLB (….elb.amazonaws.com) or EC2 host (….compute[-1].amazonaws.com) is
// not a subdomain takeover.
func awsNonTakeoverableInfra(cname string) bool {
	return strings.Contains(cname, ".elb.amazonaws.com") ||
		strings.Contains(cname, ".compute.amazonaws.com") ||
		strings.Contains(cname, ".compute-1.amazonaws.com")
}

// fetchWithHostHeader requests the CNAME'd endpoint while forcing the Host
// header to the subdomain (the way real takeover probes work), returning the
// status, response headers (lower-cased keys) and body.
func (s *TakeoverScanner) fetchWithHostHeader(ctx context.Context, host string) (int, map[string]string, string) {
	for _, scheme := range []string{"https://", "http://"} {
		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", scheme+host, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
		req.Host = host // explicit Host-header test (-H "Host:<subdomain>")
		resp, err := takeoverHTTPClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		cancel()
		hdrs := map[string]string{}
		for k := range resp.Header {
			hdrs[strings.ToLower(k)] = resp.Header.Get(k)
		}
		return resp.StatusCode, hdrs, string(body)
	}
	return 0, map[string]string{}, ""
}

// cnameTargetNXDOMAIN reports whether the CNAME target itself fails to resolve
// (the canonical "the backend is gone, claim it" signal).
func cnameTargetNXDOMAIN(ctx context.Context, cname string) bool {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := net.Resolver{}
	ips, err := r.LookupHost(c, cname)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true
		}
		return false
	}
	return len(ips) == 0
}

// subzyConfirms runs subzy against a single host as an independent second tool.
// Returns (vulnerable, ran). ran=false when subzy isn't installed.
func (s *TakeoverScanner) subzyConfirms(ctx context.Context, host string) (bool, bool) {
	if !s.exec.IsToolAvailable("subzy") {
		return false, false
	}
	vulnerable := false
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_ = s.exec.RunWithCallback(tctx, "", func(line string) {
		l := strings.ToLower(line)
		if strings.Contains(l, host) && (strings.Contains(l, "vulnerable") && !strings.Contains(l, "not vulnerable")) {
			vulnerable = true
		}
	}, "subzy", "run", "--target", host, "--hide_fails")
	return vulnerable, true
}

func (s *TakeoverScanner) storeVulnClassified(targetID, vulnType, severity, rawURL, param, payload, evidence string, confidence int, status, provenance string) {
	verdict := CandDetected
	if status == StatusFinding {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL, Method: "DNS",
		Parameter: param, Location: "dns", Payload: payload, Evidence: evidence,
		Source: "takeover", DetectionMethod: "provider-fingerprint", Confidence: confidence,
		Provenance: provenance, Verdict: verdict,
	})
}
