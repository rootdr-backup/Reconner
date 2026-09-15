package scanner

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/capture"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/pkg/logger"
)

var GuidedModules = []string{"passive", "idor", "xss", "sqli", "nosqli", "ssti", "lfi", "ssrf", "open_redirect", "cors"}
var GuidedManualModules = map[string]string{
	"authz":        "requires role/permission and expected access decisions",
	"csrf":         "requires a verified state change and browser cookie semantics",
	"xxe":          "XML entity insertion is not supported by the exact-template adapter",
	"cmdi":         "command execution probes require the separate active validation workflow",
	"jwt":          "token-specific verification requires the identity workflow",
	"csti":         "requires browser runtime verification",
	"oast":         "callback correlation is not enabled in guided runs",
	"race":         "concurrent state changes require a separate explicit test",
	"smuggling":    "connection-level probes cannot preserve this request contract",
	"cache_poison": "shared-cache mutation requires a separate explicit test",
	"nuclei":       "external templates may crawl or leave the captured request contract",
}

type GuidedTemplate struct {
	ID       string           `json:"id"`
	Request  capture.Request  `json:"request"`
	Response capture.Response `json:"response"`
}
type GuidedCheck struct {
	TemplateID string `json:"template_id"`
	Module     string `json:"module"`
}
type GuidedInput struct {
	Templates   []GuidedTemplate `json:"templates"`
	Modules     []string         `json:"modules"`
	Checks      []GuidedCheck    `json:"checks,omitempty"`
	AllowUnsafe bool             `json:"allow_unsafe"`
}
type GuidedResult struct {
	TemplateID string          `json:"template_id"`
	Module     string          `json:"module"`
	Status     string          `json:"status"`
	Reason     string          `json:"reason"`
	Requests   int             `json:"requests"`
	Findings   []GuidedFinding `json:"findings"`
}
type GuidedFinding struct {
	Type      string           `json:"type"`
	Parameter string           `json:"parameter"`
	Severity  string           `json:"severity"`
	Verdict   string           `json:"verdict"`
	Evidence  string           `json:"evidence"`
	Payload   string           `json:"payload"`
	TestCase  *capture.Request `json:"test_case,omitempty"`
	FindingID string           `json:"finding_id,omitempty"`
}
type GuidedReport struct {
	Results []GuidedResult    `json:"results"`
	Manual  map[string]string `json:"manual_modules"`
}

// PublicGuidedReport never returns recorded message bodies, payloads or evidence.
// The full report is sealed at rest and only revealed by an explicit API action.
func PublicGuidedReport(r GuidedReport) GuidedReport {
	b, _ := json.Marshal(r)
	var safe GuidedReport
	_ = json.Unmarshal(b, &safe)
	for i := range safe.Results {
		for j := range safe.Results[i].Findings {
			f := &safe.Results[i].Findings[j]
			f.Evidence = "Open test case to reveal encrypted evidence"
			f.Payload = ""
			f.TestCase = nil
		}
	}
	return safe
}

func newGuidedDB() (*database.DB, error) {
	s, e := sql.Open("sqlite3", "file:guided-"+uuid.NewString()+"?mode=memory&cache=shared&_foreign_keys=on&_busy_timeout=5000")
	if e != nil {
		return nil, e
	}
	s.SetMaxOpenConns(1)
	s.SetMaxIdleConns(1)
	db := &database.DB{DB: s}
	if e = database.RunMigrations(db); e != nil {
		db.Close()
		return nil, e
	}
	return db, nil
}

// RunGuided uses native proof ladders, but isolates every template in memory and
// pins all detector traffic to that template. No crawler, CLI or browser runs.
func RunGuided(ctx context.Context, db *database.DB, targetID string, input GuidedInput, inScope func(string) bool, progress func(GuidedReport)) (GuidedReport, error) {
	report := GuidedReport{Results: []GuidedResult{}, Manual: GuidedManualModules}
	templates := make(map[string]GuidedTemplate, len(input.Templates))
	for _, template := range input.Templates {
		templates[template.ID] = template
	}
	for _, check := range GuidedChecks(input) {
		if ctx.Err() != nil {
			return report, ctx.Err()
		}
		t, ok := templates[check.TemplateID]
		r := GuidedResult{TemplateID: check.TemplateID, Module: check.Module, Status: "completed", Findings: []GuidedFinding{}}
		switch {
		case !ok:
			r.Status = "blocked"
			r.Reason = "request template is unavailable"
		case !inScope(t.Request.URL):
			r.Status = "blocked"
			r.Reason = "request is no longer in project scope"
		case check.Module != "passive" && !capture.SafeAutomaticReplay(t.Request) && !input.AllowUnsafe:
			r.Status = "skipped"
			r.Reason = "state-changing or non-safe request: explicit approval required"
		default:
			var e error
			r, e = runGuidedModule(ctx, t, check.Module)
			if e != nil {
				r.Status = "failed"
				r.Reason = "module could not initialize or persist results"
			}
			for i := range r.Findings {
				f := &r.Findings[i]
				verdict := CandDetected
				if f.Verdict == CandConfirmed {
					verdict = VerifyVerified
				} else if f.Verdict == CandInconclusive {
					verdict = VerifyInconclusive
				}
				ids, e := RecordDetectorObservation(ctx, db, DetectorObservation{TargetID: targetID, Type: f.Type, Severity: f.Severity, URL: capture.SafeDisplayURL(t.Request.URL), Method: t.Request.Method, Parameter: f.Parameter, Location: "capture:" + t.ID, Source: "guided-capture", DetectionMethod: check.Module, Confidence: 70, Provenance: "capture-template:" + t.ID, Verdict: verdict, Evidence: "Guided capture evidence is encrypted. Open the capture test case; template " + t.ID})
				if e != nil {
					return report, fmt.Errorf("persist guided finding: %w", e)
				}
				f.FindingID = ids.FindingID
			}
		}
		report.Results = append(report.Results, r)
		if progress != nil {
			progress(report)
		}
	}
	return report, nil
}

func guidedChecks(input GuidedInput) []GuidedCheck {
	if len(input.Checks) > 0 {
		return input.Checks
	}
	checks := make([]GuidedCheck, 0, len(input.Templates)*len(input.Modules))
	for _, template := range input.Templates {
		for _, module := range input.Modules {
			checks = append(checks, GuidedCheck{TemplateID: template.ID, Module: module})
		}
	}
	return checks
}

func GuidedChecks(input GuidedInput) []GuidedCheck {
	checks := guidedChecks(input)
	return append([]GuidedCheck(nil), checks...)
}

func GuidedCheckCount(input GuidedInput) int { return len(GuidedChecks(input)) }

func runGuidedModule(parent context.Context, t GuidedTemplate, module string) (result GuidedResult, err error) {
	result = GuidedResult{TemplateID: t.ID, Module: module, Status: "completed", Findings: []GuidedFinding{}}
	defer func() {
		if recover() != nil {
			result.Status = "failed"
			result.Reason = "detector stopped unexpectedly"
		}
	}()
	if module == "passive" {
		result.Reason = "captured response inspected without network traffic"
		for _, h := range t.Response.Headers {
			if strings.EqualFold(h.Name, "Set-Cookie") && (!strings.Contains(strings.ToLower(h.Value), "httponly") || !strings.Contains(strings.ToLower(h.Value), "secure")) {
				result.Findings = append(result.Findings, GuidedFinding{Type: "cookie_security", Severity: "info", Verdict: CandDetected, Evidence: "Captured Set-Cookie lacks Secure or HttpOnly; applicability requires review"})
				break
			}
		}
		if len(result.Findings) > 0 {
			result.Status = "findings"
		}
		return result, nil
	}
	if reason, ok := GuidedManualModules[module]; ok {
		result.Status = "skipped"
		result.Reason = reason
		return result, nil
	}
	points := guidedPoints(t.Request)
	if module == "idor" {
		points = guidedIDORPoints(t.Request)
	}
	if len(points) == 0 && module != "cors" {
		result.Status = "skipped"
		result.Reason = "no supported query, form or JSON insertion points; XML/multipart/header/path mutation requires manual testing"
		return result, nil
	}
	limited := len(points) > 8
	if limited {
		points = points[:8]
	}
	ctx, cancel := context.WithTimeout(parent, 45*time.Second)
	defer cancel()
	g := &guidedContext{request: t.Request, points: points}
	ctx = context.WithValue(ctx, guidedContextKey{}, g)
	// Baseline failure is a hard stop, not a clean negative. No mutation on
	// expired authentication, redirect, WAF, or changed response contract.
	baseline, e := guidedHTTPRequest(ctx, t.Request)
	if e != nil {
		result.Status = "blocked"
		result.Reason = "invalid HTTP request"
		return result, nil
	}
	resp, e := guidedClient.Do(baseline)
	if e != nil {
		result.Status = "failed"
		result.Reason = "baseline failed or destination policy blocked it"
		result.Requests = g.sent
		return result, nil
	}
	body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512*1024+1))
	resp.Body.Close()
	result.Requests = g.sent
	if readErr != nil || resp.StatusCode < 200 || resp.StatusCode >= 300 || looksLikeBlockPage(resp.StatusCode, string(body)) || (t.Response.Status != 0 && resp.StatusCode != t.Response.Status) || (t.Response.MimeType != "" && !strings.EqualFold(strings.Split(resp.Header.Get("Content-Type"), ";")[0], strings.Split(t.Response.MimeType, ";")[0])) {
		result.Status = "blocked"
		result.Reason = "baseline stale, unauthorized, redirected, blocked or unreadable; update and recapture"
		return result, nil
	}
	scratch, e := newGuidedDB()
	if e != nil {
		return result, e
	}
	defer scratch.Close()
	_, e = scratch.Exec(`INSERT INTO targets(id,domain) VALUES(?,?)`, t.ID, "guided.invalid")
	if e != nil {
		return result, e
	}
	cfg := &config.Config{}
	cfg.Limits.MaxURLsPerModule = 8
	log := logger.NewWithWriter("error", io.Discard)
	silent := func(string, string, string) {}
	switch module {
	case "idor":
		guidedIDORChecks(ctx, scratch, t, body)
	case "ssti":
		err = NewSSTIScanner(scratch, nil, cfg, log, nil).Run(ctx, t.ID, silent)
	case "lfi":
		err = NewLFIScanner(scratch, nil, cfg, log, nil).Run(ctx, t.ID, silent)
	case "ssrf":
		err = NewSSRFScanner(scratch, nil, cfg, log, nil).Run(ctx, t.ID, silent)
	case "nosqli":
		err = NewNoSQLiScanner(scratch, nil, cfg, log, nil).Run(ctx, t.ID, silent)
	case "sqli":
		s := NewSQLiScanner(scratch, nil, cfg, log, nil)
		for _, p := range points {
			if ctx.Err() != nil {
				break
			}
			kind, evidence := s.quickProbe(ctx, p.ip, nil)
			if kind != "" {
				s.store(t.ID, "sqli", "high", p.ip, kind, evidence)
			}
		}
	case "xss", "open_redirect", "cors":
		guidedSmallChecks(ctx, scratch, t, module, body)
	default:
		result.Status = "skipped"
		result.Reason = "unsupported guided module"
	}
	rows, e := scratch.Query(`SELECT type,parameter,severity,status,evidence,payload,location FROM candidates WHERE status IN ('CONFIRMED','DETECTED','INCONCLUSIVE')`)
	if e != nil {
		return result, e
	}
	for rows.Next() {
		var f GuidedFinding
		var loc string
		if e := rows.Scan(&f.Type, &f.Parameter, &f.Severity, &f.Verdict, &f.Evidence, &f.Payload, &loc); e != nil {
			rows.Close()
			return result, e
		}
		if f.Payload != "" {
			for _, p := range points {
				if p.ip.Param == f.Parameter {
					req, e := g.injected(ctx, p.ip, f.Payload, "")
					if e == nil {
						b, _ := io.ReadAll(req.Body)
						v := t.Request
						v.URL = req.URL.String()
						v.Body = b
						f.TestCase = &v
					}
					break
				}
			}
		}
		result.Findings = append(result.Findings, f)
	}
	e = rows.Err()
	rows.Close()
	if e != nil {
		return result, e
	}
	result.Requests = g.sent
	if err != nil || ctx.Err() != nil || g.blocked > 0 || g.failed > 0 || limited {
		result.Status = "partial"
		result.Reason = "time/request/parameter limit or request failures; not a clean negative"
	}
	if len(result.Findings) > 0 && result.Status == "completed" {
		result.Status = "findings"
	}
	if module == "xss" {
		result.Reason += " Context checks only; runtime XSS proof requires browser/manual verification."
	}
	if module == "ssrf" {
		result.Reason += " In-band only; OAST callbacks not enabled."
	}
	return result, err
}

// guidedIDORChecks performs a bounded single-identity differential. A readable
// neighbouring object is deliberately INCONCLUSIVE: only an independently
// authenticated second identity and known ownership can confirm horizontal
// authorization failure.
func guidedIDORChecks(ctx context.Context, db *database.DB, t GuidedTemplate, baseline []byte) {
	g := guidedFrom(ctx)
	for _, point := range g.points {
		if ctx.Err() != nil {
			return
		}
		payloads := guidedIDORPayloads(point.ip.Value)
		for _, payload := range payloads {
			req, err := g.injected(ctx, point.ip, payload, "")
			if err != nil {
				continue
			}
			resp, err := guidedClient.Do(req)
			if err != nil {
				g.mu.Lock()
				g.failed++
				g.mu.Unlock()
				continue
			}
			body, readErr := io.ReadAll(io.LimitReader(resp.Body, 512*1024+1))
			resp.Body.Close()
			if readErr != nil || len(body) > 512*1024 {
				continue
			}
			if resp.StatusCode < 200 || resp.StatusCode >= 300 || looksLikeBlockPage(resp.StatusCode, string(body)) || BodyHash(string(body)) == BodyHash(string(baseline)) {
				continue
			}
			baseLen, probeLen := len(baseline), len(body)
			if baseLen < 64 || probeLen < baseLen/3 || probeLen > baseLen*3 {
				continue
			}
			_, _ = RecordDetectorObservation(ctx, db, DetectorObservation{
				TargetID: t.ID, Type: "idor", Severity: "medium", URL: t.Request.URL,
				Method: t.Request.Method, Parameter: point.ip.Param, Location: point.ip.Location,
				Payload: payload, Source: "guided", DetectionMethod: "single-identity-differential",
				Confidence: 65, Verdict: CandInconclusive,
				Evidence: fmt.Sprintf("A changed object identifier returned HTTP %d with a distinct, structurally comparable response (%dB baseline, %dB alternate). Confirm ownership using a second identity before reporting IDOR.", resp.StatusCode, baseLen, probeLen),
			})
			break
		}
	}
}

func guidedIDORPayloads(value string) []string {
	if n, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64); err == nil {
		out := []string{}
		if n > 1 {
			out = append(out, strconv.FormatInt(n-1, 10))
		}
		if n < 1<<62 {
			out = append(out, strconv.FormatInt(n+1, 10))
		}
		return out
	}
	if len(value) >= 16 {
		last := value[len(value)-1]
		replacement := byte('0')
		if last == replacement {
			replacement = '1'
		}
		return []string{value[:len(value)-1] + string(replacement)}
	}
	return nil
}

func guidedSmallChecks(ctx context.Context, db *database.DB, t GuidedTemplate, module string, baseline []byte) {
	g := guidedFrom(ctx)
	store := func(ip insertionPoint, payload, evidence, verdict string) {
		_, _ = RecordDetectorObservation(ctx, db, DetectorObservation{TargetID: t.ID, Type: module, Severity: "medium", URL: t.Request.URL, Method: t.Request.Method, Parameter: ip.Param, Location: ip.Location, Payload: payload, Evidence: evidence, Source: "guided", DetectionMethod: "paired-control", Confidence: 70, Verdict: verdict})
	}
	if module == "cors" {
		for _, origin := range []string{"https://reconner-a.invalid", "https://reconner-b.invalid"} {
			req, e := guidedHTTPRequest(ctx, t.Request)
			if e != nil {
				return
			}
			req.Header.Set("Origin", origin)
			resp, e := guidedClient.Do(req)
			if e != nil {
				return
			}
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
			resp.Body.Close()
			if resp.Header.Get("Access-Control-Allow-Origin") != origin || resp.Header.Get("Access-Control-Allow-Credentials") != "true" || resp.StatusCode != t.Response.Status && t.Response.Status != 0 || BodyHash(string(b)) != BodyHash(string(baseline)) {
				return
			}
		}
		store(insertionPoint{Location: "header", Param: "Origin"}, "", "Two unrelated Origins reflected with credentials and matching baseline; sensitive-data impact and browser behavior require review", CandDetected)
		return
	}
	for _, p := range g.points {
		if ctx.Err() != nil {
			return
		}
		if module == "xss" {
			marker := newXSSToken("rcnguided")
			payload := xssProbeFor(marker)
			probe := sendInjectedResponse(ctx, guidedClient, p.ip, payload, nil)
			a := analyzeReflectionProbe(probe.Body, marker, xssProbeSuffix)
			if a.Executable && browserRendersResponse(probe.Status, probe.ContentType, probe.Body, probe.NoSniff) && !looksLikeBlockPage(probe.Status, probe.Body) {
				store(p.ip, payload, "Unencoded input reaches an executable HTML context; JavaScript execution NOT proven", CandDetected)
			}
		} else {
			payload := "https://" + newXSSToken("rcn") + ".invalid/proof"
			req, e := g.injected(ctx, p.ip, payload, "")
			if e != nil {
				continue
			}
			resp, e := guidedClient.Do(req)
			if e != nil {
				continue
			}
			resp.Body.Close()
			loc, e := url.Parse(resp.Header.Get("Location"))
			want, _ := url.Parse(payload)
			if e == nil && resp.StatusCode >= 300 && resp.StatusCode < 400 && loc.Host == want.Host {
				store(p.ip, payload, "Random external redirect destination returned in Location; redirect was not followed", VerifyVerified)
			}
		}
	}
}
