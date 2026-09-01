package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type SSTIScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewSSTIScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *SSTIScanner {
	return &SSTIScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var sstiHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   15 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

type sstiProbe struct {
	payload string
	expect  string
	engine  string
}

// sstiProbeSet builds collision-resistant arithmetic probes for the major
// template syntaxes. Two independently-tagged operand pairs are used during
// verification (7*7 and 8*8), so a static page containing "49", a reflected
// payload, a cache hit, or an intermediary rewrite cannot become a finding.
func sstiProbeSet(token string, a, b int) []sstiProbe {
	result := a * b
	end := "z"
	w := func(expr, engine string) sstiProbe {
		return sstiProbe{payload: token + expr + end, expect: fmt.Sprintf("%s%dz", token, result), engine: engine}
	}
	return []sstiProbe{
		w(fmt.Sprintf("{{%d*%d}}", a, b), "Jinja2/Twig/Nunjucks/Pebble"),
		w(fmt.Sprintf("${%d*%d}", a, b), "JSP EL / Spring EL / Mako / FreeMarker"),
		w(fmt.Sprintf("#{%d*%d}", a, b), "Thymeleaf / Ruby expression"),
		w(fmt.Sprintf("<%%=%d*%d%%>", a, b), "ERB / ASP"),
		w(fmt.Sprintf("@(%d*%d)", a, b), "Razor"),
		w(fmt.Sprintf("{%d*%d}", a, b), "Smarty expression"),
		{
			payload: fmt.Sprintf("#set($rcn=%d*%d)%s${rcn}%s", a, b, token, end),
			expect:  fmt.Sprintf("%s%dz", token, result),
			engine:  "Apache Velocity",
		},
		// Code-context variants close a template expression before rendering our
		// arithmetic. These cover inputs embedded as a variable/expression name,
		// which plaintext-only {{7*7}} scanning systematically misses.
		{
			payload: fmt.Sprintf("}}%s{{%d*%d}}%s{{", token, a, b, end),
			expect:  fmt.Sprintf("%s%dz", token, result),
			engine:  "Jinja/Twig code context",
		},
		{
			payload: fmt.Sprintf("}%s${%d*%d}%s${", token, a, b, end),
			expect:  fmt.Sprintf("%s%dz", token, result),
			engine:  "EL/FreeMarker code context",
		},
	}
}

const sstiMaxParams = 150

// Run injects template expressions into request insertion points and confirms
// SSTI only after two independently-tagged arithmetic evaluations.
func (s *SSTIScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "ssti", "Starting Server-Side Template Injection checks...")

	limit := sstiMaxParams
	if s.cfg != nil {
		limit = s.cfg.URLLimit()
	}
	// Template injection can hide behind non-obvious parameter names. Route known
	// renderer/content fields first, then keep a bounded unfamiliar-name fallback.
	points := loadRoutedInsertionPoints(ctx, s.db, targetID, ClassSSTI, limit, 96)
	if len(points) == 0 {
		return nil
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	logFn("info", "ssti", fmt.Sprintf("Testing %d insertion points for SSTI...", len(points)))

	sem := make(chan struct{}, 10)
	var wg sync.WaitGroup
	var found atomic.Int64

	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()

			controlToken := newXSSToken("rcnsstic")
			controlBody, controlStatus, _ := sendInjectedFull(ctx, sstiHTTPClient, ip, controlToken+"-plain", auth)
			if looksLikeBlockPage(controlStatus, controlBody) {
				return
			}
			firstToken := newXSSToken("rcnssti")
			secondToken := newXSSToken("rcnssti")
			first := sstiProbeSet(firstToken, 7, 7)
			second := sstiProbeSet(secondToken, 8, 8)
			for i, probe := range first {
				body, status, _ := sendInjectedFull(ctx, sstiHTTPClient, ip, probe.payload, auth)
				if body == "" || looksLikeBlockPage(status, body) || !strings.Contains(body, probe.expect) ||
					strings.Contains(controlBody, probe.expect) {
					continue
				}
				confirm := second[i]
				body2, status2, _ := sendInjectedFull(ctx, sstiHTTPClient, ip, confirm.payload, auth)
				if body2 == "" || looksLikeBlockPage(status2, body2) || !strings.Contains(body2, confirm.expect) ||
					strings.Contains(body2, confirm.payload) {
					continue
				}
				ev := fmt.Sprintf("Server-side template evaluation reproduced with independent arithmetic (%s): 7*7 and 8*8 produced uniquely tagged 49/64 markers [HTTP %d/%d, %s %s]",
					probe.engine, status, status2, strings.ToUpper(ip.Method), insertionLocation(ip))
				s.store(targetID, ip, probe.payload, probe.engine, ev)
				found.Add(1)
				logFn("warn", "ssti", fmt.Sprintf("SSTI CONFIRMED (%s): %s param=%s [%s/%s]",
					probe.engine, ip.URL, ip.Param, ip.Method, insertionLocation(ip)))
				s.notify(targetID, ip.URL, ip.Param)
				return
			}
		}(ip)
	}
	wg.Wait()

	// Blind SSTI belongs to the SSTI objective. A standalone SSTI scan now plants
	// token-correlated callbacks instead of depending on the unrelated OAST module.
	s.plantBlindSSTI(ctx, targetID, points, auth, logFn)

	logFn("info", "ssti", fmt.Sprintf("SSTI check done. Found %d.", found.Load()))
	return nil
}

func (s *SSTIScanner) plantBlindSSTI(ctx context.Context, targetID string, points []insertionPoint, auth map[string]string, logFn LogFunc) {
	o, ok := newOOBCapability(s.cfg)
	if !ok || len(points) == 0 {
		return
	}
	n := o.plantClass(ctx, s.db, targetID, points, auth, "ssti", nil,
		func(_ insertionPoint, cb string) []string { return sstiOOBPayloads(cb) })
	if n > 0 {
		logFn("info", "ssti", fmt.Sprintf("Planted %d blind-SSTI OOB probe(s); callbacks are correlated to the exact insertion point.", n))
	}
}

func (s *SSTIScanner) store(targetID string, ip insertionPoint, payload, subtype, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: "ssti", Subtype: subtype, Severity: "critical", URL: ip.URL, Method: ip.Method,
		Parameter: ip.Param, Location: insertionLocation(ip), Payload: payload, Evidence: evidence,
		Source: "ssti-native", DetectionMethod: "dual-evaluated-marker-replay", Confidence: 99,
		Verdict: VerifyVerified,
	})
}

func (s *SSTIScanner) notify(targetID, rawURL, param string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "ssti", "url": rawURL, "parameter": param,
		})
	}
}
