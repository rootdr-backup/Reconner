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

// Each probe is a template expression for a different engine; when it evaluates
// server-side, the marker becomes rcnMARKER + result. Using 7*7=49 wrapped in a
// unique marker gives a near-zero false-positive signal.
var sstiProbes = []struct {
	payload string // injected value (contains the marker)
	expect  string // string that appears only if the template evaluated
	engine  string
}{
	{"rcnA{{7*7}}rcnB", "rcnA49rcnB", "Jinja2/Twig/Nunjucks ({{7*7}})"},
	{"rcnA${7*7}rcnB", "rcnA49rcnB", "JSP EL / Spring / Mako ${7*7}"},
	{"rcnA#{7*7}rcnB", "rcnA49rcnB", "Ruby/Thymeleaf #{7*7}"},
	{"rcnA<%=7*7%>rcnB", "rcnA49rcnB", "ERB/ASP <%=7*7%>"},
	{"rcnA{{7*'7'}}rcnB", "rcnA7777777rcnB", "Jinja2 string-multiply"},
	{"rcnA${{7*7}}rcnB", "rcnA49rcnB", "Freemarker ${{7*7}}"},
	{"rcnA@(7*7)rcnB", "rcnA49rcnB", "Razor @(7*7)"},
	// Smarty: bare {math} evaluates inside a template. The unique rcnA…rcnB frame
	// keeps FP at zero (a literal "49" elsewhere on the page can't satisfy it).
	{"rcnA{7*7}rcnB", "rcnA49rcnB", "Smarty {7*7}"},
	// Velocity: #set assigns, then the reference renders — VTL has no {{ }} form, so
	// it's entirely missed by the brace probes above (real gap for Java stacks).
	{"#set($rcnC=7*7)rcnA${rcnC}rcnB", "rcnA49rcnB", "Velocity #set($x=7*7)"},
	// Twig/Jinja concat (~): catches an engine where the arithmetic '*' is filtered
	// but the tilde concat operator still evaluates — a common WAF-bypass for SSTI.
	{"rcnA{{'rc'~'n49z'}}rcnB", "rcnArcn49zrcnB", "Twig/Jinja concat (~)"},
	// Pebble/Jinjava (Java Jinja dialects) share {{ }}; the string-multiply form
	// distinguishes a true evaluator from a page that merely echoes {{7*7}}.
	{"rcnA{{'7'*7}}rcnB", "rcnA7777777rcnB", "Jinja/Pebble string*int"},
}

const sstiMaxParams = 150

// Run injects template expressions into parameters and confirms SSTI when the
// server evaluates the arithmetic (marker + 49). Bounded for speed.
func (s *SSTIScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "ssti", "Starting Server-Side Template Injection checks...")

	points := loadInsertionPoints(ctx, s.db, targetID, sstiMaxParams)
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

			for _, probe := range sstiProbes {
				body, _ := sendInjected(ctx, sstiHTTPClient, ip, probe.payload, auth)
				if body == "" {
					continue
				}
				if strings.Contains(body, probe.expect) {
					ev := fmt.Sprintf("Template expression evaluated (%s) via %s: marker→%s", probe.engine, ip.Method, probe.expect)
					s.store(targetID, "ssti", "critical", ip.URL, ip.Param, probe.payload, ev)
					found.Add(1)
					logFn("warn", "ssti", fmt.Sprintf("SSTI CONFIRMED (%s): %s param=%s [%s]", probe.engine, ip.URL, ip.Param, ip.Method))
					s.notify(targetID, ip.URL, ip.Param)
					return
				}
			}
		}(ip)
	}
	wg.Wait()

	logFn("info", "ssti", fmt.Sprintf("SSTI check done. Found %d.", found.Load()))
	return nil
}

func (s *SSTIScanner) store(targetID, vulnType, severity, rawURL, param, payload, evidence string) {
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL, Method: "GET",
		Parameter: param, Location: "query", Payload: payload, Evidence: evidence,
		Source: "ssti-native", DetectionMethod: "evaluated-marker", Confidence: 96,
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
