package scanner

import (
	"context"
	"regexp"
	"strings"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// SQLmap verification adapter (Phase 5). PROVES a strong internal SQLi candidate
// with sqlmap. Conservative: structured args (no shell concat — via the executor's
// exec.CommandContext), scope-checked, low level/risk, bounded time. A POSITIVE
// sqlmap injection is the only thing that promotes a candidate to CONFIRMED; a
// non-positive run is INCONCLUSIVE (WAF/rate-limit/session/etc.), never a false
// negative asserted as "not vulnerable".

type SQLmapVerifier struct {
	exec         *tools.Executor
	cfg          *config.Config
	logger       *logger.Logger
	targetDomain string
	origins      []string
	cookie       string // from the selected identity (already-decrypted)
}

func NewSQLmapVerifier(exec *tools.Executor, cfg *config.Config, log *logger.Logger, targetDomain string, origins []string, cookie string) *SQLmapVerifier {
	return &SQLmapVerifier{exec: exec, cfg: cfg, logger: log, targetDomain: targetDomain, origins: origins, cookie: cookie}
}

func (v *SQLmapVerifier) Name() string { return "sqlmap" }

// CanVerify: SQLi candidates only, and only when enabled + tool present.
func (v *SQLmapVerifier) CanVerify(c VulnerabilityCandidate) bool {
	return c.Type == "sqli" && v.cfg != nil && v.cfg.EnableSQLmap && v.exec != nil && v.exec.IsToolAvailable("sqlmap")
}

func (v *SQLmapVerifier) Verify(ctx context.Context, c VulnerabilityCandidate) VerifyResult {
	// Scope guard: never point sqlmap at an out-of-scope / internal host.
	if !URLInScope(v.targetDomain, v.origins, c.URL) {
		return VerifyResult{Verdict: VerifyRejected, Reason: "candidate URL out of scope", Method: "sqlmap"}
	}
	args := buildSQLmapArgs(c, v.cookie)
	res, err := v.exec.Run(ctx, "sqlmap", args...)
	if err != nil && res == nil {
		return VerifyResult{Verdict: VerifyInconclusive, Reason: "sqlmap failed to run: " + err.Error(), Method: "sqlmap"}
	}
	out := res.Stdout + "\n" + res.Stderr
	positive, dbms, injType := parseSQLmapOutput(out)
	if positive {
		ev := "sqlmap CONFIRMED injection on parameter " + c.Parameter
		if injType != "" {
			ev += " (" + injType + ")"
		}
		if dbms != "" {
			ev += ", DBMS: " + dbms
		}
		return VerifyResult{Verdict: VerifyVerified, Confidence: 98, Evidence: ev, Method: "sqlmap"}
	}
	// Ran but did not positively confirm → INCONCLUSIVE with a reason (do not
	// claim "not vulnerable" — WAF/rate-limit/session/dynamic params can hide it).
	return VerifyResult{Verdict: VerifyInconclusive, Reason: sqlmapInconclusiveReason(out), Method: "sqlmap"}
}

// buildSQLmapArgs constructs a conservative, structured sqlmap argument array.
// NEVER build a shell string — the executor runs argv directly.
func buildSQLmapArgs(c VulnerabilityCandidate, cookie string) []string {
	args := []string{
		"-u", c.URL,
		"--batch",               // non-interactive
		"--disable-coloring",    // clean, parseable output
		"--level=1", "--risk=1", // conservative first pass (risk=1 avoids OR-based on UPDATEs)
		"--technique=BEUSTQ", // Boolean/Error/Union/Stacked/Time + inline queries
		"--random-agent",     // rotate UA — dodges trivial user-agent blocks
		"--timeout=15", "--retries=1", "--threads=2",
		"--answers=quit=N,crack=N,dict=N,continue=Y",
	}
	if p := strings.ToUpper(c.Method); p == "POST" && c.Location == "body" {
		args = append(args, "--method=POST")
		if c.Payload != "" {
			args = append(args, "--data", c.Payload)
		}
	}
	if c.Parameter != "" {
		args = append(args, "-p", c.Parameter)
	}
	if cookie != "" {
		args = append(args, "--cookie", cookie)
	}
	return args
}

var (
	reSQLmapVuln    = regexp.MustCompile(`(?i)parameter '?[^']*'? (?:is|appears to be) [^\n]*vulnerable|the following injection point`)
	reSQLmapType    = regexp.MustCompile(`(?i)Type:\s*([^\n]+)`)
	reSQLmapDBMS    = regexp.MustCompile(`(?i)back-end DBMS:\s*([^\n]+)`)
	reSQLmapNotVuln = regexp.MustCompile(`(?i)all tested parameters do not appear to be injectable`)
)

// parseSQLmapOutput extracts a positive-injection verdict + DBMS + type.
func parseSQLmapOutput(out string) (positive bool, dbms, injType string) {
	if reSQLmapVuln.MatchString(out) && !reSQLmapNotVuln.MatchString(out) {
		positive = true
	}
	if m := reSQLmapDBMS.FindStringSubmatch(out); len(m) == 2 {
		dbms = strings.TrimSpace(m[1])
	}
	if m := reSQLmapType.FindStringSubmatch(out); len(m) == 2 {
		injType = strings.TrimSpace(m[1])
	}
	return
}

// sqlmapInconclusiveReason gives a human reason a run didn't confirm.
func sqlmapInconclusiveReason(out string) string {
	low := strings.ToLower(out)
	switch {
	case reSQLmapNotVuln.MatchString(out):
		return "sqlmap tested the parameter and did not find it injectable (could be WAF/dynamic response — kept INCONCLUSIVE, not rejected)"
	case strings.Contains(low, "connection timed out") || strings.Contains(low, "unable to connect"):
		return "sqlmap could not reach the target (timeout/connection) — retry when stable"
	case strings.Contains(low, "403") || strings.Contains(low, "waf") || strings.Contains(low, "blocked"):
		return "sqlmap appears blocked (WAF/403) — verification inconclusive"
	default:
		return "sqlmap ran but did not positively confirm injection"
	}
}
