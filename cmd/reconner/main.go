// Command reconner is the full-power CLI for the Reconner engine — the same
// scanner modules the web build runs, driven from the terminal, no browser.
//
//	reconner scan <domain> [flags]     run a scan and write report files
//	reconner report <domain> [flags]   (re)generate reports from stored results
//	reconner list                      list targets and their finding counts
//	reconner modules                   list every available scan module
//
// Scan flags:
//
//	--modules a,b,c   only these modules (default: all)
//	--quick           fast recon subset (no heavy active injection)
//	--out DIR         report output directory (default ~/reconner-reports)
//	--html --md --pdf choose report formats (default: html + md)
//	--no-report       skip report generation
//	--quiet           only print findings, not every log line
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/api"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/scheduler"
	"github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
)

const (
	cReset  = "\033[0m"
	cDim    = "\033[2m"
	cRed    = "\033[31m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cBlue   = "\033[36m"
	cBold   = "\033[1m"
)

// quickModules is a fast recon-only subset (no slow active injection / headless).
var quickModules = []string{
	"subdomain_enum", "http_probe", "js_analysis", "js_endpoints",
	"param_discovery", "param_reflection", "dir_discovery", "backup_discovery",
	"nuclei", "passive", "takeover", "blh", "exposure", "portscan", "verify",
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(1)
	}
	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "report":
		cmdReport(os.Args[2:])
	case "list":
		cmdList()
	case "rm", "delete", "remove":
		cmdRemove(os.Args[2:])
	case "clean":
		cmdClean()
	case "serve", "bot":
		cmdServe()
	case "suspend-scans":
		cmdSuspendScans()
	case "modules":
		for _, m := range scheduler.AllModules {
			fmt.Println("  " + m)
		}
	case "-h", "--help", "help":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(1)
	}
}

func usage() {
	fmt.Print(`reconner — full-power recon CLI

USAGE:
  reconner scan <domain> [--single] [--quick] [--modules a,b,c] [--out DIR] [--html] [--md] [--pdf] [--no-report] [--quiet]
  reconner report <domain> [--out DIR] [--html] [--md] [--pdf]
  reconner list                     list targets + finding counts
  reconner rm <domain>              delete a target and ALL its data (+ old tasks)
  reconner clean                    purge old cancelled/finished tasks (keep results)
  reconner serve                    run the web watchtower (dashboard + live UI at http://host:8080)
  reconner suspend-scans            park all active scans so the next 'serve' auto-resumes them (used by deploy.sh)
  reconner modules                  list every scan module

EXAMPLES:
  reconner scan example.com
  reconner scan example.com --single      # just this host, no subdomains
  reconner scan example.com --quick
  reconner scan example.com --modules subdomain_enum,http_probe,nuclei,sqli
  reconner report example.com --html --md --out ./reports
`)
}

// engine bundles the shared runtime the CLI spins up per invocation.
type engine struct {
	cfg   *config.Config
	db    *database.DB
	sched *scheduler.Scheduler
	log   *logger.Logger
	hub   *websocket.Hub
	api   *api.Handler
}

func boot() *engine {
	cfg, err := config.Load()
	if err != nil {
		fatal("load config: %v", err)
	}
	// CLI runs on your own machine — don't cap RAM (the web default of 3072 MB
	// forced constant GC because it measured system-wide memory). 0 = unlimited.
	cfg.Limits.MaxMemoryMB = 0
	// Keep the module parallelism on for speed regardless of an old config file.
	cfg.Limits.ParallelModules = true
	// Enforce performance floors even when an OLD config.json (with the previous
	// conservative worker counts) is loaded — otherwise JS analysis etc. crawl.
	floor := func(v *int, min int) {
		if *v < min {
			*v = min
		}
	}
	floor(&cfg.Workers.JSAnalysis, 16)
	floor(&cfg.Workers.HTTPProbing, 40)
	floor(&cfg.Workers.SubdomainEnumeration, 25)
	floor(&cfg.Workers.DirectoryDiscovery, 6)
	floor(&cfg.Workers.Nuclei, 6)
	floor(&cfg.Workers.Crawling, 10)
	// CLI stays quiet at the library level; we do our own pretty logging.
	log := logger.New("error")
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		fatal("open db: %v", err)
	}
	if err := database.RunMigrations(db); err != nil {
		fatal("migrate: %v", err)
	}
	hub := websocket.NewHub()
	go hub.Run()
	sched := scheduler.New(db, hub, cfg, log)
	sched.Start()
	return &engine{cfg: cfg, db: db, sched: sched, log: log, hub: hub, api: api.NewHandler(db, hub, sched, cfg, log)}
}

func cmdScan(args []string) {
	// Accept the domain in any position, so `scan example.com --quick` works
	// (Go's flag package otherwise stops parsing at the first positional).
	domainArg, rest := extractPositional(args)
	if domainArg == "" {
		fatal("scan needs a domain: reconner scan example.com")
	}
	fs := flag.NewFlagSet("scan", flag.ExitOnError)
	modulesFlag := fs.String("modules", "", "comma-separated module list (default: all)")
	quick := fs.Bool("quick", false, "fast recon subset (no heavy active injection)")
	single := fs.Bool("single", false, "scan ONLY this exact host — no subdomain enumeration")
	out := fs.String("out", defaultReportDir(), "report output directory")
	wantHTML := fs.Bool("html", false, "write HTML report")
	wantMD := fs.Bool("md", false, "write Markdown report")
	wantPDF := fs.Bool("pdf", false, "write PDF report")
	noReport := fs.Bool("no-report", false, "skip report generation")
	quiet := fs.Bool("quiet", false, "only print findings, not every log line")
	_ = fs.Parse(rest)

	domain := normalizeDomain(domainArg)

	// Default report formats: html + md unless the user picked specific ones.
	if !*wantHTML && !*wantMD && !*wantPDF {
		*wantHTML, *wantMD = true, true
	}

	var modules []string
	switch {
	case *modulesFlag != "":
		modules = splitCSV(*modulesFlag)
	case *quick:
		modules = quickModules
	default:
		modules = scheduler.AllModules
	}

	// --single: scan just the given host. Drop subdomain enumeration and seed the
	// domain itself as the sole subdomain so http_probe (and everything after it)
	// works on exactly that one host.
	if *single {
		modules = withoutModule(modules, "subdomain_enum")
	}

	e := boot()
	defer e.db.Close()

	targetID := e.getOrCreateTarget(domain)

	if *single {
		e.seedSingleHost(targetID, domain)
		// Mark the target single-scope so URL gathering stays on the exact host
		// (no subdomain URLs from wayback/gau leaking in).
		_, _ = e.db.Exec(`UPDATE targets SET scope='single' WHERE id=?`, targetID)
	} else {
		_, _ = e.db.Exec(`UPDATE targets SET scope='full' WHERE id=?`, targetID)
	}

	task, err := e.sched.CreateTask(targetID, modules, 2)
	if err != nil {
		fatal("create task: %v", err)
	}

	fmt.Printf("%s%s▶ scanning %s%s  %s(%d modules)%s\n", cBold, cBlue, domain, cReset, cDim, len(modules), cReset)

	// Ctrl+C cancels the running scan cleanly.
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done(): // real Ctrl+C
			fmt.Printf("\n%s⚠ cancelling…%s\n", cYellow, cReset)
			_ = e.sched.CancelTask(task.ID)
		case <-done: // scan finished normally — don't print anything
		}
	}()

	status := e.waitForTask(task.ID, *quiet)
	close(done)

	e.printFindings(targetID, domain)

	if !*noReport && status != "cancelled" {
		e.writeReports(targetID, domain, *out, *wantHTML, *wantMD, *wantPDF)
	}

	e.sched.Stop()
	if status == "cancelled" {
		os.Exit(130)
	}
}

func cmdReport(args []string) {
	domainArg, rest := extractPositional(args)
	if domainArg == "" {
		fatal("report needs a domain: reconner report example.com")
	}
	fs := flag.NewFlagSet("report", flag.ExitOnError)
	out := fs.String("out", defaultReportDir(), "report output directory")
	wantHTML := fs.Bool("html", false, "write HTML report")
	wantMD := fs.Bool("md", false, "write Markdown report")
	wantPDF := fs.Bool("pdf", false, "write PDF report")
	_ = fs.Parse(rest)
	if !*wantHTML && !*wantMD && !*wantPDF {
		*wantHTML, *wantMD = true, true
	}
	domain := normalizeDomain(domainArg)

	e := boot()
	defer e.db.Close()
	targetID := e.findTarget(domain)
	if targetID == "" {
		fatal("no scan data for %s — run: reconner scan %s", domain, domain)
	}
	e.writeReports(targetID, domain, *out, *wantHTML, *wantMD, *wantPDF)
	e.sched.Stop()
}

// cmdRemove deletes a target and everything belonging to it (subdomains, hosts,
// findings, tasks — including old cancelled ones — via ON DELETE CASCADE), after
// cancelling any scan still running for it.
func cmdRemove(args []string) {
	domainArg, _ := extractPositional(args)
	if domainArg == "" {
		fatal("rm needs a domain: reconner rm example.com")
	}
	domain := normalizeDomain(domainArg)
	e := boot()
	defer e.db.Close()
	defer e.sched.Stop()
	id := e.findTarget(domain)
	if id == "" {
		fmt.Printf("%sno such target: %s%s\n", cYellow, domain, cReset)
		return
	}
	e.sched.CancelTasksForTarget(id)
	if _, err := e.db.Exec(`DELETE FROM targets WHERE id=?`, id); err != nil {
		fatal("delete: %v", err)
	}
	fmt.Printf("%s✓ removed %s and all its data%s\n", cGreen, domain, cReset)
}

// cmdClean purges finished/cancelled/failed tasks and their logs across all
// targets (keeps the scan RESULTS — subdomains, findings, reports). Handy after
// lots of cancelled runs.
func cmdClean() {
	e := boot()
	defer e.db.Close()
	defer e.sched.Stop()
	res, _ := e.db.Exec(`DELETE FROM tasks WHERE status IN ('cancelled','failed','finished')`)
	n := int64(0)
	if res != nil {
		n, _ = res.RowsAffected()
	}
	fmt.Printf("%s✓ cleaned %d old task(s) (results kept)%s\n", cGreen, n, cReset)
}

// cmdServe runs the always-on web watchtower: the scheduler stays up and the
// full web UI (dashboard, targets, live logs, findings, reports) is served over
// HTTP. Manage/monitor everything from the browser. Bind address comes from the
// config (host/port, default 0.0.0.0:8080). Ctrl+C / SIGTERM shuts it down.
func cmdServe() {
	e := boot()
	defer e.db.Close()

	// Auto-resume any scans that were parked as 'interrupted' when the service was
	// last stopped (graceful shutdown below, or `reconner suspend-scans` from
	// deploy.sh). Each is re-queued for only the modules it hadn't finished, so a
	// restart/upgrade never loses a scan or re-does completed work.
	if n := e.sched.ResumeInterrupted(); n > 0 {
		fmt.Printf("%s  ↻ resumed %d scan(s) interrupted by the last shutdown%s\n", cDim, n, cReset)
	}

	// OOB auto-config: if no blind-XSS/SSRF callback URL is set, discover this
	// server's public IP and point the callbacks at our own web server. This makes
	// blind XSS, blind SSRF, and OAST RCE work out of the box — the watchtower IS
	// the listener (handlers /bx/ and /oob/ already live on this same server).
	if e.cfg.BlindXSSCallbackURL == "" {
		if base := detectPublicBaseURL(e.cfg.Port); base != "" {
			e.cfg.BlindXSSCallbackURL = base
			fmt.Printf("%s  OOB callback auto-set to %s (blind XSS/SSRF enabled)%s\n", cDim, base, cReset)
		}
	}

	// Raw out-of-band listener for Log4Shell (JNDI/LDAP) callbacks — only useful
	// when a public callback host is known. A bind failure is non-fatal.
	if e.cfg.BlindXSSCallbackURL != "" {
		if closer, err := e.api.StartLog4ShellListener(e.cfg.OOBRawPort); err != nil {
			fmt.Printf("%s  Log4Shell OOB listener not started: %v%s\n", cDim, err, cReset)
		} else {
			p := e.cfg.OOBRawPort
			if p <= 0 {
				p = 1389
			}
			fmt.Printf("%s  Log4Shell OOB listener on :%d (JNDI/LDAP callbacks)%s\n", cDim, p, cReset)
			defer closer.Close()
		}
	}

	router := api.NewRouter(e.db, e.hub, e.sched, e.cfg, e.log)
	srv := &http.Server{
		Addr:         fmt.Sprintf("%s:%d", e.cfg.Host, e.cfg.Port),
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 120 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	fmt.Printf("%s%s▶ Reconner web watchtower running%s — http://%s  (Ctrl+C to stop)\n",
		cBold, cBlue, cReset, srv.Addr)
	fmt.Printf("%s  login: %s / (see admin_password in ~/.recon-platform/config.json)%s\n",
		cDim, e.cfg.AdminUsername, cReset)
	switch {
	case strings.HasPrefix(srv.Addr, "0.0.0.0:") || strings.HasPrefix(srv.Addr, ":"):
		fmt.Printf("%s%s  ⚠ bound to all interfaces — the dashboard is reachable from the network.%s\n",
			cBold, cBlue, cReset)
		fmt.Printf("%s    Only do this behind a firewall/VPN. For local-only access set \"host\": \"127.0.0.1\".%s\n",
			cDim, cReset)
	case strings.HasPrefix(srv.Addr, "127.0.0.1:") || strings.HasPrefix(srv.Addr, "localhost:"):
		fmt.Printf("%s  local-only by default. To reach it from another machine (e.g. your VPS):%s\n", cDim, cReset)
		fmt.Printf("%s    • SSH tunnel (safest):  ssh -L 8080:127.0.0.1:8080 user@your-server  → browse http://localhost:8080%s\n", cDim, cReset)
		fmt.Printf("%s    • or set \"host\": \"0.0.0.0\" in ~/.recon-platform/config.json and restart (behind a firewall/VPN)%s\n", cDim, cReset)
	}

	go func() {
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal("web server: %v", err)
		}
	}()

	<-ctx.Done()
	fmt.Printf("\n%sshutting down…%s\n", cYellow, cReset)
	// Park active scans BEFORE tearing anything down, so the next startup can
	// resume exactly what was running. completed_modules is already persisted per
	// module, so nothing finished is lost — a resume re-runs only what's left.
	if n, _ := e.sched.SuspendActiveForShutdown(); n > 0 {
		fmt.Printf("%s  ⏸ parked %d active scan(s) — they'll auto-resume on next start%s\n", cDim, n, cReset)
	}
	shCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_ = srv.Shutdown(shCtx)
	e.sched.Stop()
}

// cmdSuspendScans parks every active scan as 'interrupted' so the next `serve`
// startup resumes it. deploy.sh calls this while the service is stopped (the DB
// is free) as a belt-and-suspenders around the serve process's own graceful
// SIGTERM handler — covering the first upgrade to this version (whose OLD running
// binary has no handler) and any hard stop. It opens only the DB: no scheduler is
// started, so it can't race a running scan or accidentally cancel zombies.
func cmdSuspendScans() {
	cfg, err := config.Load()
	if err != nil {
		fatal("load config: %v", err)
	}
	db, err := database.New(cfg.DatabasePath)
	if err != nil {
		fatal("open db: %v", err)
	}
	defer db.Close()
	n, err := scheduler.SuspendActive(db)
	if err != nil {
		fatal("suspend scans: %v", err)
	}
	fmt.Printf("parked %d active scan(s) for resume on next start\n", n)
}

// detectPublicBaseURL asks a couple of public "what's my IP" endpoints and
// returns http://<ip>:<port>. Empty if it can't determine one (offline / blocked)
// — callers then leave OOB disabled rather than guessing wrong.
func detectPublicBaseURL(port int) string {
	client := &http.Client{Timeout: 6 * time.Second}
	for _, u := range []string{"https://api.ipify.org", "https://ifconfig.me/ip", "https://icanhazip.com"} {
		resp, err := client.Get(u)
		if err != nil {
			continue
		}
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
		resp.Body.Close()
		ip := strings.TrimSpace(string(b))
		if net.ParseIP(ip) != nil {
			return fmt.Sprintf("http://%s:%d", ip, port)
		}
	}
	return ""
}

func cmdList() {
	e := boot()
	defer e.db.Close()
	defer e.sched.Stop()
	rows, err := e.db.Query(`
		SELECT t.domain,
		       (SELECT COUNT(*) FROM subdomains  WHERE target_id=t.id) subs,
		       (SELECT COUNT(*) FROM vuln_findings WHERE target_id=t.id AND COALESCE(status,'finding')='finding') vulns,
		       COALESCE(t.scan_status,'idle')
		FROM targets t ORDER BY t.domain`)
	if err != nil {
		fatal("query: %v", err)
	}
	defer rows.Close()
	fmt.Printf("%s%-40s %8s %8s %10s%s\n", cBold, "DOMAIN", "SUBS", "VULNS", "STATUS", cReset)
	for rows.Next() {
		var d, st string
		var subs, vulns int
		_ = rows.Scan(&d, &subs, &vulns, &st)
		fmt.Printf("%-40s %8d %8d %10s\n", d, subs, vulns, st)
	}
}

// ── engine helpers ──────────────────────────────────────────────────────────

func (e *engine) findTarget(domain string) string {
	var id string
	_ = e.db.QueryRow(`SELECT id FROM targets WHERE domain=?`, domain).Scan(&id)
	return id
}

// seedSingleHost inserts the target domain itself into the subdomains table so
// the pipeline treats it as the one host to probe (used by --single).
func (e *engine) seedSingleHost(targetID, domain string) {
	_, _ = e.db.Exec(`
		INSERT INTO subdomains (id, target_id, subdomain, last_seen)
		VALUES (?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, subdomain) DO NOTHING`,
		uuid.New().String(), targetID, domain)
}

// withoutModule returns the module list with `drop` removed.
func withoutModule(mods []string, drop string) []string {
	out := make([]string, 0, len(mods))
	for _, m := range mods {
		if m != drop {
			out = append(out, m)
		}
	}
	return out
}

func (e *engine) getOrCreateTarget(domain string) string {
	if id := e.findTarget(domain); id != "" {
		return id
	}
	id := uuid.New().String()
	if _, err := e.db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?, ?, 'medium')`, id, domain); err != nil {
		fatal("create target: %v", err)
	}
	return id
}

// waitForTask streams task logs to stdout and blocks until the task ends,
// returning the final status.
func (e *engine) waitForTask(taskID string, quiet bool) string {
	var lastID int64
	tick := time.NewTicker(600 * time.Millisecond)
	defer tick.Stop()
	for range tick.C {
		if !quiet {
			lastID = e.drainLogs(taskID, lastID)
		}
		var status string
		_ = e.db.QueryRow(`SELECT status FROM tasks WHERE id=?`, taskID).Scan(&status)
		if status == "finished" || status == "failed" || status == "cancelled" {
			if !quiet {
				e.drainLogs(taskID, lastID) // flush the tail
			}
			var dur int
			_ = e.db.QueryRow(`SELECT COALESCE(CAST((julianday(finished_at)-julianday(started_at))*86400 AS INT),0) FROM tasks WHERE id=?`, taskID).Scan(&dur)
			icon, col := "✓", cGreen
			if status != "finished" {
				icon, col = "✗", cRed
			}
			fmt.Printf("%s%s scan %s%s %s(%ds)%s\n", col, icon, status, cReset, cDim, dur, cReset)
			return status
		}
	}
	return "finished"
}

func (e *engine) drainLogs(taskID string, lastID int64) int64 {
	rows, err := e.db.Query(`SELECT id, level, module, message FROM task_logs WHERE task_id=? AND id>? ORDER BY id`, taskID, lastID)
	if err != nil {
		return lastID
	}
	defer rows.Close()
	for rows.Next() {
		var id int64
		var level, module, msg string
		if rows.Scan(&id, &level, &module, &msg) != nil {
			continue
		}
		lastID = id
		col := cDim
		switch level {
		case "warn":
			col = cYellow
		case "error":
			col = cRed
		}
		fmt.Printf("%s%-16s%s %s%s%s\n", cBlue, module, cReset, col, msg, cReset)
	}
	return lastID
}

func (e *engine) printFindings(targetID, domain string) {
	rows, err := e.db.Query(`
		SELECT type, severity, url, COALESCE(parameter,''), COALESCE(confidence,0)
		FROM vuln_findings
		WHERE target_id=? AND COALESCE(status,'finding')='finding'
		ORDER BY priority DESC,
		         CASE severity WHEN 'critical' THEN 0 WHEN 'high' THEN 1 WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END`, targetID)
	if err != nil {
		return
	}
	defer rows.Close()
	var findings [][5]string
	for rows.Next() {
		var typ, sev, url, param string
		var conf int
		if rows.Scan(&typ, &sev, &url, &param, &conf) != nil {
			continue
		}
		findings = append(findings, [5]string{typ, sev, url, param, fmt.Sprintf("%d", conf)})
	}
	fmt.Printf("\n%s%s── Findings for %s (%d) ──%s\n", cBold, cGreen, domain, len(findings), cReset)
	if len(findings) == 0 {
		fmt.Printf("%s  no confirmed findings%s\n", cDim, cReset)
		return
	}
	for _, f := range findings {
		col := sevColor(f[1])
		loc := f[2]
		if f[3] != "" {
			loc += "  (param: " + f[3] + ")"
		}
		fmt.Printf("  %s%-9s%s %s%-22s%s %s  %s[%s%%]%s\n",
			col, strings.ToUpper(f[1]), cReset, cBold, f[0], cReset, loc, cDim, f[4], cReset)
	}
}

func (e *engine) writeReports(targetID, domain, dir string, html, md, pdf bool) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		fatal("mkdir %s: %v", dir, err)
	}
	stamp := time.Now().Format("20060102-150405")
	base := filepath.Join(dir, fmt.Sprintf("%s-%s", domain, stamp))
	if html {
		writeFile(base+".html", e.api.ReportHTML(targetID))
	}
	if md {
		writeFile(base+".md", e.api.ReportMarkdown(targetID))
	}
	if pdf {
		writeFile(base+".pdf", e.api.ReportPDF(targetID))
	}
}

// ── small utils ─────────────────────────────────────────────────────────────

func writeFile(path string, b []byte) {
	if len(b) == 0 {
		fmt.Printf("%s  (skipped empty %s)%s\n", cDim, filepath.Base(path), cReset)
		return
	}
	if err := os.WriteFile(path, b, 0o644); err != nil {
		fmt.Printf("%s  write %s failed: %v%s\n", cRed, path, err, cReset)
		return
	}
	fmt.Printf("%s  📄 %s%s\n", cGreen, path, cReset)
}

func sevColor(sev string) string {
	switch strings.ToLower(sev) {
	case "critical", "high":
		return cRed
	case "medium":
		return cYellow
	default:
		return cBlue
	}
}

func defaultReportDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, "reconner-reports")
}

func normalizeDomain(d string) string {
	d = strings.TrimSpace(strings.ToLower(d))
	d = strings.TrimPrefix(d, "https://")
	d = strings.TrimPrefix(d, "http://")
	return strings.TrimSuffix(d, "/")
}

// valueFlags take a following value (e.g. `--modules x`); when scanning for the
// positional domain we must skip that value so it isn't mistaken for the domain.
var valueFlags = map[string]bool{"--modules": true, "-modules": true, "--out": true, "-out": true}

// extractPositional pulls the first non-flag token (the domain) out of args and
// returns it plus the remaining args, so flags may appear in any order.
func extractPositional(args []string) (string, []string) {
	pos := ""
	rest := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		a := args[i]
		if strings.HasPrefix(a, "-") {
			rest = append(rest, a)
			// `--modules x` (space form): keep the value with the flag.
			if valueFlags[a] && !strings.Contains(a, "=") && i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
			continue
		}
		if pos == "" {
			pos = a
			continue
		}
		rest = append(rest, a)
	}
	return pos, rest
}

func splitCSV(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func fatal(format string, a ...any) {
	fmt.Fprintf(os.Stderr, "%serror:%s "+format+"\n", append([]any{cRed, cReset}, a...)...)
	os.Exit(1)
}
