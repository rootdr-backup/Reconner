package scheduler

import (
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/models"
	"github.com/recon-platform/internal/scanner"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/internal/websocket"
	"github.com/recon-platform/pkg/logger"
	"github.com/shirou/gopsutil/v3/load"
	"github.com/shirou/gopsutil/v3/mem"
)

const (
	ModuleSubdomainEnum   = "subdomain_enum"
	ModuleHTTPProbe       = "http_probe"
	ModuleJSAnalysis      = "js_analysis"
	ModuleJSEndpoints     = "js_endpoints"
	ModuleParamDiscovery  = "param_discovery"
	ModuleHeadlessCrawl   = "headless_crawl" // browser-rendered (SPA) surface discovery
	ModuleTimeMachine     = "timemachine"
	ModuleParamReflection = "param_reflection"
	ModuleParamFuzz       = "paramfuzz"
	ModuleDirDiscovery    = "dir_discovery"
	ModuleBackupDiscovery = "backup_discovery"
	ModuleOpenRedirect    = "open_redirect"
	ModuleNuclei          = "nuclei"
	ModuleDAST            = "dast"
	ModuleXSS             = "xss" // standalone reflected-XSS objective (DAST engine, XSS-only)
	ModuleVulnScan        = "vuln_scan"
	ModuleDOMXSS          = "dom_xss"
	ModuleSQLi            = "sqli"
	ModuleSSRF            = "ssrf"
	ModuleLFI             = "lfi"
	ModuleSSTI            = "ssti"
	ModuleCmdi            = "cmdi"
	ModulePassive         = "passive"
	ModuleTakeover        = "takeover"
	ModuleBLH             = "blh"
	ModuleCSRF            = "csrf"
	ModuleCORS            = "cors"
	ModuleExposure        = "exposure"
	ModuleIntel           = "intel"
	ModuleOAST            = "oast"
	ModuleXXE             = "xxe"
	ModuleIDOR            = "idor"
	ModuleJWT             = "jwt"
	ModuleATO             = "ato"
	ModuleAuthz           = "authz"
	ModuleNoSQLi          = "nosqli"
	ModuleCachePoison     = "cache_poison"
	ModuleOriginIP        = "origin_ip"
	ModulePortScan        = "portscan"
	ModuleShodan          = "shodan"
	ModuleRace            = "race"
	ModuleSmuggling       = "smuggling"
	ModuleVerify          = "verify"
	ModuleMonitor         = "monitor"
	ModuleNetwork         = "network"
	ModuleNetworkBrute    = "network_brute"
	// ModuleNetworkBackup runs backup/config-file discovery (the same engine
	// as the web backup_discovery module) against a network target's
	// discovered WEB endpoints — previously never ran for network targets at
	// all, since those endpoints live in network_services, not http_services.
	ModuleNetworkBackup = "network_backup"
	// ModuleNetworkNucleiOnly re-runs just the nuclei CVE/exposure phase
	// against ALREADY-discovered network services (see RunNucleiOnly) — no
	// port scan, no service discovery, no brute-force. For re-scanning after
	// a template update without repeating the slow discovery phase.
	ModuleNetworkNucleiOnly = "network_nuclei_only"
	// ModuleNetworkIngram runs the third-party Ingram IP-camera/DVR scanner
	// (see NetworkScanner.RunIngram) against every live host found during
	// discovery — extra vendor-specific weak-credential + known-CVE PoCs for
	// camera/DVR/NVR gear that Reconner's own engines don't cover. Same
	// active/opt-in posture as ModuleNetworkBrute.
	ModuleNetworkIngram = "network_ingram"
	// ModuleNetDevices audits network infrastructure gear (MikroTik, Cisco,
	// PPTP/VPN, and modems/routers from Huawei/ZTE/TP-Link/D-Link/Netgear/Asus/
	// Ubiquiti/Fortinet/… ) — the Ingram equivalent for routers. Fingerprint +
	// exposure + firmware-CVE flagging always run; default-credential testing
	// runs only when NetworkBruteforce is enabled (same posture as BruteRun).
	ModuleNetDevices = "network_devices"
	// ModuleNetworkInitialAccess runs the initial-access engine (see
	// NetworkScanner.RunInitialAccess): active confirmation of every service
	// that grants access with NO credentials (unauth Redis/Docker/K8s/Mongo/ES/
	// etcd/Jenkins/Portainer/Jupyter, anon FTP/LDAP/rsync, no-auth VNC) plus a
	// curated set of pre-auth file-read / auth-bypass CVEs on edge gear. Same
	// active/opt-in posture as ModuleNetworkBrute/Ingram.
	ModuleNetworkInitialAccess = "network_initial_access"
)


var AllModules = []string{
	ModuleSubdomainEnum,
	ModuleHTTPProbe,
	ModuleJSAnalysis,
	ModuleJSEndpoints,
	ModuleParamDiscovery,
	ModuleHeadlessCrawl,
	ModuleTimeMachine,
	ModuleParamReflection,
	ModuleParamFuzz,
	ModuleDirDiscovery,
	ModuleBackupDiscovery,
	ModuleOpenRedirect,
	ModuleNuclei,
	ModuleXSS,
	ModuleVulnScan,
	ModuleSQLi,
	ModuleSSRF,
	ModuleLFI,
	ModuleSSTI,
	ModuleCmdi,
	ModulePassive,
	ModuleTakeover,
	ModuleBLH,
	ModuleCSRF,
	ModuleCORS,
	ModuleExposure,
	ModuleIntel,
	ModuleOAST,
	ModuleXXE,
	ModuleIDOR,
	ModuleJWT,
	ModuleAuthz,
	ModuleATO,
	ModuleNoSQLi,
	ModuleCachePoison,
	ModuleOriginIP,
	ModuleShodan,
	ModuleRace,
	ModuleSmuggling,
	ModuleVerify,
	ModuleMonitor,
}

// Notifier is implemented by the Telegram bot to receive scan/vuln events.
type Notifier interface {
	NotifyScanStarted(domain string)
	NotifyScanFinished(domain, status string, duration time.Duration, stats map[string]int)
	NotifyNewVuln(domain, vulnType, severity, url, parameter string)
	NotifyMonitorChange(domain, changeType, url, oldVal, newVal string)
}

type Scheduler struct {
	db       *database.DB
	hub      *websocket.Hub
	cfg      *config.Config
	logger   *logger.Logger
	executor *tools.Executor
	notifier Notifier

	subdomainScanner   *scanner.SubdomainScanner
	httpScanner        *scanner.HTTPScanner
	jsScanner          *scanner.JSScanner
	jsEndpointScanner  *scanner.JSEndpointScanner
	paramScanner       *scanner.ParamScanner
	timeMachineScanner *scanner.TimeMachineScanner
	paramFuzzScanner   *scanner.ParamFuzzScanner
	dirScanner         *scanner.DirScanner
	nucleiScanner      *scanner.NucleiScanner
	dastScanner        *scanner.DASTScanner
	headlessCrawler    *scanner.HeadlessCrawler
	vulnScanner        *scanner.VulnScanner
	sqliScanner        *scanner.SQLiScanner
	ssrfScanner        *scanner.SSRFScanner
	lfiScanner         *scanner.LFIScanner
	sstiScanner        *scanner.SSTIScanner
	cmdiScanner        *scanner.CmdiScanner
	passiveScanner     *scanner.PassiveScanner
	takeoverScanner    *scanner.TakeoverScanner
	blhScanner         *scanner.BLHScanner
	csrfScanner        *scanner.CSRFScanner
	corsScanner        *scanner.CORSScanner
	exposureScanner    *scanner.ExposureScanner
	intelScanner       *scanner.IntelScanner
	oastScanner        *scanner.OASTScanner
	xxeScanner         *scanner.XXEScanner
	idorScanner        *scanner.IDORScanner
	jwtScanner         *scanner.JWTScanner
	atoEngine          *scanner.AccountTakeoverEngine
	authzEngine        *scanner.AuthzEngine
	nosqliScanner      *scanner.NoSQLiScanner
	cachePoisonScanner *scanner.CachePoisonScanner
	originIPScanner    *scanner.OriginIPScanner
	shodanScanner      *scanner.ShodanScanner
	raceScanner        *scanner.RaceScanner
	smugglingScanner   *scanner.SmugglingScanner
	verifyScanner      *scanner.VerifyScanner
	monitorScanner     *scanner.MonitorScanner

	queue     chan string
	cancelMap map[string]context.CancelFunc
	mu        sync.RWMutex
	running   map[string]bool
	// throttleLog dedupes the cooldown warning so a loaded box logs it once, not
	// every 2s drain tick.
	throttleLog atomic.Bool
	stopCh      chan struct{}
	wg          sync.WaitGroup

	pauseMu    sync.Mutex
	paused     map[string]bool               // taskID -> paused (gate checked between modules)
	skipCancel map[string]context.CancelFunc // taskID -> cancel the CURRENT phase only
	skipReq    map[string]bool               // taskID -> a skip was requested for the current phase
}

func New(db *database.DB, hub *websocket.Hub, cfg *config.Config, log *logger.Logger) *Scheduler {
	exec := tools.NewExecutor(cfg, log)

	s := &Scheduler{
		db:         db,
		hub:        hub,
		cfg:        cfg,
		logger:     log,
		executor:   exec,
		queue:      make(chan string, 100),
		cancelMap:  make(map[string]context.CancelFunc),
		skipCancel: make(map[string]context.CancelFunc),
		skipReq:    make(map[string]bool),
		running:    make(map[string]bool),
		stopCh:     make(chan struct{}),
		paused:     make(map[string]bool),
	}

	// Wrapped broadcast: fan out to websocket clients AND route high-signal
	// vuln findings to the Telegram notifier (with severity scoring).
	bc := s.broadcastAndScore

	s.subdomainScanner = scanner.NewSubdomainScanner(db, exec, cfg, log, bc)
	s.httpScanner = scanner.NewHTTPScanner(db, exec, cfg, log)
	s.jsScanner = scanner.NewJSScanner(db, exec, cfg, log, bc)
	s.jsEndpointScanner = scanner.NewJSEndpointScanner(db, exec, cfg, log, bc)
	s.paramScanner = scanner.NewParamScanner(db, exec, cfg, log, bc)
	s.timeMachineScanner = scanner.NewTimeMachineScanner(db, exec, cfg, log, bc)
	s.paramFuzzScanner = scanner.NewParamFuzzScanner(db, exec, cfg, log, bc)
	s.dirScanner = scanner.NewDirScanner(db, exec, cfg, log)
	s.nucleiScanner = scanner.NewNucleiScanner(db, exec, cfg, log)
	s.dastScanner = scanner.NewDASTScanner(db, cfg, log, bc)
	s.headlessCrawler = scanner.NewHeadlessCrawler(db, cfg, log)
	s.vulnScanner = scanner.NewVulnScanner(db, exec, cfg, log, bc)
	s.sqliScanner = scanner.NewSQLiScanner(db, exec, cfg, log, bc)
	s.ssrfScanner = scanner.NewSSRFScanner(db, exec, cfg, log, bc)
	s.lfiScanner = scanner.NewLFIScanner(db, exec, cfg, log, bc)
	s.sstiScanner = scanner.NewSSTIScanner(db, exec, cfg, log, bc)
	s.cmdiScanner = scanner.NewCmdiScanner(db, exec, cfg, log, bc)
	s.passiveScanner = scanner.NewPassiveScanner(db, exec, cfg, log, bc)
	s.takeoverScanner = scanner.NewTakeoverScanner(db, exec, cfg, log, bc)
	s.blhScanner = scanner.NewBLHScanner(db, exec, cfg, log, bc)
	s.csrfScanner = scanner.NewCSRFScanner(db, exec, cfg, log, bc)
	s.corsScanner = scanner.NewCORSScanner(db, exec, cfg, log, bc)
	s.exposureScanner = scanner.NewExposureScanner(db, exec, cfg, log, bc)
	s.intelScanner = scanner.NewIntelScanner(db, exec, cfg, log, bc)
	s.oastScanner = scanner.NewOASTScanner(db, exec, cfg, log, bc)
	s.xxeScanner = scanner.NewXXEScanner(db, exec, cfg, log, bc)
	s.idorScanner = scanner.NewIDORScanner(db, exec, cfg, log, bc)
	s.jwtScanner = scanner.NewJWTScanner(db, exec, cfg, log, bc)
	s.atoEngine = scanner.NewAccountTakeoverEngine(db, exec, cfg, log, bc)
	s.authzEngine = scanner.NewAuthzEngine(db, exec, cfg, log, bc)
	s.nosqliScanner = scanner.NewNoSQLiScanner(db, exec, cfg, log, bc)
	s.cachePoisonScanner = scanner.NewCachePoisonScanner(db, exec, cfg, log, bc)
	s.originIPScanner = scanner.NewOriginIPScanner(db, exec, cfg, log, bc)
	s.shodanScanner = scanner.NewShodanScanner(db, exec, cfg, log, bc)
	s.raceScanner = scanner.NewRaceScanner(db, exec, cfg, log, bc)
	s.smugglingScanner = scanner.NewSmugglingScanner(db, exec, cfg, log, bc)
	s.verifyScanner = scanner.NewVerifyScanner(db, exec, cfg, log, bc)
	s.monitorScanner = scanner.NewMonitorScanner(db, exec, cfg, log)

	return s
}

// broadcastAndScore forwards every event to the websocket hub and, for new
// vuln findings, pushes a Telegram alert only when the finding is high-signal
// (high/critical, or a takeover). Low/info findings stay in the dashboard only,
// avoiding alert fatigue.
func (s *Scheduler) broadcastAndScore(event string, data any) {
	s.hub.Broadcast(event, data)

	if event != "new_vuln_finding" || s.notifier == nil {
		return
	}
	m, ok := data.(map[string]any)
	if !ok {
		return
	}
	targetID, _ := m["target_id"].(string)
	vulnType, _ := m["type"].(string)
	url, _ := m["url"].(string)
	param, _ := m["parameter"].(string)
	if targetID == "" {
		return
	}

	// Look up severity + domain (payload doesn't carry them).
	var severity, domain string
	_ = s.db.QueryRow(`SELECT severity FROM vuln_findings WHERE target_id=? AND type=? AND url=? ORDER BY created_at DESC LIMIT 1`,
		targetID, vulnType, url).Scan(&severity)
	_ = s.db.QueryRow(`SELECT domain FROM targets WHERE id=?`, targetID).Scan(&domain)

	if !shouldPushVuln(vulnType, severity) {
		return
	}
	s.notifier.NotifyNewVuln(domain, vulnType, severity, url, param)
}

// shouldPushVuln decides whether a finding is worth an immediate alert.
func shouldPushVuln(vulnType, severity string) bool {
	switch strings.ToLower(severity) {
	case "critical", "high":
		return true
	}
	// Always push takeovers regardless of stored severity.
	return vulnType == "subdomain_takeover" || vulnType == "open_bucket"
}

// EmitVulnFinding broadcasts a vuln-finding event through the same scoring +
// Telegram path used by the scanners. Used by out-of-band handlers (e.g. the
// blind-XSS callback) that discover findings outside a scan run.
func (s *Scheduler) EmitVulnFinding(data map[string]any) {
	s.broadcastAndScore("new_vuln_finding", data)
}

func (s *Scheduler) SetNotifier(n Notifier) {
	s.notifier = n
}

func (s *Scheduler) Start() {
	// Clean up zombie tasks from a previous run SYNCHRONOUSLY, before the queue
	// starts — otherwise it races with any task created right after Start() and
	// wrongly cancels it (the CLI's "scan cancelled (0s)" bug).
	s.recoverPendingTasks()

	s.wg.Add(1)
	go s.processQueue()

	s.wg.Add(1)
	go s.monitorMemory()

	s.wg.Add(1)
	go s.monitoringScheduler()
}

func (s *Scheduler) Stop() {
	close(s.stopCh)
	s.wg.Wait()
}

func (s *Scheduler) recoverPendingTasks() {
	// (1) A task left in 'running' or 'paused' when the process died is a zombie:
	// its in-memory context is gone, so it can never make progress or be
	// cancelled. Mark it cancelled rather than blindly resurrecting it — that was
	// the cause of "stuck running / can't cancel" after a restart.
	rows, err := s.db.Query(`SELECT id FROM tasks WHERE status IN ('running','paused')`)
	if err == nil {
		var stale []string
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err == nil {
				stale = append(stale, id)
			}
		}
		rows.Close()
		for _, id := range stale {
			_, _ = s.db.Exec(`UPDATE tasks SET status='cancelled', finished_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`, id)
			s.hub.Broadcast("task_cancelled", map[string]string{"task_id": id})
		}
		if len(stale) > 0 {
			s.logger.Info("Cleaned up zombie running/paused tasks from previous run", "count", len(stale))
		}
	}

	// (1b) RECONCILE ORPHANED TARGET STATUS. Cancelling the zombie task above frees
	// the task row, but the OWNING TARGET keeps scan_status='running'/'paused' — so
	// the UI shows the target as still scanning while runningTaskForTarget finds
	// nothing, which is exactly the "target stuck running, but skip says 'nothing
	// running'" report. Any target that claims running/paused with no live
	// (running/paused/pending) task behind it is reset to idle.
	if res, err := s.db.Exec(`
		UPDATE targets SET scan_status='idle', updated_at=CURRENT_TIMESTAMP
		WHERE scan_status IN ('running','paused')
		  AND id NOT IN (SELECT target_id FROM tasks WHERE status IN ('running','paused','pending'))`); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			s.logger.Info("Reset orphaned target scan_status left from previous run", "count", n)
		}
	}

	// (2) STALE PENDING BACKLOG — the bug that makes a freshly-started scan sit in
	// 'pending' forever. Tasks queued before a crash/restart stay 'pending' in the
	// DB; drainPendingTasks (ORDER BY created_at ASC) then runs that OLD backlog
	// AHEAD of a scan the user just started, monopolising the concurrency slots.
	// Reconcile it: any task still 'pending' from more than 2h ago is stale and is
	// cancelled so the queue is clear. Recently-queued pendings (<2h) drain normally.
	if res, err := s.db.Exec(`
		UPDATE tasks SET status='cancelled', finished_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP
		WHERE status='pending' AND created_at < datetime('now','-2 hours')`); err == nil {
		if n, _ := res.RowsAffected(); n > 0 {
			s.logger.Info("Cleared stale pending backlog from previous runs", "count", n)
		}
	}
}

// InterruptedStatus marks a task that was ACTIVE (running or paused) when the
// service was intentionally stopped — as opposed to a crash zombie. It is a
// resume-intent state: on the next startup ResumeInterrupted() re-queues each
// such task's remaining (not-yet-completed) modules. Nothing already finished is
// re-run, because completed_modules is persisted incrementally as the scan runs,
// so at worst the single in-flight module is repeated.
const InterruptedStatus = "interrupted"

// SuspendActive flips every currently-active (running or paused) task to the
// 'interrupted' state and returns how many were affected. It is called both by
// the serve process's graceful-shutdown handler (on SIGTERM/SIGINT) and by the
// `reconner suspend-scans` CLI that deploy.sh runs while the service is stopped —
// so an in-progress scan is safely parked across a restart/upgrade instead of
// being lost or left as an uncancellable zombie. Idempotent (a second call finds
// nothing still running). Package-level so the CLI can call it with just a DB
// handle, without spinning up a full scheduler.
func SuspendActive(db *database.DB) (int, error) {
	res, err := db.Exec(`UPDATE tasks SET status=?, updated_at=CURRENT_TIMESTAMP
		WHERE status IN ('running','paused')`, InterruptedStatus)
	if err != nil {
		return 0, err
	}
	n, _ := res.RowsAffected()
	// Reflect the park on the owning targets so the UI shows "paused", not a scan
	// that looks like it's still running with nothing behind it.
	_, _ = db.Exec(`UPDATE targets SET scan_status='paused', updated_at=CURRENT_TIMESTAMP
		WHERE id IN (SELECT DISTINCT target_id FROM tasks WHERE status=?)`, InterruptedStatus)
	return int(n), nil
}

// SuspendActiveForShutdown parks all active scans as 'interrupted' during the
// serve process's graceful shutdown, so the next startup can resume them.
func (s *Scheduler) SuspendActiveForShutdown() (int, error) { return SuspendActive(s.db) }

// ResumeInterrupted re-queues every task parked as 'interrupted' (see
// SuspendActive) for the modules it had NOT yet completed, then retires the
// original row. Called once at serve startup so scans that were running when the
// service was stopped pick up automatically where they left off. Returns how many
// scans were resumed. Runs ONLY in the long-lived serve process (it enqueues onto
// the worker pool) — never from a short-lived CLI boot.
func (s *Scheduler) ResumeInterrupted() int {
	rows, err := s.db.Query(`SELECT id FROM tasks WHERE status=?`, InterruptedStatus)
	if err != nil {
		return 0
	}
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	resumed := 0
	for _, id := range ids {
		// Retire the parked task to a terminal state ResumeTask accepts, so its row
		// is a clean record and can never be resumed twice.
		_, _ = s.db.Exec(`UPDATE tasks SET status='cancelled', finished_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`, id)
		if _, err := s.ResumeTask(id); err != nil {
			if err != ErrNothingToResume {
				s.logger.Warn("Could not auto-resume interrupted scan", "task", id, "err", err)
			}
			continue
		}
		resumed++
	}
	if resumed > 0 {
		s.logger.Info("Auto-resumed scans interrupted by the last shutdown", "count", resumed)
	}
	return resumed
}

func (s *Scheduler) CreateTask(targetID string, modules []string, priority int) (*models.Task, error) {
	return s.createTask(targetID, modules, priority, "", "")
}

// CreateScopedTask creates a scan pinned to ONE asset's scope (scope_override) —
// so a target's assets scan individually instead of the whole target at once.
func (s *Scheduler) CreateScopedTask(targetID string, modules []string, priority int, scopeOverride string) (*models.Task, error) {
	return s.createTask(targetID, modules, priority, "", scopeOverride)
}

// CreateTaskTyped is CreateTask with an explicit task TYPE, used to tag
// scheduler-originated scans (e.g. "monitor_watch" for a periodic watch pass,
// "monitor_escalation" for the heavier follow-up it triggers on change) so the
// completion hook can tell them apart from a user's manual scan. An empty typeTag
// keeps the default behaviour (full_scan, or the single module's name).
func (s *Scheduler) CreateTaskTyped(targetID string, modules []string, priority int, typeTag string) (*models.Task, error) {
	return s.createTask(targetID, modules, priority, typeTag, "")
}

func (s *Scheduler) createTask(targetID string, modules []string, priority int, typeTag, scopeOverride string) (*models.Task, error) {
	if len(modules) == 0 {
		modules = AllModules
	}

	// Capability planning: a selection of vulnerability OBJECTIVES is expanded into
	// the complete pipeline needed to find them — each selected detector plus the
	// reconnaissance capabilities that populate its inputs (subdomains →
	// http_services → parameters/JS) plus a final verify pass — while adding NO
	// unrelated detector. This is what lets a user pick a single vulnerability and
	// still get a full, vulnerability-specific scan. The user's original selection
	// is remembered for the task TYPE label (the objective), while the expanded
	// list is what actually executes. (No-op for the full default set and for
	// network-only scans, which the planner passes through unchanged.)
	objective := modules
	modules = PlanModules(modules)

	task := &models.Task{
		ID:       uuid.New().String(),
		TargetID: targetID,
		Type:     "full_scan",
		Status:   "pending",
		Priority: priority,
		Modules:  modules,
		Total:    len(modules),
	}

	if len(objective) == 1 {
		task.Type = objective[0] // label the scan by the objective the user chose
	}
	if typeTag != "" {
		task.Type = typeTag
	}

	modulesJSON := models.StringSliceToJSON(modules)
	_, err := s.db.Exec(`
		INSERT INTO tasks (id, target_id, type, status, priority, modules, total, scope_override)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
	`, task.ID, task.TargetID, task.Type, task.Status, task.Priority, modulesJSON, task.Total, scopeOverride)
	if err != nil {
		return nil, fmt.Errorf("create task: %w", err)
	}

	// Non-blocking enqueue: never let a full queue block the HTTP handler (that
	// was the cause of "unable to add target / can't cancel" under load). If the
	// buffer is momentarily full, hand off to a goroutine so the request returns.
	select {
	case s.queue <- task.ID:
	default:
		go func(tid string) { s.queue <- tid }(task.ID)
	}
	s.hub.Broadcast("task_created", task)
	return task, nil
}

// ErrNothingToResume means every module the original task listed already
// completed successfully — resuming would just re-run the whole thing.
var ErrNothingToResume = fmt.Errorf("nothing to resume: all modules already completed")

// ResumeTask reads a FAILED or CANCELLED task's module list and its
// completed_modules (see executeTask), and creates a NEW task covering only
// the modules that never finished — instead of restarting the whole scan.
// This is what turns "an 8h watchdog killed a big scan 90% through" into
// "re-run the last one module" rather than "start over from zero".
func (s *Scheduler) ResumeTask(taskID string) (*models.Task, error) {
	var targetID, status, modulesJSON, completedJSON string
	var priority int
	err := s.db.QueryRow(`
		SELECT target_id, status, modules, COALESCE(completed_modules,'[]'), priority
		FROM tasks WHERE id = ?
	`, taskID).Scan(&targetID, &status, &modulesJSON, &completedJSON, &priority)
	if err != nil {
		return nil, fmt.Errorf("task not found: %w", err)
	}
	if status != "failed" && status != "cancelled" {
		return nil, fmt.Errorf("only a failed or cancelled task can be resumed (status=%s)", status)
	}

	all := models.JSONToStringSlice(modulesJSON)
	done := map[string]bool{}
	for _, m := range models.JSONToStringSlice(completedJSON) {
		done[m] = true
	}
	// A module's completion doesn't necessarily land as a clean prefix of `all`
	// (a parallel group can finish some of its members and not others), so
	// build BOTH lists by filtering in original order rather than slicing.
	var remaining, skipped []string
	for _, m := range all {
		if done[m] {
			skipped = append(skipped, m)
		} else {
			remaining = append(remaining, m)
		}
	}
	if len(remaining) == 0 {
		return nil, ErrNothingToResume
	}

	newTask, err := s.CreateTask(targetID, remaining, priority)
	if err != nil {
		return nil, err
	}
	_, _ = s.db.Exec(`
		INSERT INTO task_logs (task_id, level, message, module)
		VALUES (?, 'info', ?, 'scheduler')
	`, newTask.ID, fmt.Sprintf("Resumed from task #%s — skipping %d already-completed module(s): %v",
		shortID(taskID), len(skipped), skipped))
	return newTask, nil
}

// shortID returns the first 8 chars of a task id for log messages, without
// panicking on an id shorter than that (ids are normally 36-char UUIDs).
func shortID(id string) string {
	if len(id) > 8 {
		return id[:8]
	}
	return id
}

func (s *Scheduler) CancelTask(taskID string) error {
	s.mu.Lock()
	cancel, ok := s.cancelMap[taskID]
	// Free the concurrency slot RIGHT NOW. The scan goroutine's own defer also
	// deletes these on exit (idempotent), but doing it here means a module that's
	// slow to honor cancellation can't keep the slot — and the whole queue —
	// wedged. This is the fix for "I stopped/deleted it but scans stayed stuck."
	delete(s.cancelMap, taskID)
	delete(s.running, taskID)
	s.mu.Unlock()

	if ok {
		cancel()
	}

	_, err := s.db.Exec(`
		UPDATE tasks SET status = 'cancelled', finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = ? AND status IN ('running', 'pending')
	`, taskID)
	if err != nil {
		return err
	}

	s.hub.Broadcast("task_cancelled", map[string]string{"task_id": taskID})
	return nil
}

// CancelTasksForTarget cancels every running/pending task belonging to a target
// (context-cancels the in-flight scan goroutine and marks the rows cancelled).
// Called before a target is deleted so a scan can't keep running in the
// background — the cause of "I deleted it but an hour later Telegram pinged me".
func (s *Scheduler) CancelTasksForTarget(targetID string) {
	rows, err := s.db.Query(`SELECT id FROM tasks WHERE target_id = ? AND status IN ('running','pending')`, targetID)
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()

	// Cancel each task's context AND free its concurrency slot immediately, so a
	// module that's slow to notice cancellation can't keep the target's scan (or
	// the queue behind it) running in the background after deletion.
	s.mu.Lock()
	for _, id := range ids {
		if cancel, ok := s.cancelMap[id]; ok {
			cancel()
		}
		delete(s.cancelMap, id)
		delete(s.running, id)
	}
	s.mu.Unlock()

	for _, id := range ids {
		_, _ = s.db.Exec(`UPDATE tasks SET status='cancelled', finished_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE id=?`, id)
		s.hub.Broadcast("task_cancelled", map[string]string{"task_id": id})
	}
	if len(ids) > 0 {
		s.logger.Info("Cancelled running tasks for deleted target", "target", targetID, "count", len(ids))
	}
}

// runningTaskForTarget returns the id of the most recent running/paused task for
// a target (empty if none), so target-scoped pause/resume can find its scan.
func (s *Scheduler) runningTaskForTarget(targetID string) string {
	var id string
	_ = s.db.QueryRow(
		`SELECT id FROM tasks WHERE target_id=? AND status IN ('running','paused') ORDER BY created_at DESC LIMIT 1`,
		targetID).Scan(&id)
	return id
}

// reconcileOrphanedTarget is the on-demand counterpart to the startup reconcile:
// when an operator control (skip/pause) finds NO live task but the target still
// shows scan_status running/paused, the target is a leftover zombie from a
// crash/restart. Reset it to idle so the operator's click actually unsticks the
// UI. Returns true if it healed such a target.
func (s *Scheduler) reconcileOrphanedTarget(targetID string) bool {
	res, err := s.db.Exec(`
		UPDATE targets SET scan_status='idle', updated_at=CURRENT_TIMESTAMP
		WHERE id=? AND scan_status IN ('running','paused')
		  AND id NOT IN (SELECT target_id FROM tasks WHERE status IN ('running','paused','pending'))`, targetID)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	if n > 0 {
		s.hub.Broadcast("target_updated", map[string]string{"target_id": targetID, "scan_status": "idle"})
		return true
	}
	return false
}

// PauseTarget suspends the target's in-flight scan at the next module boundary.
// Modules already running finish; nothing new starts until ResumeTarget.
func (s *Scheduler) PauseTarget(targetID string) error {
	taskID := s.runningTaskForTarget(targetID)
	if taskID == "" {
		if s.reconcileOrphanedTarget(targetID) {
			return fmt.Errorf("scan was already stopped (stale state cleared)")
		}
		return fmt.Errorf("no running scan for this target")
	}
	s.pauseMu.Lock()
	s.paused[taskID] = true
	s.pauseMu.Unlock()
	_, _ = s.db.Exec(`UPDATE tasks SET status='paused', updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='running'`, taskID)
	_, _ = s.db.Exec(`UPDATE targets SET scan_status='paused', updated_at=CURRENT_TIMESTAMP WHERE id=?`, targetID)
	s.hub.Broadcast("task_paused", map[string]string{"task_id": taskID, "target_id": targetID})
	return nil
}

// SkipCurrentPhase aborts ONLY the module currently running for the target's scan
// and lets the scan continue to the next phase — the operator's escape hatch when
// a phase is stuck, too slow, or hitting a problem host. Unlike CancelTask it does
// not stop the whole scan; unlike PauseTarget it doesn't wait. Implemented by
// cancelling the per-phase child context the executor registers for this task.
func (s *Scheduler) SkipCurrentPhase(targetID string) error {
	taskID := s.runningTaskForTarget(targetID)
	if taskID == "" {
		if s.reconcileOrphanedTarget(targetID) {
			return fmt.Errorf("scan was already stopped (stale state cleared)")
		}
		return fmt.Errorf("no running scan for this target")
	}
	s.pauseMu.Lock()
	cancel := s.skipCancel[taskID]
	if cancel != nil {
		s.skipReq[taskID] = true
	}
	s.pauseMu.Unlock()
	if cancel == nil {
		return fmt.Errorf("no phase is currently running to skip")
	}
	cancel()
	s.hub.Broadcast("phase_skipped", map[string]string{"task_id": taskID, "target_id": targetID})
	return nil
}

// beginPhase registers a cancelable child context for the task's current phase so
// SkipCurrentPhase can abort just this phase. The returned finish() cancels the
// child, tears down the registration, and reports whether the phase ended because
// the operator SKIPPED it (as opposed to the whole task being cancelled).
func (s *Scheduler) beginPhase(parent context.Context, taskID string) (context.Context, func() bool) {
	modCtx, cancel := context.WithCancel(parent)
	s.pauseMu.Lock()
	s.skipCancel[taskID] = cancel
	s.skipReq[taskID] = false
	s.pauseMu.Unlock()
	finish := func() bool {
		cancel()
		s.pauseMu.Lock()
		skipped := s.skipReq[taskID]
		delete(s.skipCancel, taskID)
		delete(s.skipReq, taskID)
		s.pauseMu.Unlock()
		return skipped && parent.Err() == nil
	}
	return modCtx, finish
}

// ResumeTarget clears the pause gate so the scan continues from where it stopped.
func (s *Scheduler) ResumeTarget(targetID string) error {
	taskID := s.runningTaskForTarget(targetID)
	if taskID == "" {
		return fmt.Errorf("no paused scan for this target")
	}
	s.pauseMu.Lock()
	delete(s.paused, taskID)
	s.pauseMu.Unlock()
	_, _ = s.db.Exec(`UPDATE tasks SET status='running', updated_at=CURRENT_TIMESTAMP WHERE id=? AND status='paused'`, taskID)
	_, _ = s.db.Exec(`UPDATE targets SET scan_status='running', updated_at=CURRENT_TIMESTAMP WHERE id=?`, targetID)
	s.hub.Broadcast("task_resumed", map[string]string{"task_id": taskID, "target_id": targetID})
	return nil
}

func (s *Scheduler) isPaused(taskID string) bool {
	s.pauseMu.Lock()
	defer s.pauseMu.Unlock()
	return s.paused[taskID]
}

// waitIfPaused blocks (polling every second) while the task is paused, returning
// early if the scan context is cancelled. Called between modules in executeTask.
func (s *Scheduler) waitIfPaused(ctx context.Context, taskID string, logFn scanner.LogFunc) {
	logged := false
	for s.isPaused(taskID) {
		if ctx.Err() != nil {
			return
		}
		if !logged {
			logFn("info", "scheduler", "⏸ scan paused — waiting for resume…")
			logged = true
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Second):
		}
	}
	if logged {
		logFn("info", "scheduler", "▶ scan resumed")
	}
}

// expectedTools is the full external-tool roster Reconner can leverage. Each is
// optional (graceful fallback/skip), but logging presence makes coverage visible.
var expectedTools = []string{
	// subdomain / DNS
	"subfinder", "assetfinder", "findomain", "scilla", "asnmap",
	"puredns", "alterx", "shuffledns", "dnsx",
	// http / crawl / urls
	"httpx", "gau", "waybackurls", "waymore", "katana", "hakrawler", "uro",
	// scanning
	"nuclei", "dalfox", "dirsearch", "feroxbuster",
	// ports / intel / screenshots / takeover
	"naabu", "nmap", "gowitness", "subzy", "hydra",
	// active verification
	"sqlmap",
	// Ingram (IP-camera/DVR scanner) needs Python 3 on PATH — the run_ingram.py
	// script itself is a separate third-party install, not a PATH tool, so its
	// presence is checked directly by RunIngram (ingram_path in config.json).
	"python3",
}

// AuthzEngine exposes the authorization engine for researcher-triggered
// verification endpoints (e.g. state-snapshot WRITE verification).
func (s *Scheduler) AuthzEngine() *scanner.AuthzEngine { return s.authzEngine }

// ExpectedTools returns the full external-tool roster Reconner can leverage,
// so the API/UI can report real availability instead of a stale hardcoded list.
func (s *Scheduler) ExpectedTools() []string { return expectedTools }

// logToolAudit reports which expected tools are installed vs missing.
func (s *Scheduler) logToolAudit(logFn scanner.LogFunc) {
	var present, missing []string
	for _, t := range expectedTools {
		if s.executor.IsToolAvailable(t) {
			present = append(present, t)
		} else {
			missing = append(missing, t)
		}
	}
	logFn("info", "tools", fmt.Sprintf("Tools available (%d/%d): %s", len(present), len(expectedTools), strings.Join(present, ", ")))
	if len(missing) > 0 {
		logFn("warn", "tools", fmt.Sprintf("Tools MISSING (%d) — modules degrade/fallback: %s", len(missing), strings.Join(missing, ", ")))
	}
}

func (s *Scheduler) processQueue() {
	defer s.wg.Done()

	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case taskID := <-s.queue:
			s.tryStartTask(taskID)
		case <-ticker.C:
			s.drainPendingTasks()
		}
	}
}

func (s *Scheduler) drainPendingTasks() {
	rows, err := s.db.Query(`
		SELECT t.id FROM tasks t
		WHERE t.status = 'pending'
		ORDER BY t.priority DESC, t.created_at ASC
		LIMIT 10
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	var pending []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err == nil {
			pending = append(pending, id)
		}
	}
	rows.Close()

	// Visibility: if there are pending tasks but the admission ceiling is full,
	// say so (deduped) — otherwise a throttled scan looks silently "stuck".
	s.mu.RLock()
	running := len(s.running)
	s.mu.RUnlock()
	if len(pending) > 0 && running >= s.effectiveMaxConcurrent(running) {
		if s.throttleLog.CompareAndSwap(false, true) {
			s.logger.Warn("Scans queued — concurrency ceiling reached",
				"pending", len(pending), "running", running, "ceiling", s.effectiveMaxConcurrent(running))
		}
	}

	for _, id := range pending {
		s.tryStartTask(id)
	}
}

func (s *Scheduler) tryStartTask(taskID string) {
	s.mu.RLock()
	runningCount := len(s.running)
	s.mu.RUnlock()

	// Smart admission: the ceiling isn't a fixed number — it drops when the box is
	// under memory/CPU pressure (cooldown) and rises back toward the configured
	// max when things calm down. Because drainPendingTasks re-runs every 2s using
	// this same dynamic ceiling, throttled tasks auto-resume once load lightens.
	if runningCount >= s.effectiveMaxConcurrent(runningCount) {
		return
	}

	s.mu.Lock()
	if s.running[taskID] {
		s.mu.Unlock()
		return
	}
	s.running[taskID] = true
	ctx, cancel := context.WithCancel(context.Background())
	s.cancelMap[taskID] = cancel
	s.mu.Unlock()

	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		defer func() {
			s.mu.Lock()
			delete(s.running, taskID)
			delete(s.cancelMap, taskID)
			s.mu.Unlock()
		}()
		s.executeTask(ctx, taskID)
	}()
}

// baseScanWatchdog is the FLOOR of the per-scan watchdog — not the whole
// story, see effectiveWatchdog. A module that hangs while ignoring context
// cancellation would otherwise hold its concurrency slot forever, permanently
// lowering capacity until nothing new can start (a cause of scans stuck in
// 'pending'). The watchdog guarantees the slot is always freed — it exists to
// catch a WEDGED module, not to cut off a big-but-healthy scan early.
func baseScanWatchdog(cfg *config.Config) time.Duration {
	if cfg != nil && cfg.ScanWatchdogHours > 0 {
		return time.Duration(cfg.ScanWatchdogHours) * time.Hour
	}
	return 24 * time.Hour
}

// effectiveWatchdog adds adaptive headroom on top of the base floor for
// targets already KNOWN to be large (from a prior scan's subdomain count) —
// a bug-bounty domain with tens of thousands of subdomains genuinely needs
// more wall-clock time to crawl/probe/fuzz than a 5-host target, and a flat
// ceiling applied identically to both was exactly the reported bug. Capped at
// maxScanWatchdog so a wedged module still can't hold its slot indefinitely.
const maxScanWatchdog = 96 * time.Hour

func effectiveWatchdog(cfg *config.Config, knownSubdomains int) time.Duration {
	d := baseScanWatchdog(cfg)
	if knownSubdomains > 0 {
		// +3h per 1000 known subdomains — a coarse, deliberately conservative
		// proxy for "this target's surface is large", not a precise estimate.
		bonus := time.Duration(knownSubdomains/1000) * 3 * time.Hour
		d += bonus
	}
	if d > maxScanWatchdog {
		d = maxScanWatchdog
	}
	return d
}

func (s *Scheduler) executeTask(parentCtx context.Context, taskID string) {
	var targetID, modulesJSON, taskStatus, kind, taskType, scopeOverride string
	var target struct{ Domain string }
	var knownSubdomains int

	err := s.db.QueryRow(`
		SELECT t.target_id, t.modules, t.status, COALESCE(t.type,''), COALESCE(t.scope_override,''), tgt.domain, COALESCE(tgt.kind,'web'), COALESCE(tgt.subdomain_count,0)
		FROM tasks t JOIN targets tgt ON tgt.id = t.target_id
		WHERE t.id = ?
	`, taskID).Scan(&targetID, &modulesJSON, &taskStatus, &taskType, &scopeOverride, &target.Domain, &kind, &knownSubdomains)
	if err != nil {
		// No row → the target (and its tasks) was deleted; nothing to run.
		s.logger.Info("Skipping task: target/task no longer exists", "task_id", taskID)
		return
	}

	// Watchdog: bound every scan so a wedged module can never hold its slot
	// forever, but scale the bound to what's already known about the target's
	// size. On timeout ctx is cancelled → the scan ends and the slot is
	// released by tryStartTask's defer.
	watchdog := effectiveWatchdog(s.cfg, knownSubdomains)
	ctx, cancelWatchdog := context.WithTimeout(parentCtx, watchdog)
	defer cancelWatchdog()
	// The task may have been cancelled (e.g. target deletion) after it was
	// queued but before it started — don't run it.
	if taskStatus == "cancelled" {
		s.logger.Info("Skipping cancelled task", "task_id", taskID)
		return
	}

	// UNIFIED SCOPE: a target can carry web hosts AND network IP/CIDR ranges at
	// once. Split the stored scope so web modules run against the web host(s) and
	// the network scan runs against the IP/CIDR portion — the two halves are
	// threaded to the right modules below (only ModuleNetwork / NucleiOnly consume
	// the `domain` arg as a network scope; every other module reads the DB or uses
	// the web host).
	// Per-asset scans pin the scope to one asset's value (scope_override); the kind
	// is then re-derived from THAT scope, so scanning a single IP asset runs the
	// network pipeline and a domain asset runs the web pipeline, regardless of the
	// parent target's overall kind.
	effectiveScope := target.Domain
	if scopeOverride != "" {
		effectiveScope = scopeOverride
	}
	// Web application scanner: the scope is one or more web hosts. Seed every
	// explicitly-listed host as a subdomain so the web pipeline (http_probe →
	// crawl/js/params/dast/nuclei) runs against the EXACT target(s) WITHOUT
	// requiring subdomain enumeration (which runs only when explicitly selected).
	webHosts, _ := scanner.SplitScope(effectiveScope)
	webPrimary := effectiveScope
	if len(webHosts) > 0 {
		webPrimary = webHosts[0]
	}
	seeded := webHosts
	if len(seeded) == 0 && webPrimary != "" {
		seeded = []string{webPrimary}
	}
	// A scope token may be a bare host (example.com) OR a full ENDPOINT URL
	// (https://x.com/appointment?h=…). Seed the HOST into subdomains so http_probe
	// covers it, and — for endpoint URLs — register the exact URL + its query/path
	// parameters as insertion points so the whole pipeline (crawl/JS/DAST/XSS/SQLi)
	// operates on that endpoint from the first pass. Collect the endpoint URLs so
	// single-endpoint mode can confine the scan to them.
	var endpointSeeds []string
	for _, tok := range seeded {
		if tok = strings.TrimSpace(tok); tok == "" {
			continue
		}
		host, didSeed := scanner.SeedEndpointURL(ctx, s.db, targetID, tok)
		if host == "" {
			host = tok // not a URL — treat the token itself as the host
		}
		if didSeed {
			if n := scanner.NormalizeEndpointURL(tok); n != "" {
				endpointSeeds = append(endpointSeeds, n)
			}
		}
		_, _ = s.db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, source, last_seen)
			VALUES (?, ?, ?, 'seed', CURRENT_TIMESTAMP)
			ON CONFLICT(target_id, subdomain) DO NOTHING`, uuid.New().String(), targetID, host)
	}
		// Per-asset scan: confine every DB-reading module to the override host(s).
	if scopeOverride != "" {
		scopeHosts := webHosts
		if len(scopeHosts) == 0 && webPrimary != "" {
			scopeHosts = []string{webPrimary}
		}
		if len(scopeHosts) > 0 {
			ctx = scanner.WithHostScope(ctx, scopeHosts)
		}
	}
	sentModules := models.JSONToStringSlice(modulesJSON)
	var modules []string
	// Honor the per-scan speed tokens (slow/normal/fast); strip any legacy
	// network/ingram pseudo-modules a stale client might still send.
	speed := scanner.SpeedNormal
	subBrute := true       // slow permutation/brute phase of subdomain enum (default on)
	singleEndpoint := false // confine the whole scan to the seed URL(s) and paths under them
	for _, m := range sentModules {
		switch m {
		case "speed_slow":
			speed = scanner.SpeedSlow
		case "speed_fast":
			speed = scanner.SpeedFast
		case "no_subdomain_brute":
			subBrute = false
		case "single_endpoint":
			singleEndpoint = true
		default:
			if !strings.HasPrefix(m, "network") && m != "nuclei_only" && m != "bruteforce" &&
				m != "ingram" && m != "initial_access" && m != "full_ports" {
				modules = append(modules, m)
			}
		}
	}
	ctx = scanner.WithWebSpeed(ctx, speed)
	ctx = scanner.WithSubdomainBrute(ctx, subBrute)
	// Single-endpoint mode: confine the pipeline to the seeded endpoint URL(s) and
	// the paths under them. Also force the slow subdomain brute OFF (there is one
	// host) and drop subdomain enumeration from the module list — the point is to
	// scan ONE url, not map the domain.
	if singleEndpoint && len(endpointSeeds) > 0 {
		ctx = scanner.WithEndpointScope(ctx, endpointSeeds)
		ctx = scanner.WithSubdomainBrute(ctx, false)
		pruned := modules[:0]
		for _, m := range modules {
			if m == ModuleSubdomainEnum {
				continue
			}
			pruned = append(pruned, m)
		}
		modules = pruned
	}

	domainFor := func(module string) string { return webPrimary }
	startedAt := time.Now()

	// The status→'running' transition is the row the UI reads. Under SQLite write
	// contention it can hit SQLITE_BUSY; if we swallowed the error the task would
	// keep running in memory while the DB (and UI) still showed 'pending' forever.
	// Retry briefly so the transition is durable.
	for attempt := 0; attempt < 5; attempt++ {
		if _, err := s.db.Exec(`
			UPDATE tasks SET status = 'running', started_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
			WHERE id = ?`, taskID); err == nil {
			break
		}
		time.Sleep(time.Duration(attempt+1) * 200 * time.Millisecond)
	}

	_, _ = s.db.Exec(`
		UPDATE targets SET scan_status = 'running', updated_at = CURRENT_TIMESTAMP WHERE id = ?
	`, targetID)

	s.hub.Broadcast("task_started", map[string]string{"task_id": taskID, "target_id": targetID})
	if s.notifier != nil {
		s.notifier.NotifyScanStarted(target.Domain)
	}

	logFn := func(level, module, message string) {
		_, _ = s.db.Exec(`
			INSERT INTO task_logs (task_id, level, message, module)
			VALUES (?, ?, ?, ?)
		`, taskID, level, message, module)

		s.hub.Broadcast("task_log", map[string]any{
			"task_id": taskID,
			"level":   level,
			"module":  module,
			"message": message,
			"time":    time.Now().Format(time.RFC3339),
		})
	}

	// Tool availability audit: log exactly which external tools are present vs
	// missing at scan start, so it's obvious what's actually being used (and why
	// a module might be quietly degraded). Missing tools don't fail the scan —
	// every module has a built-in fallback or skips gracefully.
	s.logToolAudit(logFn)

	if singleEndpoint && len(endpointSeeds) > 0 {
		logFn("info", "scheduler", fmt.Sprintf("Single-endpoint mode: scan confined to %v and the paths under it (subdomain enumeration skipped).", endpointSeeds))
	} else if len(endpointSeeds) > 0 {
		logFn("info", "scheduler", fmt.Sprintf("Seeded %d endpoint URL(s) with their query + path parameters as insertion points: %v", len(endpointSeeds), endpointSeeds))
	}

	// Modules grouped by a parallel-GROUP id run concurrently within their group
	// (when Limits.ParallelModules is on). Groups respect data dependencies:
	//
	//   group 1 — depend only on http_services, independent of each other
	//   group 2 — active injection; all read the `parameters` table, which
	//             group-1's param_discovery + the sequential param_reflection
	//             have already populated by the time group 2 starts.
	//
	// Modules NOT in the map run sequentially in their listed position, so the
	// ordering barriers (param_discovery → param_reflection → injection → verify)
	// are preserved. Target-request pressure stays bounded by the shared
	// transport's MaxConnsPerHost cap even with many injection modules at once.
	parallelGroup := map[string]int{
		ModuleJSAnalysis:      1,
		ModuleParamDiscovery:  1,
		ModuleDirDiscovery:    1,
		ModuleBackupDiscovery: 1,
		ModuleDAST:            2,
		ModuleXSS:             2,
		ModuleVulnScan:        2,
		ModuleSQLi:            2,
		ModuleNoSQLi:          2,
		ModuleSSRF:            2,
		ModuleLFI:             2,
		ModuleSSTI:            2,
		ModuleCmdi:            2,
		ModuleXXE:             2,
		ModuleCachePoison:     2,
		ModuleRace:            2,
		ModuleIDOR:            2,
	}

	// completedModules tracks which modules finished WITHOUT error, persisted to
	// the task row as we go — this is what lets a failed/cancelled task (e.g. a
	// watchdog timeout on a big target) be RESUMED later covering only what's
	// left, instead of restarting the whole scan from module 0.
	var completedModules []string
	persistCompleted := func() {
		_, _ = s.db.Exec(`UPDATE tasks SET completed_modules = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?`,
			models.StringSliceToJSON(completedModules), taskID)
	}

	var taskErr error
	lastProgress := 0
	handled := make(map[int]bool)
	for i, module := range modules {
		if ctx.Err() != nil {
			break
		}
		if handled[i] {
			continue
		}
		// Pause gate: if the operator paused this scan, block here (between
		// modules) until they resume or cancel.
		s.waitIfPaused(ctx, taskID, logFn)
		if ctx.Err() != nil {
			break
		}

		lastProgress = i
		// ETA: seconds remaining for the whole scan and for this module, calibrated
		// to this target by the elapsed-vs-baseline ratio of the modules done so far.
		etaTotal, etaModule := scanETA(modules, i, time.Since(startedAt))
		_, _ = s.db.Exec(`
			UPDATE tasks SET current_module = ?, progress = ?, eta_seconds = ?, module_eta_seconds = ?, updated_at = CURRENT_TIMESTAMP WHERE id = ?
		`, module, i, etaTotal, etaModule, taskID)

		s.hub.Broadcast("task_progress", map[string]any{
			"task_id":            taskID,
			"progress":           i,
			"total":              len(modules),
			"current_module":     module,
			"eta_seconds":        etaTotal,
			"module_eta_seconds": etaModule,
		})

		s.checkMemoryPressure(taskID, logFn)

		// Register a per-phase cancelable context so the operator can SKIP just this
		// phase (SkipCurrentPhase) without cancelling the whole scan.
		modCtx, finishPhase := s.beginPhase(ctx, taskID)

		// Parallel fast-path: run all not-yet-handled modules in the SAME group
		// concurrently. Grouping by id keeps group 1 (recon) and group 2
		// (injection) from ever mixing, so dependencies hold.
		if gid := parallelGroup[module]; s.cfg.Limits.ParallelModules && gid > 0 {
			var group []string
			for j := i; j < len(modules); j++ {
				if parallelGroup[modules[j]] == gid && !handled[j] {
					group = append(group, modules[j])
					handled[j] = true
				}
			}
			if len(group) > 1 {
				logFn("info", "scheduler", fmt.Sprintf("Running %d modules in parallel: %v", len(group), group))
				var wg sync.WaitGroup
				var gmu sync.Mutex
				for _, gm := range group {
					wg.Add(1)
					go func(m string) {
						defer wg.Done()
						err := s.runModule(modCtx, m, targetID, domainFor(m), logFn)
						gmu.Lock()
						defer gmu.Unlock()
						if err != nil && ctx.Err() == nil && modCtx.Err() == nil {
							logFn("error", m, fmt.Sprintf("Module failed: %v", err))
							taskErr = err
							return
						}
						if err == nil {
							completedModules = append(completedModules, m)
						}
					}(gm)
				}
				wg.Wait()
				if finishPhase() {
					logFn("warn", "scheduler", fmt.Sprintf("Phase group %v SKIPPED by operator — continuing to next phase.", group))
				}
				persistCompleted()
				s.updateTargetStats(targetID)
				continue
			}
		}

		err := s.runModule(modCtx, module, targetID, domainFor(module), logFn)
		if finishPhase() {
			// Operator skipped this phase: mark it handled (so a resume doesn't
			// redo it) and move on WITHOUT recording a task error.
			logFn("warn", "scheduler", fmt.Sprintf("Phase %q SKIPPED by operator — continuing to next phase.", module))
			completedModules = append(completedModules, module)
			persistCompleted()
			s.updateTargetStats(targetID)
			continue
		}
		if err != nil {
			taskErr = err
			if ctx.Err() == nil {
				logFn("error", module, fmt.Sprintf("Module failed: %v", err))
			}
		} else {
			completedModules = append(completedModules, module)
			persistCompleted()
		}

		s.updateTargetStats(targetID)
	}

	s.pauseMu.Lock()
	delete(s.paused, taskID)
	s.pauseMu.Unlock()

	finalStatus := "finished"
	finalError := ""
	if ctx.Err() != nil {
		finalStatus = "cancelled"
		// Distinguish a watchdog timeout from a user cancel.
		if parentCtx.Err() == nil && ctx.Err() == context.DeadlineExceeded {
			finalStatus = "failed"
			finalError = fmt.Sprintf(
				"scan exceeded its %s watchdog and was stopped — results found before the cutoff are already saved (nothing was rolled back). "+
					"For a large target, raise scan_watchdog_hours in config.json (currently %s base) and re-run; the watchdog also auto-extends for targets with a large known subdomain count.",
				watchdog, baseScanWatchdog(s.cfg))
			logFn("error", "scheduler", finalError)
		}
	} else if taskErr != nil {
		finalStatus = "failed"
		finalError = taskErr.Error()
	}

	// Only a clean finish means "100% done" — on failure/cancel keep the real
	// last-reached module index (lastProgress) instead of stamping progress=total,
	// which used to make an 8h-watchdog timeout LOOK like a completed scan.
	finalProgress := lastProgress
	if finalStatus == "finished" {
		finalProgress = len(modules)
	}
	_, _ = s.db.Exec(`
		UPDATE tasks SET
			status = ?, error = ?, progress = ?, current_module = '',
			finished_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, finalStatus, finalError, finalProgress, taskID)

	_, _ = s.db.Exec(`
		UPDATE targets SET scan_status = 'idle', last_scan_at = CURRENT_TIMESTAMP, updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, targetID)

	s.hub.Broadcast("task_finished", map[string]string{
		"task_id":   taskID,
		"target_id": targetID,
		"status":    finalStatus,
	})

	logFn("info", "scheduler", fmt.Sprintf("Task %s completed with status: %s", taskID, finalStatus))

	if s.notifier != nil && finalStatus != "cancelled" {
		go s.notifyScanDone(targetID, target.Domain, finalStatus, startedAt)
	}

	// Periodic-watch escalation: when a scheduled watch pass finishes and it turned
	// up NEW attack surface (new subdomains) or drift (monitoring changes), notify
	// and enqueue the heavier value checks (backup discovery + nuclei) on the target
	// — exactly what a hunter wants the moment something new appears. Guarded to the
	// 'monitor_watch' type so a normal scan never triggers it, and the follow-up is
	// a distinct type so it can't recurse.
	if taskType == monitorWatchType && finalStatus == "finished" {
		s.escalateIfChanged(targetID, target.Domain, knownSubdomains, startedAt)
	}
}

// monitorWatchType / monitorEscalationType tag the two halves of the periodic
// watch: the light diff pass, and the heavier follow-up it triggers on change.
const (
	monitorWatchType      = "monitor_watch"
	monitorEscalationType = "monitor_escalation"
)

// escalateIfChanged checks whether a just-finished watch pass found anything new
// (new subdomains vs the pre-scan baseline, or monitoring_changes rows recorded
// during the pass) and, if so, notifies and enqueues backup-discovery + nuclei
// over the (possibly grown) surface. Silent and cheap when nothing changed.
func (s *Scheduler) escalateIfChanged(targetID, domain string, baselineSubs int, since time.Time) {
	var nowSubs, changes int
	_ = s.db.QueryRow(`SELECT COALESCE(subdomain_count,0) FROM targets WHERE id=?`, targetID).Scan(&nowSubs)
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM monitoring_changes WHERE target_id=? AND detected_at >= ?`,
		targetID, since.UTC().Format("2006-01-02 15:04:05")).Scan(&changes)

	newSubs := nowSubs - baselineSubs
	if newSubs < 0 {
		newSubs = 0
	}
	if newSubs == 0 && changes == 0 {
		return // nothing new — stay quiet, don't burn a heavy scan
	}

	s.logger.Info("Watch pass found changes — escalating", "target", domain,
		"new_subdomains", newSubs, "changes", changes)
	if s.notifier != nil {
		summary := fmt.Sprintf("%d new subdomain(s), %d change(s) — running backup discovery + nuclei", newSubs, changes)
		s.notifier.NotifyMonitorChange(domain, "new-asset", summary, "", "")
	}

	// Re-probe first so any brand-new hosts are fingerprinted, then run the value
	// checks the user asked to always run on change.
	esc := []string{ModuleHTTPProbe, ModuleBackupDiscovery, ModuleDirDiscovery, ModuleNuclei}
	if _, err := s.CreateTaskTyped(targetID, esc, 2, monitorEscalationType); err != nil {
		s.logger.Error("Failed to enqueue watch escalation", "target", domain, "error", err)
	}
}

// runModule dispatches a single module by name. Shared by the sequential and
// parallel execution paths. A panic inside any module (nil deref, slice bounds
// on a malformed response, a bad regex on hostile input) is recovered here so
// it fails ONLY that module — the scan and the server keep running instead of
// the whole process crashing and taking every concurrent scan down with it.
func (s *Scheduler) runModule(ctx context.Context, module, targetID, domain string, logFn scanner.LogFunc) (err error) {
	defer func() {
		if r := recover(); r != nil {
			err = fmt.Errorf("module %q panicked: %v", module, r)
			s.logger.Error("Recovered from module panic", "module", module, "target", targetID, "panic", r)
			logFn("error", module, fmt.Sprintf("module crashed and was isolated: %v", r))
		}
	}()
	switch module {
	case ModuleSubdomainEnum:
		return s.subdomainScanner.Run(ctx, targetID, domain, logFn)
	case ModuleHTTPProbe:
		return s.httpScanner.Run(ctx, targetID, logFn)
	case ModuleJSAnalysis:
		return s.jsScanner.Run(ctx, targetID, logFn)
	case ModuleJSEndpoints:
		return s.jsEndpointScanner.Run(ctx, targetID, logFn)
	case ModuleParamDiscovery:
		return s.paramScanner.Run(ctx, targetID, domain, logFn)
	case ModuleHeadlessCrawl:
		return s.headlessCrawler.Run(ctx, targetID, logFn)
	case ModuleTimeMachine:
		return s.timeMachineScanner.Run(ctx, targetID, domain, logFn)
	case ModuleParamReflection:
		return s.paramScanner.CheckReflection(ctx, targetID, logFn)
	case ModuleParamFuzz:
		return s.paramFuzzScanner.Run(ctx, targetID, logFn)
	case ModuleDirDiscovery:
		return s.dirScanner.Run(ctx, targetID, logFn)
	case ModuleBackupDiscovery:
		return s.dirScanner.RunBackupDiscovery(ctx, targetID, logFn)
	case ModuleOpenRedirect:
		return s.dirScanner.RunOpenRedirectDiscovery(ctx, targetID, logFn)
	case ModuleNuclei:
		return s.nucleiScanner.Run(ctx, targetID, nil, nil, logFn)
	case ModuleDAST:
		return s.dastScanner.Run(ctx, targetID, logFn)
	case ModuleXSS:
		return s.dastScanner.RunXSS(ctx, targetID, logFn)
	case ModuleVulnScan:
		return s.vulnScanner.Run(ctx, targetID, domain, logFn)
	case ModuleDOMXSS:
		// dom_xss (headless Chromium) is retired — too heavy on the server. Any
		// stale task still listing it skips cleanly instead of launching a browser.
		logFn("info", "dom_xss", "dom_xss module is disabled — skipped.")
		return nil
	case ModuleSQLi:
		return s.sqliScanner.Run(ctx, targetID, logFn)
	case ModuleSSRF:
		return s.ssrfScanner.Run(ctx, targetID, logFn)
	case ModuleLFI:
		return s.lfiScanner.Run(ctx, targetID, logFn)
	case ModuleSSTI:
		return s.sstiScanner.Run(ctx, targetID, logFn)
	case ModuleCmdi:
		return s.cmdiScanner.Run(ctx, targetID, logFn)
	case ModulePassive:
		return s.passiveScanner.Run(ctx, targetID, logFn)
	case ModuleTakeover:
		return s.takeoverScanner.Run(ctx, targetID, logFn)
	case ModuleBLH:
		return s.blhScanner.Run(ctx, targetID, logFn)
	case ModuleCSRF:
		return s.csrfScanner.Run(ctx, targetID, logFn)
	case ModuleCORS:
		return s.corsScanner.Run(ctx, targetID, logFn)
	case ModuleExposure:
		return s.exposureScanner.Run(ctx, targetID, logFn)
	case ModuleIntel:
		return s.intelScanner.Run(ctx, targetID, logFn)
	case ModuleOAST:
		return s.oastScanner.Run(ctx, targetID, logFn)
	case ModuleXXE:
		return s.xxeScanner.Run(ctx, targetID, logFn)
	case ModuleIDOR:
		return s.idorScanner.Run(ctx, targetID, logFn)
	case ModuleJWT:
		return s.jwtScanner.Run(ctx, targetID, logFn)
	case ModuleATO:
		return s.atoEngine.Run(ctx, targetID, logFn)
	case ModuleAuthz:
		return s.authzEngine.Run(ctx, targetID, domain, logFn)
	case ModuleNoSQLi:
		return s.nosqliScanner.Run(ctx, targetID, logFn)
	case ModuleCachePoison:
		return s.cachePoisonScanner.Run(ctx, targetID, logFn)
	case ModuleOriginIP:
		return s.originIPScanner.Run(ctx, targetID, logFn)
	case ModulePortScan:
		logFn("info", "portscan", "portscan module is disabled — skipped.")
		return nil
	case ModuleShodan:
		return s.shodanScanner.Run(ctx, targetID, logFn)
	case ModuleRace:
		return s.raceScanner.Run(ctx, targetID, logFn)
	case ModuleSmuggling:
		return s.smugglingScanner.Run(ctx, targetID, logFn)
	case ModuleVerify:
		return s.verifyScanner.Run(ctx, targetID, logFn)
	case ModuleMonitor:
		return s.monitorScanner.Run(ctx, targetID, logFn)
	}
	return nil
}

func (s *Scheduler) updateTargetStats(targetID string) {
	var subdomainCount, aliveCount, findingCount int

	s.db.QueryRow("SELECT COUNT(*) FROM subdomains WHERE target_id = ?", targetID).Scan(&subdomainCount)
	s.db.QueryRow("SELECT COUNT(*) FROM subdomains WHERE target_id = ? AND is_alive = 1", targetID).Scan(&aliveCount)
	// Nuclei is counted by DISTINCT template_id (not raw rows): one template that
	// fires on hundreds of near-identical URLs is ONE logical finding, so the
	// headline count reflects real issues instead of duplicated noise (matches the
	// collapsed nuclei list view).
	s.db.QueryRow(`
		SELECT
			(SELECT COUNT(DISTINCT template_id) FROM nuclei_findings WHERE target_id = ? AND COALESCE(verification,'unverified') != 'rejected') +
			(SELECT COUNT(*) FROM backup_findings WHERE target_id = ?) +
			(SELECT COUNT(*) FROM open_redirect_findings WHERE target_id = ? AND COALESCE(status,'finding')='finding') +
			(SELECT COUNT(*) FROM vuln_findings WHERE target_id = ? AND COALESCE(status,'finding')='finding')
	`, targetID, targetID, targetID, targetID).Scan(&findingCount)

	_, _ = s.db.Exec(`
		UPDATE targets SET 
			subdomain_count = ?,
			alive_host_count = ?,
			finding_count = ?,
			updated_at = CURRENT_TIMESTAMP
		WHERE id = ?
	`, subdomainCount, aliveCount, findingCount, targetID)
}

// effectiveMaxConcurrent is the load-aware admission ceiling. It starts from the
// configured MaxConcurrentTargets and shrinks under pressure so a heavy box
// doesn't thrash: high memory OR a CPU run-queue above the core count throttles
// new starts (a "cooldown"), and once load drops the ceiling climbs back toward
// the configured max on the next drain tick. Never returns below 1 (so a single
// task can always make progress), and never above the configured max.
func (s *Scheduler) effectiveMaxConcurrent(running int) int {
	base := s.cfg.Limits.MaxConcurrentTargets
	if base < 1 {
		base = 1
	}

	// Memory pressure (only when a limit is configured).
	memPressure := 0 // 0 none, 1 moderate, 2 severe
	if vm, err := mem.VirtualMemory(); err == nil {
		switch {
		case vm.UsedPercent >= 92:
			memPressure = 2
		case vm.UsedPercent >= 82:
			memPressure = 1
		}
	}

	// CPU run-queue pressure: 1-min load average relative to core count.
	cpuPressure := 0
	cores := float64(runtime.NumCPU())
	if cores < 1 {
		cores = 1
	}
	if avg, err := load.Avg(); err == nil {
		ratio := avg.Load1 / cores
		switch {
		case ratio >= 1.6:
			cpuPressure = 2
		case ratio >= 1.0:
			cpuPressure = 1
		}
	}

	pressure := memPressure
	if cpuPressure > pressure {
		pressure = cpuPressure
	}

	eff := base
	switch pressure {
	case 2: // severe — cool down hard, let in-flight work drain
		eff = base / 3
	case 1: // moderate — hold roughly half
		eff = base / 2
	}
	if eff < 1 {
		eff = 1
	}
	if eff > base {
		eff = base
	}
	// Under severe pressure, don't admit anything beyond what's already running —
	// but never below 1, so a lone task can still start on an idle-but-tight box.
	if pressure == 2 && running >= eff && eff < base {
		if s.throttleLog.CompareAndSwap(false, true) {
			s.logger.Warn("Scheduler cooldown: server under load, throttling new scans",
				"effective_max", eff, "configured_max", base, "running", running)
		}
	} else {
		s.throttleLog.Store(false)
	}
	return eff
}

func (s *Scheduler) checkMemoryPressure(taskID string, logFn scanner.LogFunc) {
	if s.cfg.Limits.MaxMemoryMB <= 0 {
		return // 0 = unlimited: never throttle / GC-spam
	}
	vm, err := mem.VirtualMemory()
	if err != nil {
		return
	}

	usedMB := int(vm.Used / 1024 / 1024)
	if usedMB > s.cfg.Limits.MaxMemoryMB {
		logFn("warn", "scheduler", fmt.Sprintf("High memory usage: %d MB / %d MB limit. Running GC...", usedMB, s.cfg.Limits.MaxMemoryMB))
		runtime.GC()
	}
}

func (s *Scheduler) monitorMemory() {
	defer s.wg.Done()

	if s.cfg.Limits.MaxMemoryMB <= 0 {
		return // 0 = unlimited: don't run the memory watchdog at all
	}
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			vm, err := mem.VirtualMemory()
			if err != nil {
				continue
			}
			usedMB := int(vm.Used / 1024 / 1024)
			if usedMB > s.cfg.Limits.MaxMemoryMB {
				runtime.GC()
				s.logger.Warn("Memory pressure detected", "used_mb", usedMB, "limit_mb", s.cfg.Limits.MaxMemoryMB)
			}
		}
	}
}

func (s *Scheduler) notifyScanDone(targetID, domain, status string, startedAt time.Time) {
	duration := time.Since(startedAt)
	var subdomains, alive, vulns, nuclei, backups int
	s.db.QueryRow("SELECT COUNT(*) FROM subdomains WHERE target_id=?", targetID).Scan(&subdomains)
	s.db.QueryRow("SELECT COUNT(*) FROM subdomains WHERE target_id=? AND is_alive=1", targetID).Scan(&alive)
	s.db.QueryRow("SELECT COUNT(*) FROM vuln_findings WHERE target_id=?", targetID).Scan(&vulns)
	s.db.QueryRow("SELECT COUNT(*) FROM nuclei_findings WHERE target_id=? AND COALESCE(verification,'unverified') != 'rejected'", targetID).Scan(&nuclei)
	s.db.QueryRow("SELECT COUNT(*) FROM backup_findings WHERE target_id=?", targetID).Scan(&backups)
	stats := map[string]int{
		"subdomains": subdomains,
		"alive":      alive,
		"vulns":      vulns,
		"nuclei":     nuclei,
		"backups":    backups,
	}
	s.notifier.NotifyScanFinished(domain, status, duration, stats)
}

func (s *Scheduler) monitoringScheduler() {
	defer s.wg.Done()

	ticker := time.NewTicker(30 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-s.stopCh:
			return
		case <-ticker.C:
			s.runDueMonitors()
		}
	}
}

func (s *Scheduler) runDueMonitors() {
	rows, err := s.db.Query(`
		SELECT id, domain FROM targets
		WHERE monitor_enabled = 1
		AND (
			monitor_last_run IS NULL
			OR datetime(monitor_last_run, '+' || monitor_interval_hours || ' hours') <= datetime('now')
		)
	`)
	if err != nil {
		return
	}
	defer rows.Close()

	for rows.Next() {
		var id, domain string
		if err := rows.Scan(&id, &domain); err != nil {
			continue
		}
		s.logger.Info("Starting scheduled watch pass", "target", domain)
		// Diff-first light pipeline: re-enumerate (passive), re-probe, re-check
		// takeovers so newly-appeared assets/dangling CNAMEs are caught, run
		// backup/config-file discovery, then the change detector. nuclei + heavy
		// dir discovery stay OFF this cheap cycle — they run only via
		// escalateIfChanged when this pass actually turns something up.
		monitorModules := []string{
			ModuleSubdomainEnum,
			ModuleHTTPProbe,
			ModuleTakeover,
			// CORS is cheap (a few header probes per endpoint) and its config
			// flips on redeploys, so it's worth re-checking on every watch cycle.
			ModuleCORS,
			// Backup/config-file discovery every cycle — a freshly-leaked .env or
			// db.sql.bak is exactly the kind of thing a periodic watch should catch.
			ModuleBackupDiscovery,
			ModuleMonitor,
		}
		if _, err := s.CreateTaskTyped(id, monitorModules, 3, monitorWatchType); err != nil {
			s.logger.Error("Failed to create watch task", "target", domain, "error", err)
			continue
		}
		_, _ = s.db.Exec(`UPDATE targets SET monitor_last_run = CURRENT_TIMESTAMP WHERE id = ?`, id)
	}
}

func (s *Scheduler) GetRunningTasks() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()

	ids := make([]string, 0, len(s.running))
	for id := range s.running {
		ids = append(ids, id)
	}
	return ids
}

func (s *Scheduler) IsRunning(taskID string) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running[taskID]
}
