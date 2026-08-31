package scanner

// ─────────────────────────────────────────────────────────────────────────────
// LEVEL C — REAL RECON end-to-end.
//
// LEVEL B (benchmark_e2e_test.go) seeds the `parameters` table, then runs a
// detector. That proves the DETECT→CONFIRM→FINDING half but assumes recon
// already happened. LEVEL C removes that assumption: NOTHING is seeded into
// `parameters` or `http_services`. The scanner must DISCOVER the attack surface
// itself through the production reconnaissance capabilities — the pure-Go,
// tool-free paths that run when httpx/katana/gau are absent:
//
//   subdomains (seed = what subdomain_enum would find)
//     → http_probe.Run   (basicHTTPProbe, pure Go)         → http_services
//     → param_discovery.Run (robots.txt/sitemap harvest)   → parameters
//     → <detector>.Run   (real request build + confirm)     → vuln_findings
//
// So this exercises the WHOLE objective pipeline through production code with no
// external binaries: RECON → DISCOVERY → INPUT MINING → DETECTION → CONFIRMATION
// → EVIDENCE → FINDING. It is the honest answer to "can a single-objective scan
// actually travel the real pipeline", not just "does the planner expand".
// ─────────────────────────────────────────────────────────────────────────────

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// realReconFixture builds a lab whose attack surface is only reachable by DOING
// recon: the vulnerable endpoint is advertised solely through /sitemap.xml (and
// /robots.txt), never seeded into the DB. handler serves the vulnerable route.
func realReconFixture(t *testing.T, route string, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	mux := http.NewServeMux()
	var srv *httptest.Server
	mux.HandleFunc("/robots.txt", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		// Advertise the sitemap; a link crawler is not needed.
		_, _ = w.Write([]byte("User-agent: *\nDisallow: /admin\nSitemap: " + srv.URL + "/sitemap.xml\n"))
	})
	mux.HandleFunc("/sitemap.xml", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>` + srv.URL + route + `</loc></url>
</urlset>`))
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><title>lab</title>home</html>"))
	})
	// The vulnerable route (path only; query carries the param).
	path := route
	if i := strings.IndexByte(route, '?'); i >= 0 {
		path = route[:i]
	}
	mux.HandleFunc(path, handler)
	srv = httptest.NewServer(mux)
	host := strings.TrimPrefix(srv.URL, "http://")
	return srv, host
}

func realReconDB(t *testing.T, host string) (*database.DB, string) {
	t.Helper()
	db, err := database.New(t.TempDir() + "/rr.db")
	if err != nil {
		t.Fatal(err)
	}
	if err := database.RunMigrations(db); err != nil {
		t.Fatal(err)
	}
	tid := uuid.New().String()
	_, _ = db.Exec(`INSERT INTO targets (id, domain, priority) VALUES (?,?, 'medium')`, tid, host)
	// Seed the subdomain exactly as subdomain_enum would; recon takes it from here.
	_, _ = db.Exec(`INSERT INTO subdomains (id, target_id, subdomain, source, last_seen) VALUES (?,?,?, 'seed', CURRENT_TIMESTAMP)`,
		uuid.New().String(), tid, host)
	return db, tid
}

func count(db *database.DB, q string, args ...any) int {
	var n int
	_ = db.QueryRow(q, args...).Scan(&n)
	return n
}

// realReconCase is one single-objective pipeline test: the vulnerable route is
// advertised only via sitemap, and after real recon the named detector must
// produce its finding.
type realReconCase struct {
	name       string
	route      string // e.g. "/search?id=1"
	param      string // the parameter recon must mine from the sitemap
	handler    http.HandlerFunc
	runDet     func(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, tid string) // stage-3 detector
	findingSQL string                                                                                          // COUNT(*) query proving the finding (one ? = target_id)
	findType   string                                                                                          // vuln_findings.type for isolation (empty = separate table)
}

// TestRealReconPipeline drives the COMPLETE tool-free pipeline (http_probe →
// param_discovery → detector) for each single-vulnerability objective. Nothing is
// seeded into http_services/parameters — the attack surface is discovered from a
// sitemap through production recon code, then the detector runs against it.
func TestRealReconPipeline(t *testing.T) {
	withLoopbackAllowed(t)
	cfg := &config.Config{}
	cfg.EnableDAST = true // production default; gates the DAST/XSS objective
	log := logger.New("error")
	exec := tools.NewToolFreeExecutor(cfg, log)
	nolog := func(_, _, _ string) {}
	ctx := context.Background()

	mysqlErr := func(param string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "text/html")
			if strings.ContainsAny(r.URL.Query().Get(param), "'\"`") {
				_, _ = w.Write([]byte("<html>You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version near '''</html>"))
				return
			}
			_, _ = w.Write([]byte("<html>results</html>"))
		}
	}

	cases := []realReconCase{
		{
			name: "sqli", route: "/search?id=1", param: "id", handler: mysqlErr("id"),
			runDet: func(db *database.DB, e *tools.Executor, c *config.Config, l *logger.Logger, tid string) {
				_ = NewSQLiScanner(db, e, c, l, nil).Run(ctx, tid, nolog)
			},
			findingSQL: `SELECT COUNT(*) FROM vuln_findings WHERE type='sqli' AND target_id=?`, findType: "sqli",
		},
		{
			name: "lfi", route: "/view?file=readme", param: "file",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/plain")
				if strings.Contains(r.URL.Query().Get("file"), "etc/passwd") {
					_, _ = w.Write([]byte("root:x:0:0:root:/root:/bin/bash\n"))
					return
				}
				_, _ = w.Write([]byte("document"))
			},
			runDet: func(db *database.DB, e *tools.Executor, c *config.Config, l *logger.Logger, tid string) {
				_ = NewLFIScanner(db, e, c, l, nil).Run(ctx, tid, nolog)
			},
			findingSQL: `SELECT COUNT(*) FROM vuln_findings WHERE type='lfi' AND target_id=?`, findType: "lfi",
		},
		{
			name: "ssti", route: "/page?q=x", param: "q",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<h1>" + sstiEval.Replace(r.URL.Query().Get("q")) + "</h1>"))
			},
			runDet: func(db *database.DB, e *tools.Executor, c *config.Config, l *logger.Logger, tid string) {
				_ = NewSSTIScanner(db, e, c, l, nil).Run(ctx, tid, nolog)
			},
			findingSQL: `SELECT COUNT(*) FROM vuln_findings WHERE type='ssti' AND target_id=?`, findType: "ssti",
		},
		{
			name: "xss", route: "/echo?q=x", param: "q",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "text/html")
				_, _ = w.Write([]byte("<div>" + r.URL.Query().Get("q") + "</div>"))
			},
			runDet: func(db *database.DB, e *tools.Executor, c *config.Config, l *logger.Logger, tid string) {
				_ = NewDASTScanner(db, c, l, nil).Run(ctx, tid, nolog)
			},
			findingSQL: `SELECT COUNT(*) FROM vuln_findings WHERE type='xss' AND target_id=?`, findType: "xss",
		},
		{
			name: "nosqli", route: "/login?user=1", param: "user",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if strings.ContainsAny(r.URL.Query().Get("user"), "{$;\"'`") {
					w.WriteHeader(http.StatusInternalServerError)
					_, _ = w.Write([]byte(`{"error":"MongoError: unterminated object"}`))
					return
				}
				_, _ = w.Write([]byte(`{"user":"alice"}`))
			},
			runDet: func(db *database.DB, e *tools.Executor, c *config.Config, l *logger.Logger, tid string) {
				_ = NewNoSQLiScanner(db, e, c, l, nil).Run(ctx, tid, nolog)
			},
			findingSQL: `SELECT COUNT(*) FROM vuln_findings WHERE type='nosql_injection' AND target_id=?`, findType: "nosql_injection",
		},
		{
			name: "open_redirect", route: "/go?next=/home", param: "next",
			handler: func(w http.ResponseWriter, r *http.Request) {
				if v := r.URL.Query().Get("next"); v != "" {
					w.Header().Set("Location", v)
					w.WriteHeader(http.StatusFound)
					return
				}
				w.WriteHeader(http.StatusOK)
			},
			runDet: func(db *database.DB, e *tools.Executor, c *config.Config, l *logger.Logger, tid string) {
				_ = NewDirScanner(db, e, c, l).RunOpenRedirectDiscovery(ctx, tid, nolog)
			},
			findingSQL: `SELECT COUNT(*) FROM open_redirect_findings WHERE verified=1 AND target_id=?`, findType: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, host := realReconFixture(t, tc.route, tc.handler)
			defer srv.Close()
			db, tid := realReconDB(t, host)
			defer db.Close()

			// STAGE 1 — HTTP probing (pure-Go basicHTTPProbe; httpx absent in CI).
			if err := NewHTTPScanner(db, exec, cfg, log).Run(ctx, tid, nolog); err != nil {
				t.Fatalf("http_probe: %v", err)
			}
			if count(db, `SELECT COUNT(*) FROM http_services WHERE target_id=?`, tid) == 0 {
				t.Fatalf("RECON GAP: http_probe discovered no live service for %s", host)
			}

			// STAGE 2 — parameter discovery (tool-free robots/sitemap harvest). The
			// scope arg is the bare hostname (as a production target domain is).
			hostname := host
			if i := strings.IndexByte(host, ':'); i >= 0 {
				hostname = host[:i]
			}
			if err := NewParamScanner(db, exec, cfg, log, nil).Run(ctx, tid, hostname, nolog); err != nil {
				t.Fatalf("param_discovery: %v", err)
			}
			if count(db, `SELECT COUNT(*) FROM parameters WHERE target_id=? AND parameter=?`, tid, tc.param) == 0 {
				t.Fatalf("INPUT-MINING GAP: recon did not discover %q from the sitemap", tc.param)
			}

			// STAGE 3 — detection over the DISCOVERED surface.
			tc.runDet(db, exec, cfg, log, tid)
			if count(db, tc.findingSQL, tid) == 0 {
				t.Fatalf("DETECTION GAP: %s not found end-to-end through real recon", tc.name)
			}

			// NEGATIVE ISOLATION from stored findings.
			if tc.findType != "" {
				rows, _ := db.Query(`SELECT DISTINCT type FROM vuln_findings WHERE target_id=?`, tid)
				defer rows.Close()
				for rows.Next() {
					var typ string
					_ = rows.Scan(&typ)
					if typ != tc.findType {
						t.Errorf("ISOLATION VIOLATION: %s-only real-recon scan also produced %q", tc.name, typ)
					}
				}
			}
			t.Logf("real-recon %-14s http_services=%d parameters=%d → finding ✓", tc.name,
				count(db, `SELECT COUNT(*) FROM http_services WHERE target_id=?`, tid),
				count(db, `SELECT COUNT(*) FROM parameters WHERE target_id=?`, tid))
		})
	}
}

// TestRealReconPipelineCORS proves the http_services-only capability closure:
// a CORS-only objective needs http_probe but NOT parameter discovery. After real
// probing, the CORS detector finds the reflected-origin+credentials misconfig on
// the discovered service — no parameters seeded or mined.
func TestRealReconPipelineCORS(t *testing.T) {
	withLoopbackAllowed(t)
	cfg := &config.Config{}
	log := logger.New("error")
	exec := tools.NewToolFreeExecutor(cfg, log)
	nolog := func(_, _, _ string) {}
	ctx := context.Background()

	// Root reflects any Origin with credentials → a critical CORS misconfig.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if o := r.Header.Get("Origin"); o != "" {
			w.Header().Set("Access-Control-Allow-Origin", o)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
		}
		w.Header().Set("Content-Type", "text/html")
		_, _ = w.Write([]byte("<html><title>api</title>ok</html>"))
	}))
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "http://")

	db, tid := realReconDB(t, host)
	defer db.Close()

	// STAGE 1 — HTTP probing populates http_services (the only input CORS needs).
	if err := NewHTTPScanner(db, exec, cfg, log).Run(ctx, tid, nolog); err != nil {
		t.Fatalf("http_probe: %v", err)
	}
	if count(db, `SELECT COUNT(*) FROM http_services WHERE target_id=?`, tid) == 0 {
		t.Fatalf("RECON GAP: no http_service discovered")
	}

	// STAGE 2 — CORS detection over the discovered service (no param discovery).
	if err := NewCORSScanner(db, exec, cfg, log, nil).Run(ctx, tid, nolog); err != nil {
		t.Fatalf("cors: %v", err)
	}
	if count(db, `SELECT COUNT(*) FROM vuln_findings WHERE type='cors_misconfig' AND target_id=?`, tid) == 0 {
		t.Fatalf("DETECTION GAP: CORS misconfig not found end-to-end through real recon")
	}
	// Isolation: nothing but the CORS finding.
	rows, _ := db.Query(`SELECT DISTINCT type FROM vuln_findings WHERE target_id=?`, tid)
	defer rows.Close()
	for rows.Next() {
		var typ string
		_ = rows.Scan(&typ)
		if typ != "cors_misconfig" {
			t.Errorf("ISOLATION VIOLATION: CORS-only scan also produced %q", typ)
		}
	}
	t.Logf("real-recon cors: http_services=%d → cors_misconfig finding ✓ (no param discovery needed)",
		count(db, `SELECT COUNT(*) FROM http_services WHERE target_id=?`, tid))
}
