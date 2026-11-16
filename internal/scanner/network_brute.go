package scanner

import (
	"bufio"
	"context"
	"database/sql"
	_ "embed"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	_ "github.com/go-sql-driver/mysql"
	"github.com/lib/pq"
	"golang.org/x/crypto/ssh"
)

// network_brute.go — OPT-IN, per-service network weak-credential audit
// (modules network_brute_ssh / network_brute_ftp / network_brute_mysql /
// network_brute_postgres / network_brute_redis). This is the network-pipeline
// counterpart to wordpress_credaudit.go, held to the exact same discipline:
//
//   - It never submits a credential unless the operator has explicitly
//     authorized active testing — the server-wide switch
//     cfg.EnableNetworkCredentialAudit, OR the per-scan "net_cred_authorized"
//     token the Network Scanner's brute-force ticks send after the operator
//     confirms. Without either, these modules do nothing active.
//   - It only ever targets services THIS scan's own network_detect/fingerprint
//     pass already verified open and identified (never guesses a port).
//   - It is conservative: a tiny curated username list per protocol + the
//     top-1000 password corpus (never a username wordlist), serial with a
//     delay, a hard attempt cap, a wall-clock budget, and stops on the first
//     hit per target.
//   - A hit is confirmed ONLY by a definitive, protocol-level auth-success
//     signal (not a banner, not a guess): a completed SSH password handshake,
//     an FTP 230 reply, a successful MySQL/PostgreSQL connection (or a
//     post-auth "database does not exist" reply — auth itself already
//     succeeded), or Redis replying +OK to AUTH. Zero false positives.
//
// RDP/VNC/Telnet/SMB are NOT implemented here: there is no safe, dependency-
// light way to prove a credential against them natively (RDP/SMB need a full
// NTLM/CredSSP handshake, VNC a still-binary RFB challenge-response), and a
// hand-rolled implementation of any of those is a real correctness risk for a
// security-sensitive auth check. They are instead covered by the tool-backed
// half of this same module in network_brute_tools.go, which shells out to
// ncrack (rdp/vnc/telnet) and hydra (smb) — two purpose-built, widely audited
// network-login crackers — under the exact same authorization/scoping/rate-
// limiting discipline as every check in this file. (This project has
// previously retired other third-party tools found unreliable or unused —
// see the "retired/unused tool" guard in tool_install_test.go — ncrack and
// hydra are a deliberate, scoped exception for these four protocols
// specifically, not a reversal of that general caution.)

//go:embed netassets/net_passwords.txt
var netPasswordListRaw string

// netTop1000Passwords is the embedded default credential-audit list for the
// network pipeline: generic high-signal defaults, device/service defaults, and
// common mutations — deliberately NOT WordPress-branded. Operators override/
// extend it via the net_passwords corpus file.
var netTop1000Passwords = func() []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(netPasswordListRaw))
	for sc.Scan() {
		if p := strings.TrimSpace(sc.Text()); p != "" {
			out = append(out, p)
		}
	}
	return out
}()

// Small, curated per-protocol username lists — the realistic defaults an
// operator or appliance actually ships, never a generic wordlist.
var (
	netUsersSSH      = []string{"root", "admin", "ubuntu", "ec2-user", "centos", "debian", "azureuser", "pi", "oracle", "test", "user", "deploy", "git", "vagrant"}
	netUsersFTP      = []string{"anonymous", "ftp", "admin", "root", "test", "ftpuser"}
	netUsersMySQL    = []string{"root", "admin", "mysql"}
	netUsersPostgres = []string{"postgres", "admin", "root"}
)

const (
	netCredMaxTargets  = 5                      // bounded ip:port pairs probed per protocol per scan
	netCredMaxAttempts = 6000                   // overall per-protocol guess cap (safety ceiling)
	netCredDelay       = 300 * time.Millisecond // slower than the WP pace: SSH/FTP lockout plugins are common
	netCredBudget      = 15 * time.Minute       // per-protocol wall-clock budget
	netDialTimeout     = 6 * time.Second
)

// networkAuthorized is the single source of truth for whether active network
// credential testing is authorized for this scan — the server-wide switch OR
// the per-scan "net_cred_authorized" token, fail-closed like the WP equivalent.
func (s *NetworkScanner) networkAuthorized(ctx context.Context) bool {
	return (s.cfg != nil && s.cfg.EnableNetworkCredentialAudit) || netCredAuthorizedFromContext(ctx)
}

// netCredResult is what a protocol-specific checker reports for one attempt.
type netCredResult struct {
	Success  bool
	Evidence string // extra detail for the finding evidence line (may be empty)
}

// netCredChecker performs ONE credential attempt against ip:port and reports a
// definitive result. Implementations must never return Success=true on an
// ambiguous/network-error outcome — only on an unambiguous protocol-level
// auth-success signal.
type netCredChecker func(ctx context.Context, ip string, port int) netCredResult

// netCredTarget is one verified open service eligible for the audit.
type netCredTarget struct {
	IP   string
	Port int
}

// loadNetCredTargets returns up to netCredMaxTargets verified network_services
// rows for targetID whose detected service name matches serviceNames, filtered
// to the active scope. Never guesses a port — only audits what this scan's own
// fingerprint pass already confirmed open and identified.
func (s *NetworkScanner) loadNetCredTargets(ctx context.Context, targetID, rawScope string, serviceNames ...string) ([]netCredTarget, error) {
	allowed, err := networkScopeSet(rawScope)
	if err != nil {
		return nil, err
	}
	placeholders := make([]string, len(serviceNames))
	args := make([]any, 0, len(serviceNames)+1)
	args = append(args, targetID)
	for i, name := range serviceNames {
		placeholders[i] = "?"
		args = append(args, name)
	}
	query := `SELECT ip, port FROM network_services WHERE target_id = ? AND service IN (` +
		strings.Join(placeholders, ",") + `) ORDER BY ip, port`
	rows, err := s.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []netCredTarget
	for rows.Next() {
		var t netCredTarget
		if rows.Scan(&t.IP, &t.Port) != nil {
			continue
		}
		if !allowed[t.IP] {
			continue
		}
		out = append(out, t)
		if len(out) >= netCredMaxTargets {
			break
		}
	}
	return out, nil
}

// runNetCredAudit is the shared engine every protocol-specific RunBruteXxx
// wraps: bounded username×password spray, serial with a delay, capped attempts
// and wall-clock budget, stopping on the first confirmed hit per target.
func (s *NetworkScanner) runNetCredAudit(
	ctx context.Context, targetID, module, vulnType, severity string,
	targets []netCredTarget, users, passwords []string,
	check func(ip string, port int, user, pass string) netCredResult,
	pocLine func(ip string, port int, user, pass string) string,
	logFn LogFunc,
) error {
	hits := 0
	attempts := 0
	started := time.Now()
targetLoop:
	for _, tgt := range targets {
		if ctx.Err() != nil {
			break
		}
		addr := net.JoinHostPort(tgt.IP, strconv.Itoa(tgt.Port))
		for _, user := range users {
			// Username-equals-password is the single highest-signal guess, tried
			// first, exactly like the WP audit.
			for _, pw := range dedupeStrings(append([]string{user}, passwords...)) {
				if ctx.Err() != nil || attempts >= netCredMaxAttempts || time.Since(started) > netCredBudget {
					break targetLoop
				}
				attempts++
				res := check(tgt.IP, tgt.Port, user, pw)
				if res.Success {
					poc := pocLine(tgt.IP, tgt.Port, user, pw)
					evidence := "Valid credential confirmed for user '" + user + "' (password " + maskSecret(pw) + ") on " + addr + "."
					if res.Evidence != "" {
						evidence += " " + res.Evidence
					}
					evidence += " This grants direct access to the service — typically full data compromise. Rotate the credential and restrict network access to trusted sources."
					_, _ = RecordDetectorObservation(ctx, s.db, DetectorObservation{
						TargetID: targetID, Type: vulnType, Severity: severity,
						URL: addr, Method: "TCP", Parameter: user, Location: "auth",
						Payload: poc, Evidence: evidence, Source: module,
						DetectionMethod: "network:" + vulnType, Confidence: 100, Priority: 500,
						Verdict: VerifyVerified,
					})
					hits++
					continue targetLoop // move to the next target on first hit
				}
				time.Sleep(netCredDelay)
			}
		}
	}
	logFn("warn", module, fmt.Sprintf("Credential audit done over %d target(s). %d valid credential(s) found.", len(targets), hits))
	return ctx.Err()
}

func (s *NetworkScanner) netPasswords() []string {
	if s.cfg != nil {
		return LoadCorpus(s.cfg.WordlistsDir, "net_passwords", netTop1000Passwords)
	}
	return netTop1000Passwords
}

// guardAuthorized is the shared not-authorized early exit every RunBruteXxx
// uses, so the log message and behaviour are identical across protocols.
func (s *NetworkScanner) guardAuthorized(ctx context.Context, module string, logFn LogFunc) bool {
	if s.networkAuthorized(ctx) {
		return true
	}
	logFn("warn", module, "Active credential testing is NOT authorized (tick the service's brute-force box in the Network Scanner, or set enable_network_credential_audit=true). Skipping password attempts.")
	return false
}

// ── SSH ──────────────────────────────────────────────────────────────────────

// RunBruteSSH implements network_brute_ssh. A successful password handshake via
// golang.org/x/crypto/ssh IS the proof — the library only returns a live client
// after the server has accepted the credential.
func (s *NetworkScanner) RunBruteSSH(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	if !s.guardAuthorized(ctx, "network_brute_ssh", logFn) {
		return ctx.Err()
	}
	targets, err := s.loadNetCredTargets(ctx, targetID, rawScope, "ssh")
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return BlockedPhase("no verified SSH service in scope for the credential audit")
	}
	logFn("info", "network_brute_ssh", fmt.Sprintf("Authorized SSH credential audit over %d target(s) (rate-limited, handshake-confirmed)...", len(targets)))
	check := func(ip string, port int, user, pass string) netCredResult {
		cfg := &ssh.ClientConfig{
			User:            user,
			Auth:            []ssh.AuthMethod{ssh.Password(pass)},
			HostKeyCallback: ssh.InsecureIgnoreHostKey(), // #nosec G106 -- credential-audit probe, not a session we trust
			Timeout:         netDialTimeout,
		}
		client, err := ssh.Dial("tcp", net.JoinHostPort(ip, strconv.Itoa(port)), cfg)
		if err != nil {
			return netCredResult{}
		}
		_ = client.Close()
		return netCredResult{Success: true, Evidence: "Confirmed by a completed SSH password handshake."}
	}
	poc := func(ip string, port int, user, pass string) string {
		return fmt.Sprintf("ssh %s@%s -p %d  (password: %s)", user, ip, port, pass)
	}
	return s.runNetCredAudit(ctx, targetID, "network_brute_ssh", "network_ssh_weak_credentials", "critical",
		targets, netUsersSSH, s.netPasswords(), check, poc, logFn)
}

// ── FTP ──────────────────────────────────────────────────────────────────────

// RunBruteFTP implements network_brute_ftp. Confirmed only by the FTP server's
// own "230" (user logged in) reply code — the definitive RFC 959 success signal.
func (s *NetworkScanner) RunBruteFTP(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	if !s.guardAuthorized(ctx, "network_brute_ftp", logFn) {
		return ctx.Err()
	}
	targets, err := s.loadNetCredTargets(ctx, targetID, rawScope, "ftp")
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return BlockedPhase("no verified FTP service in scope for the credential audit")
	}
	logFn("info", "network_brute_ftp", fmt.Sprintf("Authorized FTP credential audit over %d target(s) (rate-limited, 230-confirmed)...", len(targets)))
	check := func(ip string, port int, user, pass string) netCredResult {
		if ftpLoginSucceeds(ctx, ip, port, user, pass) {
			return netCredResult{Success: true, Evidence: "Confirmed by the server's own 230 (user logged in) reply."}
		}
		return netCredResult{}
	}
	poc := func(ip string, port int, user, pass string) string {
		return fmt.Sprintf("ftp %s %d  (USER %s / PASS %s)", ip, port, user, pass)
	}
	return s.runNetCredAudit(ctx, targetID, "network_brute_ftp", "network_ftp_weak_credentials", "critical",
		targets, netUsersFTP, s.netPasswords(), check, poc, logFn)
}

func ftpLoginSucceeds(ctx context.Context, ip string, port int, user, pass string) bool {
	conn, err := (&net.Dialer{Timeout: netDialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(netDialTimeout))
	r := bufio.NewReader(conn)
	if _, ok := ftpReadReply(r); !ok { // banner (220)
		return false
	}
	fmt.Fprintf(conn, "USER %s\r\n", ftpSanitize(user))
	code, ok := ftpReadReply(r)
	if !ok {
		return false
	}
	if code == 230 { // some anonymous-style servers log in on USER alone
		return true
	}
	if code != 331 { // "need password" — anything else means USER itself was rejected
		return false
	}
	fmt.Fprintf(conn, "PASS %s\r\n", ftpSanitize(pass))
	code, ok = ftpReadReply(r)
	return ok && code == 230
}

// ftpSanitize strips CR/LF so a crafted credential can never inject a second
// FTP command into the control channel.
func ftpSanitize(s string) string {
	return strings.NewReplacer("\r", "", "\n", "").Replace(s)
}

// ftpReadReply reads one (possibly multi-line) FTP reply and returns its
// 3-digit status code. Multi-line replies start "NNN-" and end with a final
// "NNN " line — only the terminating line's code is authoritative.
func ftpReadReply(r *bufio.Reader) (int, bool) {
	var code int
	for {
		line, err := r.ReadString('\n')
		if err != nil && line == "" {
			return 0, false
		}
		line = strings.TrimRight(line, "\r\n")
		if len(line) < 4 {
			continue
		}
		n, err := strconv.Atoi(line[:3])
		if err != nil {
			continue
		}
		code = n
		if line[3] == ' ' { // terminating line of the reply
			return code, true
		}
		// line[3] == '-' → multi-line continuation, keep reading
	}
}

// ── MySQL ────────────────────────────────────────────────────────────────────

// RunBruteMySQL implements network_brute_mysql. Uses the real MySQL wire
// protocol (go-sql-driver/mysql) rather than a hand-rolled handshake, so every
// auth-plugin variant the driver supports is handled correctly. Confirmed only
// by a successful connection — err == nil from Ping(), never a guess.
func (s *NetworkScanner) RunBruteMySQL(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	if !s.guardAuthorized(ctx, "network_brute_mysql", logFn) {
		return ctx.Err()
	}
	targets, err := s.loadNetCredTargets(ctx, targetID, rawScope, "mysql")
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return BlockedPhase("no verified MySQL service in scope for the credential audit")
	}
	logFn("info", "network_brute_mysql", fmt.Sprintf("Authorized MySQL credential audit over %d target(s) (rate-limited, connection-confirmed)...", len(targets)))
	check := func(ip string, port int, user, pass string) netCredResult {
		if mysqlLoginSucceeds(ctx, ip, port, user, pass) {
			return netCredResult{Success: true, Evidence: "Confirmed by a successful MySQL connection."}
		}
		return netCredResult{}
	}
	poc := func(ip string, port int, user, pass string) string {
		return fmt.Sprintf("mysql -h %s -P %d -u %s -p%s", ip, port, user, pass)
	}
	return s.runNetCredAudit(ctx, targetID, "network_brute_mysql", "network_mysql_weak_credentials", "critical",
		targets, netUsersMySQL, s.netPasswords(), check, poc, logFn)
}

func mysqlLoginSucceeds(ctx context.Context, ip string, port int, user, pass string) bool {
	dsn := fmt.Sprintf("%s:%s@tcp(%s)/?timeout=%s&readTimeout=%s&writeTimeout=%s",
		mysqlEscape(user), mysqlEscape(pass), net.JoinHostPort(ip, strconv.Itoa(port)),
		netDialTimeout, netDialTimeout, netDialTimeout)
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return false
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, netDialTimeout+2*time.Second)
	defer cancel()
	return db.PingContext(cctx) == nil
}

// mysqlEscape prevents a credential containing a DSN-special character
// (':', '@', '/') from being parsed as part of the DSN structure instead of
// the literal user/password value.
func mysqlEscape(s string) string {
	r := strings.NewReplacer(":", "%3A", "@", "%40", "/", "%2F")
	return r.Replace(s)
}

// ── PostgreSQL ───────────────────────────────────────────────────────────────

// RunBrutePostgres implements network_brute_postgres. Confirmed by a successful
// connection OR by the server's post-AUTH "database does not exist" error
// (SQLSTATE 3D000) — Postgres authenticates BEFORE checking the target
// database, so reaching that specific error already proves the credential.
func (s *NetworkScanner) RunBrutePostgres(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	if !s.guardAuthorized(ctx, "network_brute_postgres", logFn) {
		return ctx.Err()
	}
	targets, err := s.loadNetCredTargets(ctx, targetID, rawScope, "postgresql")
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return BlockedPhase("no verified PostgreSQL service in scope for the credential audit")
	}
	logFn("info", "network_brute_postgres", fmt.Sprintf("Authorized PostgreSQL credential audit over %d target(s) (rate-limited, connection-confirmed)...", len(targets)))
	check := func(ip string, port int, user, pass string) netCredResult {
		if ok, ev := postgresLoginSucceeds(ctx, ip, port, user, pass); ok {
			return netCredResult{Success: true, Evidence: ev}
		}
		return netCredResult{}
	}
	poc := func(ip string, port int, user, pass string) string {
		return fmt.Sprintf("PGPASSWORD=%s psql -h %s -p %d -U %s -d postgres", pass, ip, port, user)
	}
	return s.runNetCredAudit(ctx, targetID, "network_brute_postgres", "network_postgres_weak_credentials", "critical",
		targets, netUsersPostgres, s.netPasswords(), check, poc, logFn)
}

func postgresLoginSucceeds(ctx context.Context, ip string, port int, user, pass string) (bool, string) {
	dsn := fmt.Sprintf("host=%s port=%d user=%s password=%s dbname=postgres sslmode=disable connect_timeout=%d",
		ip, port, pqEscape(user), pqEscape(pass), int(netDialTimeout.Seconds()))
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		return false, ""
	}
	defer db.Close()
	cctx, cancel := context.WithTimeout(ctx, netDialTimeout+2*time.Second)
	defer cancel()
	err = db.PingContext(cctx)
	if err == nil {
		return true, "Confirmed by a successful PostgreSQL connection."
	}
	if pqErr, ok := err.(*pq.Error); ok && string(pqErr.Code) == "3D000" {
		// invalid_catalog_name: the "postgres" database doesn't exist on this
		// server, but the server only reports that AFTER authenticating us.
		return true, "Confirmed: the server authenticated the credential and only then reported the 'postgres' database does not exist."
	}
	return false, ""
}

// pqEscape prevents a credential containing a space or quote from breaking out
// of its key=value slot in a libpq connection string.
func pqEscape(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `'`, `\'`, " ", `\ `)
	return r.Replace(s)
}

// ── Redis ────────────────────────────────────────────────────────────────────

// RunBruteRedis implements network_brute_redis. Confirmed only by the server's
// own "+OK" reply to AUTH — the definitive RESP success signal. A server with
// NO password configured at all (AUTH rejected as "no password is set") is a
// different, more serious exposure reported separately by the nuclei
// Redis-unauthenticated-access check, never here.
func (s *NetworkScanner) RunBruteRedis(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	if !s.guardAuthorized(ctx, "network_brute_redis", logFn) {
		return ctx.Err()
	}
	targets, err := s.loadNetCredTargets(ctx, targetID, rawScope, "redis")
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		return BlockedPhase("no verified Redis service in scope for the credential audit")
	}
	logFn("info", "network_brute_redis", fmt.Sprintf("Authorized Redis credential audit over %d target(s) (rate-limited, +OK-confirmed)...", len(targets)))
	check := func(ip string, port int, _, pass string) netCredResult {
		if redisAuthSucceeds(ctx, ip, port, pass) {
			return netCredResult{Success: true, Evidence: "Confirmed by the server's own +OK reply to AUTH."}
		}
		return netCredResult{}
	}
	poc := func(ip string, port int, _, pass string) string {
		return fmt.Sprintf("redis-cli -h %s -p %d -a %s PING", ip, port, pass)
	}
	// Redis AUTH is password-only (no ACL username) in the overwhelming common
	// case, so the "user" axis is a single placeholder — only the password
	// corpus actually varies.
	return s.runNetCredAudit(ctx, targetID, "network_brute_redis", "network_redis_weak_credentials", "critical",
		targets, []string{"default"}, s.netPasswords(), check, poc, logFn)
}

func redisAuthSucceeds(ctx context.Context, ip string, port int, pass string) bool {
	conn, err := (&net.Dialer{Timeout: netDialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(netDialTimeout))
	// RESP array: AUTH <password> — avoids any inline-command injection risk
	// from a crafted password value.
	cmd := fmt.Sprintf("*2\r\n$4\r\nAUTH\r\n$%d\r\n%s\r\n", len(pass), pass)
	if _, err := conn.Write([]byte(cmd)); err != nil {
		return false
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return false
	}
	return strings.HasPrefix(line, "+OK")
}
