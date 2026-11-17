package scanner

import (
	"bufio"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

const networkNativeFallbackHosts = 256

// fastNetworkPorts is the curated "important ports" list for the fast profile —
// wide enough to catch the services that actually matter on a bug-bounty/pentest
// target (remote access, databases, caches, message queues, container/orchestration
// APIs, common web-admin ports) while staying far smaller than a full 65k sweep, so
// the fast profile stays genuinely fast. The deep profile still sweeps every TCP
// port regardless of this list.
var fastNetworkPorts = []int{
	20, 21, 22, 23, 25, 53, 69, 80, 88, 110, 111, 123, 135, 139, 143, 161, 389, 443, 445,
	465, 500, 512, 513, 514, 515, 548, 554, 587, 593, 623, 631, 636, 873, 902, 989, 990,
	993, 995, 1080, 1194, 1337, 1433, 1521, 1723, 1883, 2049, 2082, 2083, 2086, 2087,
	2095, 2096, 2181, 2222, 2375, 2376, 2379, 2380, 3000, 3001, 3128, 3268, 3269, 3306,
	3389, 3690, 4000, 4040, 4369, 4443, 4505, 4506, 4789, 4848, 5000, 5001, 5060, 5061,
	5222, 5269, 5351, 5353, 5355, 5432, 5555, 5601, 5671, 5672, 5900, 5901, 5984, 5985,
	5986, 6000, 6066, 6379, 6443, 6660, 6667, 6881, 7000, 7001, 7070, 7077, 7199, 7474,
	7687, 7777, 8000, 8001, 8008, 8009, 8020, 8042, 8069, 8080, 8081, 8083, 8086, 8088,
	8089, 8090, 8091, 8161, 8200, 8222, 8333, 8400, 8443, 8500, 8529, 8545, 8761, 8800,
	8834, 8848, 8888, 8983, 9000, 9001, 9009, 9042, 9043, 9050, 9080, 9090, 9092, 9100,
	9160, 9200, 9300, 9418, 9443, 9500, 9999, 10000, 10050, 10051, 10250, 10255, 11211,
	15672, 16010, 16379, 17000, 18080, 19999, 20000, 24800, 25565, 27015, 27017, 27018,
	27019, 28015, 28017, 32400, 32768, 44134, 49152, 50000, 50070, 54321,
}

type NetworkScanner struct {
	db     *database.DB
	exec   *tools.Executor
	cfg    *config.Config
	logger *logger.Logger
}

func NewNetworkScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger) *NetworkScanner {
	return &NetworkScanner{db: db, exec: exec, cfg: cfg, logger: log}
}

// basicAuthControlUser/basicAuthControlPass are a deliberately-wrong
// credential, never drawn from the real username/password corpora, used as a
// negative control (see the comment in RunBasicAuth below).
const (
	basicAuthControlUser = "reconner-control-probe"
	basicAuthControlPass = "reconner-control-probe-should-never-authenticate"
)

// RunBasicAuth is deliberately a separate module: selecting ordinary network
// discovery never sends credentials. It is gated by the same authorization
// check every other credential-audit module in this package requires
// (networkAuthorized — the server-wide switch or the per-scan
// net_cred_authorized token), bounded by the same global attempt cap and
// wall-clock budget (netCredMaxAttempts/netCredBudget) so a scan that
// discovers many Basic-Auth-protected services can never run unbounded, and
// is capped to netCredMaxTargets services for the same reason every sibling
// module caps its target count. It verifies a real Basic challenge, rejects
// an endpoint that doesn't actually discriminate on credential value (the
// negative control below), throttles attempts, aborts on lockout/rate-limit
// signals, and replays a success twice before recording it.
func (s *NetworkScanner) RunBasicAuth(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	if !s.guardAuthorized(ctx, "network_brute", logFn) {
		return ctx.Err()
	}
	allowed, err := networkScopeSet(rawScope)
	if err != nil {
		return err
	}
	rows, err := s.db.QueryContext(ctx, `SELECT ip,web_url FROM network_services WHERE target_id=? AND is_web=1 AND web_url<>'' ORDER BY ip,port`, targetID)
	if err != nil {
		return err
	}
	defer rows.Close()
	var targets []string
	for rows.Next() {
		var ip, raw string
		if rows.Scan(&ip, &raw) == nil && allowed[ip] {
			targets = append(targets, raw)
			if len(targets) >= netCredMaxTargets {
				break
			}
		}
	}
	if len(targets) == 0 {
		return BlockedPhase("no discovered network web services are eligible for Basic-auth verification")
	}
	dir := ""
	if s.cfg != nil {
		dir = s.cfg.WordlistsDir
	}
	users := LoadCorpus(dir, "basic_auth_users", defaultBasicAuthUsers())
	passwords := LoadCorpus(dir, "basic_auth_passwords", defaultBasicAuthPasswords())
	client := &http.Client{Transport: sharedHTTPTransport, Timeout: 8 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	attempts := 0
	started := time.Now()
targetLoop:
	for _, raw := range targets {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		baseline, challenge := basicAuthRequest(ctx, client, raw, "", "")
		if baseline != http.StatusUnauthorized || !strings.HasPrefix(strings.ToLower(challenge), "basic") {
			continue
		}
		// Negative control: a credential that is certainly wrong must still be
		// rejected. Without this, an endpoint that accepts ANY Authorization
		// header regardless of value (a misconfigured proxy in front of it, an
		// auth check that never actually runs) would let the very first
		// candidate tried below "pass" the replay-stability check purely
		// because it is consistently wrong for everyone — never real evidence
		// that a specific credential was accepted.
		controlStatus, _ := basicAuthRequest(ctx, client, raw, basicAuthControlUser, basicAuthControlPass)
		if controlStatus != http.StatusUnauthorized {
			logFn("info", "network_brute", fmt.Sprintf("Skipped %s: a deliberately-wrong credential was not rejected (status %d) — this endpoint does not appear to enforce Basic-Auth credentials.", raw, controlStatus))
			continue
		}
		RecordCoverage(ctx, CoverageEligible, 1)
		// First try the high-signal username=password/default pairs, then the
		// complete 1000-password corpus against the canonical admin account.
		type credential struct{ user, pass string }
		candidates := make([]credential, 0, len(users)*2+len(passwords))
		for _, user := range users {
			candidates = append(candidates, credential{user, user}, credential{user, "password"})
		}
		for _, pass := range passwords {
			candidates = append(candidates, credential{"admin", pass})
		}
		seen := map[string]bool{}
		for _, candidate := range candidates {
			key := candidate.user + "\x00" + candidate.pass
			if seen[key] {
				continue
			}
			seen[key] = true
			if ctx.Err() != nil || attempts >= netCredMaxAttempts || time.Since(started) > netCredBudget {
				break targetLoop
			}
			attempts++
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-time.After(200 * time.Millisecond):
			}
			status, _ := basicAuthRequest(ctx, client, raw, candidate.user, candidate.pass)
			RecordCoverage(ctx, CoverageAttempted, 1)
			if status == http.StatusTooManyRequests || status == http.StatusLocked {
				logFn("warn", "network_brute", "Stopped Basic-auth audit after server lockout/rate-limit response: "+raw)
				break
			}
			if status == http.StatusUnauthorized || status == 0 || status >= 500 {
				continue
			}
			status2, _ := basicAuthRequest(ctx, client, raw, candidate.user, candidate.pass)
			if status2 != status {
				continue
			}
			evidence := fmt.Sprintf("HTTP Basic credential accepted twice with stable status %d", status)
			_, _ = RecordDetectorObservation(ctx, s.db, DetectorObservation{
				TargetID: targetID, Type: "http_basic_weak_credentials", Severity: "high",
				URL: raw, Method: "GET", Parameter: "Authorization", Location: "header",
				Payload: candidate.user + ":" + candidate.pass, Evidence: evidence,
				Source: "network_brute", DetectionMethod: "stable-basic-auth-replay",
				Confidence: 95, Priority: 90, Provenance: "active", Verdict: VerifyVerified,
			})
			RecordCoverage(ctx, CoverageConfirmed, 1)
			logFn("warn", "network_brute", "Verified weak HTTP Basic credential on "+raw+" (stored in finding evidence)")
			break
		}
	}
	return nil
}

func networkScopeSet(raw string) (map[string]bool, error) {
	ips, err := ExpandNetworkScope(raw, MaxNetworkScopeHosts)
	if err != nil {
		return nil, err
	}
	out := make(map[string]bool, len(ips))
	for _, ip := range ips {
		out[ip.String()] = true
	}
	return out, nil
}

func defaultBasicAuthUsers() []string {
	return []string{"admin", "administrator", "root", "user", "operator", "manager", "support", "guest", "test", "webadmin"}
}

func basicAuthRequest(ctx context.Context, client *http.Client, raw, user, pass string) (int, string) {
	if _, err := url.ParseRequestURI(raw); err != nil {
		return 0, ""
	}
	req, err := http.NewRequestWithContext(ctx, "GET", raw, nil)
	if err != nil {
		return 0, ""
	}
	if user != "" {
		req.SetBasicAuth(user, pass)
	}
	resp, err := client.Do(req)
	if err != nil {
		return 0, ""
	}
	defer resp.Body.Close()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	return resp.StatusCode, resp.Header.Get("WWW-Authenticate")
}

type networkOpenPort struct {
	IP   string `json:"ip"`
	Port int    `json:"port"`
}

// Run performs explicit network discovery. Host discovery is informational and
// never gates the TCP scan: ICMP is commonly filtered, so treating a missing
// echo reply as a dead host creates false negatives. Every admitted, non-CDN/WAF
// address is scanned with TCP connect semantics instead.
func (s *NetworkScanner) Run(ctx context.Context, targetID, rawScope string, logFn LogFunc) error {
	ips, err := ExpandNetworkScope(rawScope, MaxNetworkScopeHosts)
	if err != nil {
		return fmt.Errorf("network scope: %w", err)
	}
	kept, blocked := FilterCDNWAF(ips)
	for _, match := range blocked {
		logFn("warn", "network", fmt.Sprintf("Skipped %s: recognised %s edge (%s), not an origin", match.IP, match.Kind, match.Provider))
		RecordCoverage(ctx, CoverageBlocked, 1)
	}
	var excluded int
	kept, excluded = FilterExcludedIPs(kept, LoadExclusions(ctx, s.db, targetID))
	if excluded > 0 {
		logFn("info", "network", fmt.Sprintf("Excluded %d out-of-scope address(es) before any network request", excluded))
		RecordCoverage(ctx, CoverageBlocked, int64(excluded))
	}
	RecordCoverage(ctx, CoverageDiscovered, int64(len(ips)))
	RecordCoverage(ctx, CoverageEligible, int64(len(kept)))
	if len(kept) == 0 {
		return BlockedPhase("all scoped addresses are recognised CDN/WAF edges")
	}
	if s.exec != nil && s.exec.IsToolAvailable("nmap") {
		if alive, pingErr := s.runPingDiscovery(ctx, targetID, kept); pingErr != nil && ctx.Err() == nil {
			logFn("warn", "network", "Host discovery was inconclusive; TCP scanning every scoped host anyway: "+pingErr.Error())
		} else if pingErr == nil {
			logFn("info", "network", fmt.Sprintf("Ping discovery observed %d responsive host(s); TCP discovery still covers all %d to avoid ICMP false negatives", alive, len(kept)))
		}
	}

	profile := networkProfileFromContext(ctx)
	logFn("info", "network", fmt.Sprintf("TCP discovery profile=%s hosts=%d (ICMP does not gate scanning)", profile, len(kept)))
	var open []networkOpenPort
	if s.exec != nil && s.exec.IsToolAvailable("naabu") {
		open, err = s.runNaabu(ctx, targetID, kept, profile)
	} else {
		if len(kept) > networkNativeFallbackHosts {
			return BlockedPhase("naabu is required for network scopes larger than 256 hosts")
		}
		logFn("warn", "network", "naabu unavailable; using bounded native TCP-connect fallback")
		open, err = nativeConnectScan(ctx, kept, fastNetworkPorts, 128, 900*time.Millisecond)
	}
	if err != nil {
		return err
	}
	RecordCoverage(ctx, CoverageAttempted, int64(len(kept)))
	RecordCoverage(ctx, CoverageConfirmed, int64(len(open)))
	if err := s.persistOpenPorts(targetID, kept, open); err != nil {
		return err
	}
	if len(open) == 0 {
		logFn("info", "network", "No open TCP ports found in the selected profile")
		return nil
	}

	if s.exec != nil && s.exec.IsToolAvailable("nmap") {
		if err := s.fingerprintWithNmap(ctx, targetID, open, profile, logFn); err != nil && ctx.Err() == nil {
			logFn("warn", "network", "nmap fingerprinting failed; retaining verified open-port results: "+err.Error())
			s.nativeFingerprint(ctx, targetID, open)
		}
	} else {
		s.nativeFingerprint(ctx, targetID, open)
		logFn("warn", "network", "nmap unavailable; stored native banners and service hints without OS fingerprinting")
	}
	return nil
}

func (s *NetworkScanner) runNaabu(ctx context.Context, targetID string, hosts []string, profile NetworkProfile) ([]networkOpenPort, error) {
	f, err := os.CreateTemp("", "reconner-network-scope-*.txt")
	if err != nil {
		return nil, err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err := io.WriteString(f, strings.Join(hosts, "\n")); err != nil {
		f.Close()
		return nil, err
	}
	if err := f.Close(); err != nil {
		return nil, err
	}

	args := []string{"-list", name, "-json", "-silent", "-scan-type", "c", "-verify", "-retries", "2", "-exclude-cdn", "-disable-update-check"}
	switch profile {
	case NetworkFast:
		args = append(args, "-p", joinPorts(fastNetworkPorts), "-rate", "2500")
	case NetworkDeep:
		args = append(args, "-p", "-", "-rate", "1200")
	default:
		args = append(args, "-top-ports", "1000", "-rate", "1800")
	}
	seen := map[string]bool{}
	var mu sync.Mutex
	var open []networkOpenPort
	err = s.exec.RunWithCallback(ctx, targetID+":network", func(line string) {
		var item networkOpenPort
		if json.Unmarshal([]byte(line), &item) != nil || net.ParseIP(item.IP) == nil || item.Port < 1 || item.Port > 65535 {
			return
		}
		key := net.JoinHostPort(item.IP, strconv.Itoa(item.Port))
		mu.Lock()
		if !seen[key] {
			seen[key] = true
			open = append(open, item)
		}
		mu.Unlock()
	}, "naabu", args...)
	if err != nil && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if err != nil {
		return nil, fmt.Errorf("naabu: %w", err)
	}
	sortOpenPorts(open)
	return open, nil
}

func nativeConnectScan(ctx context.Context, hosts []string, ports []int, workers int, timeout time.Duration) ([]networkOpenPort, error) {
	type job struct {
		ip   string
		port int
	}
	jobs := make(chan job)
	results := make(chan networkOpenPort)
	if workers < 1 {
		workers = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			d := net.Dialer{Timeout: timeout}
			for item := range jobs {
				conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(item.ip, strconv.Itoa(item.port)))
				if err == nil {
					conn.Close()
					select {
					case results <- networkOpenPort{IP: item.ip, Port: item.port}:
					case <-ctx.Done():
						return
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, ip := range hosts {
			for _, port := range ports {
				select {
				case jobs <- job{ip, port}:
				case <-ctx.Done():
					return
				}
			}
		}
	}()
	go func() { wg.Wait(); close(results) }()
	var out []networkOpenPort
	for result := range results {
		out = append(out, result)
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	sortOpenPorts(out)
	return out, nil
}

func (s *NetworkScanner) persistOpenPorts(targetID string, hosts []string, open []networkOpenPort) error {
	counts := map[string]int{}
	for _, item := range open {
		counts[item.IP]++
	}
	for _, ip := range hosts {
		_, err := s.db.Exec(`INSERT INTO network_hosts(id,target_id,ip,is_alive,open_ports,last_seen)
			VALUES(?,?,?,?,?,CURRENT_TIMESTAMP) ON CONFLICT(target_id,ip) DO UPDATE SET
			is_alive=MAX(network_hosts.is_alive,excluded.is_alive),open_ports=excluded.open_ports,last_seen=CURRENT_TIMESTAMP`,
			uuid.New().String(), targetID, ip, boolInt(counts[ip] > 0), counts[ip])
		if err != nil {
			return err
		}
	}
	for _, item := range open {
		_, err := s.db.Exec(`INSERT INTO network_services(id,target_id,ip,port,protocol,last_seen)
			VALUES(?,?,?,?, 'tcp',CURRENT_TIMESTAMP) ON CONFLICT(target_id,ip,port,protocol) DO UPDATE SET last_seen=CURRENT_TIMESTAMP`,
			uuid.New().String(), targetID, item.IP, item.Port)
		if err != nil {
			return err
		}
	}
	return nil
}

type nmapRun struct {
	Hosts []nmapHost `xml:"host"`
}
type nmapHost struct {
	Status struct {
		State string `xml:"state,attr"`
	} `xml:"status"`
	Addresses []struct {
		Addr string `xml:"addr,attr"`
		Type string `xml:"addrtype,attr"`
	} `xml:"address"`
	Hostnames []struct {
		Name string `xml:"name,attr"`
	} `xml:"hostnames>hostname"`
	Ports []struct {
		Port     int    `xml:"portid,attr"`
		Protocol string `xml:"protocol,attr"`
		State    struct {
			State string `xml:"state,attr"`
		} `xml:"state"`
		Service struct {
			Name    string `xml:"name,attr"`
			Product string `xml:"product,attr"`
			Version string `xml:"version,attr"`
			Extra   string `xml:"extrainfo,attr"`
			Tunnel  string `xml:"tunnel,attr"`
		} `xml:"service"`
	} `xml:"ports>port"`
	OS []struct {
		Name     string `xml:"name,attr"`
		Accuracy int    `xml:"accuracy,attr"`
	} `xml:"os>osmatch"`
}

func (s *NetworkScanner) runPingDiscovery(ctx context.Context, targetID string, hosts []string) (int, error) {
	f, err := os.CreateTemp("", "reconner-network-ping-*.txt")
	if err != nil {
		return 0, err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = io.WriteString(f, strings.Join(hosts, "\n")); err != nil {
		f.Close()
		return 0, err
	}
	if err = f.Close(); err != nil {
		return 0, err
	}
	result, err := s.exec.Run(ctx, "nmap", "-sn", "-PE", "-PS22,80,443,445,3389", "-PA80,443", "-n", "--host-timeout", "30s", "-iL", name, "-oX", "-")
	if err != nil {
		return 0, err
	}
	if result.ExitCode != 0 {
		return 0, fmt.Errorf("nmap ping exit %d: %s", result.ExitCode, strings.TrimSpace(result.Stderr))
	}
	var parsed nmapRun
	if err := xml.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
		return 0, err
	}
	alive := 0
	for _, host := range parsed.Hosts {
		if host.Status.State != "up" {
			continue
		}
		ip := ""
		for _, addr := range host.Addresses {
			if addr.Type == "ipv4" || addr.Type == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		alive++
		_, _ = s.db.Exec(`INSERT INTO network_hosts(id,target_id,ip,is_alive,last_seen) VALUES(?,?,?,1,CURRENT_TIMESTAMP) ON CONFLICT(target_id,ip) DO UPDATE SET is_alive=1,last_seen=CURRENT_TIMESTAMP`, uuid.New().String(), targetID, ip)
	}
	return alive, nil
}

func (s *NetworkScanner) fingerprintWithNmap(ctx context.Context, targetID string, open []networkOpenPort, profile NetworkProfile, logFn LogFunc) error {
	byHost := map[string][]int{}
	for _, item := range open {
		byHost[item.IP] = append(byHost[item.IP], item.Port)
	}
	for ip, ports := range byHost {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		baseArgs := []string{"-Pn", "-n", "-sT", "-sV", "--version-intensity", "7", "--host-timeout", "8m", "-p", joinPorts(ports), "-oX", "-", ip}
		args := append([]string{"-O", "--osscan-limit", "--max-os-tries", "1"}, baseArgs...)
		result, err := s.exec.Run(ctx, "nmap", args...)
		// Bare-metal installs may not grant raw-socket capability. Preserve service
		// and banner coverage by retrying without -O instead of losing the host.
		if err != nil || result.ExitCode != 0 {
			result, err = s.exec.Run(ctx, "nmap", baseArgs...)
		}
		if err != nil || result.ExitCode != 0 {
			if err == nil {
				err = fmt.Errorf("exit %d: %s", result.ExitCode, strings.TrimSpace(result.Stderr))
			}
			logFn("warn", "network", fmt.Sprintf("nmap fingerprint failed for %s: %v", ip, err))
			fallback := make([]networkOpenPort, 0, len(ports))
			for _, port := range ports {
				fallback = append(fallback, networkOpenPort{IP: ip, Port: port})
			}
			s.nativeFingerprint(ctx, targetID, fallback)
			continue
		}
		var parsed nmapRun
		if err := xml.Unmarshal([]byte(result.Stdout), &parsed); err != nil {
			return fmt.Errorf("parse nmap XML: %w", err)
		}
		s.persistNmap(ctx, targetID, parsed)
	}
	return nil
}

func (s *NetworkScanner) persistNmap(ctx context.Context, targetID string, run nmapRun) {
	for _, host := range run.Hosts {
		ip := ""
		for _, addr := range host.Addresses {
			if addr.Type == "ipv4" || addr.Type == "ipv6" {
				ip = addr.Addr
				break
			}
		}
		if ip == "" {
			continue
		}
		rdns, osGuess := "", ""
		if len(host.Hostnames) > 0 {
			rdns = host.Hostnames[0].Name
		}
		if len(host.OS) > 0 {
			osGuess = host.OS[0].Name
		}
		_, _ = s.db.Exec(`UPDATE network_hosts SET os_guess=?,rdns=?,last_seen=CURRENT_TIMESTAMP WHERE target_id=? AND ip=?`, osGuess, rdns, targetID, ip)
		for _, port := range host.Ports {
			if port.State.State != "open" {
				continue
			}
			isWeb, tls := webService(port.Port, port.Service.Name, port.Service.Tunnel)
			banner := strings.TrimSpace(strings.Join([]string{port.Service.Product, port.Service.Version, port.Service.Extra}, " "))
			_, _ = s.db.Exec(`UPDATE network_services SET service=?,product=?,version=?,banner=?,is_web=?,tls=?,last_seen=CURRENT_TIMESTAMP
				WHERE target_id=? AND ip=? AND port=? AND protocol=?`, port.Service.Name, port.Service.Product, port.Service.Version,
				banner, boolInt(isWeb), boolInt(tls), targetID, ip, port.Port, port.Protocol)
			if isWeb {
				s.probeNetworkHTTP(targetID, ip, port.Port, tls)
			}
			s.probeKnownExposures(ctx, targetID, ip, port.Port, port.Service.Name)
		}
	}
}

func (s *NetworkScanner) nativeFingerprint(ctx context.Context, targetID string, open []networkOpenPort) {
	for _, item := range open {
		if ctx.Err() != nil {
			return
		}
		service := serviceHint(item.Port)
		isWeb, tls := webService(item.Port, service, "")
		banner := readTCPBanner(ctx, item.IP, item.Port)
		_, _ = s.db.Exec(`UPDATE network_services SET service=?,banner=?,is_web=?,tls=? WHERE target_id=? AND ip=? AND port=? AND protocol='tcp'`,
			service, banner, boolInt(isWeb), boolInt(tls), targetID, item.IP, item.Port)
		if isWeb {
			s.probeNetworkHTTP(targetID, item.IP, item.Port, tls)
		}
		s.probeKnownExposures(ctx, targetID, item.IP, item.Port, service)
	}
}

// probeKnownExposures checks a freshly-fingerprinted service for a well-known,
// zero-FP, no-credential-guessing exposure: anonymous FTP and unauthenticated
// Redis. Both are PUBLIC server conventions, not a credential guess — RFC 1635
// defines "anonymous" as a documented, non-secret FTP login, and a Redis
// instance with no password configured accepts commands from anyone by design
// — so neither needs the opt-in credential-audit authorization the
// network_brute_* modules require. Confirmed by the exact same deterministic
// protocol logic as the brute-force checkers (see network_brute.go); never a
// guess, never ambiguous.
func (s *NetworkScanner) probeKnownExposures(ctx context.Context, targetID, ip string, port int, service string) {
	switch strings.ToLower(service) {
	case "ftp":
		if ftpLoginSucceeds(ctx, ip, port, "anonymous", "anonymous@reconner.local") {
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			s.storeNetworkFinding(ctx, targetID, "network_ftp_anonymous_access", "high", addr,
				"ftp "+addr+"  (USER anonymous / PASS anonymous@reconner.local)",
				"Anonymous FTP access is enabled — confirmed by the server's own 230 (user logged in) reply to the standard anonymous login (RFC 1635). Anyone can authenticate without a credential; review what the anonymous account can read/write and disable it if unneeded.")
		}
	case "redis":
		if ok, info := redisUnauthenticatedAccess(ctx, ip, port); ok {
			addr := net.JoinHostPort(ip, strconv.Itoa(port))
			s.storeNetworkFinding(ctx, targetID, "network_redis_unauthenticated", "critical", addr,
				"redis-cli -h "+ip+" -p "+strconv.Itoa(port)+" INFO",
				"Redis accepted the INFO command with NO authentication at all ("+info+") — the instance has no password configured. Anyone who can reach this port has full read/write/eval access to the datastore. Set requirepass or bind it to a trusted network only.")
		}
	}
}

// redisUnauthenticatedAccess sends INFO without AUTH and confirms success by
// TWO independent fields the response always carries (redis_version + run_id),
// so a stray "redis_version" substring in an unrelated banner can never match
// alone.
func redisUnauthenticatedAccess(ctx context.Context, ip string, port int) (bool, string) {
	conn, err := (&net.Dialer{Timeout: netDialTimeout}).DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return false, ""
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(netDialTimeout))
	if _, err := conn.Write([]byte("*1\r\n$4\r\nINFO\r\n")); err != nil {
		return false, ""
	}
	body, _ := io.ReadAll(io.LimitReader(conn, 64*1024))
	s := string(body)
	if strings.Contains(s, "redis_version:") && strings.Contains(s, "run_id:") {
		if m := regexp.MustCompile(`redis_version:(\S+)`).FindStringSubmatch(s); m != nil {
			return true, "redis_version " + m[1]
		}
		return true, "redis_version present"
	}
	return false, ""
}

// storeNetworkFinding is store() for the network pipeline's own zero-FP
// detections — same canonical DetectorObservation path every other detector in
// Reconner uses.
func (s *NetworkScanner) storeNetworkFinding(ctx context.Context, targetID, vulnType, severity, addr, poc, evidence string) {
	_, _ = RecordDetectorObservation(ctx, s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: addr, Method: "TCP",
		Location: "service", Payload: poc, Evidence: evidence, Source: "network",
		DetectionMethod: "network:" + vulnType, Confidence: 100, Priority: 500, Verdict: VerifyVerified,
	})
}

func (s *NetworkScanner) probeNetworkHTTP(targetID, ip string, port int, tls bool) {
	scheme := "http"
	if tls {
		scheme = "https"
	}
	rawURL := scheme + "://" + net.JoinHostPort(ip, strconv.Itoa(port))
	client := &http.Client{Transport: sharedHTTPTransport, Timeout: 7 * time.Second, CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 3 || (len(via) > 0 && !strings.EqualFold(req.URL.Hostname(), via[0].URL.Hostname())) {
			return http.ErrUseLastResponse
		}
		return nil
	}}
	req, _ := http.NewRequest("GET", rawURL, nil)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	finalURL := rawURL
	if resp.Request != nil && resp.Request.URL != nil {
		finalURL = resp.Request.URL.String()
	}
	title := extractTitle(string(body))
	_, _ = s.db.Exec(`UPDATE network_services SET web_url=?,web_title=?,web_status=? WHERE target_id=? AND ip=? AND port=? AND protocol='tcp'`, finalURL, title, resp.StatusCode, targetID, ip, port)
	_, _ = s.db.Exec(`INSERT INTO http_services(id,target_id,url,status_code,title,server,source,last_seen)
		VALUES(?,?,?,?,?,?,'network',CURRENT_TIMESTAMP) ON CONFLICT(target_id,url) DO UPDATE SET status_code=excluded.status_code,title=excluded.title,server=excluded.server,last_seen=CURRENT_TIMESTAMP`,
		uuid.New().String(), targetID, finalURL, resp.StatusCode, title, resp.Header.Get("Server"))
}

func readTCPBanner(ctx context.Context, ip string, port int) string {
	d := net.Dialer{Timeout: 1500 * time.Millisecond}
	conn, err := d.DialContext(ctx, "tcp", net.JoinHostPort(ip, strconv.Itoa(port)))
	if err != nil {
		return ""
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(800 * time.Millisecond))
	line, _ := bufio.NewReader(io.LimitReader(conn, 1024)).ReadString('\n')
	return strings.TrimSpace(line)
}

func webService(port int, service, tunnel string) (bool, bool) {
	s := strings.ToLower(service + " " + tunnel)
	tls := strings.Contains(s, "ssl") || strings.Contains(s, "https") || port == 443 || port == 8443 || port == 9443
	web := strings.Contains(s, "http")
	if !web {
		switch port {
		case 80, 443, 3000, 5601, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090, 9200:
			web = true
		}
	}
	return web, tls
}

func serviceHint(port int) string {
	known := map[int]string{21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "domain", 80: "http", 110: "pop3", 135: "msrpc", 139: "netbios-ssn", 143: "imap", 389: "ldap", 443: "https", 445: "microsoft-ds", 1433: "ms-sql-s", 1521: "oracle", 2049: "nfs", 2375: "docker", 3306: "mysql", 3389: "ms-wbt-server", 5432: "postgresql", 5900: "vnc", 6379: "redis", 8080: "http-proxy", 9200: "http", 11211: "memcached", 27017: "mongodb"}
	return known[port]
}

func joinPorts(ports []int) string {
	sort.Ints(ports)
	parts := make([]string, len(ports))
	for i, p := range ports {
		parts[i] = strconv.Itoa(p)
	}
	return strings.Join(parts, ",")
}
func sortOpenPorts(items []networkOpenPort) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].IP == items[j].IP {
			return items[i].Port < items[j].Port
		}
		return items[i].IP < items[j].IP
	})
}
func boolInt(v bool) int {
	if v {
		return 1
	}
	return 0
}
