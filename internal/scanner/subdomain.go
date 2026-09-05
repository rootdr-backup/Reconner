package scanner

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/recon-platform/internal/config"
	"github.com/recon-platform/internal/database"
	"github.com/recon-platform/internal/tools"
	"github.com/recon-platform/pkg/logger"
)

type BroadcastFunc func(event string, data any)

type SubdomainScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewSubdomainScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *SubdomainScanner {
	return &SubdomainScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

func (s *SubdomainScanner) Run(ctx context.Context, targetID, domain string, logFn LogFunc) error {
	logFn("info", "subdomain_enum", fmt.Sprintf("Starting subdomain enumeration for %s", domain))
	// Seed the first scan from program/approved-asset metadata immediately. Later
	// scans additionally reuse paths and parameter terms learned by web crawling.
	buildAdaptiveWordlist(ctx, s.db, s.cfg, targetID, nil)

	found := make(map[string]bool)
	var legacyCandidates []string
	var mu sync.Mutex

	// Snapshot the subdomain count BEFORE this run so we can tell whether the run
	// surfaced genuinely NEW subdomains. Only a re-scan of an already-enumerated
	// target (startSubCount > 0) raises a "new subdomain" notification — the first
	// enumeration is all-new and would just spam the bell.
	startSubCount := s.countSubdomains(targetID)
	// Revalidate previously stored DNS names as well. Older Reconner releases
	// eagerly inserted every passive-source string before DNS proof, which could
	// leave tens of thousands of dead/wildcard names feeding later modules. A scan
	// on this release repairs that historical data in place.
	if rows, err := s.db.QueryContext(ctx, `SELECT subdomain FROM subdomains
		WHERE target_id=? AND COALESCE(source,'dns') NOT IN ('seed','vhost')`, targetID); err == nil {
		for rows.Next() {
			var name string
			if rows.Scan(&name) == nil && isValidSubdomain(name, domain) {
				legacyCandidates = append(legacyCandidates, name)
			}
		}
		rows.Close()
	}

	// Detect wildcard DNS up front so we can flag fake passive subdomains.
	wildcardIPs, wildcardCNAMEs := detectWildcard(domain)
	if len(wildcardIPs) > 0 || len(wildcardCNAMEs) > 0 {
		logFn("warn", "subdomain_enum", fmt.Sprintf("Wildcard DNS detected (%d IPs) — passive results will be verified by resolution", len(wildcardIPs)))
	}

	// Discovery and admission are deliberately separate. Passive tools are allowed
	// to be noisy, but their strings remain in-memory candidates until the batched
	// DNS gate proves A/AAAA/CNAME evidence. This is the choke point that prevents
	// junk names from entering HTTP/JS/vulnerability pipelines.
	storeNew := func(sub string) {
		mu.Lock()
		found[sub] = true
		mu.Unlock()
	}
	// countFound reads the map size under the lock — the concurrent passive-source
	// goroutines below must NOT read len(found) directly or it's a data race
	// (concurrent map read + write) that can crash the process.
	countFound := func() int {
		mu.Lock()
		defer mu.Unlock()
		return len(found)
	}

	// Passive HTTP sources (crt.sh, certspotter, …) are fast and reliable and do
	// NOT need API keys or external binaries. Launch them CONCURRENTLY up front so
	// results start landing within seconds — instead of waiting for the sequential
	// CLI tools below (which can burn ~15 min and, on some domains/environments,
	// return nothing). We only srcWg.Wait() later, before the resolution pass, so
	// these goroutines run alongside the whole CLI-tool phase.
	type passiveSrc struct {
		name string
		fn   func(string) ([]string, error)
	}
	sources := []passiveSrc{
		{"crt.sh", queryCRTSH},
		{"certspotter", queryCertSpotter},
		{"hackertarget", queryHackerTarget},
		{"rapiddns", queryRapidDNS},
		{"otx", queryOTX},
		{"anubis", queryAnubis},
		{"urlscan", queryURLScan},
	}
	var srcWg sync.WaitGroup
	for _, src := range sources {
		srcWg.Add(1)
		go func(name string, fn func(string) ([]string, error)) {
			defer srcWg.Done()
			logFn("info", "subdomain_enum", fmt.Sprintf("Querying %s...", name))
			subs, err := fn(domain)
			if err != nil {
				// A source being rate-limited/blocked is normal and not actionable
				// — log it quietly (info) so it doesn't look like a real failure.
				lvl := "warn"
				if errors.Is(err, errSourceUnavailable) {
					lvl = "info"
				}
				logFn(lvl, "subdomain_enum", fmt.Sprintf("%s: %v", name, err))
				return
			}
			added := 0
			for _, sub := range subs {
				clean := strings.ToLower(strings.TrimSpace(sub))
				if isValidSubdomain(clean, domain) {
					storeNew(clean)
					added++
				}
			}
			logFn("info", "subdomain_enum", fmt.Sprintf("%s: +%d, total: %d", name, added, countFound()))
		}(src.name, src.fn)
	}

	// subfinder — try plain text first (most compatible). -all enables every
	// keyless source (crt.sh, wayback, etc.) so large domains still yield results
	// even without provider API keys.
	if s.exec.IsToolAvailable("subfinder") {
		logFn("info", "subdomain_enum", "Running subfinder...")
		before := countFound()
		tctx, tcancel := context.WithTimeout(ctx, 4*time.Minute)
		err := s.exec.RunWithCallback(tctx, targetID, func(line string) {
			line = strings.ToLower(strings.TrimSpace(line))
			// skip lines that look like status messages
			if line == "" || strings.Contains(line, "[") || strings.Contains(line, ":") {
				return
			}
			if isValidSubdomain(line, domain) {
				storeNew(line)
			}
		}, "subfinder", "-d", domain, "-silent", "-all")
		tcancel()
		// subfinder exits with status 1 when no API keys configured — ignore.
		// Only bail if the PARENT ctx was cancelled (real cancel), not our tool
		// timeout.
		if err != nil && ctx.Err() != nil {
			return ctx.Err()
		}
		if tctx.Err() == context.DeadlineExceeded {
			logFn("warn", "subdomain_enum", fmt.Sprintf("subfinder hit its 4m budget — %d found so far, likely PARTIAL for a large domain", countFound()-before))
		} else {
			logFn("info", "subdomain_enum", fmt.Sprintf("subfinder found %d subdomains", countFound()-before))
		}
	}
	// amass removed by design: it's the slowest passive source and added ~0 new
	// subdomains on real targets (subfinder + assetfinder + findomain + passive
	// sources cover the same surface far faster).

	// assetfinder
	if s.exec.IsToolAvailable("assetfinder") {
		logFn("info", "subdomain_enum", "Running assetfinder...")
		before := countFound()
		tctx, tcancel := context.WithTimeout(ctx, 2*time.Minute)
		result, err := s.exec.Run(tctx, "assetfinder", "--subs-only", domain)
		tcancel()
		if err == nil {
			sc := bufio.NewScanner(strings.NewReader(result.Stdout))
			for sc.Scan() {
				line := strings.ToLower(strings.TrimSpace(sc.Text()))
				if isValidSubdomain(line, domain) {
					storeNew(line)
				}
			}
		}
		if tctx.Err() == context.DeadlineExceeded {
			logFn("warn", "subdomain_enum", fmt.Sprintf("assetfinder hit its 2m budget — %d found so far, likely PARTIAL for a large domain", countFound()-before))
		} else {
			logFn("info", "subdomain_enum", fmt.Sprintf("assetfinder found %d new subdomains", countFound()-before))
		}
	}

	// findomain
	if s.exec.IsToolAvailable("findomain") {
		logFn("info", "subdomain_enum", "Running findomain...")
		before := countFound()
		tctx, tcancel := context.WithTimeout(ctx, 2*time.Minute)
		err := s.exec.RunWithCallback(tctx, targetID, func(line string) {
			line = strings.ToLower(strings.TrimSpace(line))
			if isValidSubdomain(line, domain) {
				storeNew(line)
			}
		}, "findomain", "-t", domain, "-q")
		tcancel()
		if err != nil && ctx.Err() == nil {
			s.logger.Debug("findomain error", "error", err)
		}
		if tctx.Err() == context.DeadlineExceeded {
			logFn("warn", "subdomain_enum", fmt.Sprintf("findomain hit its 2m budget — %d found so far, likely PARTIAL for a large domain", countFound()-before))
		} else {
			logFn("info", "subdomain_enum", fmt.Sprintf("findomain found %d new subdomains", countFound()-before))
		}
	}

	// scilla — extra passive/DNS subdomain source (edoardottt/scilla). Graceful
	// no-op when not installed. Parses hostnames out of its plain output.
	if s.exec.IsToolAvailable("scilla") {
		logFn("info", "subdomain_enum", "Running scilla...")
		before := countFound()
		tctx, tcancel := context.WithTimeout(ctx, 3*time.Minute)
		err := s.exec.RunWithCallback(tctx, targetID, func(line string) {
			line = strings.ToLower(strings.TrimSpace(line))
			// scilla decorates some lines; keep only things that look like a host
			// under the target domain.
			line = strings.TrimPrefix(line, "http://")
			line = strings.TrimPrefix(line, "https://")
			if i := strings.IndexAny(line, "/ \t"); i >= 0 {
				line = line[:i]
			}
			if isValidSubdomain(line, domain) {
				storeNew(line)
			}
		}, "scilla", "subdomain", "-target", domain, "-no-color")
		tcancel()
		if err != nil && ctx.Err() == nil {
			s.logger.Debug("scilla error", "error", err)
		}
		if tctx.Err() == context.DeadlineExceeded {
			logFn("warn", "subdomain_enum", fmt.Sprintf("scilla hit its 3m budget — %d found so far, likely PARTIAL for a large domain", countFound()-before))
		} else {
			logFn("info", "subdomain_enum", fmt.Sprintf("scilla found %d new subdomains", countFound()-before))
		}
	}

	// waybackurls for subdomain extraction
	if s.exec.IsToolAvailable("waybackurls") {
		logFn("info", "subdomain_enum", "Querying Wayback Machine...")
		tctx, tcancel := context.WithTimeout(ctx, 3*time.Minute)
		result, err := s.exec.Run(tctx, "waybackurls", domain)
		tcancel()
		if err == nil {
			sc := bufio.NewScanner(strings.NewReader(result.Stdout))
			for sc.Scan() {
				if sub := extractSubdomain(sc.Text(), domain); sub != "" {
					storeNew(sub)
				}
			}
		}
		if tctx.Err() == context.DeadlineExceeded {
			logFn("warn", "subdomain_enum", fmt.Sprintf("waybackurls hit its 3m budget — PARTIAL results, total so far: %d", countFound()))
		} else {
			logFn("info", "subdomain_enum", fmt.Sprintf("waybackurls added, total: %d", countFound()))
		}
	}

	// gau for subdomain extraction
	if s.exec.IsToolAvailable("gau") {
		logFn("info", "subdomain_enum", "Querying GAU (GetAllURLs)...")
		tctx, tcancel := context.WithTimeout(ctx, 3*time.Minute)
		result, err := s.exec.Run(tctx, "gau", "--subs", domain)
		tcancel()
		if err == nil {
			sc := bufio.NewScanner(strings.NewReader(result.Stdout))
			for sc.Scan() {
				if sub := extractSubdomain(sc.Text(), domain); sub != "" {
					storeNew(sub)
				}
			}
		}
		if tctx.Err() == context.DeadlineExceeded {
			logFn("warn", "subdomain_enum", fmt.Sprintf("gau hit its 3m budget — PARTIAL results, total so far: %d", countFound()))
		} else {
			logFn("info", "subdomain_enum", fmt.Sprintf("gau added, total: %d", countFound()))
		}
	}

	// Wait for the passive HTTP sources launched up front to finish before the
	// resolution pass (they've been running concurrently with the CLI tools).
	srcWg.Wait()

	// Active enumeration: brute-force a built-in wordlist + permutations of
	// already-discovered names. No external tools required; only names that
	// actually resolve (and aren't wildcard answers) are kept.
	//
	// This brute/permutation phase (plus the deep alterx/puredns pass below) is by
	// far the slowest part of enumeration, so it is per-scan toggleable: when the
	// operator disables it in the scan menu, only passive discovery + resolution +
	// ASN/vhost run, which is dramatically faster.
	if subdomainBruteEnabled(ctx) {
		s.activeEnum(ctx, targetID, domain, found, &mu, wildcardIPs, logFn)

		// Deeper DNS discovery (optional, graceful): alterx permutations +
		// puredns/massdns brute at scale. No-op when those tools aren't installed.
		s.deepDNSEnum(ctx, targetID, domain, found, &mu, wildcardIPs, logFn)
	} else {
		logFn("info", "subdomain_enum", "Permutation brute-force disabled for this scan — passive discovery + resolution only.")
	}

	// ASN ownership does not imply bug-bounty scope. Run the reverse sweep only
	// when the operator explicitly left it enabled for this scan.
	if asnDiscoveryEnabled(ctx) {
		s.asnDiscovery(ctx, targetID, domain, found, &mu, logFn)
	} else {
		logFn("info", "subdomain_enum", "ASN/CIDR discovery skipped — enable it only after program-scope/WHOIS verification.")
	}
	// Historical eager rows are revalidated, but deliberately merged only after
	// permutation generation so 20k old junk labels cannot explode into hundreds
	// of thousands of new mutations.
	mu.Lock()
	for _, name := range legacyCandidates {
		found[name] = true
	}
	mu.Unlock()

	// Parallel admission pass. It returns candidates that had neither a genuine
	// A/AAAA answer nor an explicit CNAME; wildcard-only answers remain eligible
	// for vhost proof but are not assets yet.
	rejected := s.resolveAll(ctx, targetID, found, &mu, wildcardIPs, wildcardCNAMEs, logFn)

	// Virtual-host scan: probe candidate hostnames (that do NOT resolve in DNS)
	// against the IPs we already know, via the Host header, and record any that
	// the server actually serves — internal/forgotten vhosts DNS enumeration
	// can't see. Stored with source='vhost' so the UI can flag them.
	s.vhostScan(ctx, targetID, domain, found, &mu, wildcardIPs, logFn)

	// Vhost verification had the final chance to promote wildcard/unresolved names.
	// Remove only old eager-DNS rows which still lack evidence; explicit seeds,
	// CNAME records and browser/server-proven vhosts are preserved.
	s.pruneRejectedSubdomains(ctx, targetID, rejected)

	logFn("info", "subdomain_enum", fmt.Sprintf("Subdomain enumeration complete. %d verified assets stored from %d discovered candidates.", s.countSubdomains(targetID), countFound()))

	// Notify on genuinely new subdomains (re-scan only — see startSubCount above).
	if startSubCount > 0 {
		if end := s.countSubdomains(targetID); end > startSubCount {
			n := end - startSubCount
			notify(s.db, targetID, "new_subdomain", notificationTitle("new_subdomain"),
				fmt.Sprintf("%d new subdomain(s) found on %s", n, domain), domain, "medium")
		}
	}
	return nil
}

// countSubdomains returns how many subdomains are currently stored for a target.
func (s *SubdomainScanner) countSubdomains(targetID string) int {
	var n int
	_ = s.db.QueryRow("SELECT COUNT(*) FROM subdomains WHERE target_id = ?", targetID).Scan(&n)
	return n
}

// vhostWordlist — common internal/forgotten virtual-host prefixes worth probing
// against a known IP even when they don't resolve in DNS.
var vhostWordlist = []string{
	"admin", "internal", "intranet", "dev", "development", "staging", "stage",
	"test", "testing", "uat", "qa", "preprod", "beta", "demo", "api", "api-internal",
	"portal", "dashboard", "panel", "console", "manage", "management", "vpn",
	"git", "gitlab", "jenkins", "ci", "grafana", "kibana", "prometheus", "jira",
	"confluence", "backup", "old", "legacy", "corp", "private", "secure", "auth",
	"sso", "login", "monitor", "status", "metrics", "db", "phpmyadmin", "adminer",
}

// vhostBaselineSamples is how many DISTINCT bogus hosts we probe per IP to
// characterise its default response. One sample cannot tell a stable default
// apart from a catch-all whose length merely fluctuates — the exact flaw that
// flagged an entire wordlist on one AWS IP for ewa.bh. Three samples give us a
// baseline BAND and a read on the server's own variability.
const vhostBaselineSamples = 3

// vhostCatchAllPct — if at least this share of the probed candidates "match",
// the IP is almost certainly a catch-all/default backend (no real target exposes
// half a generic wordlist of admin panels), so all of its vhost hits are
// discarded. A final backstop for catch-alls the baseline-band check misses.
const vhostCatchAllPct = 35

type vhostProbe struct {
	status  int
	length  int // raw body length
	normLen int // body length with the requested Host string neutralised
}

// vhostMatch is a candidate that passed the per-response distinctness check,
// held until the per-IP catch-all guards decide whether to commit it.
type vhostMatch struct {
	host  string
	probe vhostProbe
}

var vhostPlainClient = &http.Client{
	Timeout: 7 * time.Second,
	Transport: identityRoundTripper{base: &http.Transport{
		MaxIdleConns:        128,
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     30 * time.Second,
	}},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

// probeVhost fetches scheme://ip/ with an explicit Host header. It returns both
// the raw body length and a NORMALISED length: the body with every occurrence of
// the requested hostname removed. A server that echoes the Host into its body
// (canonical link, <title>, a redirect URL) makes each candidate's raw length
// differ purely by the length of its own name — a reflected-Host false positive.
// Comparing on normLen cancels that out, so only REAL template differences count.
func probeVhost(ctx context.Context, scheme, ip, host string) (vhostProbe, bool) {
	rctx, cancel := context.WithTimeout(ctx, 7*time.Second)
	defer cancel()
	if scheme == "http" {
		urlHost := ip
		if net.ParseIP(ip) != nil && strings.Contains(ip, ":") {
			urlHost = "[" + ip + "]"
		}
		req, err := http.NewRequestWithContext(rctx, "GET", "http://"+urlHost+"/", nil)
		if err != nil {
			return vhostProbe{}, false
		}
		req.Host = host
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
		resp, err := vhostPlainClient.Do(req)
		if err != nil {
			return vhostProbe{}, false
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
		norm := strings.ReplaceAll(strings.ToLower(string(b)), strings.ToLower(host), "")
		return vhostProbe{status: resp.StatusCode, length: len(b), normLen: len(norm)}, true
	}
	targetAddr := ip
	if _, _, err := net.SplitHostPort(ip); err != nil {
		port := "80"
		if scheme == "https" {
			port = "443"
		}
		targetAddr = net.JoinHostPort(ip, port)
	}
	dialer := &net.Dialer{Timeout: 6 * time.Second}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return dialer.DialContext(dialCtx, network, targetAddr)
		},
	}
	client := &http.Client{Timeout: 7 * time.Second, Transport: identityRoundTripper{base: transport},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer transport.CloseIdleConnections()
	// Put the candidate in the URL as well as Request.Host. The custom dialer
	// still connects to the known IP, while TLS now sends candidate-host SNI —
	// essential for HTTPS virtual hosts that reject an IP-valued SNI handshake.
	req, err := http.NewRequestWithContext(rctx, "GET", scheme+"://"+host+"/", nil)
	if err != nil {
		return vhostProbe{}, false
	}
	req.Host = host // routes the virtual host
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; Reconner/1.0)")
	resp, err := client.Do(req)
	if err != nil {
		return vhostProbe{}, false
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	norm := strings.ReplaceAll(strings.ToLower(string(b)), strings.ToLower(host), "")
	return vhostProbe{status: resp.StatusCode, length: len(b), normLen: len(norm)}, true
}

// vhostScan discovers virtual hosts served on the target's known IPs. For each
// IP it establishes a baseline with a bogus Host, then tries candidate hostnames
// (a builtin wordlist under the target domain, plus already-found names) that do
// NOT resolve in DNS. A candidate whose response differs meaningfully from the
// baseline is a real vhost and is stored with source='vhost'.
func (s *SubdomainScanner) vhostScan(ctx context.Context, targetID, domain string, found map[string]bool, mu *sync.Mutex, wildcardIPs map[string]bool, logFn LogFunc) {
	if ctx.Err() != nil {
		return
	}
	// Distinct known IPs (cap to keep the pass bounded).
	rows, err := s.db.QueryContext(ctx,
		`SELECT DISTINCT ip FROM subdomains
		 WHERE target_id=? AND ip!='' AND (subdomain=? OR subdomain LIKE ?)
		 LIMIT 40`, targetID, domain, "%."+domain)
	if err != nil {
		return
	}
	var ips []string
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			ips = append(ips, ip)
		}
	}
	rows.Close()
	// Wildcard DNS IPs may not belong to any admitted subdomain yet; they are
	// nevertheless exactly where Host-header discovery is most valuable.
	ipSeen := map[string]bool{}
	for _, ip := range ips {
		ipSeen[ip] = true
	}
	for ip := range wildcardIPs {
		if !ipSeen[ip] {
			ips = append(ips, ip)
			ipSeen[ip] = true
		}
	}
	if len(ips) == 0 {
		return
	}

	// Candidate hostnames: wordlist·domain + already-found names, deduped, capped.
	seen := map[string]bool{}
	var candidates []string
	add := func(h string) {
		h = strings.ToLower(strings.TrimSpace(h))
		if h == "" || seen[h] || !isValidSubdomain(h, domain) {
			return
		}
		seen[h] = true
		candidates = append(candidates, h)
	}
	for _, p := range vhostWordlist {
		add(p + "." + domain)
	}
	for _, p := range devToolWords {
		add(p + "." + domain)
	}
	if len(wildcardIPs) > 0 {
		// DNS brute-force is meaningless on a wildcard zone, but the same adaptive
		// names are valuable Host-header candidates. Feed a bounded slice into the
		// differential vhost verifier instead of accepting their wildcard DNS answer.
		words := s.deepDNSWords(ctx, domain, nil)
		if len(words) > 650 {
			words = words[:650]
		}
		for _, p := range words {
			add(p + "." + domain)
		}
	}
	mu.Lock()
	known := make([]string, 0, len(found))
	for n := range found {
		known = append(known, n)
	}
	mu.Unlock()
	// Map iteration order used to make the 200-name cap random. Stable ordering
	// keeps curated tool/dev words first and makes large-target runs reproducible.
	sort.Strings(known)
	for _, n := range known {
		add(n)
	}
	const vhostCandidateCap = 800
	if len(candidates) > vhostCandidateCap {
		logFn("warn", "vhost", fmt.Sprintf("vhost candidate cap hit: %d candidates; prioritising the curated/tool names and first %d stable candidates", len(candidates), vhostCandidateCap))
		candidates = candidates[:vhostCandidateCap]
	}

	// Probe names DNS cannot distinguish: NXDOMAIN/no-address candidates and names
	// whose only address is the wildcard answer. Ordinary independently-resolving
	// hosts are already admitted and do not need expensive Host-header probing.
	probeHosts := classifyVhostCandidates(ctx, candidates, wildcardIPs)

	logFn("info", "vhost", fmt.Sprintf("Virtual-host scan: %d IP(s) × %d candidate host(s)...", len(ips), len(probeHosts)))

	sem := make(chan struct{}, 12)
	discovered := 0

	for _, ip := range ips {
		if ctx.Err() != nil {
			break
		}

		// ── Multi-sample baseline ────────────────────────────────────────────
		// Characterise the IP's default response with several DISTINCT bogus hosts.
		// A single sample cannot distinguish a genuine per-host app from a catch-all
		// whose length merely fluctuates request-to-request; three give a baseline
		// BAND plus a read on the server's own variability.
		scheme := "https"
		var bases []vhostProbe
		for i := 0; i < vhostBaselineSamples; i++ {
			bogus := fmt.Sprintf("rcnb%d%d.%s", time.Now().UnixNano()%1000000, i, domain)
			bp, ok := probeVhost(ctx, scheme, ip, bogus)
			if !ok && i == 0 {
				scheme = "http"
				bp, ok = probeVhost(ctx, scheme, ip, bogus)
			}
			if ok {
				bases = append(bases, bp)
			}
		}
		if len(bases) == 0 {
			continue
		}

		baseStatus := bases[0].status
		minNorm, maxNorm := bases[0].normLen, bases[0].normLen
		stableStatus := true
		for _, b := range bases {
			if b.status/100 != baseStatus/100 {
				stableStatus = false
			}
			if b.normLen < minNorm {
				minNorm = b.normLen
			}
			if b.normLen > maxNorm {
				maxNorm = b.normLen
			}
		}
		margin := maxNorm * 8 / 100
		if margin < 512 {
			margin = 512
		}

		// ── Catch-all / instability guard ────────────────────────────────────
		// If the bogus baselines already disagree in status class, or their own
		// (host-neutralised) length band is wider than the margin, then the server
		// answers every Host with a same-ish, fluctuating page. The "length differs
		// from baseline ⇒ vhost" signal is worthless here and would flag the whole
		// wordlist — skip the IP entirely. (This is the ewa.bh / 34.254.208.11 case.)
		if !stableStatus || maxNorm-minNorm > margin {
			logFn("info", "vhost", fmt.Sprintf(
				"Skipping vhost detection on %s: catch-all/unstable default response (baseline length varies by %d bytes across probes) — length signal unreliable, would produce false positives",
				ip, maxNorm-minNorm))
			continue
		}

		// ── Phase 1: collect distinct candidates ─────────────────────────────
		var mmu sync.Mutex
		var matches []vhostMatch
		var wg sync.WaitGroup
		for _, host := range probeHosts {
			if ctx.Err() != nil {
				break
			}
			wg.Add(1)
			sem <- struct{}{}
			go func(host string) {
				defer wg.Done()
				defer func() { <-sem }()
				p, ok := probeVhost(ctx, scheme, ip, host)
				if !ok || !vhostDistinctBand(baseStatus, minNorm, maxNorm, margin, p) {
					return
				}
				// A real routing decision is reproducible. Re-probe before admitting the
				// asset so a transient 5xx, rotating error page or WAF challenge cannot
				// turn one noisy response into a vhost and trigger the whole pipeline.
				confirm, ok := probeVhost(ctx, scheme, ip, host)
				if !ok || !vhostDistinctBand(baseStatus, minNorm, maxNorm, margin, confirm) ||
					confirm.status/100 != p.status/100 || absInt(confirm.normLen-p.normLen) > margin {
					return
				}
				mmu.Lock()
				matches = append(matches, vhostMatch{host: host, probe: confirm})
				mmu.Unlock()
			}(host)
		}
		wg.Wait()

		// ── Phase 2: catch-all-by-volume backstop ────────────────────────────
		// Even with a stable baseline, a catch-all can echo the Host so consistently
		// that many names clear the band. No real host serves a third of a generic
		// admin wordlist — that ratio itself is the tell. Discard the whole IP.
		if len(probeHosts) > 0 && len(matches)*100/len(probeHosts) >= vhostCatchAllPct {
			logFn("info", "vhost", fmt.Sprintf(
				"Skipping vhost results on %s: %d/%d candidates matched (%d%%) — that ratio indicates a catch-all/default vhost, not real hosts; discarding to avoid false positives",
				ip, len(matches), len(probeHosts), len(matches)*100/len(probeHosts)))
			continue
		}

		// ── Phase 3: commit the survivors ────────────────────────────────────
		for _, m := range matches {
			if ctx.Err() != nil {
				break
			}
			if s.upsertVhost(targetID, m.host, ip) {
				discovered++
				logFn("warn", "vhost", fmt.Sprintf("Virtual host found: %s on %s (status %d, len %d vs baseline band %d–%d)", m.host, ip, m.probe.status, m.probe.length, minNorm, maxNorm))
				if s.broadcast != nil {
					s.broadcast("new_subdomain", map[string]any{"target_id": targetID, "subdomain": m.host, "ip": ip, "source": "vhost"})
				}
			}
		}
	}
	logFn("info", "vhost", fmt.Sprintf("Virtual-host scan done. %d vhost(s) discovered.", discovered))
}

func classifyVhostCandidates(ctx context.Context, candidates []string, wildcardIPs map[string]bool) []string {
	if len(candidates) == 0 {
		return nil
	}
	workers := 32
	if len(candidates) < workers {
		workers = len(candidates)
	}
	jobs := make(chan string)
	hits := make(chan string, len(candidates))
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for host := range jobs {
				ips := resolveHostIPs(ctx, host)
				if len(ips) == 0 || overlapsWildcardIPs(ips, wildcardIPs) {
					hits <- host
				}
			}
		}()
	}
	for _, host := range candidates {
		if ctx.Err() != nil {
			break
		}
		jobs <- host
	}
	close(jobs)
	wg.Wait()
	close(hits)
	var out []string
	for host := range hits {
		out = append(out, host)
	}
	sort.Strings(out)
	return out
}

func absInt(n int) int {
	if n < 0 {
		return -n
	}
	return n
}

// vhostDistinctBand decides whether a candidate response is a real, different
// virtual host vs the IP's default-response BAND [minNorm, maxNorm]. A different
// status class, or a host-neutralised length outside the band by more than the
// margin, counts. Comparing against the band (not a single baseline) plus using
// normLen (not raw length) is what stops catch-all/host-reflection floods.
func vhostDistinctBand(baseStatus, minNorm, maxNorm, margin int, cand vhostProbe) bool {
	// A candidate that just 404s/400s like the baseline is not a vhost.
	if cand.status >= 400 && cand.status == baseStatus {
		return false
	}
	if cand.status/100 != baseStatus/100 {
		return true
	}
	return cand.normLen < minNorm-margin || cand.normLen > maxNorm+margin
}

// upsertVhost inserts a vhost-discovered host with source='vhost'. On conflict it
// does NOT downgrade a host already known via DNS — vhost marks only names DNS
// couldn't see. Returns true when a NEW vhost row was created.
func (s *SubdomainScanner) upsertVhost(targetID, subdomain, ip string) bool {
	id := uuid.New().String()
	res, err := s.db.Exec(`
		INSERT INTO subdomains (id, target_id, subdomain, ip, source, last_seen)
		VALUES (?, ?, ?, ?, 'vhost', CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, subdomain) DO UPDATE SET
			ip=excluded.ip, source='vhost', last_seen=CURRENT_TIMESTAMP
		WHERE COALESCE(subdomains.source,'dns') NOT IN ('seed','vhost')`,
		id, targetID, subdomain, ip)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n > 0
}

// asnDiscovery uses asnmap to map the target's ASN/CIDR ranges, then does a
// bounded reverse-DNS sweep to surface hosts that share the org's netblocks.
// No-op when asnmap isn't installed.
func (s *SubdomainScanner) asnDiscovery(ctx context.Context, targetID, domain string, found map[string]bool, mu *sync.Mutex, logFn LogFunc) {
	if !s.exec.IsToolAvailable("asnmap") {
		return
	}
	logFn("info", "subdomain_enum", "Discovering ASN / IP ranges via asnmap...")

	var cidrs []string
	cidrSeen := map[string]bool{}
	err := s.exec.RunWithCallback(ctx, targetID, func(line string) {
		for _, field := range strings.FieldsFunc(line, func(r rune) bool {
			return r == ' ' || r == '\t' || r == ',' || r == '[' || r == ']' || r == '"'
		}) {
			field = strings.TrimSpace(field)
			if _, _, parseErr := net.ParseCIDR(field); parseErr == nil && !cidrSeen[field] && len(cidrs) < 64 {
				cidrSeen[field] = true
				cidrs = append(cidrs, field)
			}
		}
	}, "asnmap", "-d", domain, "-silent")
	if err != nil && ctx.Err() != nil {
		return
	}
	if len(cidrs) == 0 {
		return
	}
	logFn("info", "subdomain_enum", fmt.Sprintf("Found %d CIDR ranges for %s", len(cidrs), domain))

	// Reverse-DNS sweep, bounded to keep it light (max 1024 IPs per range).
	var ipList []string
	for _, cidr := range cidrs {
		ip, ipnet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue
		}
		count := 0
		for cur := ip.Mask(ipnet.Mask); ipnet.Contains(cur) && count < 1024; incIP(cur) {
			ipList = append(ipList, cur.String())
			count++
		}
	}

	workers := s.cfg.Workers.SubdomainEnumeration
	if workers <= 0 {
		workers = 20
	}
	jobs := make(chan string, len(ipList))
	var wg sync.WaitGroup
	var newFound int
	var cmu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ipStr := range jobs {
				if ctx.Err() != nil {
					return
				}
				rc, cancel := context.WithTimeout(ctx, 3*time.Second)
				names, err := net.DefaultResolver.LookupAddr(rc, ipStr)
				cancel()
				if err != nil {
					continue
				}
				for _, name := range names {
					name = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(name), "."))
					if !isValidSubdomain(name, domain) {
						continue
					}
					mu.Lock()
					isNew := !found[name]
					found[name] = true
					mu.Unlock()
					_ = s.upsertSubdomain(targetID, name, ipStr)
					if isNew {
						cmu.Lock()
						newFound++
						cmu.Unlock()
					}
				}
			}
		}()
	}
	for _, ip := range ipList {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()

	logFn("info", "subdomain_enum", fmt.Sprintf("ASN sweep: reverse-resolved %d IPs, found %d in-scope hosts", len(ipList), newFound))
}

func incIP(ip net.IP) {
	for j := len(ip) - 1; j >= 0; j-- {
		ip[j]++
		if ip[j] > 0 {
			break
		}
	}
}

// bruteWords is a compact high-hit-rate wordlist for active discovery.
var bruteWords = []string{
	"www", "api", "dev", "staging", "stage", "test", "testing", "uat", "qa",
	"admin", "administrator", "portal", "dashboard", "app", "apps", "mobile",
	"m", "beta", "alpha", "demo", "internal", "int", "corp", "vpn", "remote",
	"mail", "smtp", "imap", "pop", "webmail", "email", "mx", "ns1", "ns2",
	"dns", "ftp", "sftp", "git", "gitlab", "github", "jenkins", "ci", "cd",
	"jira", "confluence", "wiki", "docs", "support", "help", "status", "blog",
	"shop", "store", "pay", "payment", "payments", "checkout", "billing",
	"account", "accounts", "auth", "sso", "login", "oauth", "id", "identity",
	"cdn", "static", "assets", "img", "images", "media", "files", "download",
	"upload", "s3", "storage", "backup", "db", "database", "sql", "mysql",
	"postgres", "redis", "mongo", "elastic", "kibana", "grafana", "prometheus",
	"monitor", "monitoring", "metrics", "log", "logs", "logging", "kong",
	"gateway", "proxy", "lb", "k8s", "kube", "kubernetes", "docker", "registry",
	"dev-api", "api-dev", "api-staging", "staging-api", "api-v1", "api-v2",
	"v1", "v2", "v3", "old", "new", "legacy", "secure", "sec", "security",
	"partner", "partners", "client", "clients", "customer", "customers",
	"crm", "erp", "hr", "finance", "sales", "marketing", "analytics", "data",
	"ws", "websocket", "socket", "rpc", "grpc", "graphql", "rest", "soap",
	"preview", "sandbox", "playground", "lab", "labs", "research", "edge",
}

// permPrefixes/Suffixes drive permutation generation from known names.
var permPrefixes = []string{"dev", "staging", "test", "qa", "uat", "old", "new", "internal", "api", "admin"}
var permSuffixes = []string{"dev", "staging", "test", "v1", "v2", "v3", "old", "new", "internal", "api"}

func (s *SubdomainScanner) activeEnum(ctx context.Context, targetID, domain string, found map[string]bool, mu *sync.Mutex, wildcardIPs map[string]bool, logFn LogFunc) {
	// Skip active brute on wildcard domains (every name would "resolve").
	if len(wildcardIPs) > 0 {
		logFn("info", "subdomain_enum", "Wildcard domain — skipping active brute-force to avoid fake results")
		return
	}

	logFn("info", "subdomain_enum", "Starting active brute-force + permutation...")

	candidates := make(map[string]bool)
	for _, w := range bruteWords {
		candidates[w+"."+domain] = true
	}

	// Permute only already-admitted assets. Passive candidate strings have not
	// passed DNS proof yet and using a 20k junk feed as mutation seeds causes an
	// avoidable combinatorial explosion.
	existing := s.admittedSubdomainNames(ctx, targetID, domain)

	for _, name := range existing {
		if !strings.HasSuffix(name, "."+domain) {
			continue
		}
		label := strings.TrimSuffix(name, "."+domain)
		if strings.Contains(label, ".") {
			continue // only permute the left-most single-label names
		}
		for _, p := range permPrefixes {
			candidates[p+"-"+label+"."+domain] = true
			candidates[p+label+"."+domain] = true
		}
		for _, suf := range permSuffixes {
			candidates[label+"-"+suf+"."+domain] = true
			candidates[label+suf+"."+domain] = true
		}
	}

	// Drop names we already have.
	mu.Lock()
	for n := range found {
		delete(candidates, n)
	}
	mu.Unlock()

	names := make([]string, 0, len(candidates))
	for n := range candidates {
		names = append(names, n)
	}

	workers := s.cfg.Workers.SubdomainEnumeration
	if workers <= 0 {
		workers = 20
	}
	jobs := make(chan string, len(names))
	var wg sync.WaitGroup
	var newFound int
	var cmu sync.Mutex

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				if ctx.Err() != nil {
					return
				}
				ip := firstNonWildcardIP(resolveHostIPs(ctx, name), wildcardIPs)
				if ip == "" {
					continue
				}
				mu.Lock()
				isNew := !found[name]
				found[name] = true
				mu.Unlock()
				_ = s.upsertSubdomain(targetID, name, ip)
				if isNew {
					cmu.Lock()
					newFound++
					cmu.Unlock()
				}
			}
		}()
	}
	for _, n := range names {
		jobs <- n
	}
	close(jobs)
	wg.Wait()

	logFn("info", "subdomain_enum", fmt.Sprintf("Active enum: tested %d candidates, found %d new subdomains", len(names), newFound))
}

func (s *SubdomainScanner) admittedSubdomainNames(ctx context.Context, targetID, domain string) []string {
	rows, err := s.db.QueryContext(ctx, `SELECT subdomain FROM subdomains
		WHERE target_id=? AND (COALESCE(ip,'')!='' OR COALESCE(source,'dns') IN ('seed','vhost'))
		ORDER BY subdomain`, targetID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var name string
		if rows.Scan(&name) == nil && isValidSubdomain(name, domain) {
			out = append(out, name)
		}
	}
	return out
}

// resolveAll resolves every discovered subdomain concurrently and updates its
// IP. Names that resolve to a wildcard IP are kept but logged so HTTP probing
// can later dedupe them by content.
func (s *SubdomainScanner) resolveAll(ctx context.Context, targetID string, found map[string]bool, mu *sync.Mutex, wildcardIPs, wildcardCNAMEs map[string]bool, logFn LogFunc) map[string]bool {
	workers := s.cfg.Workers.SubdomainEnumeration
	if workers <= 0 {
		workers = 20
	}

	mu.Lock()
	names := make([]string, 0, len(found))
	for n := range found {
		names = append(names, n)
	}
	mu.Unlock()
	sort.Strings(names)

	jobs := make(chan string, len(names))
	var wg sync.WaitGroup
	var resolved, cnameOnly, wildcardHits, unresolved int
	var cmu sync.Mutex
	rejected := make(map[string]bool)
	cnameCandidates, cnamePrefilter := s.dnsxCNAMECandidates(ctx, targetID, names)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for name := range jobs {
				if ctx.Err() != nil {
					return
				}
				ips := resolveHostIPs(ctx, name)
				ip := firstNonWildcardIP(ips, wildcardIPs)
				if ip == "" {
					if len(ips) > 0 && overlapsWildcardIPs(ips, wildcardIPs) {
						cmu.Lock()
						rejected[name] = true
						wildcardHits++
						cmu.Unlock()
						continue
					}
					// A dangling but explicit CNAME is a real DNS asset and must remain
					// available to takeover checks, but it is not sent to the web pipeline.
					cname := ""
					if !cnamePrefilter || cnameCandidates[name] {
						cname = lookupExplicitCNAME(ctx, name)
					}
					if cname != "" && !wildcardCNAMEs[cname] {
						_ = s.upsertSubdomainSource(targetID, name, "", "dns-cname")
						cmu.Lock()
						cnameOnly++
						cmu.Unlock()
						continue
					}
					cmu.Lock()
					rejected[name] = true
					unresolved++
					cmu.Unlock()
					continue
				}
				cmu.Lock()
				resolved++
				cmu.Unlock()
				_ = s.upsertSubdomainSource(targetID, name, ip, "dns")
				if s.broadcast != nil {
					s.broadcast("new_subdomain", map[string]any{
						"target_id": targetID,
						"subdomain": name,
						"ip":        ip,
					})
				}
			}
		}()
	}

	for _, n := range names {
		jobs <- n
	}
	close(jobs)
	wg.Wait()

	logFn("info", "subdomain_enum", fmt.Sprintf("Admission gate: %d A/AAAA verified, %d explicit CNAME, %d wildcard-only, %d unresolved (from %d candidates)", resolved, cnameOnly, wildcardHits, unresolved, len(names)))
	return rejected
}

func (s *SubdomainScanner) dnsxCNAMECandidates(ctx context.Context, targetID string, names []string) (map[string]bool, bool) {
	if s.exec == nil || len(names) == 0 || !s.exec.IsToolAvailable("dnsx") {
		return nil, false
	}
	out := map[string]bool{}
	err := s.exec.RunWithInputCallback(ctx, strings.NewReader(strings.Join(names, "\n")), targetID,
		func(line string) {
			fields := strings.Fields(strings.ToLower(strings.TrimSpace(line)))
			if len(fields) > 0 {
				out[strings.TrimSuffix(fields[0], ".")] = true
			}
		}, "dnsx", "-silent", "-cname", "-retry", "1")
	if err != nil && ctx.Err() == nil {
		return nil, false
	}
	return out, true
}

// detectWildcard probes a few random hostnames; if they resolve, the shared
// IPs are wildcard answers we should treat with suspicion.
func detectWildcard(domain string) (map[string]bool, map[string]bool) {
	wildcardIPs := make(map[string]bool)
	wildcardCNAMEs := make(map[string]bool)
	probes := []string{
		"zz9z3k7q1wildcard." + domain,
		"qx84jd02noexist." + domain,
		"a1b2c3d4e5random." + domain,
		"rcn7f4a9neverexists." + domain,
		"nohost2c8e1b6d." + domain,
	}
	resolvedProbes := 0
	allIPs := map[string]bool{}
	cnameCounts := map[string]int{}
	type wildcardProbeResult struct {
		ips   []net.IPAddr
		cname string
	}
	results := make(chan wildcardProbeResult, len(probes))
	var wg sync.WaitGroup
	for _, p := range probes {
		wg.Add(1)
		go func(name string) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			ips, _ := net.DefaultResolver.LookupIPAddr(ctx, name)
			cancel()
			results <- wildcardProbeResult{ips: ips, cname: lookupExplicitCNAME(context.Background(), name)}
		}(p)
	}
	wg.Wait()
	close(results)
	for result := range results {
		if result.cname != "" {
			cnameCounts[result.cname]++
		}
		if len(result.ips) > 0 {
			resolvedProbes++
		}
		for _, ip := range result.ips {
			value := ip.IP.String()
			if value != "" {
				allIPs[value] = true
			}
		}
	}
	// Require at least three independent random labels to resolve, then retain the
	// union of their addresses. This catches rotating wildcard/CDN pools where no
	// single IP necessarily appears twice, without trusting one poisoned answer.
	if resolvedProbes >= 3 {
		for ip := range allIPs {
			wildcardIPs[ip] = true
		}
	}
	for cname, n := range cnameCounts {
		if n >= 3 {
			wildcardCNAMEs[cname] = true
		}
	}
	return wildcardIPs, wildcardCNAMEs
}

func (s *SubdomainScanner) upsertSubdomain(targetID, subdomain, ip string) error {
	return s.upsertSubdomainSource(targetID, subdomain, ip, "dns")
}

func (s *SubdomainScanner) upsertSubdomainSource(targetID, subdomain, ip, source string) error {
	id := uuid.New().String()
	_, err := s.db.Exec(`
		INSERT INTO subdomains (id, target_id, subdomain, ip, source, last_seen)
		VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
		ON CONFLICT(target_id, subdomain) DO UPDATE SET
			ip = excluded.ip,
			source = CASE WHEN COALESCE(subdomains.source,'dns') IN ('seed','vhost')
				THEN subdomains.source ELSE excluded.source END,
			last_seen = CURRENT_TIMESTAMP
	`, id, targetID, subdomain, ip, source)
	return err
}

// pruneRejectedSubdomains repairs rows created by older eager-admission builds.
// The delete is intentionally narrow: never touch explicit seeds, CNAME records,
// verified vhosts or anything that was previously observed alive.
func (s *SubdomainScanner) pruneRejectedSubdomains(ctx context.Context, targetID string, rejected map[string]bool) {
	if len(rejected) == 0 {
		return
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	stmt, err := tx.PrepareContext(ctx, `DELETE FROM subdomains
		WHERE target_id=? AND subdomain=? AND COALESCE(source,'dns')='dns'
		  AND COALESCE(is_alive,0)=0`)
	if err != nil {
		_ = tx.Rollback()
		return
	}
	for name := range rejected {
		if ctx.Err() != nil {
			break
		}
		_, _ = stmt.ExecContext(ctx, targetID, name)
	}
	_ = stmt.Close()
	_ = tx.Commit()
}

func resolveHostIPs(parent context.Context, host string) []string {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	rows, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(rows))
	for _, row := range rows {
		ip := row.IP.String()
		if ip != "" && !seen[ip] {
			seen[ip] = true
			out = append(out, ip)
		}
	}
	return out
}

func firstNonWildcardIP(ips []string, wildcard map[string]bool) string {
	// If an answer overlaps the random-label wildcard profile, treat the complete
	// RRset as wildcard. Rotating pools often return one familiar and one new IP;
	// selecting the new address would incorrectly admit the fake hostname.
	for _, ip := range ips {
		if wildcard[ip] {
			return ""
		}
	}
	for _, ip := range ips {
		return ip
	}
	return ""
}

func overlapsWildcardIPs(ips []string, wildcard map[string]bool) bool {
	if len(ips) == 0 || len(wildcard) == 0 {
		return false
	}
	for _, ip := range ips {
		if wildcard[ip] {
			return true
		}
	}
	return false
}

func lookupExplicitCNAME(parent context.Context, host string) string {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	cname, err := net.DefaultResolver.LookupCNAME(ctx, host)
	if err != nil {
		return ""
	}
	cname = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(cname), "."))
	if cname == "" || cname == strings.ToLower(strings.TrimSuffix(host, ".")) {
		return ""
	}
	return cname
}

func resolveHost(host string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
	if err != nil || len(ips) == 0 {
		return ""
	}
	return ips[0].IP.String()
}

func isValidSubdomain(sub, domain string) bool {
	sub = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(sub), "."))
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if sub == "" || domain == "" || len(sub) > 253 {
		return false
	}
	if !strings.HasSuffix(sub, "."+domain) && sub != domain {
		return false
	}
	for _, label := range strings.Split(sub, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return false
			}
		}
	}
	return true
}

func extractSubdomain(urlStr, domain string) string {
	urlStr = strings.ToLower(strings.TrimSpace(urlStr))
	urlStr = strings.TrimPrefix(urlStr, "http://")
	urlStr = strings.TrimPrefix(urlStr, "https://")
	parts := strings.SplitN(urlStr, "/", 2)
	host := parts[0]
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}
	if isValidSubdomain(host, domain) {
		return host
	}
	return ""
}
