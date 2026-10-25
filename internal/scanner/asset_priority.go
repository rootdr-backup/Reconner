package scanner

import (
	"context"
	"encoding/json"
	"sort"
	"strings"

	"github.com/recon-platform/internal/database"
)

// AssetScore is the priority score computed for one live host within a target,
// used to decide which asset gets the full detector pipeline first on a large
// scope (a HackerOne-style program with 1000+ subdomains cannot get an equally
// deep pass on every host in a bounded scan, so the highest-value hosts must go
// first). Higher Score = tested earlier / more thoroughly.
type AssetScore struct {
	Host         string
	Score        int
	Reasons      []string
	IsMainDomain bool
	// DedupOf is set when this host is a wildcard-catch-all or byte-identical
	// duplicate of another, already-scored host; callers should record it for
	// inventory but skip the full pipeline on it (see AssetPriorityPlan.Duplicates).
	DedupOf string
}

// AssetPriorityPlan is the ordered result of scoring every known host for a
// target: Ordered holds one representative per distinct app (highest score
// first, main domain always first), Duplicates holds every host collapsed into
// its representative (wildcard catch-alls / identical-content hosts).
type AssetPriorityPlan struct {
	Ordered    []AssetScore
	Duplicates []AssetScore
}

// interestingLabelTokens are subdomain-label substrings that correlate with
// higher-value application surface in real bug-bounty programs: auth/identity
// boundaries, administrative interfaces, internal tooling, and payment flows are
// where impactful access-control, auth-bypass and business-logic bugs concentrate.
var interestingLabelTokens = []string{
	"admin", "administrator", "manage", "console", "dashboard", "portal",
	"api", "graphql", "gateway", "backend", "internal", "intranet", "private",
	"staging", "stage", "stg", "dev", "development", "test", "qa", "uat", "sandbox",
	"vpn", "sso", "auth", "login", "signin", "account", "accounts", "identity", "oauth",
	"pay", "payment", "payments", "billing", "checkout", "wallet", "invoice",
	"jenkins", "gitlab", "git", "jira", "confluence", "grafana", "kibana", "prometheus",
	"k8s", "kube", "kubernetes", "ci", "cd", "deploy", "docker", "registry",
	"employee", "hr", "partner", "corp", "secure", "vault", "config", "cfg",
	"support-admin", "backoffice", "cms", "cpanel", "webmail", "remote",
}

// lowValueLabelTokens are subdomain-label substrings that correlate with pure
// infrastructure/CDN/marketing surface with a shallow attack surface — not
// excluded, just tested later than the app-shaped hosts above.
var lowValueLabelTokens = []string{
	"cdn", "static", "assets", "asset", "img", "images", "image", "media",
	"cache", "cdn-cgi", "mail", "smtp", "imap", "pop", "mx", "ns1", "ns2", "ns3",
	"autodiscover", "autoconfig", "status", "uptime", "ping", "health",
	"blog", "docs", "help", "press", "newsletter", "unsubscribe",
}

// genericTitles are page titles that mean "nothing was ever deployed here" —
// default server/framework landing pages, not a real application.
var genericTitles = map[string]bool{
	"": true, "apache2 ubuntu default page": true, "welcome to nginx!": true,
	"iis windows server": true, "403 forbidden": true, "404 not found": true,
	"index of /": true, "test page for the apache http server": true,
	"directory listing for /": true,
}

// highYieldTech names technologies/products with a long, well-documented history
// of real bug-bounty findings (admin consoles, plugin ecosystems, known-CVE-prone
// self-hosted tools) — worth testing before a hand-rolled marketing page.
var highYieldTech = []string{
	"wordpress", "jenkins", "gitlab", "confluence", "jira", "grafana", "kibana",
	"phpmyadmin", "drupal", "magento", "elasticsearch", "vbulletin", "gitea",
	"nexus", "sonarqube", "rancher", "portainer", "vcenter", "citrix", "pulse secure",
	"webmin", "cpanel", "wildfly", "jboss", "weblogic", "tomcat",
}

// assetRow is the raw per-host data pulled from subdomains + http_services
// before scoring.
type assetRow struct {
	host         string
	isAlive      bool
	statusCode   int
	title        string
	server       string
	technologies string // JSON array, from http_services
	waf          string
	cms          string
	source       string // 'dns' | 'vhost' | 'seed'
	finalURL     string // representative http_services.url for this host
	contentHash  string
	adminPanel   bool
	paramCount   int
}

// ComputeAssetPriority scores every known host for a target and returns an
// ordered plan: main domain first, then descending score, with wildcard/
// duplicate-content hosts collapsed into their representative. It never mutates
// scan state — pure read + score, safe to call repeatedly (e.g. once per scan
// start) without side effects.
func ComputeAssetPriority(ctx context.Context, db *database.DB, targetID string) (AssetPriorityPlan, error) {
	var targetDomain string
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(domain,'') FROM targets WHERE id=?`, targetID).Scan(&targetDomain)
	targetDomain = normalizeHost(hostOrRaw(targetDomain))

	rows, err := loadAssetRows(ctx, db, targetID)
	if err != nil {
		return AssetPriorityPlan{}, err
	}
	if len(rows) == 0 {
		return AssetPriorityPlan{}, nil
	}

	paramCounts := loadParamCountsByHost(ctx, db, targetID)
	for host, row := range rows {
		row.paramCount = paramCounts[host]
		rows[host] = row
	}

	reps, dupOf := dedupeWildcardHosts(rows)

	var scored []AssetScore
	for host, row := range rows {
		if rep, isDup := dupOf[host]; isDup && rep != host {
			continue // scored via its representative below
		}
		scored = append(scored, scoreAsset(row, targetDomain))
	}
	sort.SliceStable(scored, func(i, j int) bool {
		if scored[i].IsMainDomain != scored[j].IsMainDomain {
			return scored[i].IsMainDomain
		}
		if scored[i].Score != scored[j].Score {
			return scored[i].Score > scored[j].Score
		}
		return scored[i].Host < scored[j].Host
	})

	var duplicates []AssetScore
	for host, rep := range dupOf {
		if rep == host {
			continue
		}
		row := rows[host]
		duplicates = append(duplicates, AssetScore{
			Host: host, DedupOf: rep,
			Reasons: []string{"duplicate content/wildcard catch-all of " + rep},
			Score:   scoreAsset(row, targetDomain).Score,
		})
	}
	sort.SliceStable(duplicates, func(i, j int) bool { return duplicates[i].Host < duplicates[j].Host })

	_ = reps // reps kept for future use (explicit representative lookup); avoid unused-var
	return AssetPriorityPlan{Ordered: scored, Duplicates: duplicates}, nil
}

func hostOrRaw(domain string) string {
	if h := hostOfURL(domain); h != "" {
		return h
	}
	return domain
}

func loadAssetRows(ctx context.Context, db *database.DB, targetID string) (map[string]assetRow, error) {
	rows := make(map[string]assetRow)

	srows, err := db.QueryContext(ctx, `
		SELECT subdomain, is_alive, status_code, COALESCE(page_title,''), COALESCE(server,''),
		       COALESCE(technologies,'[]'), COALESCE(waf,''), COALESCE(source,'dns')
		FROM subdomains WHERE target_id=? AND COALESCE(catchall,0)=0`, targetID)
	if err != nil {
		return nil, err
	}
	for srows.Next() {
		var host, title, server, tech, waf, source string
		var alive, status int
		if srows.Scan(&host, &alive, &status, &title, &server, &tech, &waf, &source) != nil {
			continue
		}
		host = normalizeHost(host)
		if host == "" {
			continue
		}
		rows[host] = assetRow{
			host: host, isAlive: alive != 0, statusCode: status, title: title,
			server: server, technologies: tech, waf: waf, source: source,
		}
	}
	srows.Close()

	hrows, err := db.QueryContext(ctx, `
		SELECT url, status_code, COALESCE(title,''), COALESCE(server,''),
		       COALESCE(technologies,'[]'), COALESCE(waf,''), COALESCE(cms,''), COALESCE(favicon_hash,'')
		FROM http_services WHERE target_id=?`, targetID)
	if err != nil {
		return rows, nil // subdomain-only data still usable
	}
	for hrows.Next() {
		var rawURL, title, server, tech, waf, cms, favicon string
		var status int
		if hrows.Scan(&rawURL, &status, &title, &server, &tech, &waf, &cms, &favicon) != nil {
			continue
		}
		host := normalizeHost(hostOfURL(rawURL))
		if host == "" {
			continue
		}
		row, ok := rows[host]
		if !ok {
			row = assetRow{host: host, source: "dns"}
		}
		// http_services is the richer, more current probe result — prefer its
		// fields when present, but never downgrade an already-alive host to dead.
		if status > 0 {
			row.statusCode = status
			row.isAlive = row.isAlive || (status > 0 && status < 500)
		}
		if title != "" {
			row.title = title
		}
		if server != "" {
			row.server = server
		}
		if tech != "" && tech != "[]" {
			row.technologies = tech
		}
		if waf != "" {
			row.waf = waf
		}
		if cms != "" {
			row.cms = cms
		}
		if row.finalURL == "" {
			row.finalURL = rawURL
		}
		if favicon != "" {
			row.contentHash = favicon
		}
		rows[host] = row
	}
	hrows.Close()

	arows, err := db.QueryContext(ctx, `SELECT DISTINCT url FROM admin_panel_findings WHERE target_id=?`, targetID)
	if err == nil {
		for arows.Next() {
			var rawURL string
			if arows.Scan(&rawURL) != nil {
				continue
			}
			host := normalizeHost(hostOfURL(rawURL))
			if row, ok := rows[host]; ok {
				row.adminPanel = true
				rows[host] = row
			}
		}
		arows.Close()
	}

	return rows, nil
}

func loadParamCountsByHost(ctx context.Context, db *database.DB, targetID string) map[string]int {
	counts := make(map[string]int)
	rows, err := db.QueryContext(ctx, `SELECT url FROM parameters WHERE target_id=?`, targetID)
	if err != nil {
		return counts
	}
	defer rows.Close()
	for rows.Next() {
		var rawURL string
		if rows.Scan(&rawURL) != nil {
			continue
		}
		host := normalizeHost(hostOfURL(rawURL))
		if host != "" {
			counts[host]++
		}
	}
	return counts
}

// dedupeWildcardHosts groups hosts that are almost certainly the SAME
// application (a DNS wildcard catch-all, or a distinct hostname pointed at
// identical content) so the priority pass tests one representative deeply
// instead of re-running the full pipeline N times against byte-identical apps.
// Grouping key: (status code, server, technologies, favicon hash, normalized
// title) — deliberately conservative: two hosts must agree on every one of
// these signals to be folded together, so a real distinct app that merely
// shares a CDN/server banner is never silently skipped.
func dedupeWildcardHosts(rows map[string]assetRow) (representatives map[string]bool, dupOf map[string]string) {
	type groupKey struct {
		status                       int
		server, tech, favicon, title string
	}
	groups := make(map[groupKey][]string)
	for host, row := range rows {
		if !row.isAlive {
			continue
		}
		title := strings.ToLower(strings.TrimSpace(row.title))
		if title == "" || genericTitles[title] {
			continue // no signal to group on — never dedupe a host with no title
		}
		k := groupKey{status: row.statusCode, server: strings.ToLower(row.server), tech: row.technologies, favicon: row.contentHash, title: title}
		groups[k] = append(groups[k], host)
	}

	representatives = make(map[string]bool)
	dupOf = make(map[string]string)
	for host := range rows {
		dupOf[host] = host // default: everyone is their own representative
	}
	for _, hosts := range groups {
		if len(hosts) < 2 {
			continue
		}
		sort.Strings(hosts)
		rep := hosts[0]
		// Prefer the shortest hostname as representative (closer to the apex,
		// e.g. "app.example.com" over "app-3.staging.example.com").
		for _, h := range hosts[1:] {
			if len(h) < len(rep) {
				rep = h
			}
		}
		representatives[rep] = true
		for _, h := range hosts {
			dupOf[h] = rep
		}
	}
	return representatives, dupOf
}

func scoreAsset(row assetRow, targetDomain string) AssetScore {
	score := 0
	var reasons []string
	add := func(delta int, reason string) {
		score += delta
		reasons = append(reasons, reason)
	}

	isMain := targetDomain != "" && (row.host == targetDomain || row.host == "www."+targetDomain)
	if isMain {
		add(1000, "main/apex domain")
	}

	label := row.host
	if targetDomain != "" && strings.HasSuffix(label, "."+targetDomain) {
		label = strings.TrimSuffix(label, "."+targetDomain)
	}
	labelLower := strings.ToLower(label)
	for _, tok := range interestingLabelTokens {
		if labelMatchesInterestingToken(labelLower, tok) {
			add(25, "interesting name pattern: "+tok)
			break // one bonus per host, not one per matching token
		}
	}
	for _, tok := range lowValueLabelTokens {
		if strings.Contains(labelLower, tok) {
			add(-15, "generic infra name pattern: "+tok)
			break
		}
	}

	if !row.isAlive || row.statusCode == 0 {
		add(-1000, "not confirmed alive")
	} else {
		switch {
		case row.statusCode == 401 || row.statusCode == 403:
			add(15, "auth-gated (401/403) — likely a real app behind access control")
		case row.statusCode >= 500:
			add(5, "server error observed — possibly fragile custom backend")
		case row.statusCode >= 200 && row.statusCode < 400:
			add(5, "live 2xx/3xx")
		}
	}

	if row.adminPanel {
		add(80, "admin/login panel detected")
	}

	titleLower := strings.ToLower(strings.TrimSpace(row.title))
	if titleLower != "" && !genericTitles[titleLower] {
		add(10, "non-generic page title")
	}

	if row.source == "vhost" {
		add(20, "discovered via vhost scan (often internal/forgotten)")
	}

	if row.waf != "" {
		add(-10, "behind a WAF/edge (higher testing cost, more FP-prone timing signals)")
	}
	if row.cms != "" {
		add(-10, "stock CMS detected (patched core, lower expected yield)")
	}

	techLower := strings.ToLower(row.technologies)
	matchedHighYield := false
	for _, t := range highYieldTech {
		if strings.Contains(techLower, t) {
			add(20, "known high-yield technology: "+t)
			matchedHighYield = true
			break
		}
	}
	if !matchedHighYield && !looksLikeBareTechArray(row.technologies) {
		add(15, "no recognized off-the-shelf technology — likely custom-built code")
	}

	if row.paramCount > 0 {
		bonus := row.paramCount * 2
		if bonus > 60 {
			bonus = 60
		}
		add(bonus, "discovered parameter surface")
	}

	return AssetScore{Host: row.host, Score: score, Reasons: reasons, IsMainDomain: isMain}
}

// labelMatchesInterestingToken decides whether a subdomain label earns the
// "interesting name pattern" bonus for tok. Longer tokens ("admin",
// "payment", "staging") keep plain substring matching, since a compound
// label like "adminportal" or "paymentgateway" is exactly the kind of host
// this bonus should catch. Tokens of 3 characters or fewer ("cd", "ci") are
// too short for that: "cd" substring-matches "cdn7" and would hand a
// low-value CDN node the SAME +25 "interesting" bonus meant for a real CI/CD
// host, cancelling its own -15 low-value demotion and defeating the tiered-
// depth cutoff that exists specifically to skip the full pipeline on hosts
// like it. Short tokens instead require a whole delimited segment match
// (e.g. "cd.example.com" or "my-cd-box", but not "cdn7").
func labelMatchesInterestingToken(label, tok string) bool {
	if len(tok) > 3 {
		return strings.Contains(label, tok)
	}
	idx := strings.Index(label, tok)
	for idx != -1 {
		before := idx == 0 || !isLabelWordByte(label[idx-1])
		after := idx+len(tok) >= len(label) || !isLabelWordByte(label[idx+len(tok)])
		if before && after {
			return true
		}
		next := strings.Index(label[idx+1:], tok)
		if next == -1 {
			break
		}
		idx = idx + 1 + next
	}
	return false
}

func isLabelWordByte(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func looksLikeBareTechArray(techJSON string) bool {
	techJSON = strings.TrimSpace(techJSON)
	if techJSON == "" || techJSON == "[]" {
		return true
	}
	var arr []string
	if json.Unmarshal([]byte(techJSON), &arr) != nil {
		return false
	}
	return len(arr) == 0
}
