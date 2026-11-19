package scanner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
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

type TakeoverScanner struct {
	db        *database.DB
	exec      *tools.Executor
	cfg       *config.Config
	logger    *logger.Logger
	broadcast BroadcastFunc
}

func NewTakeoverScanner(db *database.DB, exec *tools.Executor, cfg *config.Config, log *logger.Logger, broadcast BroadcastFunc) *TakeoverScanner {
	return &TakeoverScanner{db: db, exec: exec, cfg: cfg, logger: log, broadcast: broadcast}
}

var takeoverHTTPClient = &http.Client{
	Transport: sharedHTTPTransport,
	Timeout:   10 * time.Second,
	CheckRedirect: func(req *http.Request, via []*http.Request) error {
		if len(via) >= 5 {
			return http.ErrUseLastResponse
		}
		return nil
	},
}

// takeoverFingerprint maps a dangling-CNAME provider to the body signature it
// returns when the resource is unclaimed. Curated from EdOverflow/can-i-take-over-xyz.
type takeoverFingerprint struct {
	service   string
	cnames    []string
	signature string
	severity  string
	// generic marks a signature phrase that is also the stock/default text of
	// countless totally unrelated servers — "404 Not Found" and Apache's
	// boilerplate "The requested URL was not found on this server" are the
	// literal default body of any ordinary 404 page, provider-specific or not.
	// A generic signature alone (no NXDOMAIN, no second-tool confirmation) is
	// exactly the shape of a false positive: any live, perfectly claimed site
	// that happens to 404 for an unrelated reason would otherwise match. See
	// takeoverConfidence, which refuses to trust a generic match on its own.
	generic bool
}

var takeoverFingerprints = []takeoverFingerprint{
	{service: "GitHub Pages", cnames: []string{"github.io", "github.map.fastly.net"}, signature: "There isn't a GitHub Pages site here", severity: "high"},
	// S3 patterns must be PRECISE. The old catch-all "amazonaws.com" swallowed every
	// AWS hostname — ELB/ALB, CloudFront, EC2, RDS — and mislabeled a live load
	// balancer (…-alb-….elb.amazonaws.com) as a dangling S3 bucket. These match only
	// real object-storage / S3-website endpoints.
	{service: "AWS S3", cnames: []string{"s3.amazonaws.com", ".s3.", "s3-website", "s3.dualstack", "s3-external"}, signature: "NoSuchBucket", severity: "high"},
	{service: "Heroku", cnames: []string{"herokuapp.com", "herokudns.com", "herokussl.com"}, signature: "No such app", severity: "high"},
	{service: "Shopify", cnames: []string{"myshopify.com"}, signature: "Sorry, this shop is currently unavailable", severity: "high"},
	{service: "Fastly", cnames: []string{"fastly.net"}, signature: "Fastly error: unknown domain", severity: "medium"},
	// Apache's own stock 404.html template contains this exact sentence
	// verbatim — it says nothing specific about Unbounce. Never trust it alone.
	{service: "Unbounce", cnames: []string{"unbouncepages.com"}, signature: "The requested URL was not found on this server", severity: "medium", generic: true},
	{service: "Tumblr", cnames: []string{"domains.tumblr.com"}, signature: "Whatever you were looking for doesn't currently exist at this address", severity: "medium"},
	{service: "Ghost", cnames: []string{"ghost.io"}, signature: "The thing you were looking for is no longer here", severity: "medium"},
	{service: "Surge.sh", cnames: []string{"surge.sh"}, signature: "project not found", severity: "medium"},
	{service: "Bitbucket", cnames: []string{"bitbucket.io"}, signature: "Repository not found", severity: "high"},
	// "404 Not Found" is the literal default body text of innumerable unrelated
	// servers (stock nginx/Apache/generic-framework 404 pages). Matching it
	// alone against a cargocollective.com CNAME would flag any ordinary,
	// perfectly live 404 response — never trust it without NXDOMAIN/subzy too.
	{service: "Cargo", cnames: []string{"cargocollective.com"}, signature: "404 Not Found", severity: "low", generic: true},
	{service: "Webflow", cnames: []string{"proxy.webflow.com", "proxy-ssl.webflow.com"}, signature: "The page you are looking for doesn't exist or has been moved", severity: "medium"},
	{service: "Wordpress", cnames: []string{"wordpress.com"}, signature: "Do you want to register", severity: "medium"},
	{service: "Pantheon", cnames: []string{"pantheonsite.io"}, signature: "404 error unknown site", severity: "medium"},
	{service: "Azure", cnames: []string{"azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net", "azureedge.net"}, signature: "404 Web Site not found", severity: "high"},
	{service: "Readme.io", cnames: []string{"readme.io"}, signature: "Project doesnt exist... yet!", severity: "medium"},
	{service: "Zendesk", cnames: []string{"zendesk.com"}, signature: "Help Center Closed", severity: "low"},
	{service: "Netlify", cnames: []string{"netlify.app", "netlify.com"}, signature: "Not Found - Request ID", severity: "medium"},
	// Vercel's unclaimed-deployment page is specific and well-documented.
	{service: "Vercel", cnames: []string{"vercel-dns.com", "cname.vercel-dns.com"}, signature: "DEPLOYMENT_NOT_FOUND", severity: "high"},
	{service: "Help Scout", cnames: []string{"helpscoutdocs.com"}, signature: "No settings were found for this company", severity: "medium"},
	{service: "UserVoice", cnames: []string{"uservoice.com"}, signature: "This UserVoice instance does not exist", severity: "medium"},
	{service: "Intercom", cnames: []string{"custom.intercom.help"}, signature: "This page is reserved for artistic dogs", severity: "low"},
	// The exact unclaimed-page wording for Statuspage.io is less certain than
	// the others here, so treat a bare match as generic (never trusted alone).
	{service: "Statuspage", cnames: []string{"statuspage.io"}, signature: "You are being redirected", severity: "low", generic: true},
}

// Run resolves CNAMEs for every subdomain and flags any that point at an
// unclaimed third-party service (subdomain takeover).
func (s *TakeoverScanner) Run(ctx context.Context, targetID string, logFn LogFunc) error {
	logFn("info", "takeover", "Checking for subdomain takeovers...")

	rows, err := s.db.QueryContext(ctx, `SELECT subdomain FROM subdomains WHERE target_id = ? AND COALESCE(catchall,0)=0`, targetID)
	if err != nil {
		return fmt.Errorf("query subdomains: %w", err)
	}
	var subs []string
	for rows.Next() {
		var sub string
		if err := rows.Scan(&sub); err == nil {
			subs = append(subs, sub)
		}
	}
	rows.Close()
	subs = filterHostsByHostScope(ctx, subs)

	if len(subs) == 0 {
		logFn("info", "takeover", "No subdomains to check")
		return nil
	}

	logFn("info", "takeover", fmt.Sprintf("Checking %d subdomains for dangling CNAMEs...", len(subs)))

	// Concurrency raised from 20 to 40: for the overwhelming majority of
	// subdomains (no third-party CNAME at all) this stage is a single fast DNS
	// lookup that returns in milliseconds — the workload is DNS-round-trip
	// bound, not CPU/HTTP bound, so a higher fan-out shortens wall-clock time
	// on a large target without materially increasing load on any one
	// upstream (each host only ever gets its own few lookups; the heavier
	// HTTP+subzy assessment below still only runs for the small subset that
	// actually fingerprint-match).
	sem := make(chan struct{}, 40)
	var wg sync.WaitGroup
	var found atomic.Int64

	// Wildcard-zone dedup: a wildcard/catch-all DNS record makes every random,
	// non-existent label under its zone resolve identically — the single
	// biggest false-positive source in subdomain-takeover scanning, since a
	// naive per-subdomain scan reports the SAME domain-wide DNS
	// misconfiguration as dozens or hundreds of independent "findings" for
	// hosts that were never individually configured at all. reportedWildcards
	// ensures each affected zone is assessed and reported exactly once.
	var wildcardMu sync.Mutex
	reportedWildcards := map[string]bool{}

	for _, sub := range subs {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(host string) {
			defer wg.Done()
			defer func() { <-sem }()

			cname, err := lookupCNAME(ctx, host)
			if err != nil || cname == "" {
				return
			}

			fp := matchTakeoverFingerprint(cname)
			if fp == nil {
				return
			}

			// Defense in depth: never flag AWS load-balancer / compute infrastructure.
			// A CNAME to a *live* ELB/ALB/NLB or EC2 host is not a subdomain takeover
			// (can-i-take-over-xyz lists AWS ELB as "Not vulnerable"); only a deleted
			// backend is, and that path is covered by the NXDOMAIN signal on real
			// claimable services. This guards against a broad fingerprint ever again
			// swallowing an ELB name (the services.ewa.bh false positive).
			if awsNonTakeoverableInfra(cname) {
				return
			}

			// Wildcard check: is this exact CNAME just the zone's catch-all record,
			// not something specific to `host`? If so, only ever report the ZONE
			// once, regardless of how many real or fabricated subdomains share it.
			wildcardNote := ""
			if zone, wcCNAME := wildcardZoneFor(ctx, host); zone != "" && wcCNAME == cname {
				wildcardMu.Lock()
				already := reportedWildcards[zone]
				reportedWildcards[zone] = true
				wildcardMu.Unlock()
				if already {
					return
				}
				wildcardNote = fmt.Sprintf(" WILDCARD DNS: verified via 2 random non-existent probe labels under *.%s — every subdomain in this zone resolves to the identical CNAME, so this is ONE domain-wide DNS misconfiguration, not evidence that %s specifically was configured; reported once for the whole zone.", zone, host)
			}

			// Assess the claim: confidence + provenance + status (finding vs
			// candidate). Below the surfacing cutoff → drop silently.
			conf, provenance := s.assessTakeover(ctx, host, cname, fp)
			status, ok := ClassifyStatus(conf)
			if !ok {
				return
			}

			evidence := fmt.Sprintf("CNAME %s → %s (%s) — unclaimed resource [%d%%].%s", host, cname, fp.service, conf, wildcardNote)
			s.storeVulnClassified(targetID, "subdomain_takeover", fp.severity, "https://"+host, "", cname, evidence, conf, status, provenance)
			if status == StatusFinding {
				found.Add(1)
			}
			logFn("warn", "takeover", fmt.Sprintf("TAKEOVER %s [%s %d%%]: %s → %s (%s)", strings.ToUpper(status), fp.severity, conf, host, cname, fp.service))
			if s.broadcast != nil && status == StatusFinding {
				s.broadcast("new_vuln_finding", map[string]any{
					"target_id": targetID,
					"type":      "subdomain_takeover",
					"url":       "https://" + host,
				})
			}
		}(sub)
	}
	wg.Wait()

	logFn("info", "takeover", fmt.Sprintf("Takeover check done. Found %d potential takeovers.", found.Load()))
	return nil
}

// wildcardCNAMECache memoizes, per DNS zone (a host's parent domain — e.g.
// "dev.example.com" for host "foo.dev.example.com"), whether random
// non-existent labels under it resolve via a wildcard CNAME. Many subdomains
// on a real target share the same immediate parent zone, and each fresh check
// costs 2 real DNS round-trips, so this keeps a large scan from re-probing the
// identical zone hundreds of times. Cleared implicitly per process (module-
// level cache); a stale wildcard record disappearing between scans just means
// one extra probe, never a correctness issue.
var wildcardCNAMECache sync.Map // zone -> string (cname target, "" = confirmed no wildcard)

// parentZone returns host's immediate parent domain — e.g. "dev.example.com"
// for "foo.dev.example.com" — or "" when host has no PROBEABLE parent: a
// bare single-label host, or a two-label host ("example.com") whose "parent"
// would be a bare public suffix ("com"). Querying random labels under a raw
// TLD is meaningless (and would just report every TLD as "wildcarded"), so
// that case is deliberately excluded rather than probed.
func parentZone(host string) string {
	i := strings.Index(host, ".")
	if i < 0 || i == len(host)-1 {
		return ""
	}
	zone := host[i+1:]
	if !strings.Contains(zone, ".") {
		return ""
	}
	return zone
}

// wildcardZoneFor reports host's immediate parent zone and, if that zone has a
// wildcard/catch-all CNAME record, the CNAME target it resolves to. Returns
// ("", "") when host has no probeable parent zone, or the zone has no
// wildcard.
func wildcardZoneFor(ctx context.Context, host string) (zone, cname string) {
	zone = parentZone(host)
	if zone == "" {
		return "", ""
	}
	if v, ok := wildcardCNAMECache.Load(zone); ok {
		return zone, v.(string)
	}
	result := probeWildcardCNAME(ctx, zone, lookupCNAME)
	wildcardCNAMECache.Store(zone, result)
	return zone, result
}

// probeWildcardCNAME queries CNAME records (via lookup, injectable for tests)
// for two random, guaranteed-non-existent labels under zone. If BOTH resolve
// and agree, that CNAME is a wildcard/catch-all — no specific subdomain was
// individually configured to point there, the zone's DNS itself is just set
// up that way.
func probeWildcardCNAME(ctx context.Context, zone string, lookup func(context.Context, string) (string, error)) string {
	probe := func() string {
		label := "rcn" + strings.ReplaceAll(uuid.New().String(), "-", "")[:16]
		cname, err := lookup(ctx, label+"."+zone)
		if err != nil {
			return ""
		}
		return cname
	}
	first := probe()
	if first == "" {
		return ""
	}
	second := probe()
	if second == "" || second != first {
		return ""
	}
	return first
}

func lookupCNAME(ctx context.Context, host string) (string, error) {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := net.Resolver{}
	cname, err := r.LookupCNAME(c, host)
	if err != nil {
		return "", err
	}
	cname = strings.TrimSuffix(strings.ToLower(cname), ".")
	if cname == strings.ToLower(host) {
		return "", nil // no real CNAME
	}
	return cname, nil
}

func matchTakeoverFingerprint(cname string) *takeoverFingerprint {
	for i := range takeoverFingerprints {
		for _, c := range takeoverFingerprints[i].cnames {
			if strings.Contains(cname, c) {
				return &takeoverFingerprints[i]
			}
		}
	}
	return nil
}

// assessTakeover decides how confident we are that `host` is takeover-able and
// returns a confidence score (see classify.go bands) plus provenance. The rule
// set is intentionally conservative — an uncertain result is a *candidate*, not
// a finding, so we never cry wolf:
//
//   - Azure: only a takeover if DNS is NXDOMAIN *or* HTTP returns the
//     "404 Web Site not found" body on *.azurewebsites.net. A 403 with
//     x-ms-forbidden-ip (or any other response) means the site IS claimed →
//     NOT a takeover.
//   - Signature body match (via Host-header request)      → evidence (90).
//   - + CNAME target is NXDOMAIN                           → strong.
//   - + a second tool (subzy) agrees                       → multi-tool (95).
//   - Only a dangling CNAME to a known service, nothing
//     else confirmed                                       → candidate (75).
func (s *TakeoverScanner) assessTakeover(ctx context.Context, host, cname string, fp *takeoverFingerprint) (int, string) {
	var prov strings.Builder
	fmt.Fprintf(&prov, "CNAME: %s -> %s (%s)\n", host, cname, fp.service)

	nx := cnameTargetNXDOMAIN(ctx, cname)
	fmt.Fprintf(&prov, "DNS: CNAME target NXDOMAIN=%v\n", nx)

	status, hdrs, body := s.fetchWithHostHeader(ctx, host)
	sigMatch := strings.Contains(body, fp.signature)
	fmt.Fprintf(&prov, "HTTP(Host:%s): status=%d signature_match=%v\n", host, status, sigMatch)

	// ── Azure-specific guard (spec) ──
	if fp.service == "Azure" {
		if forbiddenIP := hdrs["x-ms-forbidden-ip"]; forbiddenIP != "" || status == 403 {
			fmt.Fprintf(&prov, "Azure: 403/x-ms-forbidden-ip present -> site is CLAIMED, NOT takeover\n")
			return 0, prov.String() // definitively not a takeover
		}
		if !nx && !sigMatch {
			fmt.Fprintf(&prov, "Azure: neither NXDOMAIN nor 404-body -> not takeover\n")
			return 0, prov.String()
		}
	}

	// Second tool: subzy (if installed) as an independent confirmation.
	subzyConfirms, subzyRan := s.subzyConfirms(ctx, host)
	if subzyRan {
		fmt.Fprintf(&prov, "subzy: vulnerable=%v\n", subzyConfirms)
	}

	if fp.generic && sigMatch && !nx && !subzyConfirms {
		fmt.Fprintf(&prov, "note: signature %q is a generic/stock error phrase — not trusted without NXDOMAIN or subzy confirmation\n", fp.signature)
	}
	conf := takeoverConfidence(sigMatch, nx, subzyConfirms, fp.generic)
	if conf == 0 {
		fmt.Fprintf(&prov, "verdict: CNAME target resolves, no unclaimed signature, subzy negative -> CLAIMED resource, not a takeover\n")
	}
	return conf, prov.String()
}

// takeoverConfidence maps the three independent takeover signals to a confidence
// score. The critical rule: with NONE of them positive — no unclaimed-body
// signature, the CNAME target still resolves, and subzy disagrees — the resource
// is LIVE and CLAIMED, so the score is 0 (dropped). Merely pointing a CNAME at a
// known provider is normal for every working site hosted there and must never, on
// its own, surface a takeover (the services.ewa.bh live-ALB false positive).
//
// generic downgrades a body-signature match that is ALSO the stock/default
// text of countless unrelated servers ("404 Not Found", Apache's boilerplate
// "The requested URL was not found on this server") — such a match is treated
// as no signal at all unless paired with a real DNS-level dangling signal
// (NXDOMAIN) or a second tool's independent confirmation. A provider-specific
// phrase never needs this: it is evidence on its own.
func takeoverConfidence(sigMatch, nx, subzyConfirms, generic bool) int {
	if generic && sigMatch && !nx && !subzyConfirms {
		sigMatch = false
	}
	switch {
	case sigMatch && subzyConfirms:
		return ConfMultiTool // 95 — two tools agree
	case sigMatch && nx:
		return ConfMultiTool // 95 — body + DNS both prove it
	case sigMatch:
		return ConfEvidence // 90 — solid single evidence
	case subzyConfirms:
		return ConfEvidence // 90 — dedicated tool confirms
	case nx:
		return ConfCandidateHi // 85 — DNS says dangling, body unconfirmed
	default:
		return 0 // claimed / live → not a takeover
	}
}

// awsNonTakeoverableInfra matches AWS hostnames that are load balancers or compute
// endpoints — NOT claimable object-storage / website resources. A CNAME to a live
// ELB/ALB/NLB (….elb.amazonaws.com) or EC2 host (….compute[-1].amazonaws.com) is
// not a subdomain takeover.
func awsNonTakeoverableInfra(cname string) bool {
	return strings.Contains(cname, ".elb.amazonaws.com") ||
		strings.Contains(cname, ".compute.amazonaws.com") ||
		strings.Contains(cname, ".compute-1.amazonaws.com")
}

// fetchWithHostHeader requests the CNAME'd endpoint while forcing the Host
// header to the subdomain (the way real takeover probes work), returning the
// status, response headers (lower-cased keys) and body.
func (s *TakeoverScanner) fetchWithHostHeader(ctx context.Context, host string) (int, map[string]string, string) {
	for _, scheme := range []string{"https://", "http://"} {
		reqCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
		req, err := http.NewRequestWithContext(reqCtx, "GET", scheme+host, nil)
		if err != nil {
			cancel()
			continue
		}
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible)")
		req.Host = host // explicit Host-header test (-H "Host:<subdomain>")
		resp, err := takeoverHTTPClient.Do(req)
		if err != nil {
			cancel()
			continue
		}
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		cancel()
		hdrs := map[string]string{}
		for k := range resp.Header {
			hdrs[strings.ToLower(k)] = resp.Header.Get(k)
		}
		return resp.StatusCode, hdrs, string(body)
	}
	return 0, map[string]string{}, ""
}

// cnameTargetNXDOMAIN reports whether the CNAME target itself fails to resolve
// (the canonical "the backend is gone, claim it" signal).
func cnameTargetNXDOMAIN(ctx context.Context, cname string) bool {
	c, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	r := net.Resolver{}
	ips, err := r.LookupHost(c, cname)
	if err != nil {
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return true
		}
		return false
	}
	return len(ips) == 0
}

// subzyConfirms runs subzy against a single host as an independent second tool.
// Returns (vulnerable, ran). ran=false when subzy isn't installed.
func (s *TakeoverScanner) subzyConfirms(ctx context.Context, host string) (bool, bool) {
	if !s.exec.IsToolAvailable("subzy") {
		return false, false
	}
	vulnerable := false
	tctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	_ = s.exec.RunWithCallback(tctx, "", func(line string) {
		l := strings.ToLower(line)
		if strings.Contains(l, host) && (strings.Contains(l, "vulnerable") && !strings.Contains(l, "not vulnerable")) {
			vulnerable = true
		}
	}, "subzy", "run", "--target", host, "--hide_fails")
	return vulnerable, true
}

func (s *TakeoverScanner) storeVulnClassified(targetID, vulnType, severity, rawURL, param, payload, evidence string, confidence int, status, provenance string) {
	verdict := CandDetected
	if status == StatusFinding {
		verdict = VerifyVerified
	}
	_, _ = RecordDetectorObservation(context.Background(), s.db, DetectorObservation{
		TargetID: targetID, Type: vulnType, Severity: severity, URL: rawURL, Method: "DNS",
		Parameter: param, Location: "dns", Payload: payload, Evidence: evidence,
		Source: "takeover", DetectionMethod: "provider-fingerprint", Confidence: confidence,
		Provenance: provenance, Verdict: verdict,
	})
}
