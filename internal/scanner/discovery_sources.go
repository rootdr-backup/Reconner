package scanner

import (
	"bufio"
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// Discovery sources for the subdomain enumerator.
//
// The DEEP tier runs the CLI sources sequentially, each with its own historical
// budget, so the operator sees a predictable order and a predictable worst case.
//
// The WATCH (breadth) tier runs the ENABLED sources CONCURRENTLY, each on its
// own timeout (WatchSourceTimeoutMinutes). The round then costs the slowest
// source instead of the sum, and no source can eat the whole round: the DNS
// admission pass and the HTTP probe run on the parent context and always finish.

// discoverySourceIds are the ids the operator can toggle in the UI
// (config WatchEnumerationSources).
var discoverySourceIds = map[string]bool{
	"crtsh":        true,
	"certspotter":  true,
	"hackertarget": true,
	"rapiddns":     true,
	"otx":          true,
	"anubis":       true,
	"urlscan":      true,
	"subfinder":    true,
	"assetfinder":  true,
	"chaos":        true,
	"findomain":    true,
}

// watchOnlySourceIds are the sources the watch tier may use. scilla, waybackurls
// and gau are deep-only: they are slow historical-archive lookups and the
// operator removed them from the watch set (decision D28).
var watchOnlySourceIds = map[string]bool{
	"crtsh":        true,
	"certspotter":  true,
	"hackertarget": true,
	"rapiddns":     true,
	"otx":          true,
	"anubis":       true,
	"urlscan":      true,
	"subfinder":    true,
	"assetfinder":  true,
	"chaos":        true,
	"findomain":    true,
}

// WatchEnumerationSourceIDs returns the source ids the watch tier accepts, in a
// stable order. The API uses it to validate the operator's source list.
func WatchEnumerationSourceIDs() []string {
	ids := make([]string, 0, len(watchOnlySourceIds))
	for id := range watchOnlySourceIds {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// discoveryOutcome is the result of one discovery source.
type discoveryOutcome struct {
	// ok means the source ran and did not fail (empty result is still ok).
	ok bool
	// timedOut means the source hit its own timeout (partial results kept).
	timedOut bool
	// found is how many names the source added.
	found int
}

// discoveryRunner carries the per-run helpers a source needs.
type discoveryRunner struct {
	scanner *SubdomainScanner
	ctx     context.Context
	target  string
	domain  string
	logFn   LogFunc
	store   func(string)
	count   func() int
}

// runSubfinder runs the subfinder source. It is a streaming source: results are
// handed over line by line, so a timeout keeps the partial output.
func (r *discoveryRunner) runSubfinder(budget time.Duration) discoveryOutcome {
	if !r.scanner.exec.IsToolAvailable("subfinder") {
		return discoveryOutcome{}
	}
	r.logFn("info", "subdomain_enum", "Running subfinder...")
	before := r.count()
	tctx, tcancel := context.WithTimeout(r.ctx, budget)
	defer tcancel()
	err := r.scanner.exec.RunWithCallback(tctx, r.target, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.Contains(line, "[") || strings.Contains(line, ":") {
			return
		}
		if isValidSubdomain(line, r.domain) {
			r.store(line)
		}
	}, "subfinder", "-d", r.domain, "-silent", "-all")
	if err != nil && r.ctx.Err() != nil {
		// The PARENT context was cancelled (real cancel, not our timeout).
		return discoveryOutcome{timedOut: r.ctx.Err() == context.DeadlineExceeded}
	}
	if tctx.Err() == context.DeadlineExceeded {
		r.logFn("warn", "subdomain_enum", fmt.Sprintf("subfinder hit its %s budget — %d found so far, likely PARTIAL for a large domain", budgetLabel(budget), r.count()-before))
		return discoveryOutcome{ok: true, timedOut: true, found: r.count() - before}
	}
	r.logFn("info", "subdomain_enum", fmt.Sprintf("subfinder found %d subdomains", r.count()-before))
	return discoveryOutcome{ok: true, found: r.count() - before}
}

// runAssetfinder runs the assetfinder source (streaming).
func (r *discoveryRunner) runAssetfinder(budget time.Duration) discoveryOutcome {
	if !r.scanner.exec.IsToolAvailable("assetfinder") {
		return discoveryOutcome{}
	}
	r.logFn("info", "subdomain_enum", "Running assetfinder...")
	before := r.count()
	tctx, tcancel := context.WithTimeout(r.ctx, budget)
	defer tcancel()
	err := r.scanner.exec.RunWithCallback(tctx, r.target, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		if isValidSubdomain(line, r.domain) {
			r.store(line)
		}
	}, "assetfinder", "--subs-only", r.domain)
	if err != nil && r.ctx.Err() != nil {
		return discoveryOutcome{timedOut: r.ctx.Err() == context.DeadlineExceeded}
	}
	if tctx.Err() == context.DeadlineExceeded {
		r.logFn("warn", "subdomain_enum", fmt.Sprintf("assetfinder hit its %s budget — %d found so far, likely PARTIAL for a large domain", budgetLabel(budget), r.count()-before))
		return discoveryOutcome{ok: true, timedOut: true, found: r.count() - before}
	}
	r.logFn("info", "subdomain_enum", fmt.Sprintf("assetfinder found %d new subdomains", r.count()-before))
	return discoveryOutcome{ok: true, found: r.count() - before}
}

// runChaos runs the projectdiscovery chaos dataset source. It needs a
// projectdiscovery API key; without one the source is skipped (the operator
// sees why it returned nothing).
func (r *discoveryRunner) runChaos(budget time.Duration) discoveryOutcome {
	if r.scanner.cfg == nil || strings.TrimSpace(r.scanner.cfg.ChaosAPIKey) == "" {
		r.logFn("info", "subdomain_enum", "chaos skipped: no API key configured")
		return discoveryOutcome{}
	}
	if !r.scanner.exec.IsToolAvailable("chaos") {
		return discoveryOutcome{}
	}
	r.logFn("info", "subdomain_enum", "Running chaos...")
	before := r.count()
	tctx, tcancel := context.WithTimeout(r.ctx, budget)
	defer tcancel()
	err := r.scanner.exec.RunWithCallback(tctx, r.target, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		if line == "" || strings.Contains(line, "{") {
			return
		}
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		if i := strings.IndexAny(line, "/ \t"); i >= 0 {
			line = line[:i]
		}
		if isValidSubdomain(line, r.domain) {
			r.store(line)
		}
	}, "chaos", "-d", r.domain, "-silent")
	if err != nil && r.ctx.Err() != nil {
		return discoveryOutcome{timedOut: r.ctx.Err() == context.DeadlineExceeded}
	}
	if tctx.Err() == context.DeadlineExceeded {
		r.logFn("warn", "subdomain_enum", fmt.Sprintf("chaos hit its %s budget — %d found so far, likely PARTIAL", budgetLabel(budget), r.count()-before))
		return discoveryOutcome{ok: true, timedOut: true, found: r.count() - before}
	}
	r.logFn("info", "subdomain_enum", fmt.Sprintf("chaos found %d new subdomains", r.count()-before))
	return discoveryOutcome{ok: true, found: r.count() - before}
}

// runFindomain runs the findomain source. findomain is ACTIVE (it brute-forces
// DNS labels), so it is a deliberate choice in the watch set.
func (r *discoveryRunner) runFindomain(budget time.Duration) discoveryOutcome {
	if !r.scanner.exec.IsToolAvailable("findomain") {
		return discoveryOutcome{}
	}
	r.logFn("info", "subdomain_enum", "Running findomain...")
	before := r.count()
	tctx, tcancel := context.WithTimeout(r.ctx, budget)
	defer tcancel()
	err := r.scanner.exec.RunWithCallback(tctx, r.target, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		if isValidSubdomain(line, r.domain) {
			r.store(line)
		}
	}, "findomain", "-t", r.domain, "-q")
	if err != nil && r.ctx.Err() != nil {
		return discoveryOutcome{timedOut: r.ctx.Err() == context.DeadlineExceeded}
	}
	if tctx.Err() == context.DeadlineExceeded {
		r.logFn("warn", "subdomain_enum", fmt.Sprintf("findomain hit its %s budget — %d found so far, likely PARTIAL for a large domain", budgetLabel(budget), r.count()-before))
		return discoveryOutcome{ok: true, timedOut: true, found: r.count() - before}
	}
	r.logFn("info", "subdomain_enum", fmt.Sprintf("findomain found %d new subdomains", r.count()-before))
	return discoveryOutcome{ok: true, found: r.count() - before}
}

// runScilla runs the scilla source (deep tier only).
func (r *discoveryRunner) runScilla(budget time.Duration) discoveryOutcome {
	if !r.scanner.exec.IsToolAvailable("scilla") {
		return discoveryOutcome{}
	}
	r.logFn("info", "subdomain_enum", "Running scilla...")
	before := r.count()
	tctx, tcancel := context.WithTimeout(r.ctx, budget)
	defer tcancel()
	err := r.scanner.exec.RunWithCallback(tctx, r.target, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		line = strings.TrimPrefix(line, "http://")
		line = strings.TrimPrefix(line, "https://")
		if i := strings.IndexAny(line, "/ \t"); i >= 0 {
			line = line[:i]
		}
		if isValidSubdomain(line, r.domain) {
			r.store(line)
		}
	}, "scilla", "subdomain", "-target", r.domain, "-no-color")
	if err != nil && r.ctx.Err() != nil {
		return discoveryOutcome{timedOut: r.ctx.Err() == context.DeadlineExceeded}
	}
	if tctx.Err() == context.DeadlineExceeded {
		r.logFn("warn", "subdomain_enum", fmt.Sprintf("scilla hit its %s budget — %d found so far, likely PARTIAL for a large domain", budgetLabel(budget), r.count()-before))
		return discoveryOutcome{ok: true, timedOut: true, found: r.count() - before}
	}
	r.logFn("info", "subdomain_enum", fmt.Sprintf("scilla found %d new subdomains", r.count()-before))
	return discoveryOutcome{ok: true, found: r.count() - before}
}

// runWaybackurls runs the waybackurls source (deep tier only).
func (r *discoveryRunner) runWaybackurls(budget time.Duration) discoveryOutcome {
	if !r.scanner.exec.IsToolAvailable("waybackurls") {
		return discoveryOutcome{}
	}
	r.logFn("info", "subdomain_enum", "Querying Wayback Machine...")
	tctx, tcancel := context.WithTimeout(r.ctx, budget)
	defer tcancel()
	result, err := r.scanner.exec.Run(tctx, "waybackurls", r.domain)
	if err != nil && r.ctx.Err() != nil {
		return discoveryOutcome{timedOut: r.ctx.Err() == context.DeadlineExceeded}
	}
	if err == nil {
		sc := bufio.NewScanner(strings.NewReader(result.Stdout))
		for sc.Scan() {
			if sub := extractSubdomain(sc.Text(), r.domain); sub != "" {
				r.store(sub)
			}
		}
	}
	if tctx.Err() == context.DeadlineExceeded {
		r.logFn("warn", "subdomain_enum", fmt.Sprintf("waybackurls hit its %s budget — PARTIAL results, total so far: %d", budgetLabel(budget), r.count()))
		return discoveryOutcome{ok: true, timedOut: true}
	}
	r.logFn("info", "subdomain_enum", fmt.Sprintf("waybackurls added, total: %d", r.count()))
	return discoveryOutcome{ok: true}
}

// runGAU runs the gau source (deep tier only).
func (r *discoveryRunner) runGAU(budget time.Duration) discoveryOutcome {
	if !r.scanner.exec.IsToolAvailable("gau") {
		return discoveryOutcome{}
	}
	r.logFn("info", "subdomain_enum", "Querying GAU (GetAllURLs)...")
	tctx, tcancel := context.WithTimeout(r.ctx, budget)
	defer tcancel()
	result, err := r.scanner.exec.Run(tctx, "gau", "--subs", r.domain)
	if err != nil && r.ctx.Err() != nil {
		return discoveryOutcome{timedOut: r.ctx.Err() == context.DeadlineExceeded}
	}
	if err == nil {
		sc := bufio.NewScanner(strings.NewReader(result.Stdout))
		for sc.Scan() {
			if sub := extractSubdomain(sc.Text(), r.domain); sub != "" {
				r.store(sub)
			}
		}
	}
	if tctx.Err() == context.DeadlineExceeded {
		r.logFn("warn", "subdomain_enum", fmt.Sprintf("gau hit its %s budget — PARTIAL results, total so far: %d", budgetLabel(budget), r.count()))
		return discoveryOutcome{ok: true, timedOut: true}
	}
	r.logFn("info", "subdomain_enum", fmt.Sprintf("gau added, total: %d", r.count()))
	return discoveryOutcome{ok: true}
}

// budgetLabel renders a source budget for the log lines.
func budgetLabel(d time.Duration) string {
	if d >= time.Minute {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	return fmt.Sprintf("%ds", int(d.Seconds()))
}

// discoverySource is one CLI source with its deep-tier budget.
type discoverySource struct {
	id     string
	budget time.Duration
	run    func(time.Duration) discoveryOutcome
}

// runDiscoverySources runs the CLI discovery sources.
//
// Deep tier: sequential, each source with its own historical budget.
// Watch tier: the ENABLED sources run CONCURRENTLY, each with the same
// per-source timeout (watchBudget). scilla, waybackurls and gau are deep-only.
//
// It returns (ok, total): how many sources ran cleanly and how many were
// enabled. The caller uses that to fail a watch round where EVERY enabled
// source failed (decision D66): a broken setup must not spin forever.
func (r *discoveryRunner) runDiscoverySources(watchMode bool, watchBudget time.Duration) (ok, total int) {
	sources := []discoverySource{
		{"subfinder", 4 * time.Minute, r.runSubfinder},
		{"assetfinder", 2 * time.Minute, r.runAssetfinder},
		{"findomain", 2 * time.Minute, r.runFindomain},
		{"chaos", 3 * time.Minute, r.runChaos},
		{"scilla", 3 * time.Minute, r.runScilla},
		{"waybackurls", 3 * time.Minute, r.runWaybackurls},
		{"gau", 3 * time.Minute, r.runGAU},
	}

	if !watchMode {
		// Deep tier: sequential, historical budgets, every source runs.
		for _, src := range sources {
			out := src.run(src.budget)
			if out.ok {
				ok++
			}
			total++
			if r.ctx.Err() != nil {
				return ok, total
			}
		}
		return ok, total
	}

	// Watch tier: only the enabled sources, run concurrently, each with the
	// per-source timeout.
	type job struct {
		src discoverySource
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	results := map[string]discoveryOutcome{}
	enabled := make([]discoverySource, 0, len(sources))
	for _, src := range sources {
		if !watchOnlySourceIds[src.id] {
			// Deep-only source (scilla, waybackurls, gau).
			continue
		}
		if !watchSourceEnabled(r.ctx, src.id) {
			r.logFn("info", "subdomain_enum", fmt.Sprintf("%s skipped: disabled by operator", src.id))
			continue
		}
		enabled = append(enabled, src)
	}
	for _, src := range enabled {
		wg.Add(1)
		go func(j job) {
			defer wg.Done()
			out := j.src.run(watchBudget)
			mu.Lock()
			results[j.src.id] = out
			mu.Unlock()
		}(job{src})
	}
	wg.Wait()
	for _, src := range enabled {
		out := results[src.id]
		if out.ok {
			ok++
		}
		total++
	}
	return ok, total
}
