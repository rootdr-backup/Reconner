package scanner

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"
)

// This file ports WM6's deeper ProjectDiscovery-grade recon chain into
// Reconner. Every integration is OPTIONAL and skips gracefully when the
// external tool isn't installed — matching the existing tool pattern.
//
//   - alterx           → permutation generation from known subdomains
//   - puredns / massdns → DNS brute-force at scale (with public resolvers)
//   - waymore          → deep historical URL harvesting (far past gau/wayback)
//
// naabu (port scanning) and shodan (third-party intel) live in their own
// modules (portscan.go, shodan.go) since they produce different result types.

// publicResolvers is the fallback resolver set used only when no config is
// available (e.g. a test constructing the scanner without a Config).
// puredns/massdns need a resolvers file to run at scale. Normal runs use the
// operator-configured list via toolResolverList().
var publicResolvers = []string{
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"8.8.8.8", "8.8.4.4", // Google
	"9.9.9.9", "149.112.112.112", // Quad9
	"208.67.222.222", "208.67.220.220", // OpenDNS
	"64.6.64.6", "64.6.65.6", // Verisign
}

// toolResolverList returns the operator-configured DNS resolvers (or the public
// default set) as bare host / host:port entries suitable for a dnsx/puredns/
// massdns -r resolvers file. The default :53 port is stripped since those tools
// expect bare IPs; a non-standard port is preserved. This is the SAME list the
// in-process Go resolver (s.resolver) uses, so the fast-public-resolver path is
// consistent across the native resolution gate and the external brute tools.
func (s *SubdomainScanner) toolResolverList() []string {
	if s.cfg != nil {
		if list := s.cfg.DNSResolverList(); len(list) > 0 {
			out := make([]string, 0, len(list))
			for _, r := range list {
				out = append(out, strings.TrimSuffix(r, ":53"))
			}
			return out
		}
	}
	return publicResolvers
}

// deepDNSEnum runs the heavy DNS discovery chain (alterx permutations +
// puredns/massdns brute) on top of the built-in active enum. It only adds
// names that actually resolve and aren't wildcard answers.
func (s *SubdomainScanner) deepDNSEnum(ctx context.Context, targetID, domain string, found map[string]bool, mu *sync.Mutex, wildcardIPs map[string]bool, logFn LogFunc) {
	if len(wildcardIPs) > 0 {
		return // wildcard domains: brute is meaningless, skip
	}

	haveDNSX := s.exec.IsToolAvailable("dnsx")
	havePuredns := s.exec.IsToolAvailable("puredns")
	haveAlterx := s.exec.IsToolAvailable("alterx")

	// Build an adaptive large candidate set: curated infrastructure/dev-tool names,
	// environment and numeric mutations, labels learned from this target, optional
	// operator wordlists, and alterx output. Resolution remains the admission gate.
	candidates := make(map[string]bool)
	knownSnapshot := s.admittedSubdomainNames(ctx, targetID, domain)
	words := s.deepDNSWords(ctx, domain, knownSnapshot)
	for _, word := range words {
		name := strings.ToLower(strings.TrimSpace(word))
		if !strings.HasSuffix(name, "."+domain) {
			name += "." + domain
		}
		if isValidSubdomain(name, domain) {
			candidates[name] = true
		}
	}
	logFn("info", "subdomain_enum", fmt.Sprintf("Adaptive DNS wordlist: %d candidates (curated + target-derived + custom)", len(candidates)))

	if haveAlterx {
		logFn("info", "subdomain_enum", "Generating permutations with alterx...")
		known := knownSnapshot
		if len(known) > 0 {
			// Bound alterx output. Its permutation count grows multiplicatively with
			// the number of known names, so a target that already has a few hundred
			// subdomains can make alterx emit hundreds of thousands to millions of
			// candidates — the dominant cause of a scan ballooning (and, if an
			// undetected catch-all admits them, of the dashboard filling with junk
			// names). The cap keeps the adaptive brute large but finite.
			const alterxMaxPermutations = 150000
			var out []string
			capped := false
			err := s.exec.RunWithInputCallback(ctx, strings.NewReader(strings.Join(known, "\n")), targetID,
				func(line string) {
					if len(out) >= alterxMaxPermutations {
						capped = true
						return
					}
					line = strings.ToLower(strings.TrimSpace(line))
					if isValidSubdomain(line, domain) {
						out = append(out, line)
					}
				}, "alterx", "-silent")
			if err != nil && ctx.Err() != nil {
				return
			}
			for _, n := range out {
				candidates[n] = true
			}
			if capped {
				logFn("warn", "subdomain_enum", fmt.Sprintf("alterx permutation output capped at %d (target has %d known names) — brute set bounded", alterxMaxPermutations, len(known)))
			} else {
				logFn("info", "subdomain_enum", fmt.Sprintf("alterx produced %d permutation candidates", len(out)))
			}
		}
	}

	// Resolve the complete candidate graph once. dnsx is preferred because it is
	// bundled and fast; puredns and the native bounded pool are fallbacks.
	if len(candidates) == 0 {
		return
	}
	mu.Lock()
	for n := range found {
		delete(candidates, n)
	}
	mu.Unlock()

	names := make([]string, 0, len(candidates))
	for n := range candidates {
		names = append(names, n)
	}

	if haveDNSX || havePuredns {
		var resolved []string
		engine := "puredns"
		if haveDNSX {
			engine = "dnsx"
			resolved = s.dnsxResolve(ctx, targetID, names)
		} else {
			resolved = s.purednsResolve(ctx, targetID, names, logFn)
		}
		// Catch-all guard. These are RANDOM permutation/wordlist candidates, so on a
		// normal zone only a tiny fraction should resolve. A high hit rate across a
		// large candidate set means the zone answers everything (a wildcard/catch-all
		// that detectWildcard's few random probes missed — rotating or partial
		// wildcards do slip through). Admitting those would flood the target with
		// hundreds of junk "subdomains" that are all the same catch-all host — the
		// exact alterx-explosion symptom. Discard the batch instead.
		if len(names) >= 200 && len(resolved)*100 >= len(names)*60 {
			logFn("warn", "subdomain_enum", fmt.Sprintf("%s: %d/%d adaptive candidates resolved (%.0f%%) — catch-all/wildcard zone, discarding permutation batch to avoid junk flood", engine, len(resolved), len(names), float64(len(resolved))*100/float64(len(names))))
			return
		}
		for _, n := range resolved {
			ip := firstNonWildcardIP(resolveHostIPs(ctx, n, s.resolver), wildcardIPs)
			if ip == "" {
				continue // wildcard-only or unresolved on recheck — not an asset
			}
			mu.Lock()
			found[n] = true
			mu.Unlock()
			_ = s.upsertSubdomain(targetID, n, ip)
		}
		logFn("info", "subdomain_enum", fmt.Sprintf("%s resolved %d/%d adaptive candidates", engine, len(resolved), len(names)))
		return
	}

	s.resolveCandidates(ctx, targetID, names, found, mu, wildcardIPs, logFn)
}

// dnsxResolve performs only DNS resolution; every returned name is subsequently
// checked again by Reconner's wildcard-aware admission gate before storage.
func (s *SubdomainScanner) dnsxResolve(ctx context.Context, targetID string, names []string) []string {
	if len(names) == 0 {
		return nil
	}
	// Concurrency floor: a mass adaptive brute is tens of thousands of cheap DNS
	// queries. dnsx handles a high thread count comfortably, so floor it well
	// above the generic 50 default — resolving 30k permutation candidates at 50
	// threads through the system resolver was taking ~15 minutes (≈33/s).
	workers := s.cfg.Workers.SubdomainEnumeration
	if workers < 150 {
		workers = 150
	}
	if workers > 400 {
		workers = 400
	}
	args := []string{"-silent", "-retry", "2", "-t", fmt.Sprint(workers)}
	// The single biggest dnsx speedup: resolve against many fast PUBLIC resolvers
	// in parallel instead of the one (often slow/rate-limited) system resolver.
	// Same candidate set and the wildcard-aware admission gate still re-checks
	// every hit, so this only changes throughput, not which names are accepted.
	if resolverFile, err := writeTempLines("recon-dnsx-resolvers-", s.toolResolverList()); err == nil {
		defer os.Remove(resolverFile)
		args = append(args, "-r", resolverFile)
	}
	seen := map[string]bool{}
	var out []string
	_ = s.exec.RunWithInputCallback(ctx, strings.NewReader(strings.Join(names, "\n")), targetID,
		func(line string) {
			// dnsx plain output is the input hostname. Be defensive around versions
			// that append record data after whitespace.
			fields := strings.Fields(strings.ToLower(strings.TrimSpace(line)))
			if len(fields) == 0 {
				return
			}
			name := strings.TrimSuffix(fields[0], ".")
			if !seen[name] {
				seen[name] = true
				out = append(out, name)
			}
		}, "dnsx", args...)
	return out
}

// dnsxResolveIPs batch-resolves the A/AAAA record sets of a large candidate
// list in a single dnsx run and returns name -> every answer IP as canonical
// net.ParseIP strings, so comparisons against Go-resolver wildcard-probe IPs
// stay string-identical. A nil map means dnsx was unavailable or failed while
// the context was still live — the caller must run the legacy per-name path
// and must never treat nil as "everything unresolved".
func (s *SubdomainScanner) dnsxResolveIPs(ctx context.Context, targetID string, names []string) map[string][]string {
	if s.exec == nil || len(names) == 0 || !s.exec.IsToolAvailable("dnsx") {
		return nil
	}
	// Concurrency floor, mirroring dnsxResolve: a 20k-name admission pass at
	// the generic low -t crawls; dnsx handles a high thread count comfortably.
	workers := s.cfg.Workers.SubdomainEnumeration
	if workers < 150 {
		workers = 150
	}
	if workers > 400 {
		workers = 400
	}
	args := []string{"-silent", "-a", "-aaaa", "-resp", "-retry", "2", "-t", fmt.Sprint(workers)}
	// Same resolver file contract as every other dnsx pass: the operator list
	// (or the public default) — the SAME list the in-process s.resolver
	// round-robins, so answers and wildcard probes share one resolver source.
	if resolverFile, err := writeTempLines("recon-dnsx-aresp-resolvers-", s.toolResolverList()); err == nil {
		defer os.Remove(resolverFile)
		args = append(args, "-r", resolverFile)
	}
	out := map[string][]string{}
	err := s.exec.RunWithInputCallback(ctx, strings.NewReader(strings.Join(names, "\n")), targetID,
		func(line string) {
			name, toks := parseDNSXResponseLine(line)
			if name == "" {
				return
			}
			ips := make([]string, 0, len(toks))
			for _, tok := range toks {
				if ip := net.ParseIP(tok); ip != nil {
					ips = append(ips, ip.String())
				}
			}
			// dnsx can emit one -resp line per record type for the same name;
			// merge so an A-only or AAAA-only second line is never lost.
			if len(ips) > 0 {
				out[name] = append(out[name], ips...)
			}
		}, "dnsx", args...)
	if err != nil && ctx.Err() == nil {
		return nil
	}
	return out
}

// parseDNSXResponseLine splits one dnsx `-resp` output line into the hostname
// and the bracket-group tokens — separators and trailing dots stripped, lower
// cased:
//
//	sub.example.com [93.184.216.34, 2606:2800:220:1:248:1893:25c8:1946]
//	www.example.com [example.edge.cdn.net]
//
// Tokens come back as raw text; IP-vs-CNAME validation is the caller's
// concern. Lines without a usable bracket group parse as ("", nil).
func parseDNSXResponseLine(line string) (string, []string) {
	line = strings.TrimSpace(line)
	openBr := strings.Index(line, "[")
	closeBr := strings.LastIndex(line, "]")
	if openBr <= 0 || closeBr <= openBr {
		return "", nil
	}
	fields := strings.Fields(line[:openBr])
	if len(fields) == 0 {
		return "", nil
	}
	name := strings.TrimSuffix(strings.ToLower(fields[0]), ".")
	if name == "" {
		return "", nil
	}
	var toks []string
	for _, tok := range strings.FieldsFunc(line[openBr+1:closeBr], func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
		tok = strings.TrimSuffix(strings.ToLower(strings.Trim(tok, "[] \t")), ".")
		if tok != "" {
			toks = append(toks, tok)
		}
	}
	return name, toks
}

// purednsBruteforce runs `puredns bruteforce <wordlist> <domain>` with a
// generated resolvers file, returning the resolved hostnames.
func (s *SubdomainScanner) purednsBruteforce(ctx context.Context, targetID, domain string, logFn LogFunc) ([]string, error) {
	wordFile, err := writeTempLines("recon-words-", s.deepDNSWords(ctx, domain, nil))
	if err != nil {
		return nil, err
	}
	defer os.Remove(wordFile)
	resolverFile, err := writeTempLines("recon-resolvers-", s.toolResolverList())
	if err != nil {
		return nil, err
	}
	defer os.Remove(resolverFile)

	logFn("info", "subdomain_enum", "Running puredns brute-force...")
	var out []string
	err = s.exec.RunWithCallback(ctx, targetID, func(line string) {
		line = strings.ToLower(strings.TrimSpace(line))
		if line != "" {
			out = append(out, line)
		}
	}, "puredns", "bruteforce", wordFile, domain, "-r", resolverFile, "--quiet")
	if err != nil && ctx.Err() != nil {
		return nil, err
	}
	return out, nil
}

// purednsResolve resolves a list of candidate names with puredns.
func (s *SubdomainScanner) purednsResolve(ctx context.Context, targetID string, names []string, logFn LogFunc) []string {
	if len(names) == 0 {
		return nil
	}
	resolverFile, err := writeTempLines("recon-resolvers-", s.toolResolverList())
	if err != nil {
		return nil
	}
	defer os.Remove(resolverFile)

	var out []string
	err = s.exec.RunWithInputCallback(ctx, strings.NewReader(strings.Join(names, "\n")), targetID,
		func(line string) {
			line = strings.ToLower(strings.TrimSpace(line))
			if line != "" {
				out = append(out, line)
			}
		}, "puredns", "resolve", "-r", resolverFile, "--quiet")
	if err != nil && ctx.Err() != nil {
		return nil
	}
	return out
}

// resolveCandidates is the built-in fallback resolver pool for a name list.
func (s *SubdomainScanner) resolveCandidates(ctx context.Context, targetID string, names []string, found map[string]bool, mu *sync.Mutex, wildcardIPs map[string]bool, logFn LogFunc) {
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
				ip := firstNonWildcardIP(resolveHostIPs(ctx, name, s.resolver), wildcardIPs)
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
	logFn("info", "subdomain_enum", fmt.Sprintf("Resolved %d new hosts from %d permutation candidates", newFound, len(names)))
}

// writeTempLines writes lines to a temp file and returns its path.
func writeTempLines(prefix string, lines []string) (string, error) {
	f, err := os.CreateTemp("", prefix+"*.txt")
	if err != nil {
		return "", err
	}
	w := bufio.NewWriter(f)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	_ = w.Flush()
	_ = f.Close()
	return f.Name(), nil
}
