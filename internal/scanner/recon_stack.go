package scanner

import (
	"bufio"
	"context"
	"fmt"
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

// publicResolvers is a small trustworthy resolver set used when the host has no
// resolvers file of its own. puredns/massdns need resolvers to run at scale.
var publicResolvers = []string{
	"1.1.1.1", "1.0.0.1", // Cloudflare
	"8.8.8.8", "8.8.4.4", // Google
	"9.9.9.9", "149.112.112.112", // Quad9
	"208.67.222.222", "208.67.220.220", // OpenDNS
	"64.6.64.6", "64.6.65.6", // Verisign
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
			var out []string
			err := s.exec.RunWithInputCallback(ctx, strings.NewReader(strings.Join(known, "\n")), targetID,
				func(line string) {
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
			logFn("info", "subdomain_enum", fmt.Sprintf("alterx produced %d permutation candidates", len(out)))
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
		for _, n := range resolved {
			mu.Lock()
			found[n] = true
			mu.Unlock()
			ip := firstNonWildcardIP(resolveHostIPs(ctx, n), wildcardIPs)
			if ip != "" {
				_ = s.upsertSubdomain(targetID, n, ip)
			}
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
	workers := s.cfg.Workers.SubdomainEnumeration
	if workers <= 0 {
		workers = 50
	}
	if workers > 200 {
		workers = 200
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
		}, "dnsx", "-silent", "-retry", "2", "-t", fmt.Sprint(workers))
	return out
}

// purednsBruteforce runs `puredns bruteforce <wordlist> <domain>` with a
// generated resolvers file, returning the resolved hostnames.
func (s *SubdomainScanner) purednsBruteforce(ctx context.Context, targetID, domain string, logFn LogFunc) ([]string, error) {
	wordFile, err := writeTempLines("recon-words-", s.deepDNSWords(ctx, domain, nil))
	if err != nil {
		return nil, err
	}
	defer os.Remove(wordFile)
	resolverFile, err := writeTempLines("recon-resolvers-", publicResolvers)
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
	resolverFile, err := writeTempLines("recon-resolvers-", publicResolvers)
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
