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

	havePuredns := s.exec.IsToolAvailable("puredns")
	haveAlterx := s.exec.IsToolAvailable("alterx")
	if !havePuredns && !haveAlterx {
		return
	}

	// Build the candidate set: bruteWords + alterx permutations of known names.
	candidates := make(map[string]bool)

	if haveAlterx {
		logFn("info", "subdomain_enum", "Generating permutations with alterx...")
		mu.Lock()
		var known []string
		for n := range found {
			if strings.HasSuffix(n, "."+domain) {
				known = append(known, n)
			}
		}
		mu.Unlock()
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

	// puredns brute-forces the built-in wordlist against the domain at scale.
	if havePuredns {
		resolved, err := s.purednsBruteforce(ctx, targetID, domain, logFn)
		if err == nil {
			for _, n := range resolved {
				if isValidSubdomain(n, domain) {
					mu.Lock()
					isNew := !found[n]
					found[n] = true
					mu.Unlock()
					if isNew {
						ip := resolveHost(n)
						if ip != "" && !wildcardIPs[ip] {
							_ = s.upsertSubdomain(targetID, n, ip)
						}
					}
				}
			}
		}
	}

	// Resolve the alterx candidates (puredns already resolved its own output).
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

	// If puredns is available, use it to resolve the permutation list fast;
	// otherwise fall back to the built-in resolver worker pool.
	if havePuredns {
		resolved := s.purednsResolve(ctx, targetID, names, logFn)
		for _, n := range resolved {
			mu.Lock()
			isNew := !found[n]
			found[n] = true
			mu.Unlock()
			if isNew {
				ip := resolveHost(n)
				if ip != "" && !wildcardIPs[ip] {
					_ = s.upsertSubdomain(targetID, n, ip)
				}
			}
		}
		logFn("info", "subdomain_enum", fmt.Sprintf("puredns resolved %d/%d permutation candidates", len(resolved), len(names)))
		return
	}

	s.resolveCandidates(ctx, targetID, names, found, mu, wildcardIPs, logFn)
}

// purednsBruteforce runs `puredns bruteforce <wordlist> <domain>` with a
// generated resolvers file, returning the resolved hostnames.
func (s *SubdomainScanner) purednsBruteforce(ctx context.Context, targetID, domain string, logFn LogFunc) ([]string, error) {
	wordFile, err := writeTempLines("recon-words-", bruteWords)
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
				ip := resolveHost(name)
				if ip == "" || wildcardIPs[ip] {
					continue
				}
				mu.Lock()
				isNew := !found[name]
				found[name] = true
				mu.Unlock()
				if isNew {
					_ = s.upsertSubdomain(targetID, name, ip)
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
