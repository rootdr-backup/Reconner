package scanner

import (
	"context"
	"net"
	"net/url"
	"strings"

	"github.com/recon-platform/internal/database"
)

// Out-of-scope exclusions (bug-bounty). A target's exclude_scope is a
// comma/newline list of things that must NEVER be scanned even though they sit
// under the target: exact hosts, wildcard suffixes (*.dev.example.com or
// .dev.example.com), IPs, CIDRs, or full URLs (host is extracted). Enforced at
// subdomain storage — the single choke point the whole web pipeline reads from —
// so an excluded asset never gets probed, fuzzed, or reported.

// ExclusionSet is a compiled, fast-to-query set of exclusions for one target.
type ExclusionSet struct {
	hosts    map[string]bool // exact hostnames / IPs (normalized)
	suffixes []string        // wildcard suffixes, stored as ".example.com"
	cidrs    []*net.IPNet
}

// Empty reports whether nothing is excluded (lets callers skip the check cheaply).
func (e ExclusionSet) Empty() bool {
	return len(e.hosts) == 0 && len(e.suffixes) == 0 && len(e.cidrs) == 0
}

// ParseExclusions compiles a raw exclude_scope string into an ExclusionSet.
func ParseExclusions(raw string) ExclusionSet {
	e := ExclusionSet{hosts: map[string]bool{}}
	for _, tok := range strings.FieldsFunc(raw, func(r rune) bool {
		return r == ',' || r == ' ' || r == '\n' || r == '\t' || r == '\r' || r == ';'
	}) {
		tok = strings.TrimSpace(tok)
		if tok == "" {
			continue
		}
		// A URL → keep only its host.
		if strings.Contains(tok, "://") {
			if u, err := url.Parse(tok); err == nil && u.Hostname() != "" {
				tok = u.Hostname()
			}
		}
		tok = strings.ToLower(strings.Trim(tok, "."))
		// CIDR
		if strings.Contains(tok, "/") {
			if _, n, err := net.ParseCIDR(tok); err == nil {
				e.cidrs = append(e.cidrs, n)
				continue
			}
		}
		// Wildcard suffix: "*.x" or a leading-dot form → match host and any subdomain.
		if strings.HasPrefix(tok, "*.") {
			suf := strings.TrimPrefix(tok, "*.")
			if suf != "" {
				e.hosts[suf] = true // the apex itself
				e.suffixes = append(e.suffixes, "."+suf)
			}
			continue
		}
		e.hosts[tok] = true
	}
	return e
}

// Excludes reports whether host (a hostname or IP) is out of scope.
func (e ExclusionSet) Excludes(host string) bool {
	if e.Empty() {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(host), "."))
	if host == "" {
		return false
	}
	// strip a :port if present (keeps IPv6 in brackets working)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	if e.hosts[host] {
		return true
	}
	for _, suf := range e.suffixes {
		if strings.HasSuffix(host, suf) {
			return true
		}
	}
	if len(e.cidrs) > 0 {
		if ip := net.ParseIP(host); ip != nil {
			for _, n := range e.cidrs {
				if n.Contains(ip) {
					return true
				}
			}
		}
	}
	return false
}

// FilterExcludedIPs drops every IP that falls under the target's exclusions
// (exact IP or an excluded CIDR), returning the kept list and how many were
// removed — so a network scan never probes an out-of-scope IP inside an
// otherwise in-scope range.
func FilterExcludedIPs(ips []string, e ExclusionSet) (kept []string, dropped int) {
	if e.Empty() {
		return ips, 0
	}
	kept = ips[:0]
	for _, ip := range ips {
		if e.Excludes(ip) {
			dropped++
			continue
		}
		kept = append(kept, ip)
	}
	return kept, dropped
}

// LoadExclusions reads and compiles a target's exclude_scope.
func LoadExclusions(ctx context.Context, db *database.DB, targetID string) ExclusionSet {
	var raw string
	_ = db.QueryRowContext(ctx, `SELECT COALESCE(exclude_scope,'') FROM targets WHERE id=?`, targetID).Scan(&raw)
	return ParseExclusions(raw)
}
