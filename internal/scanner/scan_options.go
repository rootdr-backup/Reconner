package scanner

import (
	"context"
	"net"
	"net/url"
	"strings"
)

// Per-scan toggles carried on the scan context (set by the scheduler from the
// scan request's pseudo-modules, the same channel as the speed profile). Each
// defaults to the historical behaviour when unset, so an older client that sends
// no toggle is unaffected.

type subBruteKey string

const ctxSubBrute subBruteKey = "subdomain_brute"

// WithSubdomainBrute toggles the SLOW active phase of subdomain enumeration —
// wordlist brute-force + permutation generation (activeEnum) and the deep
// alterx/puredns/massdns pass (deepDNSEnum). Passive sources, resolution, ASN and
// vhost discovery always run. Operators disable it per scan when they only want a
// fast passive map (it is by far the longest part of enumeration).
func WithSubdomainBrute(ctx context.Context, enabled bool) context.Context {
	return context.WithValue(ctx, ctxSubBrute, enabled)
}

// subdomainBruteEnabled reports whether the slow brute/permutation phase should
// run. Defaults to TRUE when unset (preserves existing behaviour).
func subdomainBruteEnabled(ctx context.Context) bool {
	if v, ok := ctx.Value(ctxSubBrute).(bool); ok {
		return v
	}
	return true
}

// ── Single-endpoint scan mode ────────────────────────────────────────────────
//
// When the operator scans a single URL and ticks "single endpoint", the whole
// pipeline is confined to THAT url and the paths under it: crawling stays under
// the seed's directory prefix, discovery never wanders to sibling paths or other
// hosts, and every discovered surface (parameters, http_services, JS) is filtered
// to the endpoint scope before any module consumes it. The seed URL's own query
// AND path parameters are always in scope. Off by default (unset ⇒ full scan).

type endpointScopeKey string

const ctxEndpointScope endpointScopeKey = "endpoint_scope"

// WithEndpointScope confines the scan to the given seed URL prefixes (each is a
// full URL; its host + directory path becomes the allowed prefix). An empty list
// clears confinement.
func WithEndpointScope(ctx context.Context, seedURLs []string) context.Context {
	var prefixes []string
	for _, u := range seedURLs {
		if p := endpointPrefix(u); p != "" {
			prefixes = append(prefixes, p)
		}
	}
	if len(prefixes) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxEndpointScope, prefixes)
}

// endpointScopePrefixes returns the confinement prefixes, or nil when the scan is
// not in single-endpoint mode.
func endpointScopePrefixes(ctx context.Context) []string {
	if v, ok := ctx.Value(ctxEndpointScope).([]string); ok {
		return v
	}
	return nil
}

// endpointPrefix reduces a URL to its confinement prefix: lowercased host + the
// directory portion of the path (everything up to and including the last '/').
// e.g. https://x.com/a/b?q=1 → "x.com/a/"  and  https://x.com/a/b/ → "x.com/a/b/".
func endpointPrefix(raw string) string {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" {
		return ""
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	if !strings.HasSuffix(path, "/") {
		if i := strings.LastIndexByte(path, '/'); i >= 0 {
			path = path[:i+1]
		} else {
			path = "/"
		}
	}
	return strings.ToLower(u.Host) + path
}

// urlInEndpointScope reports whether rawURL falls under any confinement prefix.
// When there are no prefixes (not single-endpoint mode) everything is in scope.
func urlInEndpointScope(ctx context.Context, rawURL string) bool {
	prefixes := endpointScopePrefixes(ctx)
	if len(prefixes) == 0 {
		return true
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
	hostPath := strings.ToLower(u.Host) + u.Path
	for _, p := range prefixes {
		if strings.HasPrefix(hostPath, p) {
			return true
		}
	}
	return false
}
// ── Per-asset host scope ─────────────────────────────────────────────────────
// When the operator scans a single asset (scope_override), the pipeline is
// confined to that asset's host(s). Unset ⇒ full target (no confinement).

type hostScopeKey string

const ctxHostScope hostScopeKey = "host_scope"

// WithHostScope confines the scan to the given hostnames (exact, lowercased).
func WithHostScope(ctx context.Context, hosts []string) context.Context {
	set := map[string]bool{}
	for _, h := range hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		h = strings.TrimSuffix(h, ".")
		if h == "" {
			continue
		}
		if hh, _, err := net.SplitHostPort(h); err == nil {
			h = hh
		}
		set[h] = true
	}
	if len(set) == 0 {
		return ctx
	}
	return context.WithValue(ctx, ctxHostScope, set)
}

func hostScopeSet(ctx context.Context) map[string]bool {
	if v, ok := ctx.Value(ctxHostScope).(map[string]bool); ok {
		return v
	}
	return nil
}

// hostInScope reports whether host is allowed. Unset scope ⇒ everything in scope.
func hostInScope(ctx context.Context, host string) bool {
	set := hostScopeSet(ctx)
	if set == nil {
		return true
	}
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return set[host]
}

// urlHostInScope extracts the host from rawURL and checks hostInScope.
func urlHostInScope(ctx context.Context, rawURL string) bool {
	if hostScopeSet(ctx) == nil {
		return true
	}
	u, err := url.Parse(strings.TrimSpace(rawURL))
	if err != nil || u.Host == "" {
		return false
	}
		return hostInScope(ctx, u.Host)
}

// filterURLsByHostScope drops URLs whose host is outside the per-asset scope.
// No-op when host scope is unset (full-target scan).
func filterURLsByHostScope(ctx context.Context, urls []string) []string {
	if hostScopeSet(ctx) == nil || len(urls) == 0 {
		return urls
	}
	kept := urls[:0]
	for _, u := range urls {
		if urlHostInScope(ctx, u) {
			kept = append(kept, u)
		}
	}
	return kept
}

// filterHostsByHostScope drops bare hostnames outside the per-asset scope.
func filterHostsByHostScope(ctx context.Context, hosts []string) []string {
	if hostScopeSet(ctx) == nil || len(hosts) == 0 {
		return hosts
	}
	kept := hosts[:0]
	for _, h := range hosts {
		if hostInScope(ctx, h) {
			kept = append(kept, h)
		}
	}
	return kept
}
